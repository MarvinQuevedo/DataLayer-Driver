use std::collections::HashMap;

use chia::bls::sign;
use chia::bls::verify;
use chia::bls::PublicKey;
use chia::bls::SecretKey;
use chia::bls::Signature;
use chia::clvm_traits::clvm_tuple;
use chia::clvm_traits::FromClvm;
use chia::clvm_traits::ToClvm;
use chia::clvm_utils::tree_hash;
use chia::clvm_utils::CurriedProgram;
use chia::consensus::consensus_constants::ConsensusConstants;
use chia::consensus::gen::flags::DONT_VALIDATE_SIGNATURE;
use chia::consensus::gen::{
    flags::MEMPOOL_MODE, owned_conditions::OwnedSpendBundleConditions,
    run_block_generator::run_block_generator, solution_generator::solution_generator,
    validation_error::ValidationErr,
};
use chia::protocol::CoinState;
use chia::protocol::{
    Bytes, Bytes32, Coin, CoinSpend, CoinStateFilters, RejectHeaderRequest, RequestBlockHeader,
    RequestFeeEstimates, RespondBlockHeader, RespondFeeEstimates, SpendBundle, TransactionAck,
};
use chia::puzzles::singleton::SINGLETON_LAUNCHER_PUZZLE_HASH;
use chia::puzzles::standard::StandardArgs;
use chia::puzzles::standard::StandardSolution;
use chia::puzzles::DeriveSynthetic;
use chia_wallet_sdk::announcement_id;
use chia_wallet_sdk::AggSigConstants;
use chia_wallet_sdk::CreateCoin;
use chia_wallet_sdk::Memos;
use chia_wallet_sdk::SpendWithConditions;
use chia_wallet_sdk::TESTNET11_CONSTANTS;
use chia_wallet_sdk::{
    get_merkle_tree, select_coins as select_coins_algo, ClientError, CoinSelectionError, Condition,
    Conditions, DataStore, DataStoreMetadata, DelegatedPuzzle, DriverError, Launcher, Layer,
    MeltSingleton, OracleLayer, Peer, RequiredSignature, SignerError, SpendContext, StandardLayer,
    UpdateDataStoreMerkleRoot, WriterLayer, MAINNET_CONSTANTS,
};
use clvmr::Allocator;
use hex_literal::hex;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::rust::ServerCoin;
use crate::server_coin::urls_from_conditions;
use crate::server_coin::MirrorArgs;
use crate::server_coin::MirrorExt;
use crate::server_coin::MirrorSolution;

/* echo -n 'datastore' | sha256sum */
pub const DATASTORE_LAUNCHER_HINT: Bytes32 = Bytes32::new(hex!(
    "
    aa7e5b234e1d55967bf0a316395a2eab6cb3370332c0f251f0e44a5afb84fc68
    "
));

#[derive(Clone, Debug)]
pub struct SuccessResponse {
    pub coin_spends: Vec<CoinSpend>,
    pub new_datastore: DataStore,
}

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("{0:?}")]
    Client(#[from] ClientError),

    #[error("RejectPuzzleState")]
    RejectPuzzleState,

    #[error("RejectCoinState")]
    RejectCoinState,

    #[error("RejectPuzzleSolution")]
    RejectPuzzleSolution,

    #[error("RejectHeaderRequest")]
    RejectHeaderRequest,

    #[error("{0:?}")]
    Driver(#[from] DriverError),

    #[error("ParseError")]
    Parse,

    #[error("UnknownCoin")]
    UnknownCoin,

    #[error("Clvm error")]
    Clvm,

    #[error("Permission error: puzzle can't perform this action")]
    Permission,

    #[error("Io error: {0}")]
    Io(std::io::Error),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationErr),

    #[error("Fee estimation rejection: {0}")]
    FeeEstimateRejection(String),
}

pub struct UnspentCoinStates {
    pub coin_states: Vec<CoinState>,
    pub last_height: u32,
    pub last_header_hash: Bytes32,
}

pub async fn get_unspent_coin_states(
    peer: &Peer,
    puzzle_hash: Bytes32,
    previous_height: Option<u32>,
    previous_header_hash: Bytes32,
    allow_hints: bool,
) -> Result<UnspentCoinStates, WalletError> {
    let mut coin_states = Vec::new();
    let mut last_height = previous_height.unwrap_or_default();

    let mut last_header_hash = previous_header_hash;

    loop {
        let response = peer
            .request_puzzle_state(
                vec![puzzle_hash],
                if last_height == 0 {
                    None
                } else {
                    Some(last_height)
                },
                last_header_hash,
                CoinStateFilters {
                    include_spent: false,
                    include_unspent: true,
                    include_hinted: allow_hints,
                    min_amount: 1,
                },
                false,
            )
            .await
            .map_err(WalletError::Client)?
            .map_err(|_| WalletError::RejectPuzzleState)?;

        last_height = response.height;
        last_header_hash = response.header_hash;
        coin_states.extend(
            response
                .coin_states
                .into_iter()
                .filter(|cs| cs.spent_height.is_none()),
        );

        if response.is_finished {
            break;
        }
    }

    Ok(UnspentCoinStates {
        coin_states,
        last_height,
        last_header_hash,
    })
}

pub fn select_coins(coins: Vec<Coin>, total_amount: u64) -> Result<Vec<Coin>, CoinSelectionError> {
    select_coins_algo(coins.into_iter().collect(), total_amount.into())
}

fn spend_coins_together(
    ctx: &mut SpendContext,
    synthetic_key: PublicKey,
    coins: &[Coin],
    extra_conditions: Conditions,
    output: i64,
    change_puzzle_hash: Bytes32,
) -> Result<(), WalletError> {
    let p2 = StandardLayer::new(synthetic_key);

    let change = i64::try_from(coins.iter().map(|coin| coin.amount).sum::<u64>()).unwrap() - output;
    assert!(change >= 0);
    let change = change as u64;

    let first_coin_id = coins[0].coin_id();

    for (i, &coin) in coins.iter().enumerate() {
        if i == 0 {
            let mut conditions = extra_conditions.clone();

            if change > 0 {
                conditions = conditions.create_coin(change_puzzle_hash, change, None);
            }

            p2.spend(ctx, coin, conditions)?;
        } else {
            p2.spend(
                ctx,
                coin,
                Conditions::new().assert_concurrent_spend(first_coin_id),
            )?;
        }
    }
    Ok(())
}

pub fn send_xch(
    synthetic_key: PublicKey,
    coins: &[Coin],
    outputs: &[(Bytes32, u64, Vec<Bytes>)],
    fee: u64,
) -> Result<Vec<CoinSpend>, WalletError> {
    let mut ctx = SpendContext::new();

    let mut conditions = Conditions::new().reserve_fee(fee);
    let mut total_amount = fee;

    for output in outputs {
        let memos = ctx.alloc(&output.2)?;
        conditions = conditions.create_coin(output.0, output.1, Some(Memos::new(memos)));
        total_amount += output.1;
    }

    spend_coins_together(
        &mut ctx,
        synthetic_key,
        coins,
        conditions,
        total_amount.try_into().unwrap(),
        StandardArgs::curry_tree_hash(synthetic_key).into(),
    )?;

    Ok(ctx.take())
}

pub fn create_server_coin(
    synthetic_key: PublicKey,
    selected_coins: Vec<Coin>,
    hint: Bytes32,
    uris: Vec<String>,
    amount: u64,
    fee: u64,
) -> Result<(Vec<CoinSpend>, ServerCoin), WalletError> {
    let puzzle_hash = StandardArgs::curry_tree_hash(synthetic_key).into();

    let mut memos = Vec::with_capacity(uris.len() + 1);
    memos.push(hint.to_vec());

    for url in &uris {
        memos.push(url.as_bytes().to_vec());
    }

    let mut ctx = SpendContext::new();

    let memos = ctx.alloc(&memos)?;

    let conditions = Conditions::new()
        .create_coin(
            MirrorArgs::curry_tree_hash().into(),
            amount,
            Some(Memos::new(memos)),
        )
        .reserve_fee(fee);

    spend_coins_together(
        &mut ctx,
        synthetic_key,
        &selected_coins,
        conditions,
        (amount + fee).try_into().unwrap(),
        puzzle_hash,
    )?;

    let server_coin = ServerCoin {
        coin: Coin::new(
            selected_coins[0].coin_id(),
            MirrorArgs::curry_tree_hash().into(),
            amount,
        ),
        p2_puzzle_hash: puzzle_hash,
        memo_urls: uris,
    };

    Ok((ctx.take(), server_coin))
}

pub async fn spend_server_coins(
    peer: &Peer,
    synthetic_key: PublicKey,
    selected_coins: Vec<Coin>,
    total_fee: u64,
    network: TargetNetwork,
) -> Result<Vec<CoinSpend>, WalletError> {
    let puzzle_hash = StandardArgs::curry_tree_hash(synthetic_key).into();

    let mut fee_coins = Vec::new();
    let mut server_coins = Vec::new();

    for coin in selected_coins {
        if coin.puzzle_hash == puzzle_hash {
            fee_coins.push(coin);
        } else {
            server_coins.push(coin);
        }
    }

    if server_coins.is_empty() {
        return Ok(Vec::new());
    }

    assert!(!fee_coins.is_empty());

    let parent_coins = peer
        .request_coin_state(
            server_coins.iter().map(|sc| sc.parent_coin_info).collect(),
            None,
            match network {
                TargetNetwork::Mainnet => MAINNET_CONSTANTS.genesis_challenge,
                TargetNetwork::Testnet11 => TESTNET11_CONSTANTS.genesis_challenge,
            },
            false,
        )
        .await?
        .map_err(|_| WalletError::RejectCoinState)?
        .coin_states;

    let mut ctx = SpendContext::new();

    let mirror_puzzle = ctx.mirror_puzzle()?;

    let puzzle_reveal = ctx.serialize(&CurriedProgram {
        program: mirror_puzzle,
        args: MirrorArgs::default(),
    })?;

    let mut conditions = Conditions::new().reserve_fee(total_fee);
    let mut total_fee: i64 = total_fee.try_into().unwrap();

    for server_coin in server_coins {
        let parent_coin = parent_coins
            .iter()
            .find(|cs| cs.coin.coin_id() == server_coin.parent_coin_info)
            .copied()
            .ok_or(WalletError::UnknownCoin)?;

        if parent_coin.coin.puzzle_hash != puzzle_hash {
            return Err(WalletError::Permission);
        }

        let parent_inner_puzzle = ctx.curry(StandardArgs::new(synthetic_key))?;

        let solution = ctx.serialize(&MirrorSolution {
            parent_parent_id: parent_coin.coin.parent_coin_info,
            parent_inner_puzzle,
            parent_amount: parent_coin.coin.amount,
            parent_solution: StandardSolution {
                original_public_key: None,
                delegated_puzzle: (),
                solution: (),
            },
        })?;

        total_fee -= i64::try_from(server_coin.amount).unwrap();
        ctx.insert(CoinSpend::new(server_coin, puzzle_reveal.clone(), solution));

        conditions = conditions.assert_concurrent_spend(server_coin.coin_id());
    }

    spend_coins_together(
        &mut ctx,
        synthetic_key,
        &fee_coins,
        conditions,
        total_fee,
        puzzle_hash,
    )?;

    Ok(ctx.take())
}

pub async fn fetch_server_coin(
    peer: &Peer,
    coin_state: CoinState,
    max_cost: u64,
) -> Result<ServerCoin, WalletError> {
    let Some(created_height) = coin_state.created_height else {
        return Err(WalletError::UnknownCoin);
    };

    let spend = peer
        .request_puzzle_and_solution(coin_state.coin.parent_coin_info, created_height)
        .await?
        .map_err(|_| WalletError::RejectPuzzleSolution)?;

    let mut allocator = Allocator::new();

    let Ok(output) = spend
        .puzzle
        .run(&mut allocator, 0, max_cost, &spend.solution)
    else {
        return Err(WalletError::Clvm);
    };

    let Ok(conditions) = Vec::<Condition>::from_clvm(&allocator, output.1) else {
        return Err(WalletError::Parse);
    };

    let Some(urls) = urls_from_conditions(&allocator, &coin_state.coin, &conditions) else {
        return Err(WalletError::Parse);
    };

    let puzzle = spend
        .puzzle
        .to_clvm(&mut allocator)
        .map_err(DriverError::ToClvm)?;

    Ok(ServerCoin {
        coin: coin_state.coin,
        p2_puzzle_hash: tree_hash(&allocator, puzzle).into(),
        memo_urls: urls,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn mint_store(
    minter_synthetic_key: PublicKey,
    selected_coins: Vec<Coin>,
    root_hash: Bytes32,
    label: Option<String>,
    description: Option<String>,
    bytes: Option<u64>,
    owner_puzzle_hash: Bytes32,
    delegated_puzzles: Vec<DelegatedPuzzle>,
    fee: u64,
) -> Result<SuccessResponse, WalletError> {
    let minter_puzzle_hash: Bytes32 = StandardArgs::curry_tree_hash(minter_synthetic_key).into();
    let total_amount_from_coins = selected_coins.iter().map(|c| c.amount).sum::<u64>();

    let total_amount = fee + 1;

    let mut ctx = SpendContext::new();

    let p2 = StandardLayer::new(minter_synthetic_key);

    let lead_coin = selected_coins[0];
    let lead_coin_name = lead_coin.coin_id();

    for coin in selected_coins.into_iter().skip(1) {
        p2.spend(
            &mut ctx,
            coin,
            Conditions::new().assert_concurrent_spend(lead_coin_name),
        )?;
    }

    let (launch_singleton, datastore) = Launcher::new(lead_coin_name, 1).mint_datastore(
        &mut ctx,
        DataStoreMetadata {
            root_hash,
            label,
            description,
            bytes,
        },
        owner_puzzle_hash.into(),
        delegated_puzzles,
    )?;

    // patch: add static hint to launcher
    let launch_singleton = Conditions::new().extend(
        launch_singleton
            .into_iter()
            .map(|cond| {
                if let Condition::CreateCoin(cc) = cond {
                    if cc.puzzle_hash == SINGLETON_LAUNCHER_PUZZLE_HASH.into() {
                        let hint = ctx.hint(DATASTORE_LAUNCHER_HINT)?;

                        return Ok(Condition::CreateCoin(CreateCoin {
                            puzzle_hash: cc.puzzle_hash,
                            amount: cc.amount,
                            memos: Some(hint),
                        }));
                    }

                    return Ok(Condition::CreateCoin(cc));
                }

                Ok(cond)
            })
            .collect::<Result<Vec<_>, WalletError>>()?,
    );

    let lead_coin_conditions = if total_amount_from_coins > total_amount {
        let hint = ctx.hint(minter_puzzle_hash)?;

        launch_singleton.create_coin(
            minter_puzzle_hash,
            total_amount_from_coins - total_amount,
            Some(hint),
        )
    } else {
        launch_singleton
    };
    p2.spend(&mut ctx, lead_coin, lead_coin_conditions)?;

    Ok(SuccessResponse {
        coin_spends: ctx.take(),
        new_datastore: datastore,
    })
}

pub struct SyncStoreResponse {
    pub latest_store: DataStore,
    pub latest_height: u32,
    pub root_hash_history: Option<Vec<(Bytes32, u64)>>,
}

pub async fn sync_store(
    peer: &Peer,
    store: &DataStore,
    last_height: Option<u32>,
    last_header_hash: Bytes32,
    with_history: bool,
) -> Result<SyncStoreResponse, WalletError> {
    let mut latest_store = store.clone();
    let mut history = vec![];

    let response = peer
        .request_coin_state(
            vec![store.coin.coin_id()],
            last_height,
            last_header_hash,
            false,
        )
        .await
        .map_err(WalletError::Client)?
        .map_err(|_| WalletError::RejectCoinState)?;
    let mut last_coin_record = response
        .coin_states
        .into_iter()
        .next()
        .ok_or(WalletError::UnknownCoin)?;

    let mut ctx = SpendContext::new(); // just to run puzzles more easily

    while last_coin_record.spent_height.is_some() {
        let puzzle_and_solution_req = peer
            .request_puzzle_and_solution(
                last_coin_record.coin.coin_id(),
                last_coin_record.spent_height.unwrap(),
            )
            .await
            .map_err(WalletError::Client)?
            .map_err(|_| WalletError::RejectPuzzleSolution)?;

        let cs = CoinSpend {
            coin: last_coin_record.coin,
            puzzle_reveal: puzzle_and_solution_req.puzzle,
            solution: puzzle_and_solution_req.solution,
        };

        let new_store = DataStore::<DataStoreMetadata>::from_spend(
            &mut ctx.allocator,
            &cs,
            &latest_store.info.delegated_puzzles,
        )
        .map_err(|_| WalletError::Parse)?
        .ok_or(WalletError::Parse)?;

        if with_history {
            let resp: Result<RespondBlockHeader, RejectHeaderRequest> = peer
                .request_fallible(RequestBlockHeader {
                    height: last_coin_record.spent_height.unwrap(),
                })
                .await
                .map_err(WalletError::Client)?;
            let block_header = resp.map_err(|_| WalletError::RejectHeaderRequest)?;

            history.push((
                new_store.info.metadata.root_hash,
                block_header
                    .header_block
                    .foliage_transaction_block
                    .unwrap()
                    .timestamp,
            ));
        }

        let response = peer
            .request_coin_state(
                vec![new_store.coin.coin_id()],
                last_height,
                last_header_hash,
                false,
            )
            .await
            .map_err(WalletError::Client)?
            .map_err(|_| WalletError::RejectCoinState)?;

        last_coin_record = response
            .coin_states
            .into_iter()
            .next()
            .ok_or(WalletError::UnknownCoin)?;
        latest_store = new_store;
    }

    Ok(SyncStoreResponse {
        latest_store,
        latest_height: last_coin_record
            .created_height
            .ok_or(WalletError::UnknownCoin)?,
        root_hash_history: if with_history { Some(history) } else { None },
    })
}

pub async fn sync_store_using_launcher_id(
    peer: &Peer,
    launcher_id: Bytes32,
    last_height: Option<u32>,
    last_header_hash: Bytes32,
    with_history: bool,
) -> Result<SyncStoreResponse, WalletError> {
    let response = peer
        .request_coin_state(vec![launcher_id], last_height, last_header_hash, false)
        .await
        .map_err(WalletError::Client)?
        .map_err(|_| WalletError::RejectCoinState)?;
    let last_coin_record = response
        .coin_states
        .into_iter()
        .next()
        .ok_or(WalletError::UnknownCoin)?;

    let mut ctx = SpendContext::new(); // just to run puzzles more easily

    let puzzle_and_solution_req = peer
        .request_puzzle_and_solution(
            last_coin_record.coin.coin_id(),
            last_coin_record
                .spent_height
                .ok_or(WalletError::UnknownCoin)?,
        )
        .await
        .map_err(WalletError::Client)?
        .map_err(|_| WalletError::RejectPuzzleSolution)?;

    let cs = CoinSpend {
        coin: last_coin_record.coin,
        puzzle_reveal: puzzle_and_solution_req.puzzle,
        solution: puzzle_and_solution_req.solution,
    };

    let first_store = DataStore::<DataStoreMetadata>::from_spend(&mut ctx.allocator, &cs, &[])
        .map_err(|_| WalletError::Parse)?
        .ok_or(WalletError::Parse)?;

    let res = sync_store(
        peer,
        &first_store,
        last_height,
        last_header_hash,
        with_history,
    )
    .await?;

    // prepend root hash from launch
    let root_hash_history = if let Some(mut res_root_hash_history) = res.root_hash_history {
        let spent_timestamp = if let Some(spent_height) = last_coin_record.spent_height {
            let resp: Result<RespondBlockHeader, RejectHeaderRequest> = peer
                .request_fallible(RequestBlockHeader {
                    height: spent_height,
                })
                .await
                .map_err(WalletError::Client)?;
            let resp = resp.map_err(|_| WalletError::RejectHeaderRequest)?;

            resp.header_block
                .foliage_transaction_block
                .unwrap()
                .timestamp
        } else {
            0
        };

        res_root_hash_history.insert(0, (first_store.info.metadata.root_hash, spent_timestamp));
        Some(res_root_hash_history)
    } else {
        None
    };

    Ok(SyncStoreResponse {
        latest_store: res.latest_store,
        latest_height: res.latest_height,
        root_hash_history,
    })
}

pub async fn get_store_creation_height(
    peer: &Peer,
    launcher_id: Bytes32,
    last_height: Option<u32>,
    last_header_hash: Bytes32,
) -> Result<u32, WalletError> {
    let response = peer
        .request_coin_state(vec![launcher_id], last_height, last_header_hash, false)
        .await
        .map_err(WalletError::Client)?
        .map_err(|_| WalletError::RejectCoinState)?;
    let last_coin_record = response
        .coin_states
        .into_iter()
        .next()
        .ok_or(WalletError::UnknownCoin)?;

    last_coin_record
        .created_height
        .ok_or(WalletError::UnknownCoin)
}

pub enum DataStoreInnerSpend {
    Owner(PublicKey),
    Admin(PublicKey),
    Writer(PublicKey),
    // does not include oracle since it can't change metadata/owners :(
}

fn update_store_with_conditions(
    ctx: &mut SpendContext,
    conditions: Conditions,
    datastore: DataStore,
    inner_spend_info: DataStoreInnerSpend,
    allow_admin: bool,
    allow_writer: bool,
) -> Result<SuccessResponse, WalletError> {
    let inner_datastore_spend = match inner_spend_info {
        DataStoreInnerSpend::Owner(pk) => {
            StandardLayer::new(pk).spend_with_conditions(ctx, conditions)?
        }
        DataStoreInnerSpend::Admin(pk) => {
            if !allow_admin {
                return Err(WalletError::Permission);
            }

            StandardLayer::new(pk).spend_with_conditions(ctx, conditions)?
        }
        DataStoreInnerSpend::Writer(pk) => {
            if !allow_writer {
                return Err(WalletError::Permission);
            }

            WriterLayer::new(StandardLayer::new(pk)).spend(ctx, conditions)?
        }
    };

    let parent_delegated_puzzles = datastore.info.delegated_puzzles.clone();
    let new_spend = datastore.spend(ctx, inner_datastore_spend)?;

    let new_datastore = DataStore::<DataStoreMetadata>::from_spend(
        &mut ctx.allocator,
        &new_spend,
        &parent_delegated_puzzles,
    )?
    .ok_or(WalletError::Parse)?;

    Ok(SuccessResponse {
        coin_spends: vec![new_spend],
        new_datastore,
    })
}

pub fn update_store_ownership(
    datastore: DataStore,
    new_owner_puzzle_hash: Bytes32,
    new_delegated_puzzles: Vec<DelegatedPuzzle>,
    inner_spend_info: DataStoreInnerSpend,
) -> Result<SuccessResponse, WalletError> {
    let ctx = &mut SpendContext::new();

    let update_condition: Condition = match inner_spend_info {
        DataStoreInnerSpend::Owner(_) => {
            DataStore::<DataStoreMetadata>::owner_create_coin_condition(
                ctx,
                datastore.info.launcher_id,
                new_owner_puzzle_hash,
                new_delegated_puzzles,
                true,
            )?
        }
        DataStoreInnerSpend::Admin(_) => {
            let merkle_tree = get_merkle_tree(ctx, new_delegated_puzzles.clone())?;

            let new_merkle_root_condition = UpdateDataStoreMerkleRoot {
                new_merkle_root: merkle_tree.root(),
                memos: DataStore::<DataStoreMetadata>::get_recreation_memos(
                    datastore.info.launcher_id,
                    new_owner_puzzle_hash.into(),
                    new_delegated_puzzles,
                ),
            }
            .to_clvm(&mut ctx.allocator)
            .map_err(DriverError::ToClvm)?;

            Condition::Other(new_merkle_root_condition)
        }
        _ => return Err(WalletError::Permission),
    };

    let update_conditions = Conditions::new().with(update_condition);

    update_store_with_conditions(
        ctx,
        update_conditions,
        datastore,
        inner_spend_info,
        true,
        false,
    )
}

pub fn update_store_metadata(
    datastore: DataStore,
    new_root_hash: Bytes32,
    new_label: Option<String>,
    new_description: Option<String>,
    new_bytes: Option<u64>,
    inner_spend_info: DataStoreInnerSpend,
) -> Result<SuccessResponse, WalletError> {
    let ctx = &mut SpendContext::new();

    let new_metadata = DataStoreMetadata {
        root_hash: new_root_hash,
        label: new_label,
        description: new_description,
        bytes: new_bytes,
    };
    let mut new_metadata_condition = Conditions::new().with(
        DataStore::<DataStoreMetadata>::new_metadata_condition(ctx, new_metadata)?,
    );

    if let DataStoreInnerSpend::Owner(_) = inner_spend_info {
        new_metadata_condition = new_metadata_condition.with(
            DataStore::<DataStoreMetadata>::owner_create_coin_condition(
                ctx,
                datastore.info.launcher_id,
                datastore.info.owner_puzzle_hash,
                datastore.info.delegated_puzzles.clone(),
                false,
            )?,
        );
    }

    update_store_with_conditions(
        ctx,
        new_metadata_condition,
        datastore,
        inner_spend_info,
        true,
        true,
    )
}

pub fn melt_store(
    datastore: DataStore,
    owner_pk: PublicKey,
) -> Result<Vec<CoinSpend>, WalletError> {
    let ctx = &mut SpendContext::new();

    let melt_conditions = Conditions::new()
        .with(Condition::reserve_fee(1))
        .with(Condition::Other(
            MeltSingleton {}
                .to_clvm(&mut ctx.allocator)
                .map_err(DriverError::ToClvm)?,
        ));

    let inner_datastore_spend =
        StandardLayer::new(owner_pk).spend_with_conditions(ctx, melt_conditions)?;

    let new_spend = datastore.spend(ctx, inner_datastore_spend)?;

    Ok(vec![new_spend])
}

pub fn oracle_spend(
    spender_synthetic_key: PublicKey,
    selected_coins: Vec<Coin>,
    datastore: DataStore,
    fee: u64,
) -> Result<SuccessResponse, WalletError> {
    let Some(DelegatedPuzzle::Oracle(oracle_ph, oracle_fee)) = datastore
        .info
        .delegated_puzzles
        .iter()
        .find(|dp| matches!(dp, DelegatedPuzzle::Oracle(_, _)))
    else {
        return Err(WalletError::Permission);
    };

    let spender_puzzle_hash: Bytes32 = StandardArgs::curry_tree_hash(spender_synthetic_key).into();

    let total_amount = oracle_fee + fee;

    let ctx = &mut SpendContext::new();

    let p2 = StandardLayer::new(spender_synthetic_key);

    let lead_coin = selected_coins[0];
    let lead_coin_name = lead_coin.coin_id();

    let total_amount_from_coins = selected_coins.iter().map(|c| c.amount).sum::<u64>();
    for coin in selected_coins.into_iter().skip(1) {
        p2.spend(
            ctx,
            coin,
            Conditions::new().assert_concurrent_spend(lead_coin_name),
        )?;
    }

    let assert_oracle_conds = Conditions::new().assert_puzzle_announcement(announcement_id(
        datastore.coin.puzzle_hash,
        Bytes::new("$".into()),
    ));

    let mut lead_coin_conditions = assert_oracle_conds;
    if total_amount_from_coins > total_amount {
        let hint = ctx.hint(spender_puzzle_hash)?;

        lead_coin_conditions = lead_coin_conditions.create_coin(
            spender_puzzle_hash,
            total_amount_from_coins - total_amount,
            Some(hint),
        );
    }
    if fee > 0 {
        lead_coin_conditions = lead_coin_conditions.reserve_fee(fee);
    }
    p2.spend(ctx, lead_coin, lead_coin_conditions)?;

    let inner_datastore_spend = OracleLayer::new(*oracle_ph, *oracle_fee)
        .ok_or(DriverError::OddOracleFee)?
        .construct_spend(ctx, ())?;

    let parent_delegated_puzzles = datastore.info.delegated_puzzles.clone();
    let new_spend = datastore.spend(ctx, inner_datastore_spend)?;

    let new_datastore =
        DataStore::from_spend(&mut ctx.allocator, &new_spend, &parent_delegated_puzzles)?
            .ok_or(WalletError::Parse)?;
    ctx.insert(new_spend.clone());

    Ok(SuccessResponse {
        coin_spends: ctx.take(),
        new_datastore,
    })
}

pub fn add_fee(
    spender_synthetic_key: PublicKey,
    selected_coins: Vec<Coin>,
    coin_ids: Vec<Bytes32>,
    fee: u64,
) -> Result<Vec<CoinSpend>, WalletError> {
    let spender_puzzle_hash: Bytes32 = StandardArgs::curry_tree_hash(spender_synthetic_key).into();
    let total_amount_from_coins = selected_coins.iter().map(|c| c.amount).sum::<u64>();

    let mut ctx = SpendContext::new();

    let p2 = StandardLayer::new(spender_synthetic_key);

    let lead_coin = selected_coins[0];
    let lead_coin_name = lead_coin.coin_id();

    for coin in selected_coins.into_iter().skip(1) {
        p2.spend(
            &mut ctx,
            coin,
            Conditions::new().assert_concurrent_spend(lead_coin_name),
        )?;
    }

    let mut lead_coin_conditions = Conditions::new().reserve_fee(fee);
    if total_amount_from_coins > fee {
        let hint = ctx.hint(spender_puzzle_hash)?;

        lead_coin_conditions = lead_coin_conditions.create_coin(
            spender_puzzle_hash,
            total_amount_from_coins - fee,
            Some(hint),
        );
    }
    for coin_id in coin_ids {
        lead_coin_conditions = lead_coin_conditions.assert_concurrent_spend(coin_id);
    }

    p2.spend(&mut ctx, lead_coin, lead_coin_conditions)?;

    Ok(ctx.take())
}

pub fn public_key_to_synthetic_key(pk: PublicKey) -> PublicKey {
    pk.derive_synthetic()
}

pub fn secret_key_to_synthetic_key(sk: SecretKey) -> SecretKey {
    sk.derive_synthetic()
}

#[derive(Debug, Clone, Copy)]
pub enum TargetNetwork {
    Mainnet,
    Testnet11,
}

impl TargetNetwork {
    fn get_constants(&self) -> &ConsensusConstants {
        match self {
            TargetNetwork::Mainnet => &MAINNET_CONSTANTS,
            TargetNetwork::Testnet11 => &TESTNET11_CONSTANTS,
        }
    }
}

pub fn sign_coin_spends(
    coin_spends: Vec<CoinSpend>,
    private_keys: Vec<SecretKey>,
    network: TargetNetwork,
) -> Result<Signature, SignerError> {
    let mut allocator = Allocator::new();

    let required_signatures = RequiredSignature::from_coin_spends(
        &mut allocator,
        &coin_spends,
        &AggSigConstants::new(network.get_constants().agg_sig_me_additional_data),
    )?;

    let key_pairs = private_keys
        .iter()
        .map(|sk| {
            (
                sk.public_key(),
                sk.clone(),
                sk.public_key().derive_synthetic(),
                sk.derive_synthetic(),
            )
        })
        .flat_map(|(pk1, sk1, pk2, sk2)| vec![(pk1, sk1), (pk2, sk2)])
        .collect::<HashMap<PublicKey, SecretKey>>();

    let mut sig = Signature::default();

    for required in required_signatures {
        let RequiredSignature::Bls(required) = required else {
            continue;
        };

        let sk = key_pairs.get(&required.public_key);

        if let Some(sk) = sk {
            sig += &sign(sk, required.message());
        }
    }

    Ok(sig)
}

pub async fn broadcast_spend_bundle(
    peer: &Peer,
    spend_bundle: SpendBundle,
) -> Result<TransactionAck, WalletError> {
    peer.send_transaction(spend_bundle)
        .await
        .map_err(WalletError::Client)
}

pub async fn get_header_hash(peer: &Peer, height: u32) -> Result<Bytes32, WalletError> {
    let resp: Result<RespondBlockHeader, RejectHeaderRequest> = peer
        .request_fallible(RequestBlockHeader { height })
        .await
        .map_err(WalletError::Client)?;

    resp.map_err(|_| WalletError::RejectHeaderRequest)
        .map(|resp| resp.header_block.header_hash())
}

pub async fn get_fee_estimate(peer: &Peer, target_time_seconds: u64) -> Result<u64, WalletError> {
    let target_time_seconds = target_time_seconds
        + SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

    let resp: RespondFeeEstimates = peer
        .request_infallible(RequestFeeEstimates {
            time_targets: vec![target_time_seconds],
        })
        .await
        .map_err(WalletError::Client)?;
    let fee_estimate_group = resp.estimates;

    if let Some(error_message) = fee_estimate_group.error {
        return Err(WalletError::FeeEstimateRejection(error_message));
    }

    if let Some(first_estimate) = fee_estimate_group.estimates.first() {
        if let Some(error_message) = &first_estimate.error {
            return Err(WalletError::FeeEstimateRejection(error_message.clone()));
        }

        return Ok(first_estimate.estimated_fee_rate.mojos_per_clvm_cost);
    }

    Err(WalletError::FeeEstimateRejection(
        "No fee estimates available".to_string(),
    ))
}

pub async fn is_coin_spent(
    peer: &Peer,
    coin_id: Bytes32,
    last_height: Option<u32>,
    last_header_hash: Bytes32,
) -> Result<bool, WalletError> {
    let response = peer
        .request_coin_state(vec![coin_id], last_height, last_header_hash, false)
        .await
        .map_err(WalletError::Client)?
        .map_err(|_| WalletError::RejectCoinState)?;

    if let Some(coin_state) = response.coin_states.first() {
        return Ok(coin_state.spent_height.is_some());
    }

    Ok(false)
}

// https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0002.md#signmessage
pub fn make_message(msg: Bytes) -> Result<Bytes32, WalletError> {
    let mut alloc = Allocator::new();
    let thing_ptr = clvm_tuple!("Chia Signed Message", msg)
        .to_clvm(&mut alloc)
        .map_err(DriverError::ToClvm)?;

    Ok(tree_hash(&alloc, thing_ptr).into())
}

pub fn sign_message(message: Bytes, sk: SecretKey) -> Result<Signature, WalletError> {
    Ok(sign(&sk, make_message(message)?))
}

pub fn verify_signature(
    message: Bytes,
    pk: PublicKey,
    sig: Signature,
) -> Result<bool, WalletError> {
    Ok(verify(&sig, &pk, make_message(message)?))
}

pub fn get_cost(coin_spends: Vec<CoinSpend>) -> Result<u64, WalletError> {
    let mut alloc = Allocator::new();

    let generator = solution_generator(
        coin_spends
            .into_iter()
            .map(|cs| (cs.coin, cs.puzzle_reveal, cs.solution)),
    )
    .map_err(WalletError::Io)?;

    let conds = run_block_generator::<&[u8], _>(
        &mut alloc,
        &generator,
        [],
        u64::MAX,
        MEMPOOL_MODE | DONT_VALIDATE_SIGNATURE,
        &Signature::default(),
        None,
        TargetNetwork::Mainnet.get_constants(),
    )?;

    let conds = OwnedSpendBundleConditions::from(&alloc, conds);

    Ok(conds.cost)
}

pub struct PossibleLaunchersResponse {
    pub launcher_ids: Vec<Bytes32>,
    pub last_height: u32,
    pub last_header_hash: Bytes32,
}

pub async fn look_up_possible_launchers(
    peer: &Peer,
    previous_height: Option<u32>,
    previous_header_hash: Bytes32,
) -> Result<PossibleLaunchersResponse, WalletError> {
    let resp = get_unspent_coin_states(
        peer,
        DATASTORE_LAUNCHER_HINT,
        previous_height,
        previous_header_hash,
        true,
    )
    .await?;

    Ok(PossibleLaunchersResponse {
        last_header_hash: resp.last_header_hash,
        last_height: resp.last_height,
        launcher_ids: resp
            .coin_states
            .into_iter()
            .filter_map(|coin_state| {
                if coin_state.coin.puzzle_hash == SINGLETON_LAUNCHER_PUZZLE_HASH.into() {
                    Some(coin_state.coin.coin_id())
                } else {
                    None
                }
            })
            .collect(),
    })
}

pub async fn subscribe_to_coin_states(
    peer: &Peer,
    coin_id: Bytes32,
    previous_height: Option<u32>,
    previous_header_hash: Bytes32,
) -> Result<Option<u32>, WalletError> {
    let response = peer
        .request_coin_state(vec![coin_id], previous_height, previous_header_hash, true)
        .await
        .map_err(WalletError::Client)?
        .map_err(|_| WalletError::RejectCoinState)?;

    if let Some(coin_state) = response.coin_states.first() {
        return Ok(coin_state.spent_height);
    }

    Err(WalletError::UnknownCoin)
}

pub async fn unsubscribe_from_coin_states(
    peer: &Peer,
    coin_id: Bytes32,
) -> Result<(), WalletError> {
    peer.remove_coin_subscriptions(Some(vec![coin_id]))
        .await
        .map_err(WalletError::Client)?;

    Ok(())
}
