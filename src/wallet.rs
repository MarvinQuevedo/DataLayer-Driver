use chia::bls::PublicKey;
use chia::client::Error as ClientError;
use chia::client::Peer;
use chia_protocol::Coin;
use chia_protocol::RejectPuzzleSolution;
use chia_protocol::{Bytes32, CoinSpend};
use chia_puzzles::standard::StandardArgs;
use chia_sdk_driver::Conditions;
use chia_sdk_driver::Launcher;
use chia_sdk_driver::SpendContext;
use chia_sdk_driver::SpendError;
use chia_wallet_sdk::select_coins;
use chia_wallet_sdk::CoinSelectionError;
use clvm_traits::FromClvmError;
use thiserror::Error;

use crate::DataStoreMetadata;
use crate::DataStoreMintInfo;
use crate::LauncherExt;
use crate::{DataStoreInfo, DelegatedPuzzle};

#[derive(Clone, Debug)]

pub struct SuccessResponse {
    pub coin_spends: Vec<CoinSpend>,
    pub new_info: DataStoreInfo,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0:?}")]
    Wallet(#[from] ClientError<()>),

    #[error("{0:?}")]
    CoinSelection(#[from] CoinSelectionError),

    #[error("{0:?}")]
    RejectPuzzleSolution(#[from] ClientError<RejectPuzzleSolution>),

    #[error("{0:?}")]
    Spend(#[from] SpendError),

    #[error("{0:?}")]
    FromClvm(#[from] FromClvmError),

    #[error("ParseError")]
    Parse(),

    #[error("UnknownCoin")]
    UnknwonCoin(),
}

pub async fn mint_store(
    peer: &Peer,
    minter_synthetic_key: PublicKey,
    minter_ph_min_height: u32,
    root_hash: Bytes32,
    label: String,
    description: String,
    owner_puzzle_hash: Bytes32,
    delegated_puzzles: Vec<DelegatedPuzzle>,
    fee: u64,
) -> Result<SuccessResponse, Error> {
    let minter_puzzle_hash: Bytes32 = StandardArgs::curry_tree_hash(minter_synthetic_key).into();
    let coin_states = peer
        .register_for_ph_updates(vec![minter_puzzle_hash], minter_ph_min_height)
        .await
        .map_err(|e| Error::Wallet(e))?;

    let total_amount = fee + 1;
    let coins: Vec<Coin> = select_coins(
        coin_states
            .iter()
            .filter(|cs| cs.spent_height.is_none())
            .map(|coin_state| coin_state.coin)
            .collect(),
        total_amount.into(),
    )
    .map_err(|cserr| Error::CoinSelection(cserr))?;

    let mut ctx = SpendContext::new();

    let lead_coin = coins[0].clone();
    let lead_coin_name = lead_coin.coin_id();
    for coin in coins.iter().skip(1) {
        ctx.spend_p2_coin(
            *coin,
            minter_synthetic_key,
            Conditions::new().assert_coin_announcement(lead_coin_name, [0; 1]),
        )
        .map_err(|err| Error::Spend(err))?;
    }

    let (launch_singleton, datastore_info) = Launcher::new(lead_coin_name, 1).mint_datastore(
        &mut ctx,
        DataStoreMintInfo {
            metadata: DataStoreMetadata {
                root_hash,
                label,
                description,
            },
            owner_puzzle_hash: owner_puzzle_hash.into(),
            delegated_puzzles,
        },
    )?;

    ctx.spend_p2_coin(lead_coin, minter_synthetic_key, launch_singleton)?;

    Ok(SuccessResponse {
        coin_spends: ctx.take_spends(),
        new_info: datastore_info,
    })
}

pub struct SyncStoreResponse {
    pub latest_info: DataStoreInfo,
    pub latest_height: u32,
}

pub async fn sync_store(
    peer: &Peer,
    store_info: &DataStoreInfo,
    min_height: u32,
) -> Result<SyncStoreResponse, Error> {
    let mut latest_info = store_info.clone();

    let mut coin_states = peer
        .register_for_coin_updates(vec![latest_info.coin.coin_id()], min_height)
        .await
        .map_err(|e| Error::Wallet(e))?;
    let mut last_coin_record = coin_states.iter().next().ok_or(Error::UnknwonCoin())?;

    let mut ctx = SpendContext::new(); // just to run puzzles more easily

    while last_coin_record.spent_height.is_some() {
        let puzzle_and_solution_req = peer
            .request_puzzle_and_solution(
                last_coin_record.coin.coin_id(),
                last_coin_record.spent_height.unwrap(),
            )
            .await
            .map_err(|err| Error::RejectPuzzleSolution(err))?;

        let cs = CoinSpend {
            coin: last_coin_record.coin,
            puzzle_reveal: puzzle_and_solution_req.puzzle,
            solution: puzzle_and_solution_req.solution,
        };

        let new_info = DataStoreInfo::from_spend(
            ctx.allocator_mut(),
            &cs,
            latest_info.delegated_puzzles.clone(),
        )
        .map_err(|_| Error::Parse())?;

        coin_states = peer
            .register_for_coin_updates(vec![new_info.coin.coin_id()], min_height)
            .await
            .map_err(|e| Error::Wallet(e))?;

        last_coin_record = coin_states.iter().next().ok_or(Error::UnknwonCoin())?;
        latest_info = new_info;
    }

    Ok(SyncStoreResponse {
        latest_info,
        latest_height: last_coin_record
            .created_height
            .ok_or(Error::UnknwonCoin())?,
    })
}

pub fn burn_store(peer: &Peer, store_info: &DataStoreInfo) -> Result<SuccessResponse, Error> {
    todo!()
}

pub fn update_store(
    peer: &Peer,
    store_info: &DataStoreInfo,
    new_owner_address: &str,
    new_delegated_puzzles: Option<Vec<DelegatedPuzzle>>,
) -> Result<SuccessResponse, Error> {
    todo!()
}

pub fn update_metadata(
    peer: &Peer,
    store_info: &DataStoreInfo,
    new_root_hash: Bytes32,
    new_label: &str,
    new_description: &str,
) -> Result<SuccessResponse, Error> {
    todo!()
}

pub fn oracle_spend(peer: &Peer, store_info: &DataStoreInfo) -> Result<SuccessResponse, Error> {
    todo!()
}

// also need to be implemented/exposed:
// - puzzle for pk
// - puzzle hash for puzzle
// - DelegatedPuzzle (from puzzle hash & type etc.)
// - sign coin spends using sk
// - send sb to peer
// - wait for sb confirmation
// - address to puzzle hash
// - pk to address
