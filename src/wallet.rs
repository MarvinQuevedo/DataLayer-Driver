use std::collections::HashMap;

use chia::bls::sign;
use chia::bls::PublicKey;
use chia::bls::SecretKey;
use chia::bls::Signature;
use chia::client::Error as ClientError;
use chia::client::Peer;
use chia_protocol::Bytes;
use chia_protocol::Coin;
use chia_protocol::CoinStateFilters;
use chia_protocol::RejectHeaderRequest;
use chia_protocol::RejectPuzzleSolution;
use chia_protocol::RequestCoinState;
use chia_protocol::RequestPuzzleState;
use chia_protocol::RespondCoinState;
use chia_protocol::RespondPuzzleState;
use chia_protocol::SpendBundle;
use chia_protocol::TransactionAck;
use chia_protocol::{Bytes32, CoinSpend};
use chia_puzzles::standard::StandardArgs;
use chia_puzzles::DeriveSynthetic;
use chia_sdk_driver::Conditions;
use chia_sdk_driver::Launcher;
use chia_sdk_driver::Spend;
use chia_sdk_driver::SpendContext;
use chia_sdk_driver::SpendError;
use chia_sdk_types::conditions::AssertConcurrentSpend;
use chia_sdk_types::conditions::Condition;
use chia_sdk_types::conditions::ReserveFee;
use chia_wallet_sdk::select_coins as select_coins_algo;
use chia_wallet_sdk::CoinSelectionError;
use chia_wallet_sdk::RequiredSignature;
use chia_wallet_sdk::SignerError;
use clvm_traits::FromClvmError;
use clvm_traits::ToClvm;
use clvm_traits::ToClvmError;
use clvmr::Allocator;
use thiserror::Error;

use crate::datastore_spend;
use crate::get_memos;
use crate::get_owner_create_coin_condition;
use crate::puzzles_info::DataStoreInfo;
use crate::puzzles_info::DataStoreMetadata;
use crate::puzzles_info::DelegatedPuzzle;
use crate::puzzles_info::DelegatedPuzzleInfo;
use crate::DataStoreMintInfo;
use crate::DatastoreInnerSpend;
use crate::DefaultMetadataSolution;
use crate::DefaultMetadataSolutionMetadataList;
use crate::LauncherExt;
use crate::MeltCondition;
use crate::MerkleTree;
use crate::NewMerkleRootCondition;
use crate::NewMetadataCondition;
use crate::DL_METADATA_UPDATER_PUZZLE_HASH;

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
  RejectPuzzleSolution(#[from] ClientError<RejectPuzzleSolution>),

  #[error("{0:?}")]
  RejectHeaderRequest(#[from] ClientError<RejectHeaderRequest>),

  #[error("{0:?}")]
  Spend(#[from] SpendError),

  #[error("{0:?}")]
  FromClvm(#[from] FromClvmError),

  #[error("{0:?}")]
  ToClvm(#[from] ToClvmError),

  #[error("ParseError")]
  Parse(),

  #[error("UnknownCoin")]
  UnknwonCoin(),

  #[error("Permission error: puzzle can't perform this action")]
  Permission(),
}

pub struct UnspentCoinsResponse {
  pub coins: Vec<Coin>,
  pub last_height: u32,
  pub last_header_hash: Bytes32,
}

pub async fn get_unspent_coins(
  peer: &Peer,
  puzzle_hash: Bytes32,
  previous_height: Option<u32>,
  previous_header_hash: Bytes32,
) -> Result<UnspentCoinsResponse, chia_client::Error<()>> {
  let mut coins: Vec<Coin> = vec![];
  let mut last_height: u32 = if previous_height.is_some() {
    previous_height.unwrap()
  } else {
    0
  };
  let mut last_header_hash: Bytes32 = previous_header_hash;

  loop {
    let response = peer
      .request::<RespondPuzzleState, RequestPuzzleState>(RequestPuzzleState::new(
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
          include_hinted: false,
          min_amount: 1,
        },
        false,
      ))
      .await?;

    last_height = response.height;
    last_header_hash = response.header_hash;
    coins.extend(
      response
        .coin_states
        .into_iter()
        .filter(|cs| cs.spent_height.is_none())
        .map(|cs| cs.coin),
    );

    if response.is_finished {
      break;
    }
  }

  Ok(UnspentCoinsResponse {
    coins,
    last_height,
    last_header_hash,
  })
}

pub fn select_coins(coins: Vec<Coin>, total_amount: u64) -> Result<Vec<Coin>, CoinSelectionError> {
  select_coins_algo(coins.into_iter().collect(), total_amount.into())
}

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
) -> Result<SuccessResponse, Error> {
  let minter_puzzle_hash: Bytes32 = StandardArgs::curry_tree_hash(minter_synthetic_key).into();

  let total_amount = fee + 1;

  let mut ctx = SpendContext::new();

  let lead_coin = selected_coins[0].clone();
  let lead_coin_name = lead_coin.coin_id();
  for coin in selected_coins.iter().skip(1) {
    ctx
      .spend_p2_coin(
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
        bytes,
      },
      owner_puzzle_hash: owner_puzzle_hash.into(),
      delegated_puzzles,
    },
  )?;

  let total_amount_from_coins = selected_coins.iter().map(|c| c.amount).sum::<u64>();
  let lead_coin_conditions = if total_amount_from_coins > total_amount {
    launch_singleton.create_coin(minter_puzzle_hash, total_amount_from_coins - total_amount)
  } else {
    launch_singleton
  };
  ctx.spend_p2_coin(lead_coin, minter_synthetic_key, lead_coin_conditions)?;

  Ok(SuccessResponse {
    coin_spends: ctx.take_spends(),
    new_info: datastore_info,
  })
}

pub struct SyncStoreResponse {
  pub latest_info: DataStoreInfo,
  pub latest_height: u32,
  pub root_hash_history: Option<Vec<(Bytes32, u64)>>,
}

pub async fn sync_store(
  peer: &Peer,
  store_info: &DataStoreInfo,
  last_height: Option<u32>,
  last_header_hash: Bytes32,
  with_history: bool,
) -> Result<SyncStoreResponse, Error> {
  let mut latest_info = store_info.clone();
  let mut history = vec![];

  let response = peer
    .request::<RespondCoinState, RequestCoinState>(RequestCoinState::new(
      vec![store_info.coin.coin_id()],
      last_height,
      last_header_hash,
      false,
    ))
    .await?;
  let mut last_coin_record = response
    .coin_states
    .into_iter()
    .next()
    .ok_or(Error::UnknwonCoin())?
    .clone();

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

    let new_info =
      DataStoreInfo::from_spend(ctx.allocator_mut(), &cs, &latest_info.delegated_puzzles)
        .map_err(|_| Error::Parse())?;

    if with_history {
      let block_header = peer
        .request_block_header(last_coin_record.spent_height.unwrap())
        .await
        .map_err(|err| Error::RejectHeaderRequest(err))?;
      history.push((
        new_info.metadata.root_hash,
        block_header.foliage_transaction_block.unwrap().timestamp,
      ));
    }

    let response = peer
      .request::<RespondCoinState, RequestCoinState>(RequestCoinState::new(
        vec![new_info.coin.coin_id()],
        last_height,
        last_header_hash,
        false,
      ))
      .await?;

    last_coin_record = response
      .coin_states
      .into_iter()
      .next()
      .ok_or(Error::UnknwonCoin())?
      .clone();
    latest_info = new_info;
  }

  Ok(SyncStoreResponse {
    latest_info,
    latest_height: last_coin_record
      .created_height
      .ok_or(Error::UnknwonCoin())?,
    root_hash_history: if with_history { Some(history) } else { None },
  })
}

pub async fn sync_store_using_launcher_id(
  peer: &Peer,
  launcher_id: Bytes32,
  last_height: Option<u32>,
  last_header_hash: Bytes32,
  with_history: bool,
) -> Result<SyncStoreResponse, Error> {
  let response = peer
    .request::<RespondCoinState, RequestCoinState>(RequestCoinState::new(
      vec![launcher_id],
      last_height,
      last_header_hash,
      false,
    ))
    .await?;
  let last_coin_record = response
    .coin_states
    .into_iter()
    .next()
    .ok_or(Error::UnknwonCoin())?
    .clone();

  let mut ctx = SpendContext::new(); // just to run puzzles more easily

  let puzzle_and_solution_req = peer
    .request_puzzle_and_solution(
      last_coin_record.coin.coin_id(),
      last_coin_record.spent_height.ok_or(Error::UnknwonCoin())?,
    )
    .await
    .map_err(|err| Error::RejectPuzzleSolution(err))?;

  let cs = CoinSpend {
    coin: last_coin_record.coin,
    puzzle_reveal: puzzle_and_solution_req.puzzle,
    solution: puzzle_and_solution_req.solution,
  };

  let first_info =
    DataStoreInfo::from_spend(ctx.allocator_mut(), &cs, &vec![]).map_err(|_| Error::Parse())?;

  let res = sync_store(
    peer,
    &first_info,
    last_height,
    last_header_hash,
    with_history,
  )
  .await?;

  // prepend root hash from launch
  let root_hash_history = if let Some(mut res_root_hash_history) = res.root_hash_history {
    let spent_timestamp = if let Some(spent_height) = last_coin_record.spent_height {
      let block_header = peer
        .request_block_header(spent_height)
        .await
        .map_err(|err| Error::RejectHeaderRequest(err))?;
      block_header.foliage_transaction_block.unwrap().timestamp
    } else {
      0
    };

    res_root_hash_history.insert(0, (first_info.metadata.root_hash, spent_timestamp));
    Some(res_root_hash_history)
  } else {
    None
  };

  Ok(SyncStoreResponse {
    latest_info: res.latest_info,
    latest_height: res.latest_height,
    root_hash_history,
  })
}

pub enum DataStoreInnerSpendInfo {
  Owner(PublicKey),
  Admin(PublicKey),
  Writer(PublicKey),
  // does not include oracle since it can't change metadata/owners :(
}

fn update_store_with_conditions(
  ctx: &mut SpendContext,
  conditions: Conditions,
  store_info: DataStoreInfo,
  inner_spend_info: DataStoreInnerSpendInfo,
  allow_admin: bool,
  allow_writer: bool,
) -> Result<SuccessResponse, Error> {
  let inner_datastore_spend = match inner_spend_info {
    // todo: if no CREATE_COINs, re-create with same params
    DataStoreInnerSpendInfo::Owner(pk) => DatastoreInnerSpend::OwnerPuzzleSpend(
      conditions
        .p2_spend(ctx, pk)
        .map_err(|err| Error::Spend(err))?,
    ),
    DataStoreInnerSpendInfo::Admin(pk) => {
      if !allow_admin {
        return Err(Error::Permission());
      }

      let (dp, _) = DelegatedPuzzle::from_admin_pk(ctx, pk).map_err(|err| Error::Spend(err))?;
      DatastoreInnerSpend::DelegatedPuzzleSpend(
        dp,
        conditions
          .p2_spend(ctx, pk)
          .map_err(|err| Error::Spend(err))?,
      )
    }
    DataStoreInnerSpendInfo::Writer(pk) => {
      if !allow_writer {
        return Err(Error::Permission());
      }

      let (dp, _) = DelegatedPuzzle::from_writer_pk(ctx, pk).map_err(|err| Error::Spend(err))?;
      DatastoreInnerSpend::DelegatedPuzzleSpend(
        dp,
        conditions
          .p2_spend(ctx, pk)
          .map_err(|err| Error::Spend(err))?,
      )
    }
  };

  let new_spend =
    datastore_spend(ctx, &store_info, inner_datastore_spend).map_err(|err| Error::Spend(err))?;
  ctx.insert_coin_spend(new_spend.clone());

  let new_info = DataStoreInfo::from_spend(
    ctx.allocator_mut(),
    &new_spend,
    &store_info.delegated_puzzles.clone(),
  )
  .map_err(|_| Error::Parse())?;

  Ok(SuccessResponse {
    coin_spends: ctx.take_spends(),
    new_info,
  })
}

pub fn update_store_ownership(
  store_info: DataStoreInfo,
  new_owner_puzzle_hash: Bytes32,
  new_delegated_puzzles: Vec<DelegatedPuzzle>,
  inner_spend_info: DataStoreInnerSpendInfo,
) -> Result<SuccessResponse, Error> {
  let mut ctx = SpendContext::new();

  let update_condition: Condition = match inner_spend_info {
    DataStoreInnerSpendInfo::Owner(_) => get_owner_create_coin_condition(
      store_info.launcher_id,
      &new_owner_puzzle_hash,
      &new_delegated_puzzles,
      true,
    ),
    DataStoreInnerSpendInfo::Admin(_) => {
      let leaves: Vec<Bytes32> = new_delegated_puzzles
        .clone()
        .iter()
        .map(|dp| dp.puzzle_hash)
        .collect();
      let merkle_tree = MerkleTree::new(&leaves);
      let new_merkle_root = merkle_tree.get_root();

      let new_merkle_root_condition = NewMerkleRootCondition {
        new_merkle_root,
        memos: get_memos(
          store_info.launcher_id,
          new_owner_puzzle_hash.into(),
          new_delegated_puzzles,
        ),
      }
      .to_clvm(ctx.allocator_mut())
      .map_err(|err| Error::ToClvm(err))?;

      Condition::Other(new_merkle_root_condition)
    }
    _ => return Err(Error::Permission()),
  };

  let update_conditions = Conditions::new().condition(update_condition);

  update_store_with_conditions(
    &mut ctx,
    update_conditions,
    store_info,
    inner_spend_info,
    true,
    false,
  )
}

pub fn update_store_metadata(
  store_info: DataStoreInfo,
  new_root_hash: Bytes32,
  new_label: Option<String>,
  new_description: Option<String>,
  new_bytes: Option<u64>,
  inner_spend_info: DataStoreInnerSpendInfo,
) -> Result<SuccessResponse, Error> {
  let mut ctx = SpendContext::new();

  let new_metadata = DataStoreMetadata {
    root_hash: new_root_hash,
    label: new_label,
    description: new_description,
    bytes: new_bytes,
  };
  let new_metadata_condition = NewMetadataCondition::<i32, DataStoreMetadata, Bytes32, i32> {
    metadata_updater_reveal: 11,
    metadata_updater_solution: DefaultMetadataSolution {
      metadata_part: DefaultMetadataSolutionMetadataList {
        new_metadata: new_metadata,
        new_metadata_updater_ph: DL_METADATA_UPDATER_PUZZLE_HASH.into(),
      },
      conditions: 0,
    },
  }
  .to_clvm(ctx.allocator_mut())
  .map_err(|err| Error::ToClvm(err))?;
  let new_metadata_condition = match inner_spend_info {
    DataStoreInnerSpendInfo::Owner(_) => Conditions::new()
      .condition(Condition::Other(new_metadata_condition))
      .condition(get_owner_create_coin_condition(
        store_info.launcher_id,
        &store_info.owner_puzzle_hash,
        &store_info.delegated_puzzles,
        false,
      )),
    _ => Conditions::new().condition(Condition::Other(new_metadata_condition)),
  };

  update_store_with_conditions(
    &mut ctx,
    new_metadata_condition,
    store_info,
    inner_spend_info,
    true,
    true,
  )
}

pub fn melt_store(
  store_info: &DataStoreInfo,
  owner_pk: PublicKey,
) -> Result<Vec<CoinSpend>, Error> {
  let mut ctx = SpendContext::new();

  let melt_conditions = Conditions::new().conditions(&vec![
    Condition::ReserveFee(ReserveFee { amount: 1 }),
    Condition::Other(
      MeltCondition {
        fake_puzzle_hash: Bytes32::default(),
      }
      .to_clvm(ctx.allocator_mut())
      .map_err(|err| Error::ToClvm(err))?,
    ),
  ]);

  let inner_datastore_spend = DatastoreInnerSpend::OwnerPuzzleSpend(
    melt_conditions
      .p2_spend(&mut ctx, owner_pk)
      .map_err(|err| Error::Spend(err))?,
  );

  let new_spend = datastore_spend(&mut ctx, &store_info, inner_datastore_spend)
    .map_err(|err| Error::Spend(err))?;
  ctx.insert_coin_spend(new_spend.clone());

  Ok(ctx.take_spends())
}

pub fn oracle_spend(
  spender_synthetic_key: PublicKey,
  selected_coins: Vec<Coin>,
  store_info: &DataStoreInfo,
  fee: u64,
) -> Result<SuccessResponse, Error> {
  let oracle_delegated_puzzle = store_info
    .delegated_puzzles
    .iter()
    .find(|dp| match dp.puzzle_info {
      DelegatedPuzzleInfo::Oracle(_, _) => true,
      _ => false,
    })
    .ok_or(Error::Permission())?;

  let (oracle_ph, oracle_fee) = match oracle_delegated_puzzle.puzzle_info {
    DelegatedPuzzleInfo::Oracle(ph, fee) => (ph, fee),
    _ => unreachable!(),
  };

  let spender_puzzle_hash: Bytes32 = StandardArgs::curry_tree_hash(spender_synthetic_key).into();

  let total_amount = oracle_fee + fee;

  let mut ctx = SpendContext::new();

  let lead_coin = selected_coins[0].clone();
  let lead_coin_name = lead_coin.coin_id();
  for coin in selected_coins.iter().skip(1) {
    ctx
      .spend_p2_coin(
        *coin,
        spender_synthetic_key,
        Conditions::new().assert_coin_announcement(lead_coin_name, [0; 1]),
      )
      .map_err(|err| Error::Spend(err))?;
  }

  let assert_oracle_conds = Conditions::new()
    .assert_puzzle_announcement(store_info.coin.puzzle_hash, &Bytes::new("$".into()));

  let total_amount_from_coins = selected_coins.iter().map(|c| c.amount).sum::<u64>();

  let mut lead_coin_conditions = assert_oracle_conds;
  if total_amount_from_coins > total_amount {
    lead_coin_conditions =
      lead_coin_conditions.create_coin(spender_puzzle_hash, total_amount_from_coins - total_amount);
  }
  if fee > 0 {
    lead_coin_conditions = lead_coin_conditions.reserve_fee(fee);
  }
  ctx.spend_p2_coin(lead_coin, spender_synthetic_key, lead_coin_conditions)?;

  let oracle_puzzle_ptr =
    DelegatedPuzzle::oracle_layer_full_puzzle(ctx.allocator_mut(), oracle_ph, oracle_fee)
      .map_err(|err| Error::ToClvm(err))?;
  let inner_datastore_spend = DatastoreInnerSpend::DelegatedPuzzleSpend(
    *oracle_delegated_puzzle,
    Spend::new(
      oracle_puzzle_ptr, // oracle puzzle always available
      ctx.allocator().nil(),
    ),
  );

  let new_spend = datastore_spend(&mut ctx, store_info, inner_datastore_spend)?;
  ctx.insert_coin_spend(new_spend.clone());

  let new_datastore_info = DataStoreInfo::from_spend(
    ctx.allocator_mut(),
    &new_spend,
    &store_info.delegated_puzzles.clone(),
  )
  .map_err(|_| Error::Parse())?;

  Ok(SuccessResponse {
    coin_spends: ctx.take_spends(),
    new_info: new_datastore_info,
  })
}

pub fn add_fee(
  spender_synthetic_key: PublicKey,
  selected_coins: Vec<Coin>,
  coin_ids: Vec<Bytes32>,
  fee: u64,
) -> Result<Vec<CoinSpend>, Error> {
  let spender_puzzle_hash: Bytes32 = StandardArgs::curry_tree_hash(spender_synthetic_key).into();

  let mut ctx = SpendContext::new();

  let lead_coin = selected_coins[0].clone();
  let lead_coin_name = lead_coin.coin_id();
  for coin in selected_coins.iter().skip(1) {
    ctx
      .spend_p2_coin(
        *coin,
        spender_synthetic_key,
        Conditions::new().assert_coin_announcement(lead_coin_name, [0; 1]),
      )
      .map_err(|err| Error::Spend(err))?;
  }

  let total_amount_from_coins = selected_coins.iter().map(|c| c.amount).sum::<u64>();

  let mut lead_coin_conditions = Conditions::new().reserve_fee(fee);
  if total_amount_from_coins > fee {
    lead_coin_conditions =
      lead_coin_conditions.create_coin(spender_puzzle_hash, total_amount_from_coins - fee);
  }
  for coin_id in coin_ids {
    lead_coin_conditions =
      lead_coin_conditions.condition(Condition::AssertConcurrentSpend(AssertConcurrentSpend {
        coin_id,
      }));
  }

  ctx.spend_p2_coin(lead_coin, spender_synthetic_key, lead_coin_conditions)?;

  Ok(ctx.take_spends())
}

#[derive(Debug, Error)]
pub enum SignCoinSpendsError {
  #[error("{0:?}")]
  Signer(#[from] SignerError),
}

pub fn public_key_to_synthetic_key(pk: PublicKey) -> PublicKey {
  pk.derive_synthetic()
}

pub fn secret_key_to_synthetic_key(sk: SecretKey) -> SecretKey {
  sk.derive_synthetic()
}

pub fn sign_coin_spends(
  coin_spends: Vec<CoinSpend>,
  private_keys: Vec<SecretKey>,
  agg_sig_data: Bytes32,
) -> Result<Signature, SignCoinSpendsError> {
  let mut allocator = Allocator::new();

  let required_signatures =
    RequiredSignature::from_coin_spends(&mut allocator, &coin_spends, agg_sig_data)
      .map_err(|err| SignCoinSpendsError::Signer(err))?;

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
    let sk = key_pairs.get(&required.public_key());

    match sk {
      Some(sk) => {
        sig += &sign(sk, required.final_message());
      }
      None => {}
    }
  }

  Ok(sig)
}

pub async fn broadcast_spend_bundle(
  peer: &Peer,
  spend_bundle: SpendBundle,
) -> Result<TransactionAck, ClientError<()>> {
  peer.send_transaction(spend_bundle).await
}

pub async fn get_header_hash(
  peer: &Peer,
  height: u32,
) -> Result<Bytes32, ClientError<RejectHeaderRequest>> {
  peer
    .request_block_header(height)
    .await
    .map(|resp| resp.header_hash())
}

pub async fn get_fee_estimate(
  peer: &Peer,
  target_time_seconds: u64,
) -> Result<u64, ClientError<String>> {
  let fee_estimate_group = peer
    .request_fee_estimates(vec![target_time_seconds])
    .await
    .map_err(|e| ClientError::Rejection(format!("Request failed: {:?}", e)))?;

  if let Some(error_message) = fee_estimate_group.error {
    return Err(ClientError::Rejection(error_message));
  }

  if let Some(first_estimate) = fee_estimate_group.estimates.first() {
    return Ok(first_estimate.estimated_fee_rate.mojos_per_clvm_cost);
  }

  Err(ClientError::Rejection(
    "No fee estimates available".to_string(),
  ))
}

pub async fn is_coin_spent(
  peer: &Peer,
  coin_id: Bytes32,
  last_height: Option<u32>,
  last_header_hash: Bytes32,
) -> Result<bool, Error> {
  let response = peer
    .request::<RespondCoinState, RequestCoinState>(RequestCoinState::new(
      vec![coin_id],
      last_height,
      last_header_hash,
      false,
    ))
    .await?;

  if let Some(coin_state) = response.coin_states.first() {
    return Ok(coin_state.spent_height.is_some());
  }

  return Ok(false);
}
