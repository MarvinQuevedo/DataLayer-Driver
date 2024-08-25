use std::collections::HashMap;

use chia::bls::sign;
use chia::bls::verify;
use chia::bls::PublicKey;
use chia::bls::SecretKey;
use chia::bls::Signature;
use chia::client::Error as ClientError;
use chia::client::Peer;
use chia::consensus::error::Error as ChiaConsensusError;
use chia::consensus::gen::conditions::EmptyVisitor;
use chia::consensus::gen::flags::MEMPOOL_MODE;
use chia::consensus::gen::owned_conditions::OwnedSpendBundleConditions;
use chia::consensus::gen::run_block_generator::run_block_generator;
use chia::consensus::gen::solution_generator::solution_generator;
use chia::protocol::Bytes;
use chia::protocol::Coin;
use chia::protocol::CoinStateFilters;
use chia::protocol::RejectHeaderRequest;
use chia::protocol::RejectPuzzleSolution;
use chia::protocol::RequestCoinState;
use chia::protocol::RequestPuzzleState;
use chia::protocol::RespondCoinState;
use chia::protocol::RespondPuzzleState;
use chia::protocol::SpendBundle;
use chia::protocol::TransactionAck;
use chia::protocol::{Bytes32, CoinSpend};
use chia::puzzles::standard::StandardArgs;
use chia_wallet_sdk::select_coins as select_coins_algo;
use chia_wallet_sdk::CoinSelectionError;
use chia_wallet_sdk::Conditions;
use chia_wallet_sdk::DataStore;
use chia_wallet_sdk::DataStoreMetadata;
use chia_wallet_sdk::DelegatedPuzzle;
use chia_wallet_sdk::DriverError;
use chia_wallet_sdk::Launcher;
use chia_wallet_sdk::RequiredSignature;
use chia_wallet_sdk::SignerError;
use chia_wallet_sdk::SpendContext;
use clvmr::sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Clone, Debug)]

pub struct SuccessResponse {
  pub coin_spends: Vec<CoinSpend>,
  pub new_datastore: DataStore,
}

#[derive(Debug, Error)]
pub enum WalletError {
  #[error("{0:?}")]
  Wallet(#[from] ClientError<()>),

  #[error("{0:?}")]
  RejectPuzzleSolution(#[from] ClientError<RejectPuzzleSolution>),

  #[error("{0:?}")]
  RejectHeaderRequest(#[from] ClientError<RejectHeaderRequest>),

  #[error("{0:?}")]
  Driver(#[from] DriverError),

  #[error("{0:?}")]
  ChiaConsensus(#[from] ChiaConsensusError),

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
) -> Result<UnspentCoinsResponse, WalletError> {
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
) -> Result<SuccessResponse, WalletError> {
  let minter_puzzle_hash: Bytes32 = StandardArgs::curry_tree_hash(minter_synthetic_key).into();

  let total_amount = fee + 1;

  let mut ctx = SpendContext::new();

  let lead_coin = selected_coins[0].clone();
  let lead_coin_name = lead_coin.coin_id();

  let mut hasher = Sha256::new();
  hasher.update(lead_coin_name);
  hasher.update([0; 1]);
  let lead_ann_id = Bytes32::new(hasher.finalize());

  for coin in selected_coins.iter().skip(1) {
    ctx
      .spend_p2_coin(
        *coin,
        minter_synthetic_key,
        Conditions::new().assert_coin_announcement(lead_ann_id),
      )
      .map_err(|err| WalletError::Driver(err))?;
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

  let total_amount_from_coins = selected_coins.iter().map(|c| c.amount).sum::<u64>();
  let lead_coin_conditions = if total_amount_from_coins > total_amount {
    launch_singleton.create_coin(
      minter_puzzle_hash,
      total_amount_from_coins - total_amount,
      vec![minter_puzzle_hash.into()],
    )
  } else {
    launch_singleton
  };
  ctx.spend_p2_coin(lead_coin, minter_synthetic_key, lead_coin_conditions)?;

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
    .request::<RespondCoinState, RequestCoinState>(RequestCoinState::new(
      vec![store.coin.coin_id()],
      last_height,
      last_header_hash,
      false,
    ))
    .await?;
  let mut last_coin_record = response
    .coin_states
    .into_iter()
    .next()
    .ok_or(WalletError::UnknwonCoin())?
    .clone();

  let mut ctx = SpendContext::new(); // just to run puzzles more easily

  while last_coin_record.spent_height.is_some() {
    let puzzle_and_solution_req = peer
      .request_puzzle_and_solution(
        last_coin_record.coin.coin_id(),
        last_coin_record.spent_height.unwrap(),
      )
      .await
      .map_err(|err| WalletError::RejectPuzzleSolution(err))?;

    let cs = CoinSpend {
      coin: last_coin_record.coin,
      puzzle_reveal: puzzle_and_solution_req.puzzle,
      solution: puzzle_and_solution_req.solution,
    };

    let new_store = DataStore::<DataStoreMetadata>::from_spend(
      &mut ctx.allocator,
      &cs,
      latest_store.info.delegated_puzzles.clone(),
    )
    .map_err(|_| WalletError::Parse())?
    .ok_or(WalletError::Parse())?;

    if with_history {
      let block_header = peer
        .request_block_header(last_coin_record.spent_height.unwrap())
        .await
        .map_err(|err| WalletError::RejectHeaderRequest(err))?;
      history.push((
        new_store.info.metadata.root_hash,
        block_header.foliage_transaction_block.unwrap().timestamp,
      ));
    }

    let response = peer
      .request::<RespondCoinState, RequestCoinState>(RequestCoinState::new(
        vec![new_store.coin.coin_id()],
        last_height,
        last_header_hash,
        false,
      ))
      .await?;

    last_coin_record = response
      .coin_states
      .into_iter()
      .next()
      .ok_or(WalletError::UnknwonCoin())?
      .clone();
    latest_store = new_store;
  }

  Ok(SyncStoreResponse {
    latest_store,
    latest_height: last_coin_record
      .created_height
      .ok_or(WalletError::UnknwonCoin())?,
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
    .ok_or(WalletError::UnknwonCoin())?
    .clone();

  let mut ctx = SpendContext::new(); // just to run puzzles more easily

  let puzzle_and_solution_req = peer
    .request_puzzle_and_solution(
      last_coin_record.coin.coin_id(),
      last_coin_record
        .spent_height
        .ok_or(WalletError::UnknwonCoin())?,
    )
    .await
    .map_err(|err| WalletError::RejectPuzzleSolution(err))?;

  let cs = CoinSpend {
    coin: last_coin_record.coin,
    puzzle_reveal: puzzle_and_solution_req.puzzle,
    solution: puzzle_and_solution_req.solution,
  };

  let first_store = DataStore::<DataStoreMetadata>::from_spend(&mut ctx.allocator, &cs, vec![])
    .map_err(|_| WalletError::Parse())?
    .ok_or(WalletError::Parse())?;

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
      let block_header = peer
        .request_block_header(spent_height)
        .await
        .map_err(|err| WalletError::RejectHeaderRequest(err))?;
      block_header.foliage_transaction_block.unwrap().timestamp
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

pub enum DataStoreInnerSpendInfo {
  Owner(PublicKey),
  Admin(PublicKey),
  Writer(PublicKey),
  // does not include oracle since it can't change metadata/owners :(
}

fn update_store_with_conditions(
  ctx: &mut SpendContext,
  conditions: Conditions,
  store: DataStore,
  inner_spend_info: DataStoreInnerSpendInfo,
  allow_admin: bool,
  allow_writer: bool,
) -> Result<SuccessResponse, WalletError> {
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
  let target_time_seconds = target_time_seconds
    + SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("Time went backwards")
      .as_secs();

  let fee_estimate_group = peer
    .request_fee_estimates(vec![target_time_seconds])
    .await
    .map_err(|e| ClientError::Rejection(format!("Request failed: {:?}", e)))?;

  if let Some(error_message) = fee_estimate_group.error {
    return Err(ClientError::Rejection(error_message));
  }

  if let Some(first_estimate) = fee_estimate_group.estimates.first() {
    if let Some(error_message) = &first_estimate.error {
      return Err(ClientError::Rejection(error_message.clone()));
    }

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

// https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0002.md#signmessage
pub fn make_message(msg: Bytes) -> Bytes32 {
  let mut alloc = Allocator::new();
  let thing_ptr = clvm_tuple!("Chia Signed Message", msg)
    .to_clvm(&mut alloc)
    .expect("Could not serialize message");

  tree_hash(&alloc, thing_ptr).into()
}

pub fn sign_message(message: Bytes, sk: SecretKey) -> Signature {
  sign(&sk, &make_message(message))
}

pub fn verify_signature(message: Bytes, pk: PublicKey, sig: Signature) -> bool {
  verify(&sig, &pk, &make_message(message))
}

pub fn get_cost(coin_spends: Vec<CoinSpend>) -> Result<u64, Error> {
  let mut alloc = Allocator::new();

  let generator = solution_generator(
    coin_spends
      .into_iter()
      .map(|cs| (cs.coin, cs.puzzle_reveal, cs.solution)),
  )
  .map_err(|err| Error::Io(err))?;

  let conds =
    run_block_generator::<&[u8], EmptyVisitor>(&mut alloc, &generator, &[], u64::MAX, MEMPOOL_MODE)
      .map_err(|err| Error::Validation(err))?;

  let conds =
    OwnedSpendBundleConditions::from(&alloc, conds).map_err(|err| Error::ChiaConsensus(err))?;

  Ok(conds.cost)
}
