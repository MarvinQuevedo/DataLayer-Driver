use std::collections::HashMap;

use chia::bls::sign;
use chia::bls::verify;
use chia::bls::PublicKey;
use chia::bls::SecretKey;
use chia::bls::Signature;
use chia::client::Error as ClientError;
use chia::client::Peer;
use chia::clvm_traits::clvm_tuple;
use chia::clvm_traits::ToClvm;
use chia::clvm_utils::tree_hash;
use chia::consensus::consensus_constants::ConsensusConstants;
use chia::consensus::consensus_constants::TEST_CONSTANTS;
use chia::consensus::gen::conditions::EmptyVisitor;
use chia::consensus::gen::flags::MEMPOOL_MODE;
use chia::consensus::gen::owned_conditions::OwnedSpendBundleConditions;
use chia::consensus::gen::run_block_generator::run_block_generator;
use chia::consensus::gen::solution_generator::solution_generator;
use chia::consensus::gen::validation_error::ValidationErr;
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
use chia::puzzles::DeriveSynthetic;
use chia_wallet_sdk::get_merkle_tree;
use chia_wallet_sdk::select_coins as select_coins_algo;
use chia_wallet_sdk::CoinSelectionError;
use chia_wallet_sdk::Condition;
use chia_wallet_sdk::Conditions;
use chia_wallet_sdk::DataStore;
use chia_wallet_sdk::DataStoreMetadata;
use chia_wallet_sdk::DelegatedPuzzle;
use chia_wallet_sdk::DriverError;
use chia_wallet_sdk::Launcher;
use chia_wallet_sdk::Layer;
use chia_wallet_sdk::MeltSingleton;
use chia_wallet_sdk::NewMerkleRootCondition;
use chia_wallet_sdk::OracleLayer;
use chia_wallet_sdk::RequiredSignature;
use chia_wallet_sdk::SignerError;
use chia_wallet_sdk::SpendContext;
use chia_wallet_sdk::StandardLayer;
use chia_wallet_sdk::WriterLayer;
use clvmr::sha2::Sha256;
use clvmr::Allocator;
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

  #[error("ParseError")]
  Parse(),

  #[error("UnknownCoin")]
  UnknwonCoin(),

  #[error("Permission error: puzzle can't perform this action")]
  Permission(),

  #[error("Io error: {0}")]
  Io(std::io::Error),

  #[error("Validation error: {0}")]
  Validation(#[from] ValidationErr),
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
  let total_amount_from_coins = selected_coins.iter().map(|c| c.amount).sum::<u64>();

  let total_amount = fee + 1;

  let mut ctx = SpendContext::new();

  let lead_coin = selected_coins[0].clone();
  let lead_coin_name = lead_coin.coin_id();

  let mut hasher = Sha256::new();
  hasher.update(lead_coin_name);
  hasher.update([0; 1]);
  let lead_ann_id = Bytes32::new(hasher.finalize());

  for coin in selected_coins.into_iter().skip(1) {
    ctx.spend_p2_coin(
      coin,
      minter_synthetic_key,
      Conditions::new().assert_coin_announcement(lead_ann_id),
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
    DataStoreInnerSpend::Owner(pk) => StandardLayer::new(pk).spend(ctx, conditions)?,
    DataStoreInnerSpend::Admin(pk) => {
      if !allow_admin {
        return Err(WalletError::Permission());
      }

      StandardLayer::new(pk).spend(ctx, conditions)?
    }
    DataStoreInnerSpend::Writer(pk) => {
      if !allow_writer {
        return Err(WalletError::Permission());
      }

      WriterLayer::new(StandardLayer::new(pk)).spend(ctx, conditions)?
    }
  };

  let parent_delegated_puzzles = datastore.info.delegated_puzzles.clone();
  let new_spend = datastore.spend(ctx, inner_datastore_spend)?;

  let new_datastore = DataStore::<DataStoreMetadata>::from_spend(
    &mut ctx.allocator,
    &new_spend,
    parent_delegated_puzzles,
  )?
  .ok_or(WalletError::Parse())?;

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
    DataStoreInnerSpend::Owner(_) => DataStore::<DataStoreMetadata>::owner_create_coin_condition(
      ctx,
      datastore.info.launcher_id,
      new_owner_puzzle_hash,
      new_delegated_puzzles,
      true,
    )?,
    DataStoreInnerSpend::Admin(_) => {
      let merkle_tree = get_merkle_tree(ctx, new_delegated_puzzles.clone())?;

      let new_merkle_root_condition = NewMerkleRootCondition {
        new_merkle_root: merkle_tree.root,
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
    _ => return Err(WalletError::Permission()),
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
    new_metadata_condition =
      new_metadata_condition.with(DataStore::<DataStoreMetadata>::owner_create_coin_condition(
        ctx,
        datastore.info.launcher_id,
        datastore.info.owner_puzzle_hash,
        datastore.info.delegated_puzzles.clone(),
        false,
      )?);
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
    .with(Condition::other(
      MeltSingleton {}
        .to_clvm(&mut ctx.allocator)
        .map_err(DriverError::ToClvm)?,
    ));

  let inner_datastore_spend = StandardLayer::new(owner_pk).spend(ctx, melt_conditions)?;

  let new_spend = datastore.spend(ctx, inner_datastore_spend)?;

  Ok(vec![new_spend])
}

pub fn oracle_spend(
  spender_synthetic_key: PublicKey,
  selected_coins: Vec<Coin>,
  datastore: DataStore,
  fee: u64,
) -> Result<SuccessResponse, WalletError> {
  let Some(DelegatedPuzzle::Oracle(oracle_ph, oracle_fee)) =
    datastore.info.delegated_puzzles.iter().find(|dp| match dp {
      DelegatedPuzzle::Oracle(_, _) => true,
      _ => false,
    })
  else {
    return Err(WalletError::Permission());
  };

  let spender_puzzle_hash: Bytes32 = StandardArgs::curry_tree_hash(spender_synthetic_key).into();

  let total_amount = oracle_fee + fee;

  let ctx = &mut SpendContext::new();

  let lead_coin = selected_coins[0].clone();
  let lead_coin_name = lead_coin.coin_id();

  let mut hasher = Sha256::new();
  hasher.update(lead_coin_name);
  hasher.update([0; 1]);
  let lead_ann_id = Bytes32::new(hasher.finalize());

  let total_amount_from_coins = selected_coins.iter().map(|c| c.amount).sum::<u64>();
  for coin in selected_coins.into_iter().skip(1) {
    ctx.spend_p2_coin(
      coin,
      spender_synthetic_key,
      Conditions::new().assert_coin_announcement(lead_ann_id),
    )?;
  }

  let mut hasher2 = Sha256::new();
  hasher2.update(datastore.coin.puzzle_hash);
  hasher2.update(Bytes::new("$".into()));
  let oracle_ann_id = Bytes32::new(hasher2.finalize());

  let assert_oracle_conds = Conditions::new().assert_puzzle_announcement(oracle_ann_id);

  let mut lead_coin_conditions = assert_oracle_conds;
  if total_amount_from_coins > total_amount {
    lead_coin_conditions = lead_coin_conditions.create_coin(
      spender_puzzle_hash,
      total_amount_from_coins - total_amount,
      vec![spender_puzzle_hash.into()],
    );
  }
  if fee > 0 {
    lead_coin_conditions = lead_coin_conditions.reserve_fee(fee);
  }
  ctx.spend_p2_coin(lead_coin, spender_synthetic_key, lead_coin_conditions)?;

  let inner_datastore_spend = OracleLayer::new(oracle_ph.clone(), oracle_fee.clone())
    .ok_or(DriverError::OddOracleFee)?
    .construct_spend(ctx, ())?;

  let parent_delegated_puzzles = datastore.info.delegated_puzzles.clone();
  let new_spend = datastore.spend(ctx, inner_datastore_spend)?;

  let new_datastore =
    DataStore::from_spend(&mut ctx.allocator, &new_spend, parent_delegated_puzzles)?
      .ok_or(WalletError::Parse())?;
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

  let lead_coin = selected_coins[0].clone();
  let lead_coin_name = lead_coin.coin_id();

  let mut hasher = Sha256::new();
  hasher.update(lead_coin_name);
  hasher.update([0; 1]);
  let lead_ann_id = Bytes32::new(hasher.finalize());

  for coin in selected_coins.into_iter().skip(1) {
    ctx.spend_p2_coin(
      coin,
      spender_synthetic_key,
      Conditions::new().assert_coin_announcement(lead_ann_id),
    )?;
  }

  let mut lead_coin_conditions = Conditions::new().reserve_fee(fee);
  if total_amount_from_coins > fee {
    lead_coin_conditions = lead_coin_conditions.create_coin(
      spender_puzzle_hash,
      total_amount_from_coins - fee,
      vec![spender_puzzle_hash.into()],
    );
  }
  for coin_id in coin_ids {
    lead_coin_conditions = lead_coin_conditions.assert_concurrent_spend(coin_id);
  }

  ctx.spend_p2_coin(lead_coin, spender_synthetic_key, lead_coin_conditions)?;

  Ok(ctx.take())
}

pub fn public_key_to_synthetic_key(pk: PublicKey) -> PublicKey {
  pk.derive_synthetic()
}

pub fn secret_key_to_synthetic_key(sk: SecretKey) -> SecretKey {
  sk.derive_synthetic()
}

#[derive(Debug, Clone, Copy)]
enum TargetNetwork {
  Mainnet,
  Testnet11,
}

// TODO: only temporary
impl TargetNetwork {
  fn get_constants(&self) -> ConsensusConstants {
    match self {
      TargetNetwork::Mainnet => TEST_CONSTANTS,
      TargetNetwork::Testnet11 => TEST_CONSTANTS,
    }
  }
}

pub fn sign_coin_spends(
  coin_spends: Vec<CoinSpend>,
  private_keys: Vec<SecretKey>,
  network: TargetNetwork,
) -> Result<Signature, SignerError> {
  let mut allocator = Allocator::new();

  let required_signatures =
    RequiredSignature::from_coin_spends(&mut allocator, &coin_spends, &network.get_constants())?;

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
) -> Result<bool, WalletError> {
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
pub fn make_message(msg: Bytes) -> Result<Bytes32, WalletError> {
  let mut alloc = Allocator::new();
  let thing_ptr = clvm_tuple!("Chia Signed Message", msg).to_clvm(&mut alloc)?;

  Ok(tree_hash(&alloc, thing_ptr).into())
}

pub fn sign_message(message: Bytes, sk: SecretKey) -> Result<Signature, WalletError> {
  Ok(sign(&sk, &make_message(message)?))
}

pub fn verify_signature(
  message: Bytes,
  pk: PublicKey,
  sig: Signature,
) -> Result<bool, WalletError> {
  Ok(verify(&sig, &pk, &make_message(message)?))
}

pub fn get_cost(coin_spends: Vec<CoinSpend>) -> Result<u64, WalletError> {
  let mut alloc = Allocator::new();

  let generator = solution_generator(
    coin_spends
      .into_iter()
      .map(|cs| (cs.coin, cs.puzzle_reveal, cs.solution)),
  )
  .map_err(WalletError::Io)?;

  let conds = run_block_generator::<&[u8], EmptyVisitor, _>(
    &mut alloc,
    &generator,
    &[],
    u64::MAX,
    MEMPOOL_MODE,
    &TargetNetwork::Mainnet.get_constants(),
  )?;

  let conds = OwnedSpendBundleConditions::from(&alloc, conds);

  Ok(conds.cost)
}
