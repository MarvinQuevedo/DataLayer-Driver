use std::collections::HashMap;

use chia::bls::sign;
use chia::bls::PublicKey;
use chia::bls::SecretKey;
use chia::bls::Signature;
use chia::client::Error as ClientError;
use chia::client::Peer;
use chia_protocol::Bytes;
use chia_protocol::Coin;
use chia_protocol::RejectPuzzleSolution;
use chia_protocol::SpendBundle;
use chia_protocol::TransactionAck;
use chia_protocol::{Bytes32, CoinSpend};
use chia_puzzles::standard::StandardArgs;
use chia_puzzles::DeriveSynthetic;
use chia_sdk_driver::Conditions;
use chia_sdk_driver::Launcher;
use chia_sdk_driver::SpendContext;
use chia_sdk_driver::SpendError;
use chia_sdk_types::conditions::Condition;
use chia_sdk_types::conditions::ReserveFee;
use chia_wallet_sdk::select_coins;
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
  CoinSelection(#[from] CoinSelectionError),

  #[error("{0:?}")]
  RejectPuzzleSolution(#[from] ClientError<RejectPuzzleSolution>),

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

pub async fn get_coins(
  peer: &Peer,
  puzzle_hash: Bytes32,
  min_height: u32,
) -> Result<Vec<Coin>, Error> {
  let coin_states = peer
    .register_for_ph_updates(vec![puzzle_hash], min_height)
    .await
    .map_err(|e| Error::Wallet(e))?;

  Ok(
    coin_states
      .iter()
      .filter(|cs| cs.spent_height.is_none())
      .map(|cs| cs.coin)
      .collect(),
  )
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
      },
      owner_puzzle_hash: owner_puzzle_hash.into(),
      delegated_puzzles,
    },
  )?;

  let total_amount_from_coins = coins.iter().map(|c| c.amount).sum::<u64>();
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

pub async fn sync_store_using_launcher_id(
  peer: &Peer,
  launcher_id: Bytes32,
  min_height: u32,
) -> Result<SyncStoreResponse, Error> {
  let coin_states = peer
    .register_for_coin_updates(vec![launcher_id], min_height)
    .await
    .map_err(|e| Error::Wallet(e))?;
  let last_coin_record = coin_states.iter().next().ok_or(Error::UnknwonCoin())?;

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
    DataStoreInfo::from_spend(ctx.allocator_mut(), &cs, vec![]).map_err(|_| Error::Parse())?;

  return sync_store(peer, &first_info, min_height).await;
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
    DataStoreInnerSpendInfo::Owner(pk) => DatastoreInnerSpend::OwnerPuzzleSpend(
      conditions
        .p2_spend(ctx, pk)
        .map_err(|err| Error::Spend(err))?,
    ),
    DataStoreInnerSpendInfo::Admin(pk) => {
      if !allow_admin {
        return Err(Error::Permission());
      }

      let (dp, inner_puzzle_ptr) = DelegatedPuzzle::from_admin_pk(ctx.allocator_mut(), pk)
        .map_err(|err| Error::ToClvm(err))?;
      DatastoreInnerSpend::DelegatedPuzzleSpend(
        dp,
        inner_puzzle_ptr,
        conditions
          .p2_spend(ctx, pk)
          .map_err(|err| Error::Spend(err))?
          .solution(),
      )
    }
    DataStoreInnerSpendInfo::Writer(pk) => {
      if !allow_writer {
        return Err(Error::Permission());
      }

      let (dp, inner_puzzle_ptr) = DelegatedPuzzle::from_writer_pk(ctx.allocator_mut(), pk)
        .map_err(|err| Error::ToClvm(err))?;
      DatastoreInnerSpend::DelegatedPuzzleSpend(
        dp,
        inner_puzzle_ptr,
        conditions
          .p2_spend(ctx, pk)
          .map_err(|err| Error::Spend(err))?
          .solution(),
      )
    }
  };

  let new_spend =
    datastore_spend(ctx, &store_info, inner_datastore_spend).map_err(|err| Error::Spend(err))?;
  ctx.insert_coin_spend(new_spend.clone());

  let new_info = DataStoreInfo::from_spend(
    ctx.allocator_mut(),
    &new_spend,
    store_info.delegated_puzzles.clone(),
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

  let leaves: Vec<Bytes32> = new_delegated_puzzles
    .clone()
    .iter()
    .map(|dp| dp.puzzle_hash)
    .collect();
  let merkle_tree = MerkleTree::new(&leaves);
  let new_merkle_root = merkle_tree.get_root();

  let new_merkle_root_condition = NewMerkleRootCondition {
    new_merkle_root,
    memos: get_memos(new_owner_puzzle_hash.into(), new_delegated_puzzles),
  }
  .to_clvm(ctx.allocator_mut())
  .map_err(|err| Error::ToClvm(err))?;
  let new_merkle_root_condition =
    Conditions::new().condition(Condition::Other(new_merkle_root_condition));

  update_store_with_conditions(
    &mut ctx,
    new_merkle_root_condition,
    store_info,
    inner_spend_info,
    true,
    false,
  )
}

pub fn update_store_metadata(
  store_info: DataStoreInfo,
  new_root_hash: Bytes32,
  new_label: String,
  new_description: String,
  inner_spend_info: DataStoreInnerSpendInfo,
) -> Result<SuccessResponse, Error> {
  let mut ctx = SpendContext::new();

  let new_metadata = DataStoreMetadata {
    root_hash: new_root_hash,
    label: new_label,
    description: new_description,
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
  let new_metadata_condition =
    Conditions::new().condition(Condition::Other(new_metadata_condition));

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

pub async fn oracle_spend(
  peer: &Peer,
  spender_synthetic_key: PublicKey,
  spender_ph_min_height: u32,
  store_info: &DataStoreInfo,
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
  let coin_states = peer
    .register_for_ph_updates(vec![spender_puzzle_hash], spender_ph_min_height)
    .await
    .map_err(|e| Error::Wallet(e))?;

  let total_amount = oracle_fee;
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

  let total_amount_from_coins = coins.iter().map(|c| c.amount).sum::<u64>();
  let lead_coin_conditions = if total_amount_from_coins > total_amount {
    assert_oracle_conds.create_coin(spender_puzzle_hash, total_amount_from_coins - total_amount)
  } else {
    assert_oracle_conds
  };
  ctx.spend_p2_coin(lead_coin, spender_synthetic_key, lead_coin_conditions)?;

  let oracle_puzzle_ptr =
    DelegatedPuzzle::oracle_layer_full_puzzle(ctx.allocator_mut(), oracle_ph, oracle_fee)
      .map_err(|err| Error::ToClvm(err))?;
  let inner_datastore_spend = DatastoreInnerSpend::DelegatedPuzzleSpend(
    *oracle_delegated_puzzle,
    oracle_puzzle_ptr, // oracle puzzle always available
    ctx.allocator().nil(),
  );

  let new_spend = datastore_spend(&mut ctx, store_info, inner_datastore_spend)?;
  ctx.insert_coin_spend(new_spend.clone());

  let new_datastore_info = DataStoreInfo::from_spend(
    ctx.allocator_mut(),
    &new_spend,
    store_info.delegated_puzzles.clone(),
  )
  .map_err(|_| Error::Parse())?;

  Ok(SuccessResponse {
    coin_spends: ctx.take_spends(),
    new_info: new_datastore_info,
  })
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
