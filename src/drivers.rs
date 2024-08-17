use crate::{
  debug_log, merkle_root_for_delegated_puzzles, merkle_tree_for_delegated_puzzles,
  puzzles_info::{DataStoreInfo, DataStoreMetadata, DelegatedPuzzle, DelegatedPuzzleInfo},
  DLLauncherKVList, DelegationLayerArgs, DelegationLayerSolution, HintType,
  DELEGATION_LAYER_PUZZLE, DELEGATION_LAYER_PUZZLE_HASH, DL_METADATA_UPDATER_PUZZLE_HASH,
  WRITER_FILTER_PUZZLE, WRITER_FILTER_PUZZLE_HASH,
};
use chia_protocol::{Bytes, Bytes32, CoinSpend};
use chia_puzzles::{
  nft::{NftStateLayerArgs, NftStateLayerSolution, NFT_STATE_LAYER_PUZZLE_HASH},
  singleton::SingletonArgs,
  EveProof, Proof,
};
use chia_sdk_driver::{spend_singleton, Conditions, Launcher, Spend, SpendContext, SpendError};
use chia_sdk_types::conditions::{Condition, CreateCoin};
use clvm_traits::{simplify_int_bytes, FromClvmError, ToClvm};
use clvm_utils::{CurriedProgram, ToTreeHash, TreeHash};
use clvmr::{reduction::EvalErr, NodePtr};
use std::env;

pub trait SpendContextExt {
  fn delegation_layer_puzzle(&mut self) -> Result<NodePtr, SpendError>;
  fn delegated_writer_filter(&mut self) -> Result<NodePtr, SpendError>;
}

impl SpendContextExt for SpendContext {
  fn delegation_layer_puzzle(&mut self) -> Result<NodePtr, SpendError> {
    self.puzzle(DELEGATION_LAYER_PUZZLE_HASH, &DELEGATION_LAYER_PUZZLE)
  }

  fn delegated_writer_filter(&mut self) -> Result<NodePtr, SpendError> {
    self.puzzle(WRITER_FILTER_PUZZLE_HASH, &WRITER_FILTER_PUZZLE)
  }
}

pub enum DatastoreInnerSpend {
  OwnerPuzzleSpend(Spend),                      // owner puzzle spend
  DelegatedPuzzleSpend(DelegatedPuzzle, Spend), // delegated puzzle info + (inner) puzzle spend
}

pub fn spend_delegation_layer(
  ctx: &mut SpendContext,
  datastore_info: &DataStoreInfo,
  inner_datastore_spend: DatastoreInnerSpend,
) -> Result<Spend, SpendError> {
  if datastore_info.delegated_puzzles.len() == 0 {
    match inner_datastore_spend {
      DatastoreInnerSpend::OwnerPuzzleSpend(inner_spend) => {
        // no delegated puzzles, so there are two possible puzzles:
        // a) only owner puzzle
        // b) delegation layer with an empty root + owner puzzle
        // assume a, compute full puzzle hash, compare with the coin's to see which option is true

        let metadata_ptr = datastore_info
          .metadata
          .to_clvm(ctx.allocator_mut())
          .map_err(|err| SpendError::ToClvm(err))?;
        let nft_state_layer_inner_puzzle_hash: TreeHash = datastore_info.owner_puzzle_hash.into();

        let nft_layer_hash = CurriedProgram {
          program: NFT_STATE_LAYER_PUZZLE_HASH,
          args: NftStateLayerArgs {
            mod_hash: NFT_STATE_LAYER_PUZZLE_HASH.into(),
            metadata: ctx.tree_hash(metadata_ptr),
            metadata_updater_puzzle_hash: DL_METADATA_UPDATER_PUZZLE_HASH.into(),
            inner_puzzle: nft_state_layer_inner_puzzle_hash,
          },
        }
        .tree_hash();

        debug_log!("owner puzzle hash: {:?}", datastore_info.owner_puzzle_hash); // todo: debug
        debug_log!("nft layer hash: {:?}", nft_layer_hash); // todo: debug

        let full_ph_if_a =
          SingletonArgs::curry_tree_hash(datastore_info.launcher_id, nft_layer_hash);

        debug_log!("full_ph_if_a: {:?}", full_ph_if_a); // todo: debug

        if datastore_info.coin.puzzle_hash == full_ph_if_a.into() {
          return Ok(inner_spend);
        }

        debug_log!(
          "that pesky admin! {:?} {:?}",
          datastore_info.coin.puzzle_hash,
          full_ph_if_a
        ) // todo: debug
          // turns out the admin left delegated_puzzles=[]... (option b)
          // no problem; let the function continue execution as if delegated_puzzles!=[]
          // since merkle_root_for_delegated_puzzles will recognize [] and return the proper root
      }
      DatastoreInnerSpend::DelegatedPuzzleSpend(_, inner_spend) => {
        return Err(SpendError::Eval(EvalErr(
          inner_spend.solution(),
          String::from("data store does not have a delegation layer"),
        )))
      }
    };
  }

  let merkle_root = merkle_root_for_delegated_puzzles(&datastore_info.delegated_puzzles);

  let new_inner_puzzle_mod = ctx.delegation_layer_puzzle()?;
  let new_inner_puzzle_args = DelegationLayerArgs::new(
    datastore_info.launcher_id,
    datastore_info.owner_puzzle_hash,
    merkle_root.into(),
  );

  let new_inner_puzzle = CurriedProgram {
    program: new_inner_puzzle_mod,
    args: new_inner_puzzle_args,
  };

  match inner_datastore_spend {
    DatastoreInnerSpend::OwnerPuzzleSpend(owner_puzzle_spend) => {
      let new_inner_solution = DelegationLayerSolution {
        merkle_proof: None,
        puzzle_reveal: owner_puzzle_spend.puzzle(),
        puzzle_solution: owner_puzzle_spend.solution(),
      };

      return Ok(Spend::new(
        new_inner_puzzle.to_clvm(ctx.allocator_mut())?,
        new_inner_solution.to_clvm(ctx.allocator_mut())?,
      ));
    }
    DatastoreInnerSpend::DelegatedPuzzleSpend(delegated_puzzle, delegated_inner_spend) => {
      let full_puzzle = delegated_puzzle
        .get_full_puzzle(ctx.allocator_mut(), delegated_inner_spend.puzzle())
        .map_err(|_| {
          SpendError::FromClvm(FromClvmError::Custom(
            "could not build datastore full puzzle".to_string(),
          ))
        })?;

      let merkle_proof: (u32, Vec<chia_protocol::BytesImpl<32>>) =
        merkle_tree_for_delegated_puzzles(&datastore_info.delegated_puzzles)
          .generate_proof(delegated_puzzle.puzzle_hash)
          .ok_or(SpendError::FromClvm(FromClvmError::Custom(String::from(
            "could not generate merkle proof for spent puzzle",
          ))))?;

      debug_log!("merkle_proof: {:?}", merkle_proof); // todo: debug

      let new_inner_solution = DelegationLayerSolution::<NodePtr, NodePtr> {
        merkle_proof: Some(merkle_proof),
        puzzle_reveal: full_puzzle,
        puzzle_solution: match delegated_puzzle.puzzle_info {
          DelegatedPuzzleInfo::Admin(_) => delegated_inner_spend.solution(),
          DelegatedPuzzleInfo::Writer(_) => ctx.alloc(&vec![delegated_inner_spend.solution()])?,
          DelegatedPuzzleInfo::Oracle(_, _) => {
            ctx.alloc(&vec![delegated_inner_spend.solution()])?
          }
        },
      };

      // todo: debug
      debug_log!(
        "puz + filter puzzle hash: {:}",
        encode(ctx.tree_hash(full_puzzle))
      );
      debug_log!(
        "puz puzzle hash: {:}",
        match delegated_puzzle.puzzle_info {
          DelegatedPuzzleInfo::Admin(a) => encode(a),
          DelegatedPuzzleInfo::Writer(b) => encode(b),
          DelegatedPuzzleInfo::Oracle(_, _) => "nope".to_string(),
        }
      );
      // debug_log!(
      //     "writer puzzle reveal: {:}",
      //     encode(
      //         Program::from_node_ptr(ctx.allocator_mut(), full_puzzle)
      //             .unwrap()
      //             .clone()
      //             .to_bytes()
      //             .unwrap()
      //     )
      // ); // todo: debug
      // debug_log!(
      //     "writer puzzle solution: {:}",
      //     encode(
      //         Program::from_node_ptr(ctx.allocator_mut(), delegated_puzzle_solution)
      //             .unwrap()
      //             .clone()
      //             .to_bytes()
      //             .unwrap()
      //     )
      // ); // todo: debug
      // todo: debug

      Ok(Spend::new(
        new_inner_puzzle.to_clvm(ctx.allocator_mut())?,
        new_inner_solution.to_clvm(ctx.allocator_mut())?,
      ))
    }
  }
}

pub fn spend_nft_state_layer_custom_metadata_updated<M>(
  ctx: &mut SpendContext,
  metadata: M,
  inner_spend: Spend,
) -> Result<Spend, SpendError>
where
  M: ToClvm<NodePtr>,
{
  let nft_state_layer = ctx.nft_state_layer()?;

  let puzzle = ctx.alloc(&CurriedProgram {
    program: nft_state_layer,
    args: NftStateLayerArgs {
      mod_hash: NFT_STATE_LAYER_PUZZLE_HASH.into(),
      metadata: metadata,
      metadata_updater_puzzle_hash: DL_METADATA_UPDATER_PUZZLE_HASH.into(),
      inner_puzzle: inner_spend.puzzle(),
    },
  })?;

  let solution = ctx.alloc(&NftStateLayerSolution {
    inner_solution: inner_spend.solution(),
  })?;

  Ok(Spend::new(puzzle, solution))
}

use hex::encode;
use num_bigint::BigInt;

pub fn datastore_spend(
  ctx: &mut SpendContext,
  datastore_info: &DataStoreInfo,
  inner_datastore_spend: DatastoreInnerSpend,
) -> Result<CoinSpend, SpendError> {
  // 1. Handle delegation layer spend
  let inner_spend = spend_delegation_layer(ctx, datastore_info, inner_datastore_spend)?;
  debug_log!("inner_spend!"); // todo: debug
                              // debug_log!(
                              //     "puzzle: {:}",
                              //     encode(
                              //         Program::from_node_ptr(ctx.allocator_mut(), inner_spend.puzzle())
                              //             .unwrap()
                              //             .clone()
                              //             .to_bytes()
                              //             .unwrap()
                              //     )
                              // ); // todo: debug
                              // debug_log!(
                              //     "solution: {:}",
                              //     encode(
                              //         Program::from_node_ptr(ctx.allocator_mut(), inner_spend.solution())
                              //             .unwrap()
                              //             .clone()
                              //             .to_bytes()
                              //             .unwrap()
                              //     )
                              // ); // todo: debug

  // 2. Handle state layer spend
  // allows custom metadata updater hash
  let state_layer_spend =
    spend_nft_state_layer_custom_metadata_updated(ctx, &datastore_info.metadata, inner_spend)?;

  // 3. Spend singleton
  spend_singleton(
    ctx,
    datastore_info.coin,
    datastore_info.launcher_id,
    datastore_info.proof,
    state_layer_spend,
  )
}

pub struct DataStoreMintInfo {
  // NFT state layer
  pub metadata: DataStoreMetadata,
  // inner puzzle (either p2 or delegation_layer + p2)
  pub owner_puzzle_hash: TreeHash,
  pub delegated_puzzles: Vec<DelegatedPuzzle>,
}

pub trait LauncherExt {
  fn mint_datastore(
    self,
    ctx: &mut SpendContext,
    info: DataStoreMintInfo,
  ) -> Result<(Conditions, DataStoreInfo), SpendError>
  where
    Self: Sized;
}

pub fn get_memos(
  launcher_id: Bytes32,
  owner_puzzle_hash: TreeHash,
  delegated_puzzles: Vec<DelegatedPuzzle>,
) -> Vec<Bytes> {
  let owner_puzzle_hash: Bytes32 = owner_puzzle_hash.into();
  let mut memos: Vec<Bytes> = vec![launcher_id.into(), owner_puzzle_hash.into()];

  for delegated_puzzle in delegated_puzzles {
    match delegated_puzzle.puzzle_info {
      DelegatedPuzzleInfo::Admin(inner_puzzle_hash) => {
        memos.push(Bytes::new([HintType::AdminPuzzle.value()].into()));
        memos.push(inner_puzzle_hash.into());
      }
      DelegatedPuzzleInfo::Writer(inner_puzzle_hash) => {
        memos.push(Bytes::new([HintType::WriterPuzzle.value()].into()));
        memos.push(inner_puzzle_hash.into());
      }
      DelegatedPuzzleInfo::Oracle(oracle_puzzle_hash, oracle_fee) => {
        memos.push(Bytes::new([HintType::OraclePuzzle.value()].into()));
        memos.push(oracle_puzzle_hash.into());
        memos.push(Bytes::new(
          simplify_int_bytes(&BigInt::from(oracle_fee).to_signed_bytes_be()).into(),
        ));
      }
    }
  }

  debug_log!("memos: {:?}", memos);
  memos
}

impl LauncherExt for Launcher {
  fn mint_datastore(
    self,
    ctx: &mut SpendContext,
    info: DataStoreMintInfo,
  ) -> Result<(Conditions, DataStoreInfo), SpendError>
  where
    Self: Sized,
    TreeHash: ToTreeHash + ToClvm<TreeHash>,
    NodePtr: ToClvm<NodePtr>,
    NftStateLayerArgs<TreeHash, TreeHash>: ToClvm<TreeHash> + ToTreeHash,
  {
    let launcher_coin = self.coin();
    let launcher_id = launcher_coin.coin_id();

    let inner_puzzle_hash: TreeHash = if info.delegated_puzzles.len() == 0 {
      info.owner_puzzle_hash
    } else {
      DelegationLayerArgs::curry_tree_hash(
        launcher_id,
        info.owner_puzzle_hash.into(),
        merkle_root_for_delegated_puzzles(&info.delegated_puzzles),
      )
    };

    let metadata_ptr = ctx.alloc(&info.metadata)?;
    let metadata_hash = ctx.tree_hash(metadata_ptr);
    let state_layer_hash = CurriedProgram {
      program: NFT_STATE_LAYER_PUZZLE_HASH,
      args: NftStateLayerArgs::<TreeHash, TreeHash> {
        mod_hash: NFT_STATE_LAYER_PUZZLE_HASH.into(),
        metadata: metadata_hash,
        metadata_updater_puzzle_hash: DL_METADATA_UPDATER_PUZZLE_HASH.into(),
        inner_puzzle: inner_puzzle_hash,
      },
    }
    .tree_hash();

    let mut memos = get_memos(
      Bytes32::default(),
      info.owner_puzzle_hash,
      info.delegated_puzzles.clone(),
    )
    .into_iter()
    .skip(1)
    .collect();
    if info.delegated_puzzles.len() == 0 {
      memos = vec![];
    }
    let kv_list = DLLauncherKVList {
      metadata: info.metadata.clone(),
      state_layer_inner_puzzle_hash: inner_puzzle_hash.into(),
      memos,
    };

    let (chained_spend, eve_coin) = self.spend(ctx, state_layer_hash.into(), kv_list)?;

    let proof: Proof = Proof::Eve(EveProof {
      parent_coin_info: launcher_coin.parent_coin_info,
      amount: launcher_coin.amount,
    });

    let data_store_info: DataStoreInfo = DataStoreInfo {
      launcher_id: launcher_id,
      coin: eve_coin,
      proof,
      metadata: info.metadata,
      owner_puzzle_hash: info.owner_puzzle_hash.into(),
      delegated_puzzles: info.delegated_puzzles.clone(),
    };

    Ok((chained_spend, data_store_info))
  }
}

// As an owner use CREATE_COIN to:
//  - just re-create store (no hints needed)
//  - change delegated puzzles (hints needed)
pub fn get_owner_create_coin_condition(
  launcher_id: Bytes32,
  new_inner_puzzle_hash: &Bytes32,
  new_delegated_puzzles: &Vec<DelegatedPuzzle>,
  hint_delegated_puzzles: bool,
) -> Condition {
  let new_puzzle_hash = if new_delegated_puzzles.len() > 0 {
    let new_merkle_root = merkle_root_for_delegated_puzzles(&new_delegated_puzzles);
    DelegationLayerArgs::curry_tree_hash(
      launcher_id,
      new_inner_puzzle_hash.clone(),
      new_merkle_root,
    )
    .into()
  } else {
    new_inner_puzzle_hash.clone()
  };

  Condition::CreateCoin(CreateCoin {
    amount: 1,
    puzzle_hash: new_puzzle_hash,
    memos: if hint_delegated_puzzles {
      get_memos(
        launcher_id,
        new_inner_puzzle_hash.clone().into(),
        new_delegated_puzzles.clone(),
      )
    } else {
      vec![launcher_id.into()]
    },
  })
}

#[cfg(test)]
pub mod tests {
  use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
  };

  use crate::{
    DefaultMetadataSolution, DefaultMetadataSolutionMetadataList, MeltCondition,
    NewMerkleRootCondition, NewMetadataCondition,
  };

  use super::*;

  use chia::{
    bls::SecretKey,
    consensus::gen::{
      conditions::EmptyVisitor, flags::MEMPOOL_MODE, owned_conditions::OwnedSpendBundleConditions,
      run_block_generator::run_block_generator, solution_generator::solution_generator,
    },
  };
  use chia_protocol::{Bytes as OgBytes, Bytes32, Coin};
  use chia_puzzles::standard::StandardArgs;
  use chia_sdk_driver::Launcher;
  use chia_sdk_test::{test_transaction, Simulator};
  use chia_sdk_types::conditions::{Condition, MeltSingleton};
  use clvmr::Allocator;
  use once_cell::sync::Lazy;
  use rstest::rstest;

  use bip39::Mnemonic;
  use rand::{Rng, SeedableRng};
  use rand_chacha::ChaCha8Rng;

  pub fn secret_keys(no_keys: usize) -> Result<Vec<SecretKey>, bip39::Error> {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    let mut keys = Vec::with_capacity(no_keys);

    for _ in 0..no_keys {
      let entropy: [u8; 32] = rng.gen();
      let mnemonic = Mnemonic::from_entropy(&entropy)?;
      let seed = mnemonic.to_seed("");
      let sk = SecretKey::from_seed(&seed);
      keys.push(sk);
    }

    Ok(keys)
  }

  struct TestStats {
    launcher_tx_costs: Vec<u64>,
    normal_spend_tx_costs: Vec<u64>,
  }

  impl TestStats {
    pub fn new() -> Self {
      Self {
        launcher_tx_costs: Vec::new(),
        normal_spend_tx_costs: Vec::new(),
      }
    }

    pub fn add_launcher_tx_cost(&mut self, cost: u64) {
      self.launcher_tx_costs.push(cost);
    }

    pub fn add_normal_spend_tx_cost(&mut self, cost: u64) {
      self.normal_spend_tx_costs.push(cost);
    }

    pub fn add_launcher_tx(&mut self, cs: &CoinSpend) {
      self.add_launcher_tx_cost(Self::get_cost(cs));
    }

    pub fn add_normal_spend_tx(&mut self, cs: &CoinSpend) {
      self.add_normal_spend_tx_cost(Self::get_cost(cs));
    }

    // special thanks to Rigidity16 for this :green_heart:
    fn get_cost(cs: &CoinSpend) -> u64 {
      let mut alloc = Allocator::new();

      let generator = solution_generator([(
        cs.coin.clone(),
        cs.puzzle_reveal.clone(),
        cs.solution.clone(),
      )])
      .expect("failed to build solution generator for spend");

      let conds = run_block_generator::<&[u8], EmptyVisitor>(
        &mut alloc,
        &generator,
        &[],
        u64::MAX,
        MEMPOOL_MODE,
      )
      .expect("failed to run block generator for spend");

      let conds = OwnedSpendBundleConditions::from(&alloc, conds)
        .expect("failed to parse owned spend bundle conditions");

      conds.cost
    }

    pub fn print_stats(&self) {
      debug_log!(
        "Launcher TX Cost - Cnt: {}, Min: {}, Max: {}, Avg: {}, Median: {}",
        self.cnt(&self.launcher_tx_costs),
        self.min(&self.launcher_tx_costs),
        self.max(&self.launcher_tx_costs),
        self.avg(&self.launcher_tx_costs),
        self.median(&self.launcher_tx_costs),
      );

      debug_log!(
        "Normal Spend TX Cost - Cnt: {}, Min: {}, Max: {}, Avg: {}, Median: {}",
        self.cnt(&self.normal_spend_tx_costs),
        self.min(&self.normal_spend_tx_costs),
        self.max(&self.normal_spend_tx_costs),
        self.avg(&self.normal_spend_tx_costs),
        self.median(&self.normal_spend_tx_costs),
      );
    }

    fn cnt(&self, data: &[u64]) -> usize {
      data.len()
    }

    fn min(&self, data: &[u64]) -> u64 {
      *data.iter().min().unwrap_or(&0)
    }

    fn max(&self, data: &[u64]) -> u64 {
      *data.iter().max().unwrap_or(&0)
    }

    fn avg(&self, data: &[u64]) -> u64 {
      if data.is_empty() {
        0
      } else {
        data.iter().sum::<u64>() / data.len() as u64
      }
    }

    fn median(&self, data: &[u64]) -> u64 {
      let mut sorted = data.to_vec();
      sorted.sort_unstable();
      let len = sorted.len();
      if len == 0 {
        0
      } else if len % 2 == 0 {
        (sorted[len / 2 - 1] + sorted[len / 2]) / 2
      } else {
        sorted[len / 2]
      }
    }
  }

  static TEST_STATS: Lazy<Mutex<TestStats>> = Lazy::new(|| Mutex::new(TestStats::new()));
  static PRINTED: AtomicBool = AtomicBool::new(false);

  #[ctor::dtor]
  fn finish() {
    if !PRINTED.swap(true, Ordering::SeqCst) {
      TEST_STATS.lock().unwrap().print_stats();
    }
  }

  fn assert_datastore_info_eq(
    ctx: &mut SpendContext,
    datastore_info: &DataStoreInfo,
    new_datastore_info: &DataStoreInfo,
    for_same_coin: bool,
  ) {
    if for_same_coin {
      assert_eq!(
        new_datastore_info.coin.coin_id(),
        datastore_info.coin.coin_id()
      );
      assert_eq!(new_datastore_info.proof, datastore_info.proof);
    }
    assert_eq!(new_datastore_info.launcher_id, datastore_info.launcher_id);

    debug_log!(
      "new datastore info metadata: {:?}",
      new_datastore_info.metadata.clone()
    ); // todo: debug
    debug_log!(
      "datastore info metadata: {:?}",
      datastore_info.metadata.clone()
    ); // todo: debug
    let ptr1 = ctx.alloc(&new_datastore_info.metadata).unwrap();
    let ptr2 = ctx.alloc(&datastore_info.metadata).unwrap();
    assert_eq!(ctx.tree_hash(ptr1), ctx.tree_hash(ptr2));

    assert_eq!(
      new_datastore_info.owner_puzzle_hash,
      datastore_info.owner_puzzle_hash
    );

    if datastore_info.delegated_puzzles.len() > 0 {
      let delegated_puzzles = datastore_info.delegated_puzzles.clone();
      // when comparing delegated puzzles, don't care about
      // their full_puzzle attribute
      let new_delegated_puzzles = new_datastore_info.delegated_puzzles.clone();
      for i in 0..delegated_puzzles.len() {
        let a = delegated_puzzles.get(i).unwrap();
        let b = new_delegated_puzzles.get(i).unwrap();

        debug_log!("compating phes - a: {:?}, b: {:?}", a, b); // todo: debug
        assert_eq!(a.puzzle_hash, b.puzzle_hash);
        assert_eq!(a.puzzle_info, b.puzzle_info);
      }
    } else {
      assert_eq!(new_datastore_info.delegated_puzzles.len(), 0);
    }
  }

  #[tokio::test]
  async fn test_simple_datastore() -> anyhow::Result<()> {
    let sim = Simulator::new().await?;
    let peer = sim.connect().await?;

    let [sk]: [SecretKey; 1] = secret_keys(1).unwrap().try_into().unwrap();
    let pk = sk.public_key();

    let puzzle_hash = StandardArgs::curry_tree_hash(pk).into();
    let coin = sim.mint_coin(puzzle_hash, 1).await;

    let ctx = &mut SpendContext::new();

    let (launch_singleton, datastore_info) = Launcher::new(coin.coin_id(), 1).mint_datastore(
      ctx,
      DataStoreMintInfo {
        metadata: DataStoreMetadata::root_hash_only(Hash::ZERO.value()),
        owner_puzzle_hash: puzzle_hash.into(),
        delegated_puzzles: vec![],
      },
    )?;

    ctx.spend_p2_coin(coin, pk, launch_singleton)?;

    let spends = ctx.take_spends();
    for spend in spends {
      if spend.coin.coin_id() == datastore_info.launcher_id {
        let new_datastore_info =
          DataStoreInfo::from_spend(ctx.allocator_mut(), &spend, &vec![]).unwrap();

        assert_datastore_info_eq(ctx, &datastore_info, &new_datastore_info, true);

        {
          let mut stats = TEST_STATS.lock().unwrap();
          stats.add_launcher_tx(&spend);
        }
      }

      ctx.insert_coin_spend(spend);
    }

    let datastore_inner_spend = Conditions::new()
      .create_coin(puzzle_hash, 1)
      .p2_spend(ctx, pk)?;
    let inner_datastore_spend = DatastoreInnerSpend::OwnerPuzzleSpend(datastore_inner_spend);
    let new_spend = datastore_spend(ctx, &datastore_info, inner_datastore_spend)?;
    {
      let mut stats = TEST_STATS.lock().unwrap();
      stats.add_normal_spend_tx(&new_spend);
    }

    ctx.insert_coin_spend(new_spend);

    test_transaction(
      &peer,
      ctx.take_spends(),
      &[sk],
      sim.config().genesis_challenge,
    )
    .await;

    // Make sure the datastore was created.
    let coin_state = sim
      .coin_state(datastore_info.coin.coin_id())
      .await
      .expect("expected datastore coin");
    assert_eq!(coin_state.coin, datastore_info.coin);
    assert!(coin_state.spent_height.is_some());

    Ok(())
  }

  #[derive(PartialEq)]
  pub enum Label {
    NONE,
    SOME,
    NEW,
  }

  impl Label {
    pub fn value(&self) -> Option<String> {
      match self {
        Label::NONE => None,
        Label::SOME => Some(String::from("label")),
        Label::NEW => Some(String::from("new_label")),
      }
    }
  }

  #[derive(PartialEq)]
  pub enum Description {
    NONE,
    SOME,
    NEW,
  }

  impl Description {
    pub fn value(&self) -> Option<String> {
      match self {
        Description::NONE => None,
        Description::SOME => Some(String::from("description")),
        Description::NEW => Some(String::from("new_description")),
      }
    }
  }

  #[derive(PartialEq)]
  pub enum Hash {
    ZERO,
    SOME,
  }

  impl Hash {
    pub fn value(&self) -> Bytes32 {
      match self {
        Hash::ZERO => Bytes32::from([0; 32]),
        Hash::SOME => Bytes32::from([1; 32]),
      }
    }
  }

  #[derive(PartialEq)]
  pub enum Bytes {
    NONE,
    SOME,
    NEW,
  }

  impl Bytes {
    pub fn value(&self) -> Option<u64> {
      match self {
        Bytes::NONE => None,
        Bytes::SOME => Some(1337),
        Bytes::NEW => Some(42),
      }
    }
  }

  #[tokio::test]
  async fn test_datastore_with_delegation_layer() -> anyhow::Result<()> {
    let sim = Simulator::new().await?;
    let peer = sim.connect().await?;

    let [owner_sk, admin_sk, writer_sk]: [SecretKey; 3] =
      secret_keys(3).unwrap().try_into().unwrap();

    let owner_pk = owner_sk.public_key();
    let admin_pk = admin_sk.public_key();
    let writer_pk = writer_sk.public_key();

    let oracle_puzzle_hash: Bytes32 = [1; 32].into();
    let oracle_fee = 1000;

    let owner_puzzle_hash = StandardArgs::curry_tree_hash(owner_pk).into();
    let coin = sim.mint_coin(owner_puzzle_hash, 1).await;

    let ctx = &mut SpendContext::new();

    // let owner_puzzle: NodePtr = CurriedProgram {
    //     program: ctx.standard_puzzle()?,
    //     args: StandardArgs::new(owner_pk),
    // }
    // .to_clvm(ctx.allocator_mut())?;

    let admin_puzzle: NodePtr = CurriedProgram {
      program: ctx.standard_puzzle()?,
      args: StandardArgs::new(admin_pk),
    }
    .to_clvm(ctx.allocator_mut())?;

    let writer_puzzle: NodePtr = CurriedProgram {
      program: ctx.standard_puzzle()?,
      args: StandardArgs::new(writer_pk),
    }
    .to_clvm(ctx.allocator_mut())?;

    let admin_delegated_puzzle =
      DelegatedPuzzle::from_admin_inner_puzzle(ctx.allocator_mut(), admin_puzzle).unwrap();
    let writer_delegated_puzzle =
      DelegatedPuzzle::from_writer_inner_puzzle(ctx.allocator_mut(), writer_puzzle).unwrap();
    debug_log!(
      "writer puzzle hash: {:}",
      encode(writer_delegated_puzzle.puzzle_hash)
    ); // todo: debug

    let oracle_delegated_puzzle =
      DelegatedPuzzle::new_oracle(ctx.allocator_mut(), oracle_puzzle_hash, oracle_fee).unwrap();
    let (launch_singleton, datastore_info) = Launcher::new(coin.coin_id(), 1).mint_datastore(
      ctx,
      DataStoreMintInfo {
        metadata: DataStoreMetadata::default(),
        owner_puzzle_hash: owner_puzzle_hash.into(),
        delegated_puzzles: vec![
          admin_delegated_puzzle,
          writer_delegated_puzzle,
          oracle_delegated_puzzle,
        ],
      },
    )?;

    ctx.spend_p2_coin(coin, owner_pk, launch_singleton)?;

    let spends = ctx.take_spends();
    for spend in spends {
      if spend.coin.coin_id() == datastore_info.launcher_id {
        let new_datastore_info =
          DataStoreInfo::from_spend(ctx.allocator_mut(), &spend, &vec![]).unwrap();

        {
          let mut stats = TEST_STATS.lock().unwrap();
          stats.add_launcher_tx(&spend);
        }

        assert_datastore_info_eq(ctx, &datastore_info, &new_datastore_info, true);
      }

      ctx.insert_coin_spend(spend);
    }

    assert_eq!(
      encode(datastore_info.metadata.root_hash),
      "0000000000000000000000000000000000000000000000000000000000000000" // serializing to bytes prepends a0 = len
    );

    // writer: update metadata
    let new_metadata = DataStoreMetadata {
      root_hash: Hash::SOME.value(),
      label: Label::SOME.value(),
      description: Description::SOME.value(),
      bytes: Bytes::SOME.value(),
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
    .unwrap();

    let new_metadata_inner_spend = Conditions::new()
      .condition(Condition::Other(new_metadata_condition))
      .p2_spend(ctx, writer_pk)?;

    // delegated puzzle info + inner puzzle reveal + solution
    let inner_datastore_spend = DatastoreInnerSpend::DelegatedPuzzleSpend(
      writer_delegated_puzzle,
      Spend::new(writer_puzzle, new_metadata_inner_spend.solution()),
    );
    let new_spend = datastore_spend(ctx, &datastore_info, inner_datastore_spend)?;
    {
      let mut stats = TEST_STATS.lock().unwrap();
      stats.add_normal_spend_tx(&new_spend);
    }
    ctx.insert_coin_spend(new_spend.clone());

    let datastore_info = DataStoreInfo::from_spend(
      ctx.allocator_mut(),
      &new_spend,
      &datastore_info.delegated_puzzles,
    )
    .unwrap();
    assert_eq!(
      encode(datastore_info.metadata.root_hash),
      "0101010101010101010101010101010101010101010101010101010101010101" // serializing to bytes prepends a0 = len
    );
    assert_eq!(datastore_info.metadata.label, Label::SOME.value());
    assert_eq!(
      datastore_info.metadata.description,
      Description::SOME.value()
    );

    // admin: remove writer from delegated puzzles
    let delegated_puzzles = vec![admin_delegated_puzzle, oracle_delegated_puzzle];
    let new_merkle_root = merkle_root_for_delegated_puzzles(&delegated_puzzles);

    let new_merkle_root_condition = NewMerkleRootCondition {
      new_merkle_root,
      memos: get_memos(
        datastore_info.launcher_id,
        owner_puzzle_hash.into(),
        delegated_puzzles,
      ),
    }
    .to_clvm(ctx.allocator_mut())
    .unwrap();

    let inner_spend = Conditions::new()
      .condition(Condition::Other(new_merkle_root_condition))
      .p2_spend(ctx, writer_pk)?;

    // delegated puzzle info + inner puzzle reveal + solution
    let inner_datastore_spend = DatastoreInnerSpend::DelegatedPuzzleSpend(
      admin_delegated_puzzle,
      Spend::new(admin_puzzle, inner_spend.solution()),
    );
    let new_spend = datastore_spend(ctx, &datastore_info, inner_datastore_spend)?;
    {
      let mut stats = TEST_STATS.lock().unwrap();
      stats.add_normal_spend_tx(&new_spend);
    }
    ctx.insert_coin_spend(new_spend.clone());

    let datastore_info = DataStoreInfo::from_spend(
      ctx.allocator_mut(),
      &new_spend,
      &datastore_info.delegated_puzzles,
    )
    .unwrap();
    assert!(datastore_info.delegated_puzzles.len() > 0);

    let dep_puzzs = datastore_info.clone().delegated_puzzles;
    assert!(dep_puzzs.len() == 2);
    assert_eq!(dep_puzzs[0].puzzle_hash, admin_delegated_puzzle.puzzle_hash);
    assert_eq!(
      dep_puzzs[1].puzzle_hash,
      oracle_delegated_puzzle.puzzle_hash
    );

    // oracle: just spend :)
    // delegated puzzle info + inner puzzle reveal + solution

    let inner_datastore_spend = DatastoreInnerSpend::DelegatedPuzzleSpend(
      oracle_delegated_puzzle,
      Spend::new(
        DelegatedPuzzle::oracle_layer_full_puzzle(
          ctx.allocator_mut(),
          oracle_puzzle_hash,
          oracle_fee,
        )
        .unwrap(),
        ctx.allocator().nil(),
      ),
    );
    let new_spend = datastore_spend(ctx, &datastore_info, inner_datastore_spend)?;
    ctx.insert_coin_spend(new_spend.clone());

    let new_datastore_info = DataStoreInfo::from_spend(
      ctx.allocator_mut(),
      &new_spend,
      &datastore_info.delegated_puzzles,
    )
    .unwrap();
    assert_datastore_info_eq(ctx, &datastore_info, &new_datastore_info, false);
    let datastore_info = new_datastore_info;

    // mint a coin that asserts the announcement and has enough value
    let new_coin = sim.mint_coin(owner_puzzle_hash, oracle_fee).await;
    ctx.spend_p2_coin(
      new_coin,
      owner_pk,
      Conditions::new()
        .assert_puzzle_announcement(datastore_info.coin.puzzle_hash, &OgBytes::new("$".into())),
    )?;

    // finally, remove delegation layer altogether
    let datastore_remove_delegation_layer_inner_spend = Conditions::new()
      .create_coin(owner_puzzle_hash, 1)
      .p2_spend(ctx, owner_pk)?;
    let inner_datastore_spend =
      DatastoreInnerSpend::OwnerPuzzleSpend(datastore_remove_delegation_layer_inner_spend);
    let new_spend = datastore_spend(ctx, &datastore_info, inner_datastore_spend)?;
    {
      let mut stats = TEST_STATS.lock().unwrap();
      stats.add_normal_spend_tx(&new_spend);
    }
    ctx.insert_coin_spend(new_spend.clone());

    let new_datastore_info =
      DataStoreInfo::from_spend(ctx.allocator_mut(), &new_spend, &vec![]).unwrap();
    assert_eq!(new_datastore_info.delegated_puzzles.len(), 0);
    assert_eq!(new_datastore_info.owner_puzzle_hash, owner_puzzle_hash);

    test_transaction(
      &peer,
      ctx.take_spends(),
      &[owner_sk, admin_sk, writer_sk],
      sim.config().genesis_challenge,
    )
    .await;

    // Make sure the datastore was created.
    let coin_state = sim
      .coin_state(datastore_info.coin.coin_id())
      .await
      .expect("expected datastore coin");
    assert_eq!(coin_state.coin, datastore_info.coin);
    assert!(coin_state.spent_height.is_some());

    Ok(())
  }

  #[rstest]
  #[tokio::test]
  async fn test_datastore_launch(
    #[values(true, false)] use_meta_fields: bool,
    #[values(true, false)] with_writer: bool,
    #[values(true, false)] with_admin: bool,
    #[values(true, false)] with_oracle: bool,
  ) -> anyhow::Result<()> {
    let sim = Simulator::new().await?;
    let peer = sim.connect().await?;

    let [owner_sk, admin_sk, writer_sk]: [SecretKey; 3] =
      secret_keys(3).unwrap().try_into().unwrap();

    let owner_pk = owner_sk.public_key();
    let admin_pk = admin_sk.public_key();
    let writer_pk = writer_sk.public_key();

    let oracle_puzzle_hash: Bytes32 = [7; 32].into();
    let oracle_fee = 1000;

    let owner_puzzle_hash = StandardArgs::curry_tree_hash(owner_pk).into();
    let coin = sim.mint_coin(owner_puzzle_hash, 1).await;

    let ctx = &mut SpendContext::new();

    let (admin_delegated_puzzle, _) = DelegatedPuzzle::from_admin_pk(ctx, admin_pk).unwrap();

    let (writer_delegated_puzzle, _) = DelegatedPuzzle::from_writer_pk(ctx, writer_pk).unwrap();

    let oracle_delegated_puzzle =
      DelegatedPuzzle::new_oracle(ctx.allocator_mut(), oracle_puzzle_hash, oracle_fee).unwrap();

    let mut delegated_puzzles: Vec<DelegatedPuzzle> = vec![];
    if with_admin {
      delegated_puzzles.push(admin_delegated_puzzle);
    }
    if with_writer {
      delegated_puzzles.push(writer_delegated_puzzle);
    }
    if with_oracle {
      delegated_puzzles.push(oracle_delegated_puzzle);
    }

    let (launch_singleton, datastore_info) = Launcher::new(coin.coin_id(), 1).mint_datastore(
      ctx,
      DataStoreMintInfo {
        metadata: if use_meta_fields {
          DataStoreMetadata {
            root_hash: Hash::ZERO.value(),
            label: Label::SOME.value(),
            description: Description::SOME.value(),
            bytes: Bytes::SOME.value(),
          }
        } else {
          DataStoreMetadata::default()
        },
        owner_puzzle_hash: owner_puzzle_hash.into(),
        delegated_puzzles: delegated_puzzles,
      },
    )?;

    ctx.spend_p2_coin(coin, owner_pk, launch_singleton)?;

    let spends = ctx.take_spends();
    for spend in spends.clone() {
      if spend.coin.coin_id() == datastore_info.launcher_id {
        let new_datastore_info =
          DataStoreInfo::from_spend(ctx.allocator_mut(), &spend, &vec![]).unwrap();
        {
          let mut stats = TEST_STATS.lock().unwrap();
          stats.add_launcher_tx(&spend);
        }

        assert_datastore_info_eq(ctx, &datastore_info, &new_datastore_info, true);
      }

      ctx.insert_coin_spend(spend);
    }

    assert_eq!(
      encode(datastore_info.metadata.root_hash),
      "0000000000000000000000000000000000000000000000000000000000000000" // serializing to bytes prepends a0 = len
    );

    test_transaction(
      &peer,
      spends,
      &[owner_sk, admin_sk, writer_sk],
      sim.config().genesis_challenge,
    )
    .await;

    // Make sure the datastore was created.
    let coin_state = sim
      .coin_state(datastore_info.coin.coin_id())
      .await
      .expect("expected datastore coin");
    assert_eq!(coin_state.coin, datastore_info.coin);
    assert!(coin_state.created_height.is_some());

    Ok(())
  }

  #[derive(PartialEq, Debug)]
  enum DstAdmin {
    None,
    Same,
    New,
  }
  #[rstest(
    src_with_writer => [true, false],
    src_with_oracle => [true, false],
    dst_with_writer => [true, false],
    dst_with_oracle => [true, false],
    src_meta => [
      (Hash::ZERO, Label::NONE, Description::NONE, Bytes::NONE),
      (Hash::SOME, Label::SOME, Description::SOME, Bytes::SOME),
    ],
    dst_meta => [
      (Hash::ZERO, Label::NONE, Description::NONE, Bytes::NONE),
      (Hash::ZERO, Label::SOME, Description::SOME, Bytes::SOME),
      (Hash::ZERO, Label::NEW, Description::NEW, Bytes::NEW),
    ],
    dst_admin => [
      DstAdmin::None,
      DstAdmin::Same,
      DstAdmin::New,
    ]
  )]
  #[tokio::test]
  async fn test_datastore_admin_transition(
    src_meta: (Hash, Label, Description, Bytes),
    src_with_writer: bool,
    // src must have admin layer in this scenario
    src_with_oracle: bool,
    dst_with_writer: bool,
    dst_with_oracle: bool,
    dst_admin: DstAdmin,
    dst_meta: (Hash, Label, Description, Bytes),
  ) -> anyhow::Result<()> {
    let sim = Simulator::new().await?;
    let peer = sim.connect().await?;

    let [owner_sk, admin_sk, admin2_sk, writer_sk]: [SecretKey; 4] =
      secret_keys(4).unwrap().try_into().unwrap();

    let owner_pk = owner_sk.public_key();
    let admin_pk = admin_sk.public_key();
    let admin2_pk = admin2_sk.public_key();
    let writer_pk = writer_sk.public_key();

    let oracle_puzzle_hash: Bytes32 = [7; 32].into();
    let oracle_fee = 1000;

    let owner_puzzle_hash = StandardArgs::curry_tree_hash(owner_pk).into();
    let coin = sim.mint_coin(owner_puzzle_hash, 1).await;

    let ctx = &mut SpendContext::new();

    let (admin_delegated_puzzle, admin_inner_puzzle_reveal) =
      DelegatedPuzzle::from_admin_pk(ctx, admin_pk).unwrap();

    let (admin2_delegated_puzzle, _) = DelegatedPuzzle::from_admin_pk(ctx, admin2_pk).unwrap();

    let (writer_delegated_puzzle, _) = DelegatedPuzzle::from_writer_pk(ctx, writer_pk).unwrap();

    let oracle_delegated_puzzle =
      DelegatedPuzzle::new_oracle(ctx.allocator_mut(), oracle_puzzle_hash, oracle_fee).unwrap();

    let mut src_delegated_puzzles: Vec<DelegatedPuzzle> = vec![];
    src_delegated_puzzles.push(admin_delegated_puzzle);
    if src_with_writer {
      src_delegated_puzzles.push(writer_delegated_puzzle);
    }
    if src_with_oracle {
      src_delegated_puzzles.push(oracle_delegated_puzzle);
    }

    let (launch_singleton, src_datastore_info) = Launcher::new(coin.coin_id(), 1).mint_datastore(
      ctx,
      DataStoreMintInfo {
        metadata: DataStoreMetadata {
          root_hash: src_meta.0.value(),
          label: src_meta.1.value(),
          description: src_meta.2.value(),
          bytes: src_meta.3.value(),
        },
        owner_puzzle_hash: owner_puzzle_hash.into(),
        delegated_puzzles: src_delegated_puzzles.clone(),
      },
    )?;

    ctx.spend_p2_coin(coin, owner_pk, launch_singleton)?;
    let spends = ctx.take_spends();
    for spend in spends.clone() {
      if spend.coin.coin_id() == src_datastore_info.launcher_id {
        {
          let mut stats = TEST_STATS.lock().unwrap();
          stats.add_launcher_tx(&spend);
        }
      }

      ctx.insert_coin_spend(spend);
    }

    // transition from src to dst
    let mut admin_inner_spend = Conditions::new();

    let mut dst_delegated_puzzles: Vec<DelegatedPuzzle> = src_delegated_puzzles.clone();
    if src_with_writer != dst_with_writer
      || src_with_oracle != dst_with_oracle
      || dst_admin != DstAdmin::Same
    {
      dst_delegated_puzzles.clear();

      if dst_with_writer {
        dst_delegated_puzzles.push(writer_delegated_puzzle);
      }
      if dst_with_oracle {
        dst_delegated_puzzles.push(oracle_delegated_puzzle);
      }

      match dst_admin {
        DstAdmin::None => {}
        DstAdmin::Same => {
          dst_delegated_puzzles.push(admin_delegated_puzzle);
        }
        DstAdmin::New => {
          dst_delegated_puzzles.push(admin2_delegated_puzzle);
        }
      }

      let new_merkle_root = merkle_root_for_delegated_puzzles(&dst_delegated_puzzles);

      let new_merkle_root_condition = NewMerkleRootCondition {
        new_merkle_root,
        memos: get_memos(
          src_datastore_info.launcher_id,
          owner_puzzle_hash.into(),
          dst_delegated_puzzles.clone(),
        ),
      }
      .to_clvm(ctx.allocator_mut())
      .unwrap();

      admin_inner_spend = admin_inner_spend.condition(Condition::Other(new_merkle_root_condition));
    }

    if src_meta.0 != dst_meta.0 || src_meta.1 != dst_meta.1 || src_meta.2 != dst_meta.2 {
      let new_metadata = DataStoreMetadata {
        root_hash: dst_meta.0.value(),
        label: dst_meta.1.value(),
        description: dst_meta.2.value(),
        bytes: dst_meta.3.value(),
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
      .unwrap();

      admin_inner_spend = admin_inner_spend.condition(Condition::Other(new_metadata_condition));
    }

    // delegated puzzle info + inner puzzle reveal + solution
    let inner_datastore_spend = DatastoreInnerSpend::DelegatedPuzzleSpend(
      admin_delegated_puzzle,
      Spend::new(
        admin_inner_puzzle_reveal,
        admin_inner_spend.p2_spend(ctx, admin_pk)?.solution(),
      ),
    );
    let new_spend = datastore_spend(ctx, &src_datastore_info, inner_datastore_spend)?;

    {
      let mut stats = TEST_STATS.lock().unwrap();
      stats.add_normal_spend_tx(&new_spend);
    }
    ctx.insert_coin_spend(new_spend.clone());

    let dst_datastore_info = DataStoreInfo::from_spend(
      ctx.allocator_mut(),
      &new_spend,
      &src_datastore_info.delegated_puzzles,
    )
    .unwrap();

    assert_eq!(src_datastore_info.delegated_puzzles, src_delegated_puzzles);
    assert_eq!(src_datastore_info.owner_puzzle_hash, owner_puzzle_hash);

    assert_eq!(src_datastore_info.metadata.root_hash, src_meta.0.value());
    assert_eq!(src_datastore_info.metadata.label, src_meta.1.value());
    assert_eq!(src_datastore_info.metadata.description, src_meta.2.value());

    assert!(!src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == admin2_delegated_puzzle.puzzle_hash));
    assert!(src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == admin_delegated_puzzle.puzzle_hash));
    let writer_found = src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == writer_delegated_puzzle.puzzle_hash);
    if src_with_writer {
      assert!(writer_found);
    } else {
      assert!(!writer_found);
    }

    let oracle_found = src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == oracle_delegated_puzzle.puzzle_hash);
    if src_with_oracle {
      assert!(oracle_found);
    } else {
      assert!(!oracle_found);
    }

    assert_eq!(dst_datastore_info.delegated_puzzles, dst_delegated_puzzles);
    assert_eq!(dst_datastore_info.owner_puzzle_hash, owner_puzzle_hash);

    assert_eq!(dst_datastore_info.metadata.root_hash, dst_meta.0.value());
    assert_eq!(dst_datastore_info.metadata.label, dst_meta.1.value());
    assert_eq!(dst_datastore_info.metadata.description, dst_meta.2.value());

    let admin_found = dst_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == admin_delegated_puzzle.puzzle_hash);
    let admin2_found = dst_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == admin2_delegated_puzzle.puzzle_hash);
    match dst_admin {
      DstAdmin::None => {
        assert!(!admin_found && !admin2_found);
      }
      DstAdmin::Same => {
        assert!(admin_found && !admin2_found);
      }
      DstAdmin::New => {
        assert!(!admin_found && admin2_found);
      }
    };

    let writer_found = dst_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == writer_delegated_puzzle.puzzle_hash);
    if dst_with_writer {
      assert!(writer_found);
    } else {
      assert!(!writer_found);
    }

    let oracle_found = dst_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == oracle_delegated_puzzle.puzzle_hash);
    if dst_with_oracle {
      assert!(oracle_found);
    } else {
      assert!(!oracle_found);
    }

    test_transaction(
      &peer,
      ctx.take_spends(),
      &[owner_sk, admin_sk, writer_sk],
      sim.config().genesis_challenge,
    )
    .await;

    let src_coin_state = sim
      .coin_state(src_datastore_info.coin.coin_id())
      .await
      .expect("expected datastore coin");
    assert_eq!(src_coin_state.coin, src_datastore_info.coin);
    assert!(src_coin_state.spent_height.is_some());
    let dst_coin_state = sim
      .coin_state(dst_datastore_info.coin.coin_id())
      .await
      .expect("expected datastore coin");
    assert_eq!(dst_coin_state.coin, dst_datastore_info.coin);
    assert!(dst_coin_state.created_height.is_some());

    Ok(())
  }

  #[rstest(
    src_with_admin => [true, false],
    src_with_writer => [true, false],
    src_with_oracle => [true, false],
    dst_with_admin => [true, false],
    dst_with_writer => [true, false],
    dst_with_oracle => [true, false],
    src_meta => [
      (Hash::ZERO, Label::NONE, Description::NONE, Bytes::NONE),
      (Hash::SOME, Label::SOME, Description::SOME, Bytes::SOME),
    ],
    dst_meta => [
      (Hash::ZERO, Label::NONE, Description::NONE, Bytes::NONE),
      (Hash::ZERO, Label::SOME, Description::SOME, Bytes::SOME),
      (Hash::ZERO, Label::NEW, Description::NEW, Bytes::NEW),
    ],
    also_change_owner => [true, false],
  )]
  #[tokio::test]
  async fn test_datastore_owner_transition(
    src_meta: (Hash, Label, Description, Bytes),
    src_with_admin: bool,
    src_with_writer: bool,
    src_with_oracle: bool,
    dst_with_admin: bool,
    dst_with_writer: bool,
    dst_with_oracle: bool,
    dst_meta: (Hash, Label, Description, Bytes),
    also_change_owner: bool,
  ) -> anyhow::Result<()> {
    let sim = Simulator::new().await?;
    let peer = sim.connect().await?;

    let [owner_sk, owner2_sk, admin_sk, writer_sk]: [SecretKey; 4] =
      secret_keys(4).unwrap().try_into().unwrap();

    let owner_pk = owner_sk.public_key();
    let owner2_pk = owner2_sk.public_key();
    let admin_pk = admin_sk.public_key();
    let writer_pk = writer_sk.public_key();

    let oracle_puzzle_hash: Bytes32 = [7; 32].into();
    let oracle_fee = 1000;

    let owner_puzzle_hash = StandardArgs::curry_tree_hash(owner_pk).into();
    let coin = sim.mint_coin(owner_puzzle_hash, 1).await;

    let owner2_puzzle_hash = StandardArgs::curry_tree_hash(owner2_pk).into();
    assert_ne!(owner_puzzle_hash, owner2_puzzle_hash);

    let ctx = &mut SpendContext::new();

    let (admin_delegated_puzzle, _) = DelegatedPuzzle::from_admin_pk(ctx, admin_pk).unwrap();

    let (writer_delegated_puzzle, _) = DelegatedPuzzle::from_writer_pk(ctx, writer_pk).unwrap();

    let oracle_delegated_puzzle =
      DelegatedPuzzle::new_oracle(ctx.allocator_mut(), oracle_puzzle_hash, oracle_fee).unwrap();

    let mut src_delegated_puzzles: Vec<DelegatedPuzzle> = vec![];
    if src_with_admin {
      src_delegated_puzzles.push(admin_delegated_puzzle);
    }
    if src_with_writer {
      src_delegated_puzzles.push(writer_delegated_puzzle);
    }
    if src_with_oracle {
      src_delegated_puzzles.push(oracle_delegated_puzzle);
    }

    let (launch_singleton, src_datastore_info) = Launcher::new(coin.coin_id(), 1).mint_datastore(
      ctx,
      DataStoreMintInfo {
        metadata: DataStoreMetadata {
          root_hash: src_meta.0.value(),
          label: src_meta.1.value(),
          description: src_meta.2.value(),
          bytes: src_meta.3.value(),
        },
        owner_puzzle_hash: owner_puzzle_hash.into(),
        delegated_puzzles: src_delegated_puzzles.clone(),
      },
    )?;
    ctx.spend_p2_coin(coin, owner_pk, launch_singleton)?;

    let spends = ctx.take_spends();
    for spend in spends.clone() {
      if spend.coin.coin_id() == src_datastore_info.launcher_id {
        {
          let mut stats = TEST_STATS.lock().unwrap();
          stats.add_launcher_tx(&spend);
        }
      }

      ctx.insert_coin_spend(spend);
    }

    // transition from src to dst using owner puzzle
    let mut owner_output_conds = Conditions::new();

    let mut dst_delegated_puzzles: Vec<DelegatedPuzzle> = src_delegated_puzzles.clone();
    let mut hint_new_delegated_puzzles = false;
    if src_with_admin != dst_with_admin
      || src_with_writer != dst_with_writer
      || src_with_oracle != dst_with_oracle
      || dst_delegated_puzzles.len() == 0
      || also_change_owner
    {
      dst_delegated_puzzles.clear();
      hint_new_delegated_puzzles = true;

      if dst_with_admin {
        dst_delegated_puzzles.push(admin_delegated_puzzle);
      }
      if dst_with_writer {
        dst_delegated_puzzles.push(writer_delegated_puzzle);
      }
      if dst_with_oracle {
        dst_delegated_puzzles.push(oracle_delegated_puzzle);
      }
    }

    owner_output_conds = owner_output_conds.condition(get_owner_create_coin_condition(
      src_datastore_info.launcher_id,
      if also_change_owner {
        &owner2_puzzle_hash
      } else {
        &owner_puzzle_hash
      },
      &dst_delegated_puzzles,
      hint_new_delegated_puzzles,
    ));
    debug_log!("owner_output_conds: {:?}", owner_output_conds); // todo: debug

    if src_meta.0 != dst_meta.0 || src_meta.1 != dst_meta.1 || src_meta.2 != dst_meta.2 {
      let new_metadata = DataStoreMetadata {
        root_hash: dst_meta.0.value(),
        label: dst_meta.1.value(),
        description: dst_meta.2.value(),
        bytes: dst_meta.3.value(),
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
      .unwrap();

      owner_output_conds = owner_output_conds.condition(Condition::Other(new_metadata_condition));
    }

    // delegated puzzle info + inner puzzle reveal + solution
    let inner_datastore_spend =
      DatastoreInnerSpend::OwnerPuzzleSpend(owner_output_conds.p2_spend(ctx, owner_pk)?);
    let new_spend = datastore_spend(ctx, &src_datastore_info, inner_datastore_spend)?;

    {
      let mut stats = TEST_STATS.lock().unwrap();
      stats.add_normal_spend_tx(&new_spend);
    }
    ctx.insert_coin_spend(new_spend.clone());

    // print_spend_bundle(vec![new_spend.clone()], Signature::default()); // todo: debug

    let dst_datastore_info = DataStoreInfo::from_spend(
      ctx.allocator_mut(),
      &new_spend,
      &src_datastore_info.delegated_puzzles,
    )
    .unwrap();

    if src_datastore_info.delegated_puzzles.len() > 0 {
      assert_eq!(src_datastore_info.delegated_puzzles, src_delegated_puzzles);
    } else {
      assert_eq!(src_datastore_info.delegated_puzzles.len(), 0);
    }
    assert_eq!(src_datastore_info.owner_puzzle_hash, owner_puzzle_hash);

    assert_eq!(src_datastore_info.metadata.root_hash, src_meta.0.value());
    assert_eq!(src_datastore_info.metadata.label, src_meta.1.value());
    assert_eq!(src_datastore_info.metadata.description, src_meta.2.value());

    let admin_found = src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == admin_delegated_puzzle.puzzle_hash);
    if src_with_admin {
      assert!(admin_found);
    } else {
      assert!(!admin_found);
    }

    let writer_found = src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == writer_delegated_puzzle.puzzle_hash);
    if src_with_writer {
      assert!(writer_found);
    } else {
      assert!(!writer_found);
    }

    let oracle_found = src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == oracle_delegated_puzzle.puzzle_hash);
    if src_with_oracle {
      assert!(oracle_found);
    } else {
      assert!(!oracle_found);
    }

    if dst_datastore_info.delegated_puzzles.len() > 0 {
      assert_eq!(dst_datastore_info.delegated_puzzles, dst_delegated_puzzles);
    } else {
      assert_eq!(dst_datastore_info.delegated_puzzles.len(), 0);
    }
    if also_change_owner {
      assert_eq!(dst_datastore_info.owner_puzzle_hash, owner2_puzzle_hash);
    } else {
      assert_eq!(dst_datastore_info.owner_puzzle_hash, owner_puzzle_hash);
    }

    assert_eq!(dst_datastore_info.metadata.root_hash, dst_meta.0.value());
    assert_eq!(dst_datastore_info.metadata.label, dst_meta.1.value());
    assert_eq!(dst_datastore_info.metadata.description, dst_meta.2.value());

    let admin_found = dst_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == admin_delegated_puzzle.puzzle_hash);
    if dst_with_admin {
      assert!(admin_found);
    } else {
      assert!(!admin_found);
    }

    let writer_found = dst_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == writer_delegated_puzzle.puzzle_hash);
    if dst_with_writer {
      assert!(writer_found);
    } else {
      assert!(!writer_found);
    }

    let oracle_found = dst_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == oracle_delegated_puzzle.puzzle_hash);
    if dst_with_oracle {
      assert!(oracle_found);
    } else {
      assert!(!oracle_found);
    }

    test_transaction(
      &peer,
      ctx.take_spends(),
      &[owner_sk, admin_sk, writer_sk],
      sim.config().genesis_challenge,
    )
    .await;

    let src_coin_state = sim
      .coin_state(src_datastore_info.coin.coin_id())
      .await
      .expect("expected datastore coin");
    assert_eq!(src_coin_state.coin, src_datastore_info.coin);
    assert!(src_coin_state.spent_height.is_some());
    let dst_coin_state = sim
      .coin_state(dst_datastore_info.coin.coin_id())
      .await
      .expect("expected datastore coin");
    assert_eq!(dst_coin_state.coin, dst_datastore_info.coin);
    assert!(dst_coin_state.created_height.is_some());

    Ok(())
  }

  #[rstest(
    with_admin_layer => [true, false],
    with_oracle_layer => [true, false],
    meta_transition => [
      (
        (Hash::ZERO, Hash::ZERO),
        (Label::NONE, Label::SOME),
        (Description::NONE, Description::SOME),
        (Bytes::NONE, Bytes::SOME)
      ),
      (
        (Hash::ZERO, Hash::SOME),
        (Label::NONE, Label::NONE),
        (Description::NONE, Description::NONE),
        (Bytes::NONE, Bytes::NONE)
      ),
      (
        (Hash::ZERO, Hash::SOME),
        (Label::SOME, Label::SOME),
        (Description::SOME, Description::SOME),
        (Bytes::SOME, Bytes::SOME)
      ),
      (
        (Hash::ZERO, Hash::ZERO),
        (Label::SOME, Label::NEW),
        (Description::SOME, Description::NEW),
        (Bytes::SOME, Bytes::NEW)
      ),
      (
        (Hash::ZERO, Hash::ZERO),
        (Label::NONE, Label::NONE),
        (Description::NONE, Description::NONE),
        (Bytes::NONE, Bytes::SOME)
      ),
    ],
  )]
  #[tokio::test]
  async fn test_datastore_writer_transition(
    with_admin_layer: bool,
    with_oracle_layer: bool,
    meta_transition: (
      (Hash, Hash),
      (Label, Label),
      (Description, Description),
      (Bytes, Bytes),
    ),
  ) -> anyhow::Result<()> {
    let sim = Simulator::new().await?;
    let peer = sim.connect().await?;

    let [owner_sk, admin_sk, writer_sk]: [SecretKey; 3] =
      secret_keys(3).unwrap().try_into().unwrap();

    let owner_pk = owner_sk.public_key();
    let admin_pk = admin_sk.public_key();
    let writer_pk = writer_sk.public_key();

    let oracle_puzzle_hash: Bytes32 = [7; 32].into();
    let oracle_fee = 1000;

    let owner_puzzle_hash = StandardArgs::curry_tree_hash(owner_pk).into();
    let coin = sim.mint_coin(owner_puzzle_hash, 1).await;

    let ctx = &mut SpendContext::new();

    let (admin_delegated_puzzle, _) = DelegatedPuzzle::from_admin_pk(ctx, admin_pk).unwrap();

    let (writer_delegated_puzzle, writer_inner_puzzle_ptr) =
      DelegatedPuzzle::from_writer_pk(ctx, writer_pk).unwrap();

    let oracle_delegated_puzzle =
      DelegatedPuzzle::new_oracle(ctx.allocator_mut(), oracle_puzzle_hash, oracle_fee).unwrap();

    let mut delegated_puzzles: Vec<DelegatedPuzzle> = vec![];
    delegated_puzzles.push(writer_delegated_puzzle);

    if with_admin_layer {
      delegated_puzzles.push(admin_delegated_puzzle);
    }
    if with_oracle_layer {
      delegated_puzzles.push(oracle_delegated_puzzle);
    }

    let (launch_singleton, src_datastore_info) = Launcher::new(coin.coin_id(), 1).mint_datastore(
      ctx,
      DataStoreMintInfo {
        metadata: DataStoreMetadata {
          root_hash: meta_transition.0 .0.value(),
          label: meta_transition.1 .0.value(),
          description: meta_transition.2 .0.value(),
          bytes: meta_transition.3 .0.value(),
        },
        owner_puzzle_hash: owner_puzzle_hash.into(),
        delegated_puzzles: delegated_puzzles.clone(),
      },
    )?;

    ctx.spend_p2_coin(coin, owner_pk, launch_singleton)?;

    let spends = ctx.take_spends();
    for spend in spends.clone() {
      if spend.coin.coin_id() == src_datastore_info.launcher_id {
        {
          let mut stats = TEST_STATS.lock().unwrap();
          stats.add_launcher_tx(&spend);
        }
      }

      ctx.insert_coin_spend(spend);
    }

    // transition from src to dst using writer (update metadata)
    let new_metadata = DataStoreMetadata {
      root_hash: meta_transition.0 .1.value(),
      label: meta_transition.1 .1.value(),
      description: meta_transition.2 .1.value(),
      bytes: meta_transition.3 .1.value(),
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
    .unwrap();

    let writer_conds = Conditions::new().condition(Condition::Other(new_metadata_condition));

    // delegated puzzle info
    let inner_datastore_spend = DatastoreInnerSpend::DelegatedPuzzleSpend(
      writer_delegated_puzzle,
      Spend::new(
        writer_inner_puzzle_ptr,
        writer_conds.p2_spend(ctx, writer_pk)?.solution(),
      ),
    );
    let new_spend = datastore_spend(ctx, &src_datastore_info, inner_datastore_spend)?;

    {
      let mut stats = TEST_STATS.lock().unwrap();
      stats.add_normal_spend_tx(&new_spend);
    }
    ctx.insert_coin_spend(new_spend.clone());

    // print_spend_bundle(vec![new_spend.clone()], Signature::default()); // todo: debug

    let dst_datastore_info = DataStoreInfo::from_spend(
      ctx.allocator_mut(),
      &new_spend,
      &src_datastore_info.delegated_puzzles,
    )
    .unwrap();

    assert_eq!(dst_datastore_info.delegated_puzzles, delegated_puzzles);
    assert_eq!(src_datastore_info.owner_puzzle_hash, owner_puzzle_hash);

    assert_eq!(
      src_datastore_info.metadata.root_hash,
      meta_transition.0 .0.value()
    );
    assert_eq!(
      src_datastore_info.metadata.label,
      meta_transition.1 .0.value()
    );
    assert_eq!(
      src_datastore_info.metadata.description,
      meta_transition.2 .0.value()
    );

    let admin_found = src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == admin_delegated_puzzle.puzzle_hash);
    if with_admin_layer {
      assert!(admin_found);
    } else {
      assert!(!admin_found);
    }

    let writer_found = src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == writer_delegated_puzzle.puzzle_hash);
    assert!(writer_found);

    let oracle_found = src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == oracle_delegated_puzzle.puzzle_hash);
    if with_oracle_layer {
      assert!(oracle_found);
    } else {
      assert!(!oracle_found);
    }

    assert_eq!(dst_datastore_info.owner_puzzle_hash, owner_puzzle_hash);
    assert_eq!(dst_datastore_info.delegated_puzzles, delegated_puzzles);

    assert_eq!(
      dst_datastore_info.metadata.root_hash,
      meta_transition.0 .1.value()
    );
    assert_eq!(
      dst_datastore_info.metadata.label,
      meta_transition.1 .1.value()
    );
    assert_eq!(
      dst_datastore_info.metadata.description,
      meta_transition.2 .1.value()
    );

    let admin_found = dst_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == admin_delegated_puzzle.puzzle_hash);
    if with_admin_layer {
      assert!(admin_found);
    } else {
      assert!(!admin_found);
    }

    let writer_found = dst_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == writer_delegated_puzzle.puzzle_hash);
    assert!(writer_found);

    let oracle_found = dst_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == oracle_delegated_puzzle.puzzle_hash);
    if with_oracle_layer {
      assert!(oracle_found);
    } else {
      assert!(!oracle_found);
    }

    test_transaction(
      &peer,
      ctx.take_spends(),
      &[owner_sk, admin_sk, writer_sk],
      sim.config().genesis_challenge,
    )
    .await;

    let src_coin_state = sim
      .coin_state(src_datastore_info.coin.coin_id())
      .await
      .expect("expected datastore coin");
    assert_eq!(src_coin_state.coin, src_datastore_info.coin);
    assert!(src_coin_state.spent_height.is_some());
    let dst_coin_state = sim
      .coin_state(dst_datastore_info.coin.coin_id())
      .await
      .expect("expected datastore coin");
    assert_eq!(dst_coin_state.coin, dst_datastore_info.coin);
    assert!(dst_coin_state.created_height.is_some());

    Ok(())
  }

  #[rstest(
    with_admin_layer => [true, false],
    with_writer_layer => [true, false],
    meta => [
      (Hash::ZERO, Label::NONE, Description::NONE, Bytes::NONE),
      (Hash::ZERO, Label::NONE, Description::NONE, Bytes::SOME),
      (Hash::ZERO, Label::NONE, Description::SOME, Bytes::SOME),
      (Hash::ZERO, Label::SOME, Description::SOME, Bytes::SOME),
    ],
  )]
  #[tokio::test]
  async fn test_datastore_oracle_transition(
    with_admin_layer: bool,
    with_writer_layer: bool,
    meta: (Hash, Label, Description, Bytes),
  ) -> anyhow::Result<()> {
    let sim = Simulator::new().await?;
    let peer = sim.connect().await?;

    let [owner_sk, admin_sk, writer_sk, dude_sk]: [SecretKey; 4] =
      secret_keys(4).unwrap().try_into().unwrap();

    let owner_pk = owner_sk.public_key();
    let admin_pk = admin_sk.public_key();
    let writer_pk = writer_sk.public_key();
    let dude_pk = dude_sk.public_key();

    let oracle_puzzle_hash: Bytes32 = [7; 32].into();
    let oracle_fee = 1000;

    let owner_puzzle_hash = StandardArgs::curry_tree_hash(owner_pk).into();
    let coin = sim.mint_coin(owner_puzzle_hash, 1).await;

    let dude_puzzle_hash = StandardArgs::curry_tree_hash(dude_pk).into();

    let ctx = &mut SpendContext::new();

    let (admin_delegated_puzzle, _) = DelegatedPuzzle::from_admin_pk(ctx, admin_pk).unwrap();

    let (writer_delegated_puzzle, _) = DelegatedPuzzle::from_writer_pk(ctx, writer_pk).unwrap();

    let oracle_delegated_puzzle =
      DelegatedPuzzle::new_oracle(ctx.allocator_mut(), oracle_puzzle_hash, oracle_fee).unwrap();

    let mut delegated_puzzles: Vec<DelegatedPuzzle> = vec![];
    delegated_puzzles.push(oracle_delegated_puzzle);

    if with_admin_layer {
      delegated_puzzles.push(admin_delegated_puzzle);
    }
    if with_writer_layer {
      delegated_puzzles.push(writer_delegated_puzzle);
    }

    let (launch_singleton, src_datastore_info) = Launcher::new(coin.coin_id(), 1).mint_datastore(
      ctx,
      DataStoreMintInfo {
        metadata: DataStoreMetadata {
          root_hash: meta.0.value(),
          label: meta.1.value(),
          description: meta.2.value(),
          bytes: meta.3.value(),
        },
        owner_puzzle_hash: owner_puzzle_hash.into(),
        delegated_puzzles: delegated_puzzles.clone(),
      },
    )?;

    ctx.spend_p2_coin(coin, owner_pk, launch_singleton)?;

    let spends = ctx.take_spends();
    for spend in spends.clone() {
      if spend.coin.coin_id() == src_datastore_info.launcher_id {
        {
          let mut stats = TEST_STATS.lock().unwrap();
          stats.add_launcher_tx(&spend);
        }
      }

      ctx.insert_coin_spend(spend);
    }

    // 'dude' spends oracle
    let inner_datastore_spend = DatastoreInnerSpend::DelegatedPuzzleSpend(
      oracle_delegated_puzzle,
      Spend::new(
        DelegatedPuzzle::oracle_layer_full_puzzle(
          ctx.allocator_mut(),
          oracle_puzzle_hash,
          oracle_fee,
        )
        .unwrap(),
        ctx.allocator().nil(),
      ),
    );
    let new_spend = datastore_spend(ctx, &src_datastore_info, inner_datastore_spend)?;
    ctx.insert_coin_spend(new_spend.clone());

    // print_spend_bundle(vec![new_spend.clone()], Signature::default()); // todo: debug

    let dst_datastore_info = DataStoreInfo::from_spend(
      ctx.allocator_mut(),
      &new_spend,
      &src_datastore_info.delegated_puzzles,
    )
    .unwrap();
    assert_datastore_info_eq(ctx, &src_datastore_info, &dst_datastore_info, false);

    // mint a coin that asserts the announcement and has enough value
    let new_coin = sim.mint_coin(dude_puzzle_hash, oracle_fee).await;
    ctx.spend_p2_coin(
      new_coin,
      dude_pk,
      Conditions::new().assert_puzzle_announcement(
        src_datastore_info.coin.puzzle_hash,
        &OgBytes::new("$".into()),
      ),
    )?;

    // asserts

    assert_eq!(dst_datastore_info.delegated_puzzles, delegated_puzzles);
    assert_eq!(src_datastore_info.owner_puzzle_hash, owner_puzzle_hash);

    assert_eq!(src_datastore_info.metadata.root_hash, meta.0.value());
    assert_eq!(src_datastore_info.metadata.label, meta.1.value());
    assert_eq!(src_datastore_info.metadata.description, meta.2.value());

    let admin_found = src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == admin_delegated_puzzle.puzzle_hash);
    if with_admin_layer {
      assert!(admin_found);
    } else {
      assert!(!admin_found);
    }

    let writer_found = src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == writer_delegated_puzzle.puzzle_hash);
    if with_writer_layer {
      assert!(writer_found);
    } else {
      assert!(!writer_found);
    }

    let oracle_found = src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == oracle_delegated_puzzle.puzzle_hash);
    assert!(oracle_found);

    assert_eq!(dst_datastore_info.owner_puzzle_hash, owner_puzzle_hash);
    assert_eq!(dst_datastore_info.delegated_puzzles, delegated_puzzles);

    assert_eq!(dst_datastore_info.metadata.root_hash, meta.0.value());
    assert_eq!(dst_datastore_info.metadata.label, meta.1.value());
    assert_eq!(dst_datastore_info.metadata.description, meta.2.value());

    let admin_found = dst_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == admin_delegated_puzzle.puzzle_hash);
    if with_admin_layer {
      assert!(admin_found);
    } else {
      assert!(!admin_found);
    }

    let writer_found = dst_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == writer_delegated_puzzle.puzzle_hash);
    if with_writer_layer {
      assert!(writer_found);
    } else {
      assert!(!writer_found);
    }

    let oracle_found = dst_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == oracle_delegated_puzzle.puzzle_hash);
    assert!(oracle_found);

    test_transaction(
      &peer,
      ctx.take_spends(),
      &[owner_sk, dude_sk],
      sim.config().genesis_challenge,
    )
    .await;

    let src_datastore_coin_id = src_datastore_info.coin.coin_id();
    let src_coin_state = sim
      .coin_state(src_datastore_coin_id)
      .await
      .expect("expected src datastore coin");
    assert_eq!(src_coin_state.coin, src_datastore_info.coin);
    assert!(src_coin_state.spent_height.is_some());
    let dst_coin_state = sim
      .coin_state(dst_datastore_info.coin.coin_id())
      .await
      .expect("expected dst datastore coin");
    assert_eq!(dst_coin_state.coin, dst_datastore_info.coin);
    assert!(dst_coin_state.created_height.is_some());

    let oracle_coin = Coin::new(src_datastore_coin_id, oracle_puzzle_hash, oracle_fee);
    let oracle_coin_state = sim
      .coin_state(oracle_coin.coin_id())
      .await
      .expect("expected oracle coin");
    assert_eq!(oracle_coin_state.coin, oracle_coin);
    assert!(oracle_coin_state.created_height.is_some());

    Ok(())
  }

  #[rstest(
    with_admin_layer => [true, false],
    with_writer_layer => [true, false],
    with_oracle_layer => [true, false],
    meta => [
      (Hash::ZERO, Label::NONE, Description::NONE, Bytes::NONE),
      (Hash::ZERO, Label::SOME, Description::SOME, Bytes::SOME),
    ],
  )]
  #[tokio::test]
  async fn test_melt(
    with_admin_layer: bool,
    with_writer_layer: bool,
    with_oracle_layer: bool,
    meta: (Hash, Label, Description, Bytes),
  ) -> anyhow::Result<()> {
    let sim = Simulator::new().await?;
    let peer = sim.connect().await?;

    let [owner_sk, admin_sk, writer_sk]: [SecretKey; 3] =
      secret_keys(3).unwrap().try_into().unwrap();

    let owner_pk = owner_sk.public_key();
    let admin_pk = admin_sk.public_key();
    let writer_pk = writer_sk.public_key();

    let oracle_puzzle_hash: Bytes32 = [7; 32].into();
    let oracle_fee = 1000;

    let owner_puzzle_hash = StandardArgs::curry_tree_hash(owner_pk).into();
    let coin = sim.mint_coin(owner_puzzle_hash, 1).await;

    let ctx = &mut SpendContext::new();

    let (admin_delegated_puzzle, _) = DelegatedPuzzle::from_admin_pk(ctx, admin_pk).unwrap();

    let (writer_delegated_puzzle, _) = DelegatedPuzzle::from_writer_pk(ctx, writer_pk).unwrap();

    let oracle_delegated_puzzle =
      DelegatedPuzzle::new_oracle(ctx.allocator_mut(), oracle_puzzle_hash, oracle_fee).unwrap();

    let mut delegated_puzzles: Vec<DelegatedPuzzle> = vec![];

    if with_admin_layer {
      delegated_puzzles.push(admin_delegated_puzzle);
    }
    if with_writer_layer {
      delegated_puzzles.push(writer_delegated_puzzle);
    }
    if with_oracle_layer {
      delegated_puzzles.push(oracle_delegated_puzzle);
    }

    let (launch_singleton, src_datastore_info) = Launcher::new(coin.coin_id(), 1).mint_datastore(
      ctx,
      DataStoreMintInfo {
        metadata: DataStoreMetadata {
          root_hash: meta.0.value(),
          label: meta.1.value(),
          description: meta.2.value(),
          bytes: meta.3.value(),
        },
        owner_puzzle_hash: owner_puzzle_hash.into(),
        delegated_puzzles: delegated_puzzles.clone(),
      },
    )?;

    ctx.spend_p2_coin(coin, owner_pk, launch_singleton)?;

    let spends = ctx.take_spends();
    for spend in spends.clone() {
      if spend.coin.coin_id() == src_datastore_info.launcher_id {
        {
          let mut stats = TEST_STATS.lock().unwrap();
          stats.add_launcher_tx(&spend);
        }
      }

      ctx.insert_coin_spend(spend);
    }

    // owner melts
    let inner_datastore_spend = DatastoreInnerSpend::OwnerPuzzleSpend(
      Conditions::new()
        .condition(Condition::Other(
          MeltSingleton {}.to_clvm(ctx.allocator_mut())?,
        ))
        .p2_spend(ctx, owner_pk)?,
    );
    let new_spend = datastore_spend(ctx, &src_datastore_info, inner_datastore_spend)?;
    ctx.insert_coin_spend(new_spend.clone());

    // asserts

    assert_eq!(src_datastore_info.owner_puzzle_hash, owner_puzzle_hash);

    assert_eq!(src_datastore_info.metadata.root_hash, meta.0.value());
    assert_eq!(src_datastore_info.metadata.label, meta.1.value());
    assert_eq!(src_datastore_info.metadata.description, meta.2.value());

    let admin_found = src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == admin_delegated_puzzle.puzzle_hash);
    if with_admin_layer {
      assert!(admin_found);
    } else {
      assert!(!admin_found);
    }

    let writer_found = src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == writer_delegated_puzzle.puzzle_hash);
    if with_writer_layer {
      assert!(writer_found);
    } else {
      assert!(!writer_found);
    }

    let oracle_found = src_datastore_info
      .delegated_puzzles
      .clone()
      .into_iter()
      .any(|dp| dp.puzzle_hash == oracle_delegated_puzzle.puzzle_hash);
    if with_oracle_layer {
      assert!(oracle_found);
    } else {
      assert!(!oracle_found);
    }

    test_transaction(
      &peer,
      ctx.take_spends(),
      &[owner_sk],
      sim.config().genesis_challenge,
    )
    .await;

    let src_datastore_coin_id = src_datastore_info.coin.coin_id();
    let src_coin_state = sim
      .coin_state(src_datastore_coin_id)
      .await
      .expect("expected src datastore coin");
    assert_eq!(src_coin_state.coin, src_datastore_info.coin);
    assert!(src_coin_state.spent_height.is_some()); // tx happened

    Ok(())
  }

  enum FilterPuzzle {
    Admin,
    Writer,
  }

  #[rstest(
    puzzle => [FilterPuzzle::Admin, FilterPuzzle::Writer],
  )]
  #[tokio::test]
  async fn test_filter_create_coin(puzzle: FilterPuzzle) -> anyhow::Result<()> {
    let sim = Simulator::new().await?;

    let [owner_sk, puzzle_sk]: [SecretKey; 2] = secret_keys(2).unwrap().try_into().unwrap();

    let owner_pk = owner_sk.public_key();
    let puzzle_pk = puzzle_sk.public_key();

    let owner_puzzle_hash = StandardArgs::curry_tree_hash(owner_pk).into();
    let puzzle_ownership_puzzle_hash = StandardArgs::curry_tree_hash(puzzle_pk).into();
    let coin = sim.mint_coin(owner_puzzle_hash, 1).await;

    let ctx = &mut SpendContext::new();

    let delegated_puzzle = match puzzle {
      FilterPuzzle::Admin => DelegatedPuzzle::from_admin_pk(ctx, puzzle_pk).unwrap().0,
      FilterPuzzle::Writer => DelegatedPuzzle::from_writer_pk(ctx, puzzle_pk).unwrap().0,
    };

    let (launch_singleton, src_datastore_info) = Launcher::new(coin.coin_id(), 1).mint_datastore(
      ctx,
      DataStoreMintInfo {
        metadata: DataStoreMetadata::default(),
        owner_puzzle_hash: owner_puzzle_hash.into(),
        delegated_puzzles: vec![delegated_puzzle.clone()],
      },
    )?;

    ctx.spend_p2_coin(coin, owner_pk, launch_singleton)?;

    let spends = ctx.take_spends();
    for spend in spends.clone() {
      if spend.coin.coin_id() == src_datastore_info.launcher_id {
        {
          let mut stats = TEST_STATS.lock().unwrap();
          stats.add_launcher_tx(&spend);
        }
      }

      ctx.insert_coin_spend(spend);
    }

    // delegated puzzle tries to steal the coin
    let inner_datastore_spend = DatastoreInnerSpend::DelegatedPuzzleSpend(
      delegated_puzzle,
      Conditions::new()
        .condition(Condition::CreateCoin(CreateCoin {
          puzzle_hash: puzzle_ownership_puzzle_hash,
          amount: 1,
          memos: vec![],
        }))
        .p2_spend(ctx, puzzle_pk)?,
    );
    let new_spend = datastore_spend(ctx, &src_datastore_info, inner_datastore_spend)?;

    let puzzle_reveal_ptr = ctx.alloc(&new_spend.puzzle_reveal).unwrap();
    let solution_ptr = ctx.alloc(&new_spend.solution).unwrap();
    match ctx.run(puzzle_reveal_ptr, solution_ptr) {
      Ok(_) => panic!("expected error"),
      Err(err) => match err {
        SpendError::Eval(eval_err) => {
          assert_eq!(eval_err.1, "clvm raise");
          Ok(())
        }
        _ => panic!("expected 'clvm raise' error"),
      },
    }
  }

  #[rstest(
    puzzle => [FilterPuzzle::Admin, FilterPuzzle::Writer],
    puzzle_hash => [Hash::ZERO, Hash::SOME],
  )]
  #[tokio::test]
  async fn test_filter_melt(puzzle: FilterPuzzle, puzzle_hash: Hash) -> anyhow::Result<()> {
    let sim = Simulator::new().await?;

    let [owner_sk, puzzle_sk]: [SecretKey; 2] = secret_keys(2).unwrap().try_into().unwrap();

    let owner_pk = owner_sk.public_key();
    let puzzle_pk = puzzle_sk.public_key();

    let owner_puzzle_hash = StandardArgs::curry_tree_hash(owner_pk).into();
    let coin = sim.mint_coin(owner_puzzle_hash, 1).await;

    let ctx = &mut SpendContext::new();

    let delegated_puzzle = match puzzle {
      FilterPuzzle::Admin => DelegatedPuzzle::from_admin_pk(ctx, puzzle_pk).unwrap().0,
      FilterPuzzle::Writer => DelegatedPuzzle::from_writer_pk(ctx, puzzle_pk).unwrap().0,
    };

    let (launch_singleton, src_datastore_info) = Launcher::new(coin.coin_id(), 1).mint_datastore(
      ctx,
      DataStoreMintInfo {
        metadata: DataStoreMetadata::default(),
        owner_puzzle_hash: owner_puzzle_hash.into(),
        delegated_puzzles: vec![delegated_puzzle.clone()],
      },
    )?;

    ctx.spend_p2_coin(coin, owner_pk, launch_singleton)?;

    let spends = ctx.take_spends();
    for spend in spends.clone() {
      if spend.coin.coin_id() == src_datastore_info.launcher_id {
        {
          let mut stats = TEST_STATS.lock().unwrap();
          stats.add_launcher_tx(&spend);
        }
      }

      ctx.insert_coin_spend(spend);
    }

    // delegated puzzle tries to steal the coin
    let inner_datastore_spend = DatastoreInnerSpend::DelegatedPuzzleSpend(
      delegated_puzzle,
      Conditions::new()
        .condition(Condition::Other(
          MeltCondition {
            fake_puzzle_hash: puzzle_hash.value(),
          }
          .to_clvm(ctx.allocator_mut())
          .unwrap(),
        ))
        .p2_spend(ctx, puzzle_pk)?,
    );
    let new_spend = datastore_spend(ctx, &src_datastore_info, inner_datastore_spend)?;

    let puzzle_reveal_ptr = ctx.alloc(&new_spend.puzzle_reveal).unwrap();
    let solution_ptr = ctx.alloc(&new_spend.solution).unwrap();
    match ctx.run(puzzle_reveal_ptr, solution_ptr) {
      Ok(_) => panic!("expected error"),
      Err(err) => match err {
        SpendError::Eval(eval_err) => {
          assert_eq!(eval_err.1, "clvm raise");
          Ok(())
        }
        _ => panic!("expected 'clvm raise' error"),
      },
    }
  }
}
