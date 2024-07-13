use crate::{
  merkle_root_for_delegated_puzzles, merkle_tree_for_delegated_puzzles,
  puzzles_info::{DataStoreInfo, DataStoreMetadata, DelegatedPuzzle, DelegatedPuzzleInfo},
  DLLauncherKVList, DelegationLayerArgs, DelegationLayerSolution, HintType, ADMIN_FILTER_PUZZLE,
  ADMIN_FILTER_PUZZLE_HASH, DELEGATION_LAYER_PUZZLE, DELEGATION_LAYER_PUZZLE_HASH,
  DL_METADATA_UPDATER_PUZZLE_HASH, WRITER_FILTER_PUZZLE, WRITER_FILTER_PUZZLE_HASH,
};
use chia_protocol::{Bytes, Bytes32, CoinSpend};
use chia_puzzles::{
  nft::{NftStateLayerArgs, NftStateLayerSolution, NFT_STATE_LAYER_PUZZLE_HASH},
  EveProof, Proof,
};
use chia_sdk_driver::{spend_singleton, Conditions, Launcher, Spend, SpendContext, SpendError};
use chia_sdk_types::conditions::{Condition, CreateCoin};
use clvm_traits::{simplify_int_bytes, FromClvmError, ToClvm};
use clvm_utils::{CurriedProgram, ToTreeHash, TreeHash};
use clvmr::{reduction::EvalErr, NodePtr};

pub trait SpendContextExt {
  fn delegation_layer_puzzle(&mut self) -> Result<NodePtr, SpendError>;
  fn delegated_admin_filter(&mut self) -> Result<NodePtr, SpendError>;
  fn delegated_writer_filter(&mut self) -> Result<NodePtr, SpendError>;
}

impl SpendContextExt for SpendContext {
  fn delegation_layer_puzzle(&mut self) -> Result<NodePtr, SpendError> {
    self.puzzle(DELEGATION_LAYER_PUZZLE_HASH, &DELEGATION_LAYER_PUZZLE)
  }

  fn delegated_admin_filter(&mut self) -> Result<NodePtr, SpendError> {
    self.puzzle(ADMIN_FILTER_PUZZLE_HASH, &ADMIN_FILTER_PUZZLE)
  }

  fn delegated_writer_filter(&mut self) -> Result<NodePtr, SpendError> {
    self.puzzle(WRITER_FILTER_PUZZLE_HASH, &WRITER_FILTER_PUZZLE)
  }
}

pub enum DatastoreInnerSpend {
  OwnerPuzzleSpend(Spend),                                 // owner puzzle spend
  DelegatedPuzzleSpend(DelegatedPuzzle, NodePtr, NodePtr), // delegated puzzle info + inner puzzle reveal + solution
}

pub fn spend_delegation_layer(
  ctx: &mut SpendContext,
  datastore_info: &DataStoreInfo,
  inner_datastore_spend: DatastoreInnerSpend,
) -> Result<Spend, SpendError> {
  if datastore_info.delegated_puzzles.len() == 0 {
    return match inner_datastore_spend {
      DatastoreInnerSpend::OwnerPuzzleSpend(inner_spend) => Ok(inner_spend),
      DatastoreInnerSpend::DelegatedPuzzleSpend(_, __, inner_spend) => {
        Err(SpendError::Eval(EvalErr(
          inner_spend,
          String::from("data store does not have a delegation layer"),
        )))
      }
    };
  }

  let merkle_root = merkle_root_for_delegated_puzzles(&datastore_info.delegated_puzzles);

  let new_inner_puzzle_mod = ctx.delegation_layer_puzzle()?;
  let new_inner_puzzle_args =
    DelegationLayerArgs::new(datastore_info.owner_puzzle_hash, merkle_root.into());

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
    DatastoreInnerSpend::DelegatedPuzzleSpend(
      delegated_puzzle,
      delegated_inner_puzzle_reveal,
      delegated_puzzle_solution,
    ) => {
      let full_puzzle = delegated_puzzle
        .get_full_puzzle(ctx.allocator_mut(), delegated_inner_puzzle_reveal)
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

      println!("merkle_proof: {:?}", merkle_proof); // todo: debug

      let solution: Vec<NodePtr> = vec![delegated_puzzle_solution];
      let new_inner_solution = DelegationLayerSolution::<NodePtr, NodePtr> {
        merkle_proof: Some(merkle_proof),
        puzzle_reveal: full_puzzle,
        puzzle_solution: ctx.alloc(&solution)?,
      };

      // todo: debug
      println!(
        "puz + filter puzzle hash: {:}",
        encode(ctx.tree_hash(full_puzzle))
      );
      println!(
        "puz puzzle hash: {:}",
        match delegated_puzzle.puzzle_info {
          DelegatedPuzzleInfo::Admin(a) => encode(a),
          DelegatedPuzzleInfo::Writer(b) => encode(b),
          DelegatedPuzzleInfo::Oracle(_, _) => "nope".to_string(),
        }
      );
      // println!(
      //     "writer puzzle reveal: {:}",
      //     encode(
      //         Program::from_node_ptr(ctx.allocator_mut(), full_puzzle)
      //             .unwrap()
      //             .clone()
      //             .to_bytes()
      //             .unwrap()
      //     )
      // ); // todo: debug
      // println!(
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
  println!("inner_spend!"); // todo: debug
                            // println!(
                            //     "puzzle: {:}",
                            //     encode(
                            //         Program::from_node_ptr(ctx.allocator_mut(), inner_spend.puzzle())
                            //             .unwrap()
                            //             .clone()
                            //             .to_bytes()
                            //             .unwrap()
                            //     )
                            // ); // todo: debug
                            // println!(
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
  owner_puzzle_hash: TreeHash,
  delegated_puzzles: Vec<DelegatedPuzzle>,
) -> Vec<Bytes> {
  let hint: Bytes32 = owner_puzzle_hash.into();
  let mut memos: Vec<Bytes> = vec![hint.into()];

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

  println!("memos: {:?}", memos);
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
    let inner_puzzle_hash: TreeHash = if info.delegated_puzzles.len() == 0 {
      info.owner_puzzle_hash
    } else {
      DelegationLayerArgs::curry_tree_hash(
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

    let mut memos = get_memos(info.owner_puzzle_hash, info.delegated_puzzles.clone());
    if info.delegated_puzzles.len() == 0 && info.metadata.description.len() == 0 {
      memos = vec![];
    } else {
      memos.insert(
        0,
        Bytes::from(info.metadata.description.clone().into_bytes()),
      );
      memos.insert(0, Bytes::from(info.metadata.label.clone().into_bytes()));
    }
    let kv_list = DLLauncherKVList {
      root_hash: info.metadata.root_hash,
      state_layer_inner_puzzle_hash: inner_puzzle_hash.into(),
      memos,
    };

    let launcher_coin = self.coin();
    let (chained_spend, eve_coin) = self.spend(ctx, state_layer_hash.into(), kv_list)?;

    let proof: Proof = Proof::Eve(EveProof {
      parent_coin_info: launcher_coin.parent_coin_info,
      amount: launcher_coin.amount,
    });

    let data_store_info: DataStoreInfo = DataStoreInfo {
      launcher_id: launcher_coin.coin_id(),
      coin: eve_coin,
      proof,
      metadata: info.metadata.clone(),
      owner_puzzle_hash: info.owner_puzzle_hash.into(),
      delegated_puzzles: info.delegated_puzzles.clone(),
    };

    Ok((chained_spend, data_store_info))
  }
}

// Always use CREATE_COIN + hints to change ownership
// Since new merkle root might end up costing a lil' bit more
pub fn get_new_ownership_inner_condition(
  new_inner_puzzle_hash: &Bytes32,
  new_delegated_puzzles: &Vec<DelegatedPuzzle>,
) -> Condition {
  let memos = get_memos(
    new_inner_puzzle_hash.clone().into(),
    new_delegated_puzzles.clone(),
  );

  let new_puzzle_hash = if new_delegated_puzzles.len() > 0 {
    let new_merkle_root = merkle_root_for_delegated_puzzles(&new_delegated_puzzles);
    DelegationLayerArgs::curry_tree_hash(new_inner_puzzle_hash.clone(), new_merkle_root).into()
  } else {
    new_inner_puzzle_hash.clone()
  };

  Condition::CreateCoin(CreateCoin {
    amount: 1,
    puzzle_hash: new_puzzle_hash,
    memos,
  })
}

#[cfg(test)]
mod tests {
  use crate::{
    DefaultMetadataSolution, DefaultMetadataSolutionMetadataList, NewMerkleRootCondition,
    NewMetadataCondition,
  };

  use super::*;

  use chia::bls::SecretKey;
  use chia_protocol::{Bytes32, Coin};
  use chia_puzzles::standard::StandardArgs;
  use chia_sdk_driver::Launcher;
  use chia_sdk_test::{test_transaction, Simulator};
  use chia_sdk_types::conditions::{Condition, MeltSingleton};
  use rstest::rstest;

  use bip39::Mnemonic;
  use rand::{Rng, SeedableRng};
  use rand_chacha::ChaCha8Rng;

  fn secret_keys(no_keys: usize) -> Result<Vec<SecretKey>, bip39::Error> {
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

    println!(
      "new datastore info metadata: {:?}",
      new_datastore_info.metadata.clone()
    ); // todo: debug
    println!(
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

        println!("compating phes - a: {:?}, b: {:?}", a, b); // todo: debug
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
        metadata: DataStoreMetadata {
          root_hash: Bytes32::new([0; 32]),
          label: String::default(),
          description: String::default(),
        },
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
      }

      ctx.insert_coin_spend(spend);
    }

    let datastore_inner_spend = Conditions::new()
      .create_coin(puzzle_hash, 1)
      .p2_spend(ctx, pk)?;
    let inner_datastore_spend = DatastoreInnerSpend::OwnerPuzzleSpend(datastore_inner_spend);
    let new_spend = datastore_spend(ctx, &datastore_info, inner_datastore_spend)?;
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
    println!(
      "writer puzzle hash: {:}",
      encode(writer_delegated_puzzle.puzzle_hash)
    ); // todo: debug

    let oracle_delegated_puzzle =
      DelegatedPuzzle::new_oracle(ctx.allocator_mut(), oracle_puzzle_hash, oracle_fee).unwrap();
    let (launch_singleton, datastore_info) = Launcher::new(coin.coin_id(), 1).mint_datastore(
      ctx,
      DataStoreMintInfo {
        metadata: DataStoreMetadata {
          root_hash: Bytes32::new([0; 32]),
          label: String::default(),
          description: String::default(),
        },
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
      root_hash: Bytes32::new([1; 32]),
      label: String::from("label"),
      description: String::from("description"),
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
      writer_puzzle,
      new_metadata_inner_spend.solution(),
    );
    let new_spend = datastore_spend(ctx, &datastore_info, inner_datastore_spend)?;
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
    assert_eq!(datastore_info.metadata.label, String::from("label"));
    assert_eq!(
      datastore_info.metadata.description,
      String::from("description")
    );

    // admin: remove writer from delegated puzzles
    let delegated_puzzles = vec![admin_delegated_puzzle, oracle_delegated_puzzle];
    let new_merkle_root = merkle_root_for_delegated_puzzles(&delegated_puzzles);

    let new_merkle_root_condition = NewMerkleRootCondition {
      new_merkle_root,
      memos: get_memos(owner_puzzle_hash.into(), delegated_puzzles),
    }
    .to_clvm(ctx.allocator_mut())
    .unwrap();

    let inner_spend = Conditions::new()
      .condition(Condition::Other(new_merkle_root_condition))
      .p2_spend(ctx, writer_pk)?;

    // delegated puzzle info + inner puzzle reveal + solution
    let inner_datastore_spend = DatastoreInnerSpend::DelegatedPuzzleSpend(
      admin_delegated_puzzle,
      admin_puzzle,
      inner_spend.solution(),
    );
    let new_spend = datastore_spend(ctx, &datastore_info, inner_datastore_spend)?;
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
      DelegatedPuzzle::oracle_layer_full_puzzle(
        ctx.allocator_mut(),
        oracle_puzzle_hash,
        oracle_fee,
      )
      .unwrap(),
      ctx.allocator().nil(),
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
        .assert_puzzle_announcement(datastore_info.coin.puzzle_hash, &Bytes::new("$".into())),
    )?;

    // finally, remove delegation layer altogether
    let datastore_remove_delegation_layer_inner_spend = Conditions::new()
      .create_coin(owner_puzzle_hash, 1)
      .p2_spend(ctx, owner_pk)?;
    let inner_datastore_spend =
      DatastoreInnerSpend::OwnerPuzzleSpend(datastore_remove_delegation_layer_inner_spend);
    let new_spend = datastore_spend(ctx, &datastore_info, inner_datastore_spend)?;
    ctx.insert_coin_spend(new_spend.clone());

    let new_datastore_info =
      DataStoreInfo::from_spend(ctx.allocator_mut(), &new_spend, &vec![]).unwrap();
    assert_eq!(new_datastore_info.delegated_puzzles.len(), 0);
    assert_eq!(new_datastore_info.owner_puzzle_hash, owner_puzzle_hash);

    let spends = ctx.take_spends();
    // print_spend_bundle_to_file(spends.clone(), G2Element::default(), "sb.debug");
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
    assert!(coin_state.spent_height.is_some());

    Ok(())
  }

  #[rstest]
  #[tokio::test]
  async fn test_datastore_launch(
    #[values(true, false)] use_label_and_desc: bool,
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

    let label = if use_label_and_desc {
      "label".to_string()
    } else {
      String::default()
    };

    let description = if use_label_and_desc {
      "description".to_string()
    } else {
      String::default()
    };

    let (launch_singleton, datastore_info) = Launcher::new(coin.coin_id(), 1).mint_datastore(
      ctx,
      DataStoreMintInfo {
        metadata: DataStoreMetadata {
          root_hash: Bytes32::new([0; 32]),
          label: label,
          description: description,
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
  enum AdminTransitionDstAdminLayerOption {
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
      (Bytes32::from([0; 32]), "".to_string(), "".to_string()),
      (Bytes32::from([0; 32]), "label".to_string(), "description".to_string()),
    ],
    dst_meta => [
      (Bytes32::from([0; 32]), "".to_string(), "".to_string()),
      (Bytes32::from([0; 32]), "label".to_string(), "description".to_string()),
      (Bytes32::from([0; 32]), "new_label".to_string(), "new_description".to_string()),
    ],
    dst_admin => [
      AdminTransitionDstAdminLayerOption::None,
      AdminTransitionDstAdminLayerOption::Same,
      AdminTransitionDstAdminLayerOption::New,
    ]
  )]
  #[tokio::test]
  async fn test_datastore_admin_transition(
    src_meta: (Bytes32, String, String),
    src_with_writer: bool,
    // src must have admin layer in this scenario
    src_with_oracle: bool,
    dst_with_writer: bool,
    dst_with_oracle: bool,
    dst_admin: AdminTransitionDstAdminLayerOption,
    dst_meta: (Bytes32, String, String),
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
          root_hash: src_meta.0,
          label: src_meta.1.clone(),
          description: src_meta.2.clone(),
        },
        owner_puzzle_hash: owner_puzzle_hash.into(),
        delegated_puzzles: src_delegated_puzzles.clone(),
      },
    )?;

    ctx.spend_p2_coin(coin, owner_pk, launch_singleton)?;

    // transition from src to dst
    let mut admin_inner_spend = Conditions::new();

    let mut dst_delegated_puzzles: Vec<DelegatedPuzzle> = src_delegated_puzzles.clone();
    if src_with_writer != dst_with_writer
      || src_with_oracle != dst_with_oracle
      || dst_admin != AdminTransitionDstAdminLayerOption::Same
    {
      dst_delegated_puzzles.clear();

      if dst_with_writer {
        dst_delegated_puzzles.push(writer_delegated_puzzle);
      }
      if dst_with_oracle {
        dst_delegated_puzzles.push(oracle_delegated_puzzle);
      }

      match dst_admin {
        AdminTransitionDstAdminLayerOption::None => {}
        AdminTransitionDstAdminLayerOption::Same => {
          dst_delegated_puzzles.push(admin_delegated_puzzle);
        }
        AdminTransitionDstAdminLayerOption::New => {
          dst_delegated_puzzles.push(admin2_delegated_puzzle);
        }
      }

      let new_merkle_root = merkle_root_for_delegated_puzzles(&dst_delegated_puzzles);

      let new_merkle_root_condition = NewMerkleRootCondition {
        new_merkle_root,
        memos: get_memos(owner_puzzle_hash.into(), dst_delegated_puzzles.clone()),
      }
      .to_clvm(ctx.allocator_mut())
      .unwrap();

      admin_inner_spend = admin_inner_spend.condition(Condition::Other(new_merkle_root_condition));
    }

    if src_meta.0 != dst_meta.0 || src_meta.1 != dst_meta.1 || src_meta.2 != dst_meta.2 {
      let new_metadata = DataStoreMetadata {
        root_hash: dst_meta.0,
        label: dst_meta.1.clone(),
        description: dst_meta.2.clone(),
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
      admin_inner_puzzle_reveal,
      admin_inner_spend.p2_spend(ctx, admin_pk)?.solution(),
    );
    let new_spend = datastore_spend(ctx, &src_datastore_info, inner_datastore_spend)?;
    ctx.insert_coin_spend(new_spend.clone());

    let dst_datastore_info = DataStoreInfo::from_spend(
      ctx.allocator_mut(),
      &new_spend,
      &src_datastore_info.delegated_puzzles,
    )
    .unwrap();

    assert_eq!(src_datastore_info.delegated_puzzles, src_delegated_puzzles);
    assert_eq!(src_datastore_info.owner_puzzle_hash, owner_puzzle_hash);

    assert_eq!(src_datastore_info.metadata.root_hash, src_meta.0);
    assert_eq!(src_datastore_info.metadata.label, src_meta.1);
    assert_eq!(src_datastore_info.metadata.description, src_meta.2);

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

    assert_eq!(dst_datastore_info.metadata.root_hash, dst_meta.0);
    assert_eq!(dst_datastore_info.metadata.label, dst_meta.1);
    assert_eq!(dst_datastore_info.metadata.description, dst_meta.2);

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
      AdminTransitionDstAdminLayerOption::None => {
        assert!(!admin_found && !admin2_found);
      }
      AdminTransitionDstAdminLayerOption::Same => {
        assert!(admin_found && !admin2_found);
      }
      AdminTransitionDstAdminLayerOption::New => {
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
      (Bytes32::from([0; 32]), "".to_string(), "".to_string()),
      (Bytes32::from([0; 32]), "label".to_string(), "description".to_string()),
    ],
    dst_meta => [
      (Bytes32::from([0; 32]), "".to_string(), "".to_string()),
      (Bytes32::from([0; 32]), "label".to_string(), "description".to_string()),
      (Bytes32::from([0; 32]), "new_label".to_string(), "new_description".to_string()),
    ],
    also_change_owner => [true, false],
  )]
  #[tokio::test]
  async fn test_datastore_owner_transition(
    src_meta: (Bytes32, String, String),
    src_with_admin: bool,
    src_with_writer: bool,
    src_with_oracle: bool,
    dst_with_admin: bool,
    dst_with_writer: bool,
    dst_with_oracle: bool,
    dst_meta: (Bytes32, String, String),
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
          root_hash: src_meta.0,
          label: src_meta.1.clone(),
          description: src_meta.2.clone(),
        },
        owner_puzzle_hash: owner_puzzle_hash.into(),
        delegated_puzzles: src_delegated_puzzles.clone(),
      },
    )?;

    ctx.spend_p2_coin(coin, owner_pk, launch_singleton)?;

    // transition from src to dst using owner puzzle
    let mut owner_output_conds = Conditions::new();

    let mut dst_delegated_puzzles: Vec<DelegatedPuzzle> = src_delegated_puzzles.clone();
    if src_with_admin != dst_with_admin
      || src_with_writer != dst_with_writer
      || src_with_oracle != dst_with_oracle
      || dst_delegated_puzzles.len() == 0
      || also_change_owner
    {
      dst_delegated_puzzles.clear();

      if dst_with_admin {
        dst_delegated_puzzles.push(admin_delegated_puzzle);
      }
      if dst_with_writer {
        dst_delegated_puzzles.push(writer_delegated_puzzle);
      }
      if dst_with_oracle {
        dst_delegated_puzzles.push(oracle_delegated_puzzle);
      }

      owner_output_conds = owner_output_conds.condition(get_new_ownership_inner_condition(
        if also_change_owner {
          &owner2_puzzle_hash
        } else {
          &owner_puzzle_hash
        },
        &dst_delegated_puzzles,
      ));
    }

    if src_meta.0 != dst_meta.0 || src_meta.1 != dst_meta.1 || src_meta.2 != dst_meta.2 {
      let new_metadata = DataStoreMetadata {
        root_hash: dst_meta.0,
        label: dst_meta.1.clone(),
        description: dst_meta.2.clone(),
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

    assert_eq!(src_datastore_info.metadata.root_hash, src_meta.0);
    assert_eq!(src_datastore_info.metadata.label, src_meta.1);
    assert_eq!(src_datastore_info.metadata.description, src_meta.2);

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

    assert_eq!(dst_datastore_info.metadata.root_hash, dst_meta.0);
    assert_eq!(dst_datastore_info.metadata.label, dst_meta.1);
    assert_eq!(dst_datastore_info.metadata.description, dst_meta.2);

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
        (Bytes32::from([0; 32]), Bytes32::from([0; 32])),
        ("".to_string(), "label".to_string()),
        ("".to_string(), "description".to_string())
      ),
      (
        (Bytes32::from([0; 32]), Bytes32::from([1; 32])),
        ("".to_string(), "".to_string()),
        ("".to_string(), "".to_string())
      ),
      (
        (Bytes32::from([0; 32]), Bytes32::from([1; 32])),
        ("label".to_string(), "label".to_string()),
        ("description".to_string(), "description".to_string())
      ),
      (
        (Bytes32::from([0; 32]), Bytes32::from([0; 32])),
        ("label".to_string(), "new_label".to_string()),
        ("description".to_string(), "new_description".to_string())
      ),
    ],
  )]
  #[tokio::test]
  async fn test_datastore_writer_transition(
    with_admin_layer: bool,
    with_oracle_layer: bool,
    meta_transition: ((Bytes32, Bytes32), (String, String), (String, String)),
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
          root_hash: meta_transition.0 .0,
          label: meta_transition.1 .0.clone(),
          description: meta_transition.2 .0.clone(),
        },
        owner_puzzle_hash: owner_puzzle_hash.into(),
        delegated_puzzles: delegated_puzzles.clone(),
      },
    )?;

    ctx.spend_p2_coin(coin, owner_pk, launch_singleton)?;

    // transition from src to dst using writer (update metadata)
    let new_metadata = DataStoreMetadata {
      root_hash: meta_transition.0 .1,
      label: meta_transition.1 .1.clone(),
      description: meta_transition.2 .1.clone(),
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
      writer_inner_puzzle_ptr,
      writer_conds.p2_spend(ctx, writer_pk)?.solution(),
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

    assert_eq!(dst_datastore_info.delegated_puzzles, delegated_puzzles);
    assert_eq!(src_datastore_info.owner_puzzle_hash, owner_puzzle_hash);

    assert_eq!(src_datastore_info.metadata.root_hash, meta_transition.0 .0);
    assert_eq!(src_datastore_info.metadata.label, meta_transition.1 .0);
    assert_eq!(
      src_datastore_info.metadata.description,
      meta_transition.2 .0
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

    assert_eq!(dst_datastore_info.metadata.root_hash, meta_transition.0 .1);
    assert_eq!(dst_datastore_info.metadata.label, meta_transition.1 .1);
    assert_eq!(
      dst_datastore_info.metadata.description,
      meta_transition.2 .1
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
      (Bytes32::from([0; 32]), "".to_string(), "".to_string()),
      (Bytes32::from([0; 32]), "label".to_string(), "description".to_string()),
    ],
  )]
  #[tokio::test]
  async fn test_datastore_oracle_transition(
    with_admin_layer: bool,
    with_writer_layer: bool,
    meta: (Bytes32, String, String),
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
          root_hash: meta.0,
          label: meta.1.clone(),
          description: meta.2.clone(),
        },
        owner_puzzle_hash: owner_puzzle_hash.into(),
        delegated_puzzles: delegated_puzzles.clone(),
      },
    )?;

    ctx.spend_p2_coin(coin, owner_pk, launch_singleton)?;

    // 'dude' spends oracle
    let inner_datastore_spend = DatastoreInnerSpend::DelegatedPuzzleSpend(
      oracle_delegated_puzzle,
      DelegatedPuzzle::oracle_layer_full_puzzle(
        ctx.allocator_mut(),
        oracle_puzzle_hash,
        oracle_fee,
      )
      .unwrap(),
      ctx.allocator().nil(),
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
      Conditions::new()
        .assert_puzzle_announcement(src_datastore_info.coin.puzzle_hash, &Bytes::new("$".into())),
    )?;

    // asserts

    assert_eq!(dst_datastore_info.delegated_puzzles, delegated_puzzles);
    assert_eq!(src_datastore_info.owner_puzzle_hash, owner_puzzle_hash);

    assert_eq!(src_datastore_info.metadata.root_hash, meta.0);
    assert_eq!(src_datastore_info.metadata.label, meta.1);
    assert_eq!(src_datastore_info.metadata.description, meta.2);

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

    assert_eq!(dst_datastore_info.metadata.root_hash, meta.0);
    assert_eq!(dst_datastore_info.metadata.label, meta.1);
    assert_eq!(dst_datastore_info.metadata.description, meta.2);

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
      (Bytes32::from([0; 32]), "".to_string(), "".to_string()),
      (Bytes32::from([0; 32]), "label".to_string(), "description".to_string()),
    ],
  )]
  #[tokio::test]
  async fn test_melt(
    with_admin_layer: bool,
    with_writer_layer: bool,
    with_oracle_layer: bool,
    meta: (Bytes32, String, String),
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
          root_hash: meta.0,
          label: meta.1.clone(),
          description: meta.2.clone(),
        },
        owner_puzzle_hash: owner_puzzle_hash.into(),
        delegated_puzzles: delegated_puzzles.clone(),
      },
    )?;

    ctx.spend_p2_coin(coin, owner_pk, launch_singleton)?;

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

    assert_eq!(src_datastore_info.metadata.root_hash, meta.0);
    assert_eq!(src_datastore_info.metadata.label, meta.1);
    assert_eq!(src_datastore_info.metadata.description, meta.2);

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
}
