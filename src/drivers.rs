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
  OwnerPuzzleSpend(Spend), // owner puzzle spend
  DelegatedPuzzleSpend(DelegatedPuzzle, Option<NodePtr>, NodePtr), // delegated puzzle info + inner puzzle reveal + solution
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
        "writer + filter puzzle hash: {:}",
        encode(ctx.tree_hash(full_puzzle))
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
    if info.delegated_puzzles.len() == 0 {
      memos = vec![]; // owner ph = inner_puzzle_hash
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

#[cfg(test)]
mod tests {
  use crate::{
    print_spend_bundle_to_file, DefaultMetadataSolution, DefaultMetadataSolutionMetadataList,
    MerkleTree, NewMerkleRootCondition, NewMetadataCondition,
  };

  use super::*;

  use chia::{bls::G2Element, traits::Streamable};
  use chia_protocol::{Bytes32, Program};
  use chia_puzzles::standard::StandardArgs;
  use chia_sdk_driver::Launcher;
  use chia_sdk_test::{secret_key, test_transaction, Simulator};
  use chia_sdk_types::conditions::Condition;
  use clvm_traits::FromNodePtr;

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

    let sk = secret_key()?;
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
          DataStoreInfo::from_spend(ctx.allocator_mut(), &spend, vec![]).unwrap();

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

    let owner_sk = secret_key()?;
    let owner_pk = owner_sk.public_key();

    let admin_sk = secret_key()?;
    let admin_pk = admin_sk.public_key();

    let writer_sk = secret_key()?;
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
          DataStoreInfo::from_spend(ctx.allocator_mut(), &spend, vec![]).unwrap();

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
      Some(writer_puzzle),
      new_metadata_inner_spend.solution(),
    );
    let new_spend = datastore_spend(ctx, &datastore_info, inner_datastore_spend)?;
    ctx.insert_coin_spend(new_spend.clone());

    let datastore_info = DataStoreInfo::from_spend(
      ctx.allocator_mut(),
      &new_spend,
      datastore_info.delegated_puzzles,
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

    let leaves: Vec<Bytes32> = delegated_puzzles
      .clone()
      .iter()
      .map(|dp| dp.puzzle_hash)
      .collect();
    let merkle_tree = MerkleTree::new(&leaves);
    let new_merkle_root = merkle_tree.get_root();

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
      Some(admin_puzzle),
      inner_spend.solution(),
    );
    let new_spend = datastore_spend(ctx, &datastore_info, inner_datastore_spend)?;
    ctx.insert_coin_spend(new_spend.clone());

    let datastore_info = DataStoreInfo::from_spend(
      ctx.allocator_mut(),
      &new_spend,
      datastore_info.delegated_puzzles,
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

    println!(
      "oracle full puzzle: {:}",
      encode(
        Program::from_node_ptr(
          ctx.allocator_mut(),
          oracle_delegated_puzzle.full_puzzle.unwrap()
        )
        .unwrap()
        .clone()
        .to_bytes()
        .unwrap()
      )
    ); // todo: debug

    let inner_datastore_spend = DatastoreInnerSpend::DelegatedPuzzleSpend(
      oracle_delegated_puzzle,
      Some(oracle_delegated_puzzle.full_puzzle.unwrap()), // oracle puzzle always available
      ctx.allocator().nil(),
    );
    let new_spend = datastore_spend(ctx, &datastore_info, inner_datastore_spend)?;
    ctx.insert_coin_spend(new_spend.clone());

    let new_datastore_info = DataStoreInfo::from_spend(
      ctx.allocator_mut(),
      &new_spend,
      datastore_info.clone().delegated_puzzles,
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
      DataStoreInfo::from_spend(ctx.allocator_mut(), &new_spend, vec![]).unwrap();
    assert_eq!(new_datastore_info.delegated_puzzles.len(), 0);
    assert_eq!(new_datastore_info.owner_puzzle_hash, owner_puzzle_hash);

    let spends = ctx.take_spends();
    print_spend_bundle_to_file(spends.clone(), G2Element::default(), "sb.debug");
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
}
