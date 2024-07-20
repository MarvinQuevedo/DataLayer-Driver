use chia_protocol::Bytes32;
use clvm_traits::{apply_constants, FromClvm, ToClvm};
use clvm_utils::ToTreeHash;
use clvm_utils::{CurriedProgram, TreeHash};
use hex_literal::hex;

#[derive(ToClvm, FromClvm)]
#[apply_constants]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[clvm(curry)]
pub struct DelegationLayerArgs {
  pub mod_hash: Bytes32,
  pub inner_puzzle_hash: Bytes32,
  pub merkle_root: Bytes32,
}

impl DelegationLayerArgs {
  pub fn new(inner_puzzle_hash: Bytes32, merkle_root: Bytes32) -> Self {
    Self {
      mod_hash: DELEGATION_LAYER_PUZZLE_HASH.into(),
      inner_puzzle_hash,
      merkle_root,
    }
  }
}

impl DelegationLayerArgs {
  pub fn curry_tree_hash(inner_puzzle_hash: Bytes32, merkle_root: Bytes32) -> TreeHash {
    CurriedProgram {
      program: DELEGATION_LAYER_PUZZLE_HASH,
      args: DelegationLayerArgs {
        mod_hash: DELEGATION_LAYER_PUZZLE_HASH.into(),
        inner_puzzle_hash,
        merkle_root,
      },
    }
    .tree_hash()
  }
}

#[derive(ToClvm, FromClvm)]
#[apply_constants]
#[derive(Debug, Clone, PartialEq, Eq)]
#[clvm(list)]
pub struct DelegationLayerSolution<P, S> {
  pub merkle_proof: Option<(u32, Vec<chia_protocol::Bytes32>)>,
  pub puzzle_reveal: P,
  pub puzzle_solution: S,
}

pub const DELEGATION_LAYER_PUZZLE: [u8; 881] = hex!(
  "
    ff02ffff01ff02ff12ffff04ff02ffff04ff05ffff04ff0bffff04ffff02ff5fff81bf80ffff04ff
    ff04ff17ff8080ffff04ffff02ff1effff04ff02ffff04ffff02ff1affff04ff02ffff04ff5fff80
    808080ffff04ff0bffff04ff17ffff04ff2fff80808080808080ff8080808080808080ffff04ffff
    01ffffff3381f3ff02ffffa04bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c
    7785459aa09dcf97a184f32623d11a73124ceb99a5709b083721e878a16d78f596718ba7b2ffa102
    a12871fee210fb8619291eaea194581cbd2531e4b23759d225f6806923f63222a102a8d5dd63fba4
    71ebcb1f3e8f7c1e1879b7152a6e7298a91ce119a63400ade7c5ffffff02ffff03ff17ffff01ff02
    ffff03ffff09ff47ff1880ffff01ff02ff12ffff04ff02ffff04ff05ffff04ff0bffff04ff37ffff
    04ff67ffff01ff956f64645f6372656174655f636f696e5f666f756e6480808080808080ffff01ff
    04ff27ffff02ff12ffff04ff02ffff04ff05ffff04ff0bffff04ff37ffff04ff2fffff04ff5fff80
    808080808080808080ff0180ffff01ff02ffff03ff5fffff01ff04ffff04ff10ffff04ffff0bff5c
    ffff0bff14ffff0bff14ff6cff0580ffff0bff14ffff0bff7cffff0bff14ffff0bff14ff6cffff0b
    ffff0101ff058080ffff0bff14ffff0bff7cffff0bff14ffff0bff14ff6cffff0bffff0101ff0b80
    80ffff0bff14ffff0bff7cffff0bff14ffff0bff14ff6cffff0bffff0101ff4f8080ffff0bff14ff
    6cff4c808080ff4c808080ff4c808080ff4c808080ffff04ffff0101ffff04ff6fff8080808080ff
    8080ff8080ff018080ff0180ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff1affff04
    ff02ffff04ff09ff80808080ffff02ff1affff04ff02ffff04ff0dff8080808080ffff01ff0bffff
    0101ff058080ff0180ffff02ffff03ff1bffff01ff02ff16ffff04ff02ffff04ffff02ffff03ffff
    18ffff0101ff1380ffff01ff0bffff0102ff2bff0580ffff01ff0bffff0102ff05ff2b8080ff0180
    ffff04ffff04ffff17ff13ffff0181ff80ff3b80ff8080808080ffff010580ff0180ff02ffff03ff
    ff09ff05ff0b80ff80ffff01ff02ffff03ffff09ff17ffff02ff16ffff04ff02ffff04ffff0bffff
    0101ff0580ffff04ff2fff808080808080ffff01ff0101ffff01ff088080ff018080ff0180ff0180
    80
    "
);

pub const DELEGATION_LAYER_PUZZLE_HASH: TreeHash = TreeHash::new(hex!(
  "
    f5ecc72012675d5b9c7beafc1d0c81b17e7a557dfe99d24cda801da5ae75459c
    "
));

#[derive(ToClvm, FromClvm)]
#[apply_constants]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[clvm(curry)]
pub struct AdminFilterArgs<I> {
  pub inner_puzzle: I,
}

impl<I> AdminFilterArgs<I> {
  pub fn new(inner_puzzle: I) -> Self {
    Self { inner_puzzle }
  }
}

impl AdminFilterArgs<TreeHash> {
  pub fn curry_tree_hash(inner_puzzle: TreeHash) -> TreeHash {
    CurriedProgram {
      program: ADMIN_FILTER_PUZZLE_HASH,
      args: AdminFilterArgs { inner_puzzle },
    }
    .tree_hash()
  }
}

#[derive(ToClvm, FromClvm)]
#[apply_constants]
#[derive(Debug, Clone, PartialEq, Eq)]
#[clvm(list)]
pub struct AdminFilterSolution<I> {
  pub inner_solution: I,
}

pub const ADMIN_FILTER_PUZZLE: [u8; 182] = hex!(
  "
    ff02ffff01ff02ff02ffff04ff02ffff04ffff02ff05ff0b80ff80808080ffff04ffff01ff02ffff
    03ff05ffff01ff02ffff03ffff02ffff03ffff09ff11ffff0181e880ffff01ff22ffff09ff820159
    ff8080ffff09ff820299ffff01a057bfd1cb0adda3d94315053fda723f2028320faa8338225d99f6
    29e3d46d43a98080ff8080ff0180ffff01ff04ff09ffff02ff02ffff04ff02ffff04ff0dff808080
    8080ffff01ff088080ff0180ff8080ff0180ff018080
    "
);

pub const ADMIN_FILTER_PUZZLE_HASH: TreeHash = TreeHash::new(hex!(
  "
    ff41e0759732ab08adc419b265cfcdc2dc18115c3a6930f47f0157c5c0caa61b
    "
));

#[derive(ToClvm, FromClvm)]
#[apply_constants]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[clvm(curry)]
pub struct WriterFilterArgs<I> {
  pub inner_puzzle: I,
}

impl<I> WriterFilterArgs<I> {
  pub fn new(inner_puzzle: I) -> Self {
    Self { inner_puzzle }
  }
}

impl WriterFilterArgs<TreeHash> {
  pub fn curry_tree_hash(inner_puzzle: TreeHash) -> TreeHash {
    CurriedProgram {
      program: WRITER_FILTER_PUZZLE_HASH,
      args: WriterFilterArgs { inner_puzzle },
    }
    .tree_hash()
  }
}

#[derive(ToClvm, FromClvm)]
#[apply_constants]
#[derive(Debug, Clone, PartialEq, Eq)]
#[clvm(list)]
pub struct WriterFilterSolution<I> {
  pub inner_solution: I,
}

pub const WRITER_FILTER_PUZZLE: [u8; 201] = hex!(
  "
    ff02ffff01ff02ff02ffff04ff02ffff04ffff02ff05ff0b80ff80808080ffff04ffff01ff02ffff
    03ff05ffff01ff02ffff03ffff21ffff09ff11ffff0181f380ffff02ffff03ffff09ff11ffff0181
    e880ffff01ff20ffff22ffff09ff820159ff8080ffff09ff820299ffff01a057bfd1cb0adda3d943
    15053fda723f2028320faa8338225d99f629e3d46d43a9808080ff8080ff018080ffff01ff0880ff
    ff01ff04ff09ffff02ff02ffff04ff02ffff04ff0dff808080808080ff0180ff8080ff0180ff0180
    80
    "
);

pub const WRITER_FILTER_PUZZLE_HASH: TreeHash = TreeHash::new(hex!(
  "
    0f3e06290983010f0c1f748a58a1d7daa4354d2298c6df7f115966881aebb0f2
    "
));

// bytes(ACS_MU).hex()
pub const DL_METADATA_UPDATER_PUZZLE: [u8; 1] = hex!(
  "
    0b
    "
);

pub const DL_METADATA_UPDATER_PUZZLE_HASH: TreeHash = TreeHash::new(hex!(
  "
    57bfd1cb0adda3d94315053fda723f2028320faa8338225d99f629e3d46d43a9
    "
));

#[cfg(test)]
mod tests {
  use chia::traits::Streamable;
  use chia_protocol::Program;
  use chia_puzzles::standard::STANDARD_PUZZLE;
  use chia_sdk_driver::{SpendContext, SpendError};
  use chia_sdk_types::conditions::CreateCoin;
  use clvm_traits::{clvm_quote, FromNodePtr};
  use clvm_utils::tree_hash;
  use clvmr::{serde::node_from_bytes, Allocator, NodePtr};
  use hex::encode;
  use rstest::rstest;

  use crate::{
    DefaultMetadataSolution, DefaultMetadataSolutionMetadataList, MeltCondition,
    NewMetadataCondition,
  };

  use super::*;

  // unfortunately, this isn't publicly exported, so I had to copy-paste
  // use chia_puzzles::assert_puzzle_hash;
  #[macro_export]
  macro_rules! assert_puzzle_hash {
    ($puzzle:ident => $puzzle_hash:ident) => {
      let mut a = clvmr::Allocator::new();
      let ptr = clvmr::serde::node_from_bytes(&mut a, &$puzzle).unwrap();
      let hash = clvm_utils::tree_hash(&mut a, ptr);
      assert_eq!($puzzle_hash, hash);
    };
  }

  #[test]
  fn puzzle_hashes() {
    assert_puzzle_hash!(DELEGATION_LAYER_PUZZLE => DELEGATION_LAYER_PUZZLE_HASH);
    assert_puzzle_hash!(ADMIN_FILTER_PUZZLE => ADMIN_FILTER_PUZZLE_HASH);
    assert_puzzle_hash!(WRITER_FILTER_PUZZLE => WRITER_FILTER_PUZZLE_HASH);
    assert_puzzle_hash!(DL_METADATA_UPDATER_PUZZLE => DL_METADATA_UPDATER_PUZZLE_HASH);
  }

  enum TestFilterPuzzle {
    Admin,
    Writer,
  }

  fn get_filter_puzzle_ptr(
    allocator: &mut Allocator,
    filter_puzzle: &TestFilterPuzzle,
    inner_puzzle_ptr: NodePtr,
  ) -> Result<NodePtr, SpendError> {
    match filter_puzzle {
      TestFilterPuzzle::Admin => CurriedProgram {
        program: node_from_bytes(allocator, &ADMIN_FILTER_PUZZLE)
          .map_err(|err| SpendError::Io(err))?,
        args: AdminFilterArgs::new(inner_puzzle_ptr),
      }
      .to_clvm(allocator)
      .map_err(|err| SpendError::ToClvm(err)),
      TestFilterPuzzle::Writer => CurriedProgram {
        program: node_from_bytes(allocator, &WRITER_FILTER_PUZZLE)
          .map_err(|err| SpendError::Io(err))?,
        args: WriterFilterArgs::new(inner_puzzle_ptr),
      }
      .to_clvm(allocator)
      .map_err(|err| SpendError::ToClvm(err)),
    }
  }

  #[rstest]
  #[case(TestFilterPuzzle::Admin, hex!("80").to_vec())] // run -d '(mod () ())'
  #[case(TestFilterPuzzle::Admin, hex!("01").to_vec())] // run -d '(mod solution solution)'
  #[case(TestFilterPuzzle::Admin, STANDARD_PUZZLE.to_vec())]
  #[case(TestFilterPuzzle::Writer, hex!("80").to_vec())] // run -d '(mod () ())'
  #[case(TestFilterPuzzle::Writer, hex!("01").to_vec())] // run -d '(mod solution solution)'
  #[case(TestFilterPuzzle::Writer, STANDARD_PUZZLE.to_vec())]
  fn filter_curry_tree_hash(
    #[case] filter_puzzle: TestFilterPuzzle,
    #[case] inner_puzzle_bytes: Vec<u8>,
  ) -> Result<(), ()> {
    let allocator: &mut Allocator = &mut Allocator::new();
    let inner_puzzle_ptr = node_from_bytes(allocator, &inner_puzzle_bytes).unwrap();

    let full_puzzle_ptr =
      get_filter_puzzle_ptr(allocator, &filter_puzzle, inner_puzzle_ptr).unwrap();

    let full_puzzle_hash = tree_hash(allocator, full_puzzle_ptr);

    let inner_puzzle_hash: TreeHash = tree_hash(allocator, inner_puzzle_ptr);
    let curry_puzzle_hash = match filter_puzzle {
      TestFilterPuzzle::Admin => AdminFilterArgs::curry_tree_hash(inner_puzzle_hash),
      TestFilterPuzzle::Writer => WriterFilterArgs::curry_tree_hash(inner_puzzle_hash),
    };

    assert_eq!(
      hex::encode(full_puzzle_hash),
      hex::encode(curry_puzzle_hash)
    );

    Ok(())
  }

  const NULL_B32: [u8; 32] =
    hex!("0000000000000000000000000000000000000000000000000000000000000000");
  const FULL_B32: [u8; 32] =
    hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

  #[rstest]
  #[case(Bytes32::from(NULL_B32), Bytes32::from(FULL_B32))]
  #[case(Bytes32::from(FULL_B32), Bytes32::from(NULL_B32))]
  #[case(Bytes32::from(NULL_B32), Bytes32::from(FULL_B32))]
  #[case(Bytes32::from(FULL_B32), Bytes32::from(FULL_B32))]
  fn delegation_layer_curry_tree_hash(
    #[case] inner_puzzle_hash: Bytes32,
    #[case] merkle_root: Bytes32,
  ) -> Result<(), ()> {
    let mut allocator = Allocator::new();

    let delegation_layer_mod_ptr =
      node_from_bytes(&mut allocator, &DELEGATION_LAYER_PUZZLE).unwrap();

    let full_puzzle = CurriedProgram {
      program: delegation_layer_mod_ptr,
      args: DelegationLayerArgs::new(inner_puzzle_hash, merkle_root),
    }
    .to_clvm(&mut allocator)
    .unwrap();
    let full_puzzle_hash = tree_hash(&allocator, full_puzzle);

    let curry_puzzle_hash = DelegationLayerArgs::curry_tree_hash(inner_puzzle_hash, merkle_root);

    assert_eq!(
      hex::encode(full_puzzle_hash),
      hex::encode(curry_puzzle_hash)
    );

    Ok(())
  }

  // tests that it indeed returns the third argument
  #[rstest]
  #[case(hex!("8379616b").to_vec())] // run -d '"yak"'
  #[case(hex!("ff018379616b").to_vec())] // run -d '(mod () "yak"))'
  #[case(hex!("ff01ff0180").to_vec())] // run -d '(mod () (list 1)))'
  #[case(hex!("ff01ff01ff02ff0380").to_vec())] // run -d '(mod () (list 1 2 3)))'
  #[case(hex!("ff01ff01ffff02ff0380ffff04ff0580ffff060780").to_vec())] // run -d '(mod () (list 1 (list 2 3) (list 4 5) (c 6 7))))'
  fn dl_metadata_updater_puzzle(#[case] third_arg: Vec<u8>) -> Result<(), ()> {
    let mut ctx = SpendContext::new();

    let third_arg_ptr = node_from_bytes(ctx.allocator_mut(), &third_arg).unwrap();
    let solution_ptr = vec![ctx.allocator().nil(), ctx.allocator().nil(), third_arg_ptr]
      .to_clvm(ctx.allocator_mut())
      .unwrap();

    let puzzle_ptr = node_from_bytes(ctx.allocator_mut(), &DL_METADATA_UPDATER_PUZZLE).unwrap();
    let output = ctx.run(puzzle_ptr, solution_ptr).unwrap();

    assert_eq!(
      encode(
        Program::from_node_ptr(ctx.allocator_mut(), output)
          .unwrap()
          .to_bytes()
          .unwrap()
      ),
      encode(
        Program::from_node_ptr(ctx.allocator_mut(), third_arg_ptr)
          .unwrap()
          .to_bytes()
          .unwrap()
      )
    );

    Ok(())
  }

  #[rstest]
  #[case(TestFilterPuzzle::Admin)]
  #[case(TestFilterPuzzle::Writer)]
  fn test_create_coin_filter(#[case] filter_puzzle: TestFilterPuzzle) -> Result<(), ()> {
    let mut ctx = SpendContext::new();

    let inner_puzzle = clvm_quote!(vec![CreateCoin {
      puzzle_hash: [0; 32].into(),
      amount: 1,
      memos: vec![],
    }
    .to_clvm(ctx.allocator_mut())
    .unwrap(),])
    .to_clvm(ctx.allocator_mut())
    .unwrap();

    let filter_puzzle_ptr =
      get_filter_puzzle_ptr(ctx.allocator_mut(), &filter_puzzle, inner_puzzle).unwrap();

    let solution_ptr = vec![ctx.allocator().nil()]
      .to_clvm(ctx.allocator_mut())
      .unwrap();

    match ctx.run(filter_puzzle_ptr, solution_ptr) {
      Ok(_) => Err(()),
      Err(err) => match err {
        SpendError::Eval(eval_err) => {
          assert_eq!(eval_err.1, "clvm raise");
          Ok(())
        }
        _ => Err(()),
      },
    }
  }

  #[derive(ToClvm)]
  #[apply_constants]
  #[derive(Debug, Clone, PartialEq, Eq)]
  #[clvm(list)]
  pub struct NewMerkleRootCondition<M = Bytes32> {
    #[clvm(constant = -13)]
    pub opcode: i32,
    pub new_merkle_root: Bytes32,
    #[clvm(rest)]
    pub memos: Vec<M>,
  }

  #[rstest]
  #[case(TestFilterPuzzle::Admin, Bytes32::from(NULL_B32), vec![])]
  #[case(TestFilterPuzzle::Admin, Bytes32::from(FULL_B32), vec![])]
  #[case(TestFilterPuzzle::Admin, Bytes32::from(NULL_B32), vec![Bytes32::from(NULL_B32)])]
  #[case(TestFilterPuzzle::Admin, Bytes32::from(FULL_B32), vec![Bytes32::from(NULL_B32)])]
  #[case(TestFilterPuzzle::Admin, Bytes32::from(NULL_B32), vec![Bytes32::from(FULL_B32)])]
  #[case(TestFilterPuzzle::Admin, Bytes32::from(FULL_B32), vec![Bytes32::from(FULL_B32)])]
  #[case(TestFilterPuzzle::Writer, Bytes32::from(NULL_B32), vec![])]
  #[case(TestFilterPuzzle::Writer, Bytes32::from(FULL_B32), vec![])]
  #[case(TestFilterPuzzle::Writer, Bytes32::from(NULL_B32), vec![Bytes32::from(NULL_B32)])]
  #[case(TestFilterPuzzle::Writer, Bytes32::from(FULL_B32), vec![Bytes32::from(NULL_B32)])]
  #[case(TestFilterPuzzle::Writer, Bytes32::from(NULL_B32), vec![Bytes32::from(FULL_B32)])]
  #[case(TestFilterPuzzle::Writer, Bytes32::from(FULL_B32), vec![Bytes32::from(FULL_B32)])]
  fn test_new_merkle_root_filter(
    #[case] filter_puzzle: TestFilterPuzzle,
    #[case] new_merkle_root: Bytes32,
    #[case] memos: Vec<Bytes32>,
  ) -> Result<(), ()> {
    let mut ctx = SpendContext::new();

    let inner_puzzle = clvm_quote!(vec![NewMerkleRootCondition::<Bytes32> {
      new_merkle_root,
      memos,
    }
    .to_clvm(ctx.allocator_mut())
    .unwrap(),])
    .to_clvm(ctx.allocator_mut())
    .unwrap();

    let filter_puzzle_ptr =
      get_filter_puzzle_ptr(ctx.allocator_mut(), &filter_puzzle, inner_puzzle).unwrap();

    let solution_ptr = vec![ctx.allocator().nil()]
      .to_clvm(ctx.allocator_mut())
      .unwrap();

    match ctx.run(filter_puzzle_ptr, solution_ptr) {
      Ok(_) => match filter_puzzle {
        TestFilterPuzzle::Admin => Ok(()),
        TestFilterPuzzle::Writer => Err(()),
      },
      Err(err) => match err {
        SpendError::Eval(eval_err) => match filter_puzzle {
          TestFilterPuzzle::Admin => Err(()),
          TestFilterPuzzle::Writer => {
            assert_eq!(eval_err.1, "clvm raise");
            Ok(())
          }
        },
        _ => Err(()),
      },
    }
  }

  #[rstest]
  // fail because of wrong new updater ph
  #[case(
    TestFilterPuzzle::Admin,
    Bytes32::from(NULL_B32),
    Bytes32::from(NULL_B32),
    false,
    true
  )]
  #[case(
    TestFilterPuzzle::Admin,
    Bytes32::from(NULL_B32),
    Bytes32::from(FULL_B32),
    false,
    true
  )]
  #[case(
    TestFilterPuzzle::Admin,
    Bytes32::from(FULL_B32),
    Bytes32::from(NULL_B32),
    false,
    true
  )]
  #[case(
    TestFilterPuzzle::Admin,
    Bytes32::from(FULL_B32),
    Bytes32::from(FULL_B32),
    false,
    true
  )]
  #[case(
    TestFilterPuzzle::Writer,
    Bytes32::from(NULL_B32),
    Bytes32::from(NULL_B32),
    false,
    true
  )]
  #[case(
    TestFilterPuzzle::Writer,
    Bytes32::from(NULL_B32),
    Bytes32::from(FULL_B32),
    false,
    true
  )]
  #[case(
    TestFilterPuzzle::Writer,
    Bytes32::from(FULL_B32),
    Bytes32::from(NULL_B32),
    false,
    true
  )]
  #[case(
    TestFilterPuzzle::Writer,
    Bytes32::from(FULL_B32),
    Bytes32::from(FULL_B32),
    false,
    true
  )]
  // valid metadata update - should not fail
  #[case(
    TestFilterPuzzle::Admin,
    Bytes32::from(NULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    false,
    false
  )]
  #[case(
    TestFilterPuzzle::Writer,
    Bytes32::from(FULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    false,
    false
  )]
  #[case(
    TestFilterPuzzle::Admin,
    Bytes32::from(NULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    false,
    false
  )]
  #[case(
    TestFilterPuzzle::Writer,
    Bytes32::from(FULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    false,
    false
  )]
  // should fail because output conditions are not empty
  #[case(
    TestFilterPuzzle::Admin,
    Bytes32::from(NULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    true,
    true
  )]
  #[case(
    TestFilterPuzzle::Writer,
    Bytes32::from(FULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    true,
    true
  )]
  #[case(
    TestFilterPuzzle::Admin,
    Bytes32::from(NULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    true,
    true
  )]
  #[case(
    TestFilterPuzzle::Writer,
    Bytes32::from(FULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    true,
    true
  )]
  fn test_metadata_filter(
    #[case] filter_puzzle: TestFilterPuzzle,
    #[case] new_metadata: Bytes32,
    #[case] new_updater_ph: Bytes32,
    #[case] output_conditions: bool,
    #[case] should_error_out: bool,
  ) -> Result<(), ()> {
    let mut ctx = SpendContext::new();

    let cond = NewMetadataCondition {
      metadata_updater_reveal: 11,
      metadata_updater_solution: DefaultMetadataSolution {
        metadata_part: DefaultMetadataSolutionMetadataList {
          new_metadata: new_metadata,
          new_metadata_updater_ph: new_updater_ph,
        },
        conditions: if output_conditions {
          vec![CreateCoin {
            puzzle_hash: [0; 32].into(),
            amount: 1,
            memos: vec![],
          }]
        } else {
          vec![]
        },
      },
    };
    let inner_puzzle = clvm_quote!(vec![cond.to_clvm(ctx.allocator_mut()).unwrap(),])
      .to_clvm(ctx.allocator_mut())
      .unwrap();

    let filter_puzzle_ptr =
      get_filter_puzzle_ptr(ctx.allocator_mut(), &filter_puzzle, inner_puzzle).unwrap();

    let solution_ptr = vec![ctx.allocator().nil()]
      .to_clvm(ctx.allocator_mut())
      .unwrap();

    match ctx.run(filter_puzzle_ptr, solution_ptr) {
      Ok(_) => {
        if should_error_out {
          Err(())
        } else {
          Ok(())
        }
      }
      Err(err) => match err {
        SpendError::Eval(eval_err) => {
          if should_error_out {
            if output_conditions {
              assert_eq!(eval_err.1, "= on list");
            } else {
              assert_eq!(eval_err.1, "clvm raise");
            }
            Ok(())
          } else {
            Err(())
          }
        }
        _ => Err(()),
      },
    }
  }

  #[rstest]
  #[case(TestFilterPuzzle::Admin, Bytes32::from(NULL_B32))]
  #[case(TestFilterPuzzle::Admin, Bytes32::from(FULL_B32))]
  #[case(TestFilterPuzzle::Writer, Bytes32::from(NULL_B32))]
  #[case(TestFilterPuzzle::Writer, Bytes32::from(FULL_B32))]
  fn test_melt_filter(
    #[case] filter_puzzle: TestFilterPuzzle,
    #[case] puzzle_hash: Bytes32,
  ) -> Result<(), ()> {
    let mut ctx = SpendContext::new();

    let inner_puzzle = clvm_quote!(vec![MeltCondition {
      fake_puzzle_hash: puzzle_hash
    }
    .to_clvm(ctx.allocator_mut())
    .unwrap(),])
    .to_clvm(ctx.allocator_mut())
    .unwrap();

    let filter_puzzle_ptr =
      get_filter_puzzle_ptr(ctx.allocator_mut(), &filter_puzzle, inner_puzzle).unwrap();

    let solution_ptr = vec![ctx.allocator().nil()]
      .to_clvm(ctx.allocator_mut())
      .unwrap();

    match ctx.run(filter_puzzle_ptr, solution_ptr) {
      Ok(_) => Err(()),
      Err(err) => match err {
        SpendError::Eval(eval_err) => {
          assert_eq!(eval_err.1, "clvm raise");
          Ok(())
        }
        _ => Err(()),
      },
    }
  }
}
