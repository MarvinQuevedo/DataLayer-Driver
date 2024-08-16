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
  pub launcher_id: Bytes32,
  pub inner_puzzle_hash: Bytes32,
  pub merkle_root: Bytes32,
}

impl DelegationLayerArgs {
  pub fn new(launcher_id: Bytes32, inner_puzzle_hash: Bytes32, merkle_root: Bytes32) -> Self {
    Self {
      mod_hash: DELEGATION_LAYER_PUZZLE_HASH.into(),
      launcher_id,
      inner_puzzle_hash,
      merkle_root,
    }
  }
}

impl DelegationLayerArgs {
  pub fn curry_tree_hash(
    launcher_id: Bytes32,
    inner_puzzle_hash: Bytes32,
    merkle_root: Bytes32,
  ) -> TreeHash {
    CurriedProgram {
      program: DELEGATION_LAYER_PUZZLE_HASH,
      args: DelegationLayerArgs {
        mod_hash: DELEGATION_LAYER_PUZZLE_HASH.into(),
        launcher_id,
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

pub const DELEGATION_LAYER_PUZZLE: [u8; 1021] = hex!(
  "
    ff02ffff01ff02ff12ffff04ff02ffff04ff05ffff04ff0bffff04ff17ffff04ff2fffff04ff5fff
    ff04ffff02ff81bfff82017f80ffff04ffff02ff16ffff04ff02ffff04ff81bfff80808080ff8080
    8080808080808080ffff04ffff01ffffff3381f3ff02ffffa04bf5122f344554c53bde2ebb8cd2b7
    e3d1600ad631c385a5d7cce23c7785459aa09dcf97a184f32623d11a73124ceb99a5709b083721e8
    78a16d78f596718ba7b2ffa102a12871fee210fb8619291eaea194581cbd2531e4b23759d225f680
    6923f63222a102a8d5dd63fba471ebcb1f3e8f7c1e1879b7152a6e7298a91ce119a63400ade7c5ff
    ffff02ffff03ffff09ff82017fff1780ffff0181bfffff01ff02ffff03ffff09ff2fffff02ff1eff
    ff04ff02ffff04ffff0bffff0101ff82017f80ffff04ff5fff808080808080ffff01ff02ff1affff
    04ff02ffff04ff05ffff04ff0bffff04ff17ffff04ff81bfffff04ffff04ff2fffff04ff0bff8080
    80ff8080808080808080ffff01ff088080ff018080ff0180ff02ffff03ff2fffff01ff02ffff03ff
    ff09ff818fff1880ffff01ff02ff1affff04ff02ffff04ff05ffff04ff17ffff04ff6fffff04ff81
    cfff80808080808080ffff01ff04ffff02ffff03ffff02ffff03ffff09ff818fffff0181e880ffff
    01ff22ffff09ff820acfff8080ffff09ff8214cfffff01a057bfd1cb0adda3d94315053fda723f20
    28320faa8338225d99f629e3d46d43a98080ffff01ff010180ff0180ffff014fffff01ff088080ff
    0180ffff02ff1affff04ff02ffff04ff05ffff04ff0bffff04ff17ffff04ff6fffff04ff5fff8080
    8080808080808080ff0180ffff01ff04ffff04ff10ffff04ffff0bff5cffff0bff14ffff0bff14ff
    6cff0580ffff0bff14ffff0bff7cffff0bff14ffff0bff14ff6cffff0bffff0101ff058080ffff0b
    ff14ffff0bff7cffff0bff14ffff0bff14ff6cffff0bffff0101ff0b8080ffff0bff14ffff0bff7c
    ffff0bff14ffff0bff14ff6cffff0bffff0101ff178080ffff0bff14ffff0bff7cffff0bff14ffff
    0bff14ff6cffff0bffff0101ff819f8080ffff0bff14ff6cff4c808080ff4c808080ff4c808080ff
    4c808080ff4c808080ffff04ffff0101ffff04ff81dfff8080808080ff808080ff0180ffff02ffff
    03ffff07ff0580ffff01ff0bffff0102ffff02ff16ffff04ff02ffff04ff09ff80808080ffff02ff
    16ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff02ffff03ff1b
    ffff01ff02ff1effff04ff02ffff04ffff02ffff03ffff18ffff0101ff1380ffff01ff0bffff0102
    ff2bff0580ffff01ff0bffff0102ff05ff2b8080ff0180ffff04ffff04ffff17ff13ffff0181ff80
    ff3b80ff8080808080ffff010580ff0180ff018080
    "
);

pub const DELEGATION_LAYER_PUZZLE_HASH: TreeHash = TreeHash::new(hex!(
  "
    e5752c7e5f85b5ae5b7627a3fcb3eacfae9687fed36423f9f00023bd288a821f
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

pub const WRITER_FILTER_PUZZLE: [u8; 110] = hex!(
  "
    ff02ffff01ff02ff02ffff04ff02ffff04ffff02ff05ff0b80ff80808080ffff04ffff01ff02ffff
    03ff05ffff01ff02ffff03ffff09ff11ffff0181f380ffff01ff0880ffff01ff04ff09ffff02ff02
    ffff04ff02ffff04ff0dff808080808080ff0180ff8080ff0180ff018080
    "
);

pub const WRITER_FILTER_PUZZLE_HASH: TreeHash = TreeHash::new(hex!(
  "
    407f70ea751c25052708219ae148b45db2f61af2287da53d600b2486f12b3ca6
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
    DefaultMetadataSolution, DefaultMetadataSolutionMetadataList, MerkleTree, NewMetadataCondition,
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
  fn test_puzzle_hashes() {
    assert_puzzle_hash!(DELEGATION_LAYER_PUZZLE => DELEGATION_LAYER_PUZZLE_HASH);
    assert_puzzle_hash!(WRITER_FILTER_PUZZLE => WRITER_FILTER_PUZZLE_HASH);
    assert_puzzle_hash!(DL_METADATA_UPDATER_PUZZLE => DL_METADATA_UPDATER_PUZZLE_HASH);
  }

  enum TestPuzzle {
    Admin,
    Writer,
  }

  fn get_filter_puzzle_ptr(
    allocator: &mut Allocator,
    filter_puzzle: &TestPuzzle,
    inner_puzzle_ptr: NodePtr,
  ) -> Result<NodePtr, SpendError> {
    match filter_puzzle {
      TestPuzzle::Admin => Ok(inner_puzzle_ptr),
      TestPuzzle::Writer => CurriedProgram {
        program: node_from_bytes(allocator, &WRITER_FILTER_PUZZLE)
          .map_err(|err| SpendError::Io(err))?,
        args: WriterFilterArgs::new(inner_puzzle_ptr),
      }
      .to_clvm(allocator)
      .map_err(|err| SpendError::ToClvm(err)),
    }
  }

  #[rstest]
  #[case(hex!("80").to_vec())] // run -d '(mod () ())'
  #[case(hex!("01").to_vec())] // run -d '(mod solution solution)'
  #[case(STANDARD_PUZZLE.to_vec())]
  fn test_writer_filter_curry_tree_hash(#[case] inner_puzzle_bytes: Vec<u8>) -> Result<(), ()> {
    let allocator: &mut Allocator = &mut Allocator::new();
    let inner_puzzle_ptr = node_from_bytes(allocator, &inner_puzzle_bytes).unwrap();

    let full_puzzle_ptr =
      get_filter_puzzle_ptr(allocator, &TestPuzzle::Writer, inner_puzzle_ptr).unwrap();

    let full_puzzle_hash = tree_hash(allocator, full_puzzle_ptr);

    let inner_puzzle_hash: TreeHash = tree_hash(allocator, inner_puzzle_ptr);
    let curry_puzzle_hash = WriterFilterArgs::curry_tree_hash(inner_puzzle_hash);

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
  fn test_delegation_layer_curry_tree_hash() -> Result<(), ()> {
    let mut allocator = Allocator::new();

    let delegation_layer_mod_ptr =
      node_from_bytes(&mut allocator, &DELEGATION_LAYER_PUZZLE).unwrap();

    let inner_puzzle_hash = Bytes32::from([1; 32]);
    let merkle_root = Bytes32::from([2; 32]);
    let launcher_id = Bytes32::from([3; 32]);

    let full_puzzle = CurriedProgram {
      program: delegation_layer_mod_ptr,
      args: DelegationLayerArgs::new(launcher_id, inner_puzzle_hash, merkle_root),
    }
    .to_clvm(&mut allocator)
    .unwrap();
    let full_puzzle_hash = tree_hash(&allocator, full_puzzle);

    let curry_puzzle_hash =
      DelegationLayerArgs::curry_tree_hash(launcher_id, inner_puzzle_hash, merkle_root);

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
  fn test_dl_metadata_updater_puzzle(#[case] third_arg: Vec<u8>) -> Result<(), ()> {
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
  #[case(TestPuzzle::Admin, Bytes32::from(NULL_B32), vec![])]
  #[case(TestPuzzle::Admin, Bytes32::from(FULL_B32), vec![])]
  #[case(TestPuzzle::Admin, Bytes32::from(NULL_B32), vec![Bytes32::from(NULL_B32)])]
  #[case(TestPuzzle::Admin, Bytes32::from(FULL_B32), vec![Bytes32::from(NULL_B32)])]
  #[case(TestPuzzle::Admin, Bytes32::from(NULL_B32), vec![Bytes32::from(FULL_B32)])]
  #[case(TestPuzzle::Admin, Bytes32::from(FULL_B32), vec![Bytes32::from(FULL_B32)])]
  #[case(TestPuzzle::Writer, Bytes32::from(NULL_B32), vec![])]
  #[case(TestPuzzle::Writer, Bytes32::from(FULL_B32), vec![])]
  #[case(TestPuzzle::Writer, Bytes32::from(NULL_B32), vec![Bytes32::from(NULL_B32)])]
  #[case(TestPuzzle::Writer, Bytes32::from(FULL_B32), vec![Bytes32::from(NULL_B32)])]
  #[case(TestPuzzle::Writer, Bytes32::from(NULL_B32), vec![Bytes32::from(FULL_B32)])]
  #[case(TestPuzzle::Writer, Bytes32::from(FULL_B32), vec![Bytes32::from(FULL_B32)])]
  fn test_new_merkle_root_filter(
    #[case] test_puzzle: TestPuzzle,
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

    let test_puzzle_ptr =
      get_filter_puzzle_ptr(ctx.allocator_mut(), &test_puzzle, inner_puzzle).unwrap();

    let solution_ptr = vec![ctx.allocator().nil()]
      .to_clvm(ctx.allocator_mut())
      .unwrap();

    match ctx.run(test_puzzle_ptr, solution_ptr) {
      Ok(_) => match test_puzzle {
        TestPuzzle::Admin => Ok(()),
        TestPuzzle::Writer => Err(()),
      },
      Err(err) => match err {
        SpendError::Eval(eval_err) => match test_puzzle {
          TestPuzzle::Admin => Err(()),
          TestPuzzle::Writer => {
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
    TestPuzzle::Admin,
    Bytes32::from(NULL_B32),
    Bytes32::from(NULL_B32),
    false,
    true
  )]
  #[case(
    TestPuzzle::Admin,
    Bytes32::from(NULL_B32),
    Bytes32::from(FULL_B32),
    false,
    true
  )]
  #[case(
    TestPuzzle::Admin,
    Bytes32::from(FULL_B32),
    Bytes32::from(NULL_B32),
    false,
    true
  )]
  #[case(
    TestPuzzle::Admin,
    Bytes32::from(FULL_B32),
    Bytes32::from(FULL_B32),
    false,
    true
  )]
  #[case(
    TestPuzzle::Writer,
    Bytes32::from(NULL_B32),
    Bytes32::from(NULL_B32),
    false,
    true
  )]
  #[case(
    TestPuzzle::Writer,
    Bytes32::from(NULL_B32),
    Bytes32::from(FULL_B32),
    false,
    true
  )]
  #[case(
    TestPuzzle::Writer,
    Bytes32::from(FULL_B32),
    Bytes32::from(NULL_B32),
    false,
    true
  )]
  #[case(
    TestPuzzle::Writer,
    Bytes32::from(FULL_B32),
    Bytes32::from(FULL_B32),
    false,
    true
  )]
  // valid metadata update - should not fail
  #[case(
    TestPuzzle::Admin,
    Bytes32::from(NULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    false,
    false
  )]
  #[case(
    TestPuzzle::Writer,
    Bytes32::from(FULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    false,
    false
  )]
  #[case(
    TestPuzzle::Admin,
    Bytes32::from(NULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    false,
    false
  )]
  #[case(
    TestPuzzle::Writer,
    Bytes32::from(FULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    false,
    false
  )]
  // should fail because output conditions are not empty
  #[case(
    TestPuzzle::Admin,
    Bytes32::from(NULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    true,
    true
  )]
  #[case(
    TestPuzzle::Writer,
    Bytes32::from(FULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    true,
    true
  )]
  #[case(
    TestPuzzle::Admin,
    Bytes32::from(NULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    true,
    true
  )]
  #[case(
    TestPuzzle::Writer,
    Bytes32::from(FULL_B32),
    DL_METADATA_UPDATER_PUZZLE_HASH.into(),
    true,
    true
  )]
  fn test_metadata_filter(
    #[case] test_puzzle: TestPuzzle,
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

    let test_puzzle_ptr =
      get_filter_puzzle_ptr(ctx.allocator_mut(), &test_puzzle, inner_puzzle).unwrap();

    let test_puzzle_hash = ctx.tree_hash(test_puzzle_ptr);
    let merkle_tree = MerkleTree::new(&vec![test_puzzle_hash.into()]);

    let deleg_layer_puz = CurriedProgram {
      program: node_from_bytes(ctx.allocator_mut(), &DELEGATION_LAYER_PUZZLE).unwrap(),
      args: DelegationLayerArgs::new(
        Bytes32::default(),
        Bytes32::default(),
        merkle_tree.get_root(),
      ),
    }
    .to_clvm(ctx.allocator_mut())
    .unwrap();

    let test_puzzle_solution_ptr = vec![ctx.allocator().nil()]
      .to_clvm(ctx.allocator_mut())
      .unwrap();

    let deleg_layer_sol = DelegationLayerSolution {
      merkle_proof: merkle_tree.generate_proof(test_puzzle_hash.into()),
      puzzle_reveal: test_puzzle_ptr,
      puzzle_solution: test_puzzle_solution_ptr,
    }
    .to_clvm(ctx.allocator_mut())
    .unwrap();

    match ctx.run(deleg_layer_puz, deleg_layer_sol) {
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
}
