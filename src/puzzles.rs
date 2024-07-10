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

pub const DELEGATION_LAYER_PUZZLE: [u8; 904] = hex!(
  "
    ff02ffff01ff02ff12ffff04ff02ffff04ff05ffff04ff0bffff04ffff02ff5fff81bf80ffff04ff
    ff04ff17ff8080ffff04ffff02ff1effff04ff02ffff04ffff02ff1affff04ff02ffff04ff5fff80
    808080ffff04ff0bffff04ff17ffff04ff2fff80808080808080ff8080808080808080ffff04ffff
    01ffffff3381f3ff02ffffa04bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c
    7785459aa09dcf97a184f32623d11a73124ceb99a5709b083721e878a16d78f596718ba7b2ffa102
    a12871fee210fb8619291eaea194581cbd2531e4b23759d225f6806923f63222a102a8d5dd63fba4
    71ebcb1f3e8f7c1e1879b7152a6e7298a91ce119a63400ade7c5ffffff02ffff03ff17ffff01ff02
    ffff03ffff09ff47ff1880ffff01ff02ff12ffff04ff02ffff04ff05ffff04ff0bffff04ff37ffff
    04ff67ffff04ff5fff8080808080808080ffff01ff04ff27ffff02ff12ffff04ff02ffff04ff05ff
    ff04ff0bffff04ff37ffff04ff2fffff04ffff21ff5fffff02ffff03ffff09ff47ff1080ffff01ff
    09ffff18ff820167ffff010180ffff010180ff8080ff018080ff80808080808080808080ff0180ff
    ff01ff02ffff03ff5fff80ffff01ff04ffff04ff10ffff04ffff0bff5cffff0bff14ffff0bff14ff
    6cff0580ffff0bff14ffff0bff7cffff0bff14ffff0bff14ff6cffff0bffff0101ff058080ffff0b
    ff14ffff0bff7cffff0bff14ffff0bff14ff6cffff0bffff0101ff0b8080ffff0bff14ffff0bff7c
    ffff0bff14ffff0bff14ff6cffff0bffff0101ff4f8080ffff0bff14ff6cff4c808080ff4c808080
    ff4c808080ff4c808080ffff04ffff0101ffff04ff6fff8080808080ff808080ff018080ff0180ff
    02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff1affff04ff02ffff04ff09ff80808080ff
    ff02ff1affff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ffff02ff
    ff03ff1bffff01ff02ff16ffff04ff02ffff04ffff02ffff03ffff18ffff0101ff1380ffff01ff0b
    ffff0102ff2bff0580ffff01ff0bffff0102ff05ff2b8080ff0180ffff04ffff04ffff17ff13ffff
    0181ff80ff3b80ff8080808080ffff010580ff0180ff02ffff03ffff09ff05ff0b80ff80ffff01ff
    02ffff03ffff09ff17ffff02ff16ffff04ff02ffff04ffff0bffff0101ff0580ffff04ff2fff8080
    80808080ff80ffff01ff088080ff018080ff0180ff018080
    "
);

pub const DELEGATION_LAYER_PUZZLE_HASH: TreeHash = TreeHash::new(hex!(
  "
    b8285eb41ad8934a5d8651d14d5fb68916f0f1d91019d0a3e1a3b1ff8a65861e
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

pub const ADMIN_FILTER_PUZZLE: [u8; 200] = hex!(
  "
    ff02ffff01ff02ff06ffff04ff02ffff04ffff02ff05ff0b80ff80808080ffff04ffff01ff33ff02
    ffff03ff05ffff01ff02ffff03ffff21ffff09ff11ff0480ffff02ffff03ffff09ff11ffff0181e8
    80ffff01ff20ffff22ffff09ff820159ff8080ffff09ff820299ffff01a057bfd1cb0adda3d94315
    053fda723f2028320faa8338225d99f629e3d46d43a9808080ff8080ff018080ffff01ff0880ffff
    01ff04ff09ffff02ff06ffff04ff02ffff04ff0dff808080808080ff0180ff8080ff0180ff018080
    "
);

pub const ADMIN_FILTER_PUZZLE_HASH: TreeHash = TreeHash::new(hex!(
  "
    c8c657bbcb1af0b7ef7855cb35490ec703c034a2b085213c1463d2865a434ed1
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

pub const WRITER_FILTER_PUZZLE: [u8; 211] = hex!(
  "
    ff02ffff01ff02ff06ffff04ff02ffff04ffff02ff05ff0b80ff80808080ffff04ffff01ff33ff02
    ffff03ff05ffff01ff02ffff03ffff21ffff09ff11ff0480ffff09ff11ffff0181f380ffff02ffff
    03ffff09ff11ffff0181e880ffff01ff20ffff22ffff09ff820159ff8080ffff09ff820299ffff01
    a057bfd1cb0adda3d94315053fda723f2028320faa8338225d99f629e3d46d43a9808080ff8080ff
    018080ffff01ff0880ffff01ff04ff09ffff02ff06ffff04ff02ffff04ff0dff808080808080ff01
    80ff8080ff0180ff018080
    "
);

pub const WRITER_FILTER_PUZZLE_HASH: TreeHash = TreeHash::new(hex!(
  "
    a2418beeba739e93a139c895c58d813de0bab2a7dc27ee4fe73927b5a6690205
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

  #[rstest]
  #[case(Bytes32::from(hex!("0000000000000000000000000000000000000000000000000000000000000000")), Bytes32::from(hex!("0000000000000000000000000000000000000000000000000000000000000000")))]
  #[case(Bytes32::from(hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")), Bytes32::from(hex!("0000000000000000000000000000000000000000000000000000000000000000")))]
  #[case(Bytes32::from(hex!("0000000000000000000000000000000000000000000000000000000000000000")), Bytes32::from(hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")))]
  #[case(Bytes32::from(hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")), Bytes32::from(hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")))]
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
}
