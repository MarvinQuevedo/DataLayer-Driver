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

pub const DELEGATION_LAYER_PUZZLE: [u8; 384] = hex!(
    "
    ff02ffff01ff02ffff03ff2fffff01ff02ffff03ffff09ff17ffff02ff06ffff04ff02ffff04ffff
0bffff0101ffff02ff04ffff04ff02ffff04ff5fff8080808080ffff04ff2fff808080808080ffff
01ff02ff5fff81bf80ffff01ff08ffff019070682070726f6f6620696e76616c69648080ff0180ff
ff01ff02ffff03ffff09ffff02ff04ffff04ff02ffff04ff5fff80808080ff0b80ffff01ff02ff5f
ff81bf80ffff01ff08ffff018a706820696e76616c69648080ff018080ff0180ffff04ffff01ffff
02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff04ffff04ff02ffff04ff09ff80808080ff
ff02ff04ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff02ffff
03ff1bffff01ff02ff06ffff04ff02ffff04ffff02ffff03ffff18ffff0101ff1380ffff01ff0bff
ff0102ff2bff0580ffff01ff0bffff0102ff05ff2b8080ff0180ffff04ffff04ffff17ff13ffff01
81ff80ff3b80ff8080808080ffff010580ff0180ff018080
    "
);

pub const DELEGATION_LAYER_PUZZLE_HASH: TreeHash = TreeHash::new(hex!(
    "
    fc6f7278d7dd11a0d82202a1223092aa8db89c1ecd177e973e721a8f22351c1e
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

#[derive(ToClvm, FromClvm)]
#[apply_constants]
#[derive(Debug, Clone, PartialEq, Eq)]
#[clvm(list)]
pub struct AdminFilterSolution<I> {
    pub inner_solution: I,
}

pub const ADMIN_FILTER_PUZZLE: [u8; 163] = hex!(
    "
    ff02ffff01ff02ff06ffff04ff02ffff04ffff02ff05ff0b80ff80808080ffff04ffff01ff33ff02
    ffff03ff05ffff01ff02ffff03ffff21ffff09ff11ff0480ffff09ff11ffff01818f80ffff02ffff
    03ffff09ff11ffff0181e880ffff01ff20ffff09ff820159ff808080ff8080ff018080ffff01ff08
    80ffff01ff04ff09ffff02ff06ffff04ff02ffff04ff0dff808080808080ff0180ff8080ff0180ff
    018080
    "
);

pub const ADMIN_FILTER_PUZZLE_HASH: TreeHash = TreeHash::new(hex!(
    "
    ae2d0ca2e3a95223f9e79937a903e3411d3024136fbc716d14e74f0c4661817b
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

#[derive(ToClvm, FromClvm)]
#[apply_constants]
#[derive(Debug, Clone, PartialEq, Eq)]
#[clvm(list)]
pub struct WriterFilterSolution<I> {
    pub inner_solution: I,
}

pub const WRITER_FILTER_PUZZLE: [u8; 174] = hex!(
    "
    ff02ffff01ff02ff06ffff04ff02ffff04ffff02ff05ff0b80ff80808080ffff04ffff01ff33ff02
    ffff03ff05ffff01ff02ffff03ffff21ffff09ff11ff0480ffff09ff11ffff01818f80ffff09ff11
    ffff0181f380ffff02ffff03ffff09ff11ffff0181e880ffff01ff20ffff09ff820159ff808080ff
    8080ff018080ffff01ff0880ffff01ff04ff09ffff02ff06ffff04ff02ffff04ff0dff8080808080
    80ff0180ff8080ff0180ff018080
    "
);

pub const WRITER_FILTER_PUZZLE_HASH: TreeHash = TreeHash::new(hex!(
    "
    a523826bfccfc93e88b69fcdda09431633c4605c4eacabb9d6dabc08d2eb02f0
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
}
