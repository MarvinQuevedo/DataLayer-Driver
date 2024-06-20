use chia::consensus::merkle_tree::MerkleSet;
use chia_protocol::{Bytes32, Coin};
use chia_puzzles::Proof;
use chia_sdk_driver::SpendContext;
use clvm_traits::ToClvm;
use clvm_utils::CurriedProgram;
use clvmr::NodePtr;

use crate::{
    get_oracle_puzzle, AdminFilterArgs, WriterFilterArgs, ADMIN_FILTER_PUZZLE, WRITER_FILTER_PUZZLE,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum DelegatedPuzzleInfo {
    Admin(NodePtr),
    Writer(NodePtr),
    Oracle(Bytes32, u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct DelegatedPuzzle {
    pub puzzle_hash: Bytes32,
    pub puzzle_info: Option<DelegatedPuzzleInfo>,
}

impl DelegatedPuzzle {
    pub fn get_full_puzzle(&self, ctx: &mut SpendContext<'_>) -> Result<NodePtr, String> {
        match self.puzzle_info {
            Some(DelegatedPuzzleInfo::Admin(inner_puzzle)) => {
                let curried_prog = CurriedProgram {
                    program: ADMIN_FILTER_PUZZLE,
                    args: AdminFilterArgs { inner_puzzle },
                };

                match curried_prog.to_clvm(ctx.allocator_mut()) {
                    Ok(prog) => Ok(prog),
                    Err(_) => Err(String::from("Failed to curry admin filter puzzle")),
                }
            }
            Some(DelegatedPuzzleInfo::Writer(inner_puzzle)) => {
                let curried_prog = CurriedProgram {
                    program: WRITER_FILTER_PUZZLE,
                    args: WriterFilterArgs { inner_puzzle },
                };

                match curried_prog.to_clvm(ctx.allocator_mut()) {
                    Ok(prog) => Ok(prog),
                    Err(_) => Err(String::from("Failed to curry writer filter puzzle")),
                }
            }
            Some(DelegatedPuzzleInfo::Oracle(oracle_puzzle_hash, oracle_fee)) => {
                let oracle_puzzle_result =
                    get_oracle_puzzle(ctx.allocator_mut(), &oracle_puzzle_hash, oracle_fee);

                match oracle_puzzle_result {
                    Ok(oracle_puzzle) => Ok(oracle_puzzle),
                    Err(_) => Err(String::from("Failed to build oracle puzzle")),
                }
            }
            None => Err(String::from("Delegated puzzle info is missing")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct DataStoreInfo<M> {
    pub coin: Coin,
    // singleton layer
    pub launcher_id: Bytes32,
    pub proof: Proof,
    // NFT state layer
    pub metadata: M,
    // inner puzzle (either p2 or delegation_layer + p2)
    pub owner_puzzle_hash: Bytes32,
    pub delegated_puzzles: Option<Vec<DelegatedPuzzle>>,
}

pub fn merkle_set_for_delegated_puzzles(delegated_puzzles: &Vec<DelegatedPuzzle>) -> MerkleSet {
    let mut leafs: Vec<[u8; 32]> = delegated_puzzles
        .iter()
        .map(|delegated_puzzle| -> [u8; 32] { delegated_puzzle.puzzle_hash.into() })
        .collect();

    MerkleSet::from_leafs(&mut leafs)
}

pub fn merkle_root_for_delegated_puzzles(delegated_puzzles: &Vec<DelegatedPuzzle>) -> Bytes32 {
    merkle_set_for_delegated_puzzles(&delegated_puzzles)
        .get_root()
        .into()
}
