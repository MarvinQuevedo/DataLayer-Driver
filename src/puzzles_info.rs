use chia::consensus::merkle_tree::MerkleSet;
use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend};
use chia_puzzles::{
    singleton::{LauncherSolution, SINGLETON_LAUNCHER_PUZZLE_HASH},
    Proof,
};
use chia_sdk_driver::SpendContext;
use chia_sdk_parser::{CurriedPuzzle, ParseError, Puzzle};
use clvm_traits::{match_list, FromClvm, ToClvm, ToClvmError, ToNodePtr};
use clvm_utils::{tree_hash, CurriedProgram};
use clvmr::{reduction::EvalErr, Allocator, NodePtr, SExp};

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
    pub fn new_admin(inner_puzzle: NodePtr) -> Result<Self, ToClvmError> {
        let mut allocator = Allocator::new();

        let curried_prog = CurriedProgram {
            program: ADMIN_FILTER_PUZZLE,
            args: AdminFilterArgs { inner_puzzle },
        };

        let full_puzzle = curried_prog.to_clvm(&mut allocator)?;

        Ok(Self {
            puzzle_hash: tree_hash(&allocator, full_puzzle).into(),
            puzzle_info: Some(DelegatedPuzzleInfo::Admin(inner_puzzle)),
        })
    }

    pub fn new_writer(inner_puzzle: NodePtr) -> Result<Self, ToClvmError> {
        let mut allocator = Allocator::new();

        let curried_prog = CurriedProgram {
            program: WRITER_FILTER_PUZZLE,
            args: WriterFilterArgs { inner_puzzle },
        };

        let full_puzzle = curried_prog.to_clvm(&mut allocator)?;

        Ok(Self {
            puzzle_hash: tree_hash(&allocator, full_puzzle).into(),
            puzzle_info: Some(DelegatedPuzzleInfo::Writer(inner_puzzle)),
        })
    }

    pub fn new_oracle(oracle_puzzle_hash: Bytes32, oracle_fee: u64) -> Result<Self, EvalErr> {
        let mut allocator = Allocator::new();

        let full_puzzle = get_oracle_puzzle(&mut allocator, &oracle_puzzle_hash, oracle_fee)?;

        Ok(Self {
            puzzle_hash: tree_hash(&allocator, full_puzzle).into(),
            puzzle_info: Some(DelegatedPuzzleInfo::Oracle(oracle_puzzle_hash, oracle_fee)),
        })
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[clvm(list)]
pub struct KeyValueList<T> {
    pub singleton_puzzle_hash: Bytes32,
    pub amount: u64,
    pub key_value_list: T,
}

#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct MetadataItem<T = NodePtr> {
    key: Bytes,
    #[clvm(rest)]
    value: Vec<T>,
}

pub type Metadata<T = NodePtr> = Vec<MetadataItem<T>>;

impl<M> DataStoreInfo<M> {
    pub fn from_spend(
        allocator: &mut Allocator,
        cs: &CoinSpend,
    ) -> Result<DataStoreInfo<M>, ParseError>
    where
        M: FromClvm<NodePtr>,
    {
        let Ok(puzzle_node_ptr) = cs.puzzle_reveal.to_node_ptr(allocator) else {
            return Err(ParseError::NonStandardLayer);
        };

        let puzzle = Puzzle::parse(allocator, puzzle_node_ptr);
        let Some(puzzle): Option<CurriedPuzzle> = puzzle.as_curried() else {
            return Err(ParseError::NonStandardLayer);
        };

        if puzzle.mod_hash == SINGLETON_LAUNCHER_PUZZLE_HASH {
            // we're just launching this singleton :)
            // solution is (singleton_full_puzzle_hash amount key_value_list)
            let Ok(solution_node_ptr) = cs.solution.to_node_ptr(allocator) else {
                return Err(ParseError::NonStandardLayer);
            };

            let solution = LauncherSolution::<Metadata>::from_clvm(allocator, solution_node_ptr)
                .map_err(|_| ParseError::NonStandardLayer)?;

            let hint_key = &Bytes::new("h".into()); // stands for 'hint(s)'
            solution.key_value_list.iter().for_each(|item| {
                if item.key.eq(hint_key) {
                    return;
                }

                // todo
            });

            return Err(ParseError::NonStandardLayer);
        }

        return Err(ParseError::NonStandardLayer);
    }
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
