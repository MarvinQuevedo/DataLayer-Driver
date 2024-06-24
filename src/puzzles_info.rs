use chia::consensus::merkle_tree::MerkleSet;
use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend};
use chia_puzzles::{
    singleton::{LauncherSolution, SINGLETON_LAUNCHER_PUZZLE_HASH},
    EveProof, Proof,
};
use chia_sdk_driver::SpendContext;
use chia_sdk_parser::{CurriedPuzzle, ParseError, Puzzle};
use clvm_traits::{FromClvm, ToClvm, ToClvmError, ToNodePtr};
use clvm_utils::{tree_hash, CurriedProgram};
use clvmr::{reduction::EvalErr, Allocator, NodePtr};

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

#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct KeyValueListItem<T = NodePtr> {
    key: Bytes,
    #[clvm(rest)]
    value: Vec<T>,
}

pub type KeyValueList<T> = Vec<KeyValueListItem<T>>;

#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct Metadata<T = NodePtr> {
    #[clvm(rest)]
    pub items: Vec<T>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct DataStoreInfo {
    pub coin: Coin,
    // singleton layer
    pub launcher_id: Bytes32,
    pub proof: Proof,
    // NFT state layer
    pub metadata: Metadata,
    // inner puzzle (either p2 or delegation_layer + p2)
    pub owner_puzzle_hash: Bytes32,
    pub delegated_puzzles: Option<Vec<DelegatedPuzzle>>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[clvm(list)]
pub struct CreateCoinConditionWithMemos<T = NodePtr> {
    pub singleton_puzzle_hash: Bytes32,
    pub amount: u64,
    pub memos: T,
}

impl DataStoreInfo {
    pub fn build_datastore_info(
        allocator: &mut Allocator,
        coin: Coin,
        launcher_id: Bytes32,
        proof: Proof,
        metadata: Metadata,
        contents_hint: &Vec<NodePtr>,
    ) -> Result<DataStoreInfo, ParseError> {
        if contents_hint.len() < 1 {
            return Err(ParseError::MissingHint);
        }

        let owner_puzzle_hash =
            Bytes32::from_clvm(allocator, contents_hint[0]).map_err(|_| ParseError::MissingHint)?;

        let delegated_puzzles = if contents_hint.len() > 1 {
            let mut delegated_puzzles = Vec::new();

            for hint in contents_hint.iter().skip(1) {
                // let delegated_puzzle =
                //     DelegatedPuzzle::from_clvm(allocator, *hint).map_err(|_| {
                //         return ParseError::MissingHint;
                //     })?;

                // delegated_puzzles.push(delegated_puzzle);
                // todo

                return Err(ParseError::MissingHint);
            }

            Ok(Some(delegated_puzzles))
        } else {
            Ok(None)
        }
        .map_err(|_: ParseError| ParseError::MissingHint)?;

        Ok(DataStoreInfo {
            coin,
            launcher_id,
            proof,
            metadata,
            owner_puzzle_hash,
            delegated_puzzles,
        })
    }

    pub fn from_spend(
        allocator: &mut Allocator,
        cs: &CoinSpend,
    ) -> Result<DataStoreInfo, ParseError>
    where
        KeyValueList<NodePtr>: FromClvm<NodePtr>,
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

            let solution =
                LauncherSolution::<KeyValueList<NodePtr>>::from_clvm(allocator, solution_node_ptr)
                    .map_err(|_| ParseError::NonStandardLayer)?;

            let metadata_key: &Bytes = &Bytes::new("m".into()); // stands for 'metadata'
            let metadata_info: &KeyValueListItem = solution
                .key_value_list
                .iter()
                .find(|item| {
                    if item.key.eq(metadata_key) {
                        return true;
                    }

                    return false;
                })
                .ok_or(ParseError::MissingHint)?;

            let delegation_hint_key: &Bytes = &Bytes::new("h".into()); // stands for 'hint(s)'
            let delegation_layer_info: &KeyValueListItem = solution
                .key_value_list
                .iter()
                .find(|item| {
                    if item.key.eq(delegation_hint_key) {
                        return true;
                    }

                    return false;
                })
                .ok_or(ParseError::MissingHint)?;

            let metadata = Metadata::<NodePtr>::from_clvm(
                allocator,
                *metadata_info.value.first().ok_or(ParseError::MissingHint)?,
            )
            .map_err(|_| {
                return ParseError::MissingHint;
            })?;

            let launcher_id = cs.coin.coin_id();
            let new_coin = Coin {
                parent_coin_info: launcher_id,
                puzzle_hash: solution.singleton_puzzle_hash,
                amount: solution.amount,
            };

            let proof = Proof::Eve(EveProof {
                parent_coin_info: cs.coin.parent_coin_info,
                amount: cs.coin.amount,
            });

            return DataStoreInfo::build_datastore_info(
                allocator,
                new_coin,
                launcher_id,
                proof,
                metadata,
                &delegation_layer_info.value,
            );
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
