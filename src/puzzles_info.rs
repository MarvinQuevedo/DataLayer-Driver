use chia::consensus::{
    gen::opcodes::{CREATE_COIN, CREATE_PUZZLE_ANNOUNCEMENT},
    merkle_tree::MerkleSet,
};
use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend};
use chia_puzzles::{
    singleton::{LauncherSolution, SINGLETON_LAUNCHER_PUZZLE_HASH},
    EveProof, Proof,
};
use chia_sdk_parser::{CurriedPuzzle, ParseError, Puzzle};
use clvm_traits::{FromClvm, ToClvm, ToClvmError, ToNodePtr};
use clvm_utils::{tree_hash, CurriedProgram, ToTreeHash, TreeHash};
use clvmr::{reduction::EvalErr, Allocator, NodePtr};

use crate::{
    AdminFilterArgs, WriterFilterArgs, ADMIN_FILTER_PUZZLE, ADMIN_FILTER_PUZZLE_HASH,
    WRITER_FILTER_PUZZLE, WRITER_FILTER_PUZZLE_HASH,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum DelegatedPuzzleInfo {
    Admin(Bytes32),
    Writer(Bytes32),
    Oracle(Bytes32, u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct DelegatedPuzzle {
    pub puzzle_hash: Bytes32,
    pub puzzle_info: DelegatedPuzzleInfo,
    pub full_puzzle: Option<NodePtr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[repr(u8)]
#[clvm(atom)]
pub enum HintType {
    AdminPuzzle = 0,
    WriterPuzzle = 1,
    OraclePuzzle = 2,
    // Add other variants as needed
}

#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct HintContents<T = NodePtr> {
    pub puzzle_type: HintType,
    #[clvm(rest)]
    pub puzzle_info: Vec<T>,
}

impl DelegatedPuzzle {
    pub fn admin_layer_full_puzzle(
        allocator: &mut Allocator,
        inner_puzzle: NodePtr,
    ) -> Result<NodePtr, ToClvmError> {
        let curried_prog = CurriedProgram {
            program: ADMIN_FILTER_PUZZLE,
            args: AdminFilterArgs { inner_puzzle },
        };

        let full_puzzle = curried_prog.to_clvm(allocator)?;
        Ok(full_puzzle)
    }

    pub fn from_admin_inner_puzzle(
        allocator: &mut Allocator,
        inner_puzzle: NodePtr,
    ) -> Result<Self, ToClvmError> {
        let inner_puzzle_hash: TreeHash = tree_hash(&allocator, inner_puzzle);
        let full_puzzle_hash = CurriedProgram {
            program: ADMIN_FILTER_PUZZLE_HASH,
            args: vec![inner_puzzle_hash],
        }
        .tree_hash();

        let full_puzzle = DelegatedPuzzle::admin_layer_full_puzzle(allocator, inner_puzzle)?;

        Ok(Self {
            puzzle_hash: full_puzzle_hash.into(),
            puzzle_info: DelegatedPuzzleInfo::Admin(inner_puzzle_hash.into()),
            full_puzzle: Some(full_puzzle),
        })
    }

    pub fn writer_layer_full_puzzle(
        allocator: &mut Allocator,
        inner_puzzle: NodePtr,
    ) -> Result<NodePtr, ToClvmError> {
        let curried_prog = CurriedProgram {
            program: WRITER_FILTER_PUZZLE,
            args: WriterFilterArgs { inner_puzzle },
        };

        let full_puzzle = curried_prog.to_clvm(allocator)?;
        Ok(full_puzzle)
    }

    pub fn from_writer_inner_puzzle(
        allocator: &mut Allocator,
        inner_puzzle: NodePtr,
    ) -> Result<Self, ToClvmError> {
        let inner_puzzle_hash: TreeHash = tree_hash(&allocator, inner_puzzle);
        let full_puzzle_hash = CurriedProgram {
            program: WRITER_FILTER_PUZZLE_HASH,
            args: vec![inner_puzzle_hash],
        }
        .tree_hash();

        let full_puzzle = DelegatedPuzzle::writer_layer_full_puzzle(allocator, inner_puzzle)?;

        Ok(Self {
            puzzle_hash: full_puzzle_hash.into(),
            puzzle_info: DelegatedPuzzleInfo::Writer(inner_puzzle_hash.into()),
            full_puzzle: Some(full_puzzle),
        })
    }

    pub fn oracle_layer_full_puzzle(
        allocator: &mut Allocator,
        oracle_puzzle_hash: Bytes32,
        oracle_fee: u64,
    ) -> Result<NodePtr, EvalErr> {
        // first condition: (list CREATE_COIN oracle_puzzle_hash oracle_fee)
        // second condition: (list CREATE_PUZZLE_ANNOUNCEMENT '$')

        let first_condition = {
            let create_coin = allocator.new_number(CREATE_COIN.into())?;
            let ph = allocator.new_atom(&oracle_puzzle_hash)?;
            let fee = allocator.new_number(oracle_fee.into())?;
            let nil = allocator.nil();
            let fee_nil = allocator.new_pair(fee, nil)?;
            let ph_fee_nil = allocator.new_pair(ph, fee_nil)?;

            allocator.new_pair(create_coin, ph_fee_nil)?
        };

        let second_condition = {
            let create_puzzle_ann = allocator.new_number(CREATE_PUZZLE_ANNOUNCEMENT.into())?;
            let ann = allocator.new_atom(&['$' as u8])?;
            let nil = allocator.nil();
            let ann_nil = allocator.new_pair(ann, nil)?;

            allocator.new_pair(create_puzzle_ann, ann_nil)?
        };

        let program = {
            let one = allocator.one();
            let first_second = allocator.new_pair(first_condition, second_condition)?;
            let nil = allocator.nil();

            let conditions = allocator.new_pair(first_second, nil)?;
            allocator.new_pair(one, conditions)?
        };

        Ok(program)
    }

    pub fn new_oracle(oracle_puzzle_hash: Bytes32, oracle_fee: u64) -> Result<Self, EvalErr> {
        let mut allocator = Allocator::new();

        let full_puzzle = DelegatedPuzzle::oracle_layer_full_puzzle(
            &mut allocator,
            oracle_puzzle_hash,
            oracle_fee,
        )?;

        Ok(Self {
            puzzle_hash: tree_hash(&allocator, full_puzzle).into(),
            puzzle_info: DelegatedPuzzleInfo::Oracle(oracle_puzzle_hash, oracle_fee),
            full_puzzle: Some(full_puzzle),
        })
    }

    pub fn from_hint(allocator: &mut Allocator, hint: &NodePtr) -> Result<Self, ParseError> {
        let hint = HintContents::<NodePtr>::from_clvm(allocator, *hint).map_err(|_| {
            return ParseError::NonStandardLayer;
        })?;

        match hint.puzzle_type {
            HintType::AdminPuzzle => {
                if hint.puzzle_info.len() != 1 {
                    return Err(ParseError::MissingHint);
                }

                let inner_puzzle_hash = Bytes32::from_clvm(allocator, hint.puzzle_info[0])
                    .map_err(|_| ParseError::MissingHint)?;

                let full_puzzle_hash = CurriedProgram {
                    program: ADMIN_FILTER_PUZZLE_HASH,
                    args: vec![inner_puzzle_hash],
                }
                .tree_hash();

                Ok(DelegatedPuzzle {
                    puzzle_hash: full_puzzle_hash.into(),
                    puzzle_info: DelegatedPuzzleInfo::Admin(inner_puzzle_hash),
                    full_puzzle: None,
                })
            }
            HintType::WriterPuzzle => {
                if hint.puzzle_info.len() != 1 {
                    return Err(ParseError::MissingHint);
                }

                let inner_puzzle_hash = Bytes32::from_clvm(allocator, hint.puzzle_info[0])
                    .map_err(|_| ParseError::MissingHint)?;

                let full_puzzle_hash = CurriedProgram {
                    program: WRITER_FILTER_PUZZLE_HASH,
                    args: vec![inner_puzzle_hash],
                }
                .tree_hash();

                Ok(DelegatedPuzzle {
                    puzzle_hash: full_puzzle_hash.into(),
                    puzzle_info: DelegatedPuzzleInfo::Writer(inner_puzzle_hash),
                    full_puzzle: None,
                })
            }
            HintType::OraclePuzzle => {
                if hint.puzzle_info.len() != 2 {
                    return Err(ParseError::MissingHint);
                }

                // bech32m_decode(oracle_address), not puzzle hash of the whole oracle puzze!
                let oracle_puzzle_hash = Bytes32::from_clvm(allocator, hint.puzzle_info[0])
                    .map_err(|_| ParseError::MissingHint)?;
                let oracle_fee = u64::from_clvm(allocator, hint.puzzle_info[1])
                    .map_err(|_| ParseError::MissingHint)?;

                let oracle_puzzle = DelegatedPuzzle::oracle_layer_full_puzzle(
                    allocator,
                    oracle_puzzle_hash,
                    oracle_fee,
                )
                .map_err(|_| ParseError::MissingHint)?;
                let full_puzzle_hash = tree_hash(allocator, oracle_puzzle);

                Ok(DelegatedPuzzle {
                    puzzle_hash: full_puzzle_hash.into(),
                    puzzle_info: DelegatedPuzzleInfo::Oracle(oracle_puzzle_hash, oracle_fee),
                    full_puzzle: Some(oracle_puzzle),
                })
            }
        }
    }

    pub fn get_full_puzzle(
        self: Self,
        allocator: &mut Allocator,
        inner_puzzle_reveal: Option<NodePtr>,
    ) -> Result<NodePtr, ToClvmError> {
        match self.full_puzzle {
            Some(full_puzzle) => return Ok(full_puzzle),
            None => {
                let full_puzzle = match self.puzzle_info {
                    DelegatedPuzzleInfo::Admin(_) => {
                        if let Some(inner_puzzle) = inner_puzzle_reveal {
                            Ok(DelegatedPuzzle::admin_layer_full_puzzle(
                                allocator,
                                inner_puzzle,
                            )?)
                        } else {
                            Err(ToClvmError::Custom(
                                "Missing inner puzzle reveal".to_string(),
                            ))
                        }
                    }
                    DelegatedPuzzleInfo::Writer(_) => {
                        if let Some(inner_puzzle) = inner_puzzle_reveal {
                            Ok(DelegatedPuzzle::writer_layer_full_puzzle(
                                allocator,
                                inner_puzzle,
                            )?)
                        } else {
                            Err(ToClvmError::Custom(
                                "Missing inner puzzle reveal".to_string(),
                            ))
                        }
                    }
                    DelegatedPuzzleInfo::Oracle(oracle_puzzle_hash, oracle_fee) => {
                        Ok(DelegatedPuzzle::oracle_layer_full_puzzle(
                            allocator,
                            oracle_puzzle_hash,
                            oracle_fee,
                        )
                        .map_err(|_| {
                            ToClvmError::Custom("Could not build oracle puzzle".to_string())
                        })?)
                    }
                }?;

                return Ok(full_puzzle);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct KeyValueListItem<T = NodePtr> {
    pub key: Bytes,
    #[clvm(rest)]
    pub value: Vec<T>,
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
pub enum HintKeys {
    MetadataReveal,
    DelegationLayerInfo,
}

impl HintKeys {
    pub fn value(&self) -> Bytes {
        match self {
            HintKeys::MetadataReveal => Bytes::new("m".into()), // stands for 'metadata'
            HintKeys::DelegationLayerInfo => Bytes::new("h".into()), // stands for 'hint(s)'
        }
    }
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
            let d_puzz = contents_hint
                .iter()
                .skip(1)
                .map(|hint| DelegatedPuzzle::from_hint(allocator, hint))
                .collect::<Result<_, _>>()?;

            Ok(Some(d_puzz))
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
        if cs.coin.puzzle_hash == SINGLETON_LAUNCHER_PUZZLE_HASH.into() {
            // we're just launching this singleton :)
            // solution is (singleton_full_puzzle_hash amount key_value_list)
            let Ok(solution_node_ptr) = cs.solution.to_node_ptr(allocator) else {
                println!("err 1"); // todo: debug
                return Err(ParseError::NonStandardLayer);
            };

            let solution =
                LauncherSolution::<KeyValueList<NodePtr>>::from_clvm(allocator, solution_node_ptr)
                    .map_err(|_| ParseError::NonStandardLayer)?;

            println!("parsing metadata info..."); // todo: debug
            let metadata_info: &KeyValueListItem = solution
                .key_value_list
                .iter()
                .find(|item| {
                    if item.key.eq(&HintKeys::MetadataReveal.value()) {
                        return true;
                    }

                    return false;
                })
                .ok_or(ParseError::MissingHint)?;

            println!("parsing delegation layer info..."); // todo: debug
            let delegation_layer_info: &KeyValueListItem = solution
                .key_value_list
                .iter()
                .find(|item| {
                    println!("key: {:?}", item.key); // todo: debug
                    if item.key.eq(&HintKeys::DelegationLayerInfo.value()) {
                        return true;
                    }

                    return false;
                })
                .ok_or(ParseError::MissingHint)?;

            println!("converting metadata..."); // todo: debug
            println!("metadata_info: {:?}", metadata_info); // todo: debug
            let metadata = Metadata::<NodePtr>::from_clvm(
                allocator,
                *metadata_info.value.get(0).ok_or(ParseError::MissingHint)?,
            )
            .map_err(|_| {
                println!("err 1023948"); // todo: debug
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

            println!("building datastore info..."); // todo: debug
            return DataStoreInfo::build_datastore_info(
                allocator,
                new_coin,
                launcher_id,
                proof,
                metadata,
                &delegation_layer_info.value,
            );
        }

        let Ok(puzzle_node_ptr) = cs.puzzle_reveal.to_node_ptr(allocator) else {
            println!("err 2"); // todo: debug
            return Err(ParseError::NonStandardLayer);
        };

        let puzzle = Puzzle::parse(allocator, puzzle_node_ptr);
        let Some(puzzle): Option<CurriedPuzzle> = puzzle.as_curried() else {
            println!("err 3"); // todo: debug
            return Err(ParseError::NonStandardLayer);
        };

        println!("err 4"); // todo: debug
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
