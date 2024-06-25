use chia::consensus::gen::opcodes::{CREATE_COIN, CREATE_PUZZLE_ANNOUNCEMENT};
use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend};
use chia_puzzles::{
    nft::{NftStateLayerArgs, NftStateLayerSolution, NFT_STATE_LAYER_PUZZLE_HASH},
    singleton::{LauncherSolution, SingletonSolution, SINGLETON_LAUNCHER_PUZZLE_HASH},
    EveProof, Proof,
};
use chia_sdk_parser::{run_puzzle, ParseError, Puzzle, SingletonPuzzle};
use chia_sdk_types::conditions::Condition;
use clvm_traits::apply_constants;
use clvm_traits::{FromClvm, ToClvm, ToClvmError, ToNodePtr};
use clvm_utils::{tree_hash, CurriedProgram, ToTreeHash, TreeHash};
use clvmr::{reduction::EvalErr, serde::node_from_bytes, Allocator, NodePtr};

use crate::{
    AdminFilterArgs, DelegationLayerArgs, DelegationLayerSolution, MerkleTree, WriterFilterArgs,
    ADMIN_FILTER_PUZZLE, ADMIN_FILTER_PUZZLE_HASH, DELEGATION_LAYER_PUZZLE_HASH,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct DefaultMetadataSolutionMetadataList<M = Metadata<NodePtr>, T = NodePtr> {
    pub new_metadata: M,
    pub new_metadata_updater_ph: Option<T>, // 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct DefaultMetadataSolution<M = Metadata<NodePtr>, T = NodePtr, C = NodePtr> {
    pub metadata_part: DefaultMetadataSolutionMetadataList<M, T>,
    pub conditions: C, // usually ()
}

#[derive(ToClvm, FromClvm)]
#[apply_constants]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[clvm(list)]
pub struct NewMetadataCondition<P = NodePtr, M = Metadata<NodePtr>, T = NodePtr, C = NodePtr> {
    #[clvm(constant = -24)]
    pub opcode: i32,
    pub metadata_updater_reveal: P,
    pub metadata_updater_solution: DefaultMetadataSolution<M, T, C>,
}

impl DelegatedPuzzle {
    pub fn admin_layer_full_puzzle(
        allocator: &mut Allocator,
        inner_puzzle: NodePtr,
    ) -> Result<NodePtr, ToClvmError> {
        let curried_prog = CurriedProgram {
            program: node_from_bytes(allocator, &ADMIN_FILTER_PUZZLE)
                .map_err(|_| ToClvmError::Custom(String::from("could not load puzzle")))?,
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
            args: AdminFilterArgs {
                inner_puzzle: inner_puzzle_hash,
            },
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
            program: node_from_bytes(allocator, &WRITER_FILTER_PUZZLE)
                .map_err(|_| ToClvmError::Custom(String::from("could not load puzzle")))?,
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
            args: WriterFilterArgs {
                inner_puzzle: inner_puzzle_hash,
            },
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

                let inner_puzzle_hash: TreeHash =
                    Bytes32::from_clvm(allocator, hint.puzzle_info[0])
                        .map_err(|_| ParseError::MissingHint)?
                        .into();

                let full_puzzle_hash = CurriedProgram {
                    program: ADMIN_FILTER_PUZZLE_HASH,
                    args: AdminFilterArgs {
                        inner_puzzle: inner_puzzle_hash,
                    },
                }
                .tree_hash();

                Ok(DelegatedPuzzle {
                    puzzle_hash: full_puzzle_hash.into(),
                    puzzle_info: DelegatedPuzzleInfo::Admin(inner_puzzle_hash.into()),
                    full_puzzle: None,
                })
            }
            HintType::WriterPuzzle => {
                if hint.puzzle_info.len() != 1 {
                    return Err(ParseError::MissingHint);
                }

                let inner_puzzle_hash: TreeHash =
                    Bytes32::from_clvm(allocator, hint.puzzle_info[0])
                        .map_err(|_| ParseError::MissingHint)?
                        .into();

                let full_puzzle_hash = CurriedProgram {
                    program: WRITER_FILTER_PUZZLE_HASH,
                    args: WriterFilterArgs {
                        inner_puzzle: inner_puzzle_hash,
                    },
                }
                .tree_hash();

                Ok(DelegatedPuzzle {
                    puzzle_hash: full_puzzle_hash.into(),
                    puzzle_info: DelegatedPuzzleInfo::Writer(inner_puzzle_hash.into()),
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

#[derive(ToClvm, FromClvm)]
#[apply_constants]
#[derive(Debug, Clone, PartialEq, Eq)]
#[clvm(list)]
pub struct CreateCoinWithMemos<T = NodePtr>
where
    T: Eq,
{
    #[clvm(constant = 51)]
    pub opcode: u8,
    pub puzzle_hash: Bytes32,
    pub amount: u64,
    #[clvm(default)]
    pub memos: Vec<T>,
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

    // info from parent spend (prev_*) only used if
    // spend did not reveal anything from hints and
    // the delegation layer has no odd create coins
    pub fn from_spend(
        allocator: &mut Allocator,
        cs: &CoinSpend,
        prev_delegated_puzzles: Option<Vec<DelegatedPuzzle>>,
    ) -> Result<DataStoreInfo, ParseError>
    where
        KeyValueList<NodePtr>: FromClvm<NodePtr>,
    {
        println!("func start"); // todo: debug
        let Ok(solution_node_ptr) = cs.solution.to_node_ptr(allocator) else {
            println!("err 1"); // todo: debug
            return Err(ParseError::NonStandardLayer);
        };

        if cs.coin.puzzle_hash == SINGLETON_LAUNCHER_PUZZLE_HASH.into() {
            // we're just launching this singleton :)
            // solution is (singleton_full_puzzle_hash amount key_value_list)
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
            return match DataStoreInfo::build_datastore_info(
                allocator,
                new_coin,
                launcher_id,
                proof,
                metadata,
                &delegation_layer_info.value,
            ) {
                Ok(info) => Ok(info),
                Err(err) => Err(err),
            };
        }

        let Ok(puzzle_node_ptr) = cs.puzzle_reveal.to_node_ptr(allocator) else {
            println!("err 2"); // todo: debug
            return Err(ParseError::NonStandardLayer);
        };
        println!("got puzzle_node_ptr"); // todo: debug

        let full_puzzle = Puzzle::parse(allocator, puzzle_node_ptr);

        let singleton_puzzle = SingletonPuzzle::parse(allocator, &full_puzzle)?
            .ok_or_else(|| ParseError::NonStandardLayer)?;

        // parser for NFT state layer is bakend into NFT parser :(
        let state_layer_puzzle = singleton_puzzle
            .inner_puzzle
            .as_curried()
            .ok_or_else(|| ParseError::NonStandardLayer)?;

        if state_layer_puzzle.mod_hash != NFT_STATE_LAYER_PUZZLE_HASH {
            return Err(ParseError::NonStandardLayer);
        }

        let state_args =
            NftStateLayerArgs::<NodePtr, Metadata>::from_clvm(allocator, state_layer_puzzle.args)?;

        let solution = SingletonSolution::<NftStateLayerSolution<NodePtr>>::from_clvm(
            allocator,
            solution_node_ptr,
        )
        .map_err(|err| ParseError::FromClvm(err))?;

        let mut new_metadata = state_args.metadata;

        println!("running inner (state layer) puzzle...");
        // was the coin re-created with hints?
        // run inner state layer so we also catch -24 conditions
        let inner_inner_output = run_puzzle(
            allocator,
            state_args.inner_puzzle,
            solution.inner_solution.inner_solution,
        )
        .map_err(|_| ParseError::MismatchedOutput)?;
        println!("ran state layer's inner puzzle");
        let inner_inner_output_conditions =
            Vec::<NodePtr>::from_clvm(allocator, inner_inner_output)?;

        inner_inner_output_conditions.iter().for_each(|cond| {
            match NewMetadataCondition::<NodePtr, Metadata<NodePtr>, NodePtr, NodePtr>::from_clvm(
                allocator, *cond,
            ) {
                Ok(cond) => {
                    println!("new metadata condition found and processed!!!"); // todo: debug
                    new_metadata = cond.metadata_updater_solution.metadata_part.new_metadata;
                }
                _ => {}
            }
        });

        let odd_create_coin: Option<&NodePtr> =
            inner_inner_output_conditions.iter().find(
                |cond| match Condition::<NodePtr>::from_clvm(allocator, **cond) {
                    Ok(Condition::CreateCoin(create_coin)) => {
                        return create_coin.amount % 2 == 1;
                    }
                    _ => false,
                },
            );
        println!("odd_create_coin: {:?}", odd_create_coin); // todo: debug

        if odd_create_coin.is_some() {
            let odd_create_coin =
                CreateCoinWithMemos::<NodePtr>::from_clvm(allocator, *odd_create_coin.unwrap())
                    .map_err(|err| ParseError::FromClvm(err))?;

            println!("odd_create_coin build info"); // todo: debug
            if odd_create_coin.memos.len() >= 1 {
                return match DataStoreInfo::build_datastore_info(
                    allocator,
                    cs.coin.clone(),
                    singleton_puzzle.launcher_id,
                    Proof::Lineage(singleton_puzzle.lineage_proof(cs.coin)),
                    new_metadata,
                    &odd_create_coin.memos,
                ) {
                    Ok(info) => Ok(info),
                    Err(err) => Err(err),
                };
            }
        }

        let mut owner_puzzle_hash: Bytes32 = tree_hash(allocator, state_args.inner_puzzle).into();
        // does the coin currently have a delegation layer? if the inner puzzle did not return any odd CREATE_COINs, the layer will be re-created with the same options
        let delegation_layer_ptr = state_args.inner_puzzle;
        let delegation_layer_puzzle = Puzzle::parse(&allocator, delegation_layer_ptr);
        if delegation_layer_puzzle.is_curried()
            && delegation_layer_puzzle.mod_hash() == DELEGATION_LAYER_PUZZLE_HASH
        {
            println!("has deleg layer"); // todo: debug
            let delegation_layer_solution = solution.inner_solution.inner_solution;
            let delegation_layer_solution = DelegationLayerSolution::<NodePtr, NodePtr>::from_clvm(
                allocator,
                delegation_layer_solution,
            )
            .map_err(|err| ParseError::FromClvm(err))?;

            let output = run_puzzle(
                allocator,
                delegation_layer_solution.puzzle_reveal,
                delegation_layer_solution.puzzle_solution,
            )
            .map_err(|_| ParseError::MismatchedOutput)?;

            let odd_create_coin = Vec::<NodePtr>::from_clvm(allocator, output)?
                .iter()
                .map(|cond| Condition::<NodePtr>::from_clvm(allocator, *cond))
                .find(|cond| match cond {
                    Ok(Condition::CreateCoin(create_coin)) => create_coin.amount % 2 == 1,
                    _ => false,
                });

            println!("odd_create_coin: {:?}", odd_create_coin); // todo: debug
            if odd_create_coin.is_none() {
                println!("no odd create coin from deleg layer inner puzzle"); // todo: debug
                let deleg_puzzle_hash = DelegationLayerArgs::from_clvm(
                    allocator,
                    delegation_layer_puzzle.as_curried().unwrap().args,
                )
                .unwrap();

                return Ok(DataStoreInfo {
                    coin: cs.coin.clone(),
                    launcher_id: singleton_puzzle.launcher_id,
                    proof: Proof::Lineage(singleton_puzzle.lineage_proof(cs.coin)),
                    metadata: new_metadata,
                    owner_puzzle_hash: deleg_puzzle_hash.inner_puzzle_hash,
                    delegated_puzzles: prev_delegated_puzzles,
                }); // get most info from parent spend :)
            }

            let odd_create_coin = odd_create_coin
                .unwrap()
                .map_err(|err| ParseError::FromClvm(err))?;

            // if there were any memos, the if above would have caught it since it processes
            // output conditions
            // therefore, this spend is 'exiting' the delegation layer
            if let Condition::CreateCoin(create_coin) = odd_create_coin {
                owner_puzzle_hash = create_coin.puzzle_hash;
            }
        }

        // all methods exhausted; this coin doesn't seem to have a delegation layer
        Ok(DataStoreInfo {
            coin: cs.coin.clone(),
            launcher_id: singleton_puzzle.launcher_id,
            proof: Proof::Lineage(singleton_puzzle.lineage_proof(cs.coin)),
            metadata: new_metadata,
            owner_puzzle_hash: owner_puzzle_hash,
            delegated_puzzles: None,
        })
    }
}

pub fn merkle_tree_for_delegated_puzzles(delegated_puzzles: &Vec<DelegatedPuzzle>) -> MerkleTree {
    let leafs: Vec<Bytes32> = delegated_puzzles
        .iter()
        .map(|delegated_puzzle| -> Bytes32 { delegated_puzzle.puzzle_hash.into() })
        .collect();

    MerkleTree::new(&leafs)
}

pub fn merkle_root_for_delegated_puzzles(delegated_puzzles: &Vec<DelegatedPuzzle>) -> Bytes32 {
    merkle_tree_for_delegated_puzzles(&delegated_puzzles)
        .get_root()
        .into()
}
