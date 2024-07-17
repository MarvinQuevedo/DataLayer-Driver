use chia::{bls::PublicKey, traits::Streamable};
use chia_protocol::{Bytes, Bytes32, Coin, CoinSpend, Program};
use chia_puzzles::{
  nft::{NftStateLayerArgs, NftStateLayerSolution, NFT_STATE_LAYER_PUZZLE_HASH},
  singleton::{LauncherSolution, SingletonArgs, SingletonSolution, SINGLETON_LAUNCHER_PUZZLE_HASH},
  standard::StandardArgs,
  EveProof, Proof,
};
use chia_sdk_driver::{SpendContext, SpendError};
use chia_sdk_parser::{ParseError, Puzzle, SingletonPuzzle};
use chia_sdk_types::conditions::{run_puzzle, Condition, CreateCoin, CreatePuzzleAnnouncement};
use clvm_traits::{
  apply_constants, clvm_quote, ClvmDecoder, ClvmEncoder, FromClvmError, FromNodePtr,
};
use clvm_traits::{FromClvm, ToClvm, ToClvmError, ToNodePtr};
use clvm_utils::{tree_hash, CurriedProgram, ToTreeHash, TreeHash};
use clvmr::{serde::node_from_bytes, Allocator, NodePtr};
use hex::encode;
use num_bigint::BigInt;

use crate::{
  AdminFilterArgs, DelegationLayerArgs, DelegationLayerSolution, MerkleTree, WriterFilterArgs,
  ADMIN_FILTER_PUZZLE, ADMIN_FILTER_PUZZLE_HASH, DELEGATION_LAYER_PUZZLE_HASH,
  DL_METADATA_UPDATER_PUZZLE_HASH, WRITER_FILTER_PUZZLE, WRITER_FILTER_PUZZLE_HASH,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum DelegatedPuzzleInfo {
  Admin(Bytes32),
  Writer(Bytes32),
  Oracle(Bytes32, u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[repr(u8)]
#[clvm(atom)]
pub enum HintType {
  // 0 skipped to prevent confusion with () which is also none (end of list)
  AdminPuzzle = 1,
  WriterPuzzle = 2,
  OraclePuzzle = 3,
}

impl HintType {
  pub fn value(&self) -> u8 {
    *self as u8
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct DefaultMetadataSolutionMetadataList<M = DataStoreMetadata, T = NodePtr> {
  pub new_metadata: M,
  pub new_metadata_updater_ph: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct DefaultMetadataSolution<M = DataStoreMetadata, T = NodePtr, C = NodePtr> {
  pub metadata_part: DefaultMetadataSolutionMetadataList<M, T>,
  pub conditions: C, // usually ()
}

#[derive(ToClvm, FromClvm)]
#[apply_constants]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[clvm(list)]
pub struct NewMetadataCondition<P = NodePtr, M = DataStoreMetadata, T = NodePtr, C = NodePtr> {
  #[clvm(constant = -24)]
  pub opcode: i32,
  pub metadata_updater_reveal: P,
  pub metadata_updater_solution: DefaultMetadataSolution<M, T, C>,
}

#[derive(ToClvm, FromClvm)]
#[apply_constants]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[clvm(list)]
pub struct MeltCondition {
  #[clvm(constant = 51)]
  pub opcode: u8,
  pub fake_puzzle_hash: Bytes32,
  #[clvm(constant = -113)]
  pub amount: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct DelegatedPuzzle {
  pub puzzle_hash: Bytes32,
  pub puzzle_info: DelegatedPuzzleInfo,
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

    Ok(Self {
      puzzle_hash: full_puzzle_hash.into(),
      puzzle_info: DelegatedPuzzleInfo::Admin(inner_puzzle_hash.into()),
    })
  }

  pub fn from_admin_pk(
    ctx: &mut SpendContext,
    synthetic_key: PublicKey,
  ) -> Result<(Self, NodePtr), SpendError> {
    let inner_puzzle_ptr: NodePtr = CurriedProgram {
      program: ctx.standard_puzzle()?,
      args: StandardArgs {
        synthetic_key: synthetic_key,
      },
    }
    .to_clvm(ctx.allocator_mut())
    .map_err(|err| SpendError::ToClvm(err))?;

    Ok((
      DelegatedPuzzle::from_admin_inner_puzzle(ctx.allocator_mut(), inner_puzzle_ptr)?,
      inner_puzzle_ptr,
    ))
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

    Ok(Self {
      puzzle_hash: full_puzzle_hash.into(),
      puzzle_info: DelegatedPuzzleInfo::Writer(inner_puzzle_hash.into()),
    })
  }

  pub fn from_writer_pk(
    ctx: &mut SpendContext,
    synthetic_key: PublicKey,
  ) -> Result<(Self, NodePtr), SpendError> {
    let inner_puzzle_ptr: NodePtr = CurriedProgram {
      program: ctx.standard_puzzle()?,
      args: StandardArgs {
        synthetic_key: synthetic_key,
      },
    }
    .to_clvm(ctx.allocator_mut())
    .map_err(|err| SpendError::ToClvm(err))?;

    Ok((
      DelegatedPuzzle::from_writer_inner_puzzle(ctx.allocator_mut(), inner_puzzle_ptr)?,
      inner_puzzle_ptr,
    ))
  }

  pub fn oracle_layer_full_puzzle(
    allocator: &mut Allocator,
    oracle_puzzle_hash: Bytes32,
    oracle_fee: u64,
  ) -> Result<NodePtr, ToClvmError> {
    // first condition: (list CREATE_COIN oracle_puzzle_hash oracle_fee)
    // second condition: (list CREATE_PUZZLE_ANNOUNCEMENT '$')

    clvm_quote!(vec![
      CreateCoin {
        puzzle_hash: oracle_puzzle_hash,
        amount: oracle_fee,
        memos: vec![],
      }
      .to_clvm(allocator)?,
      CreatePuzzleAnnouncement {
        message: Bytes::new("$".into()),
      }
      .to_clvm(allocator)?,
    ])
    .to_clvm(allocator)
  }

  pub fn new_oracle(
    allocator: &mut Allocator,
    oracle_puzzle_hash: Bytes32,
    oracle_fee: u64,
  ) -> Result<Self, ToClvmError> {
    let full_puzzle =
      DelegatedPuzzle::oracle_layer_full_puzzle(allocator, oracle_puzzle_hash, oracle_fee)?;

    if oracle_fee % 2 == 1 {
      return Err(ToClvmError::Custom("Oracle fee must be even".to_string()));
    }

    Ok(Self {
      puzzle_hash: tree_hash(&allocator, full_puzzle).into(),
      puzzle_info: DelegatedPuzzleInfo::Oracle(oracle_puzzle_hash, oracle_fee),
    })
  }

  pub fn from_hint(
    allocator: &mut Allocator,
    remaining_hints: &mut Vec<Bytes>,
  ) -> Result<Self, ParseError> {
    if remaining_hints.len() < 2 {
      return Err(ParseError::MissingHint);
    }

    let puzzle_type: u8 = BigInt::from_signed_bytes_be(&remaining_hints.drain(0..1).next().unwrap())
      .to_u32_digits()
      .1[0] as u8;

    // under current specs, first value will always be a puzzle hash
    let puzzle_hash: TreeHash = Bytes32::from_bytes(&remaining_hints.drain(0..1).next().unwrap())
      .map_err(|_| ParseError::MissingHint)?
      .into();

    if puzzle_type == HintType::AdminPuzzle.value() {
      let full_puzzle_hash = CurriedProgram {
        program: ADMIN_FILTER_PUZZLE_HASH,
        args: AdminFilterArgs {
          inner_puzzle: puzzle_hash,
        },
      }
      .tree_hash();

      return Ok(DelegatedPuzzle {
        puzzle_hash: full_puzzle_hash.into(),
        puzzle_info: DelegatedPuzzleInfo::Admin(puzzle_hash.into()),
      });
    } else if puzzle_type == HintType::WriterPuzzle.value() {
      let full_puzzle_hash = CurriedProgram {
        program: WRITER_FILTER_PUZZLE_HASH,
        args: WriterFilterArgs {
          inner_puzzle: puzzle_hash,
        },
      }
      .tree_hash();

      return Ok(DelegatedPuzzle {
        puzzle_hash: full_puzzle_hash.into(),
        puzzle_info: DelegatedPuzzleInfo::Writer(puzzle_hash.into()),
      });
    } else if puzzle_type == HintType::OraclePuzzle.value() {
      if remaining_hints.len() < 1 {
        return Err(ParseError::MissingHint);
      }

      // puzzle hash bech32m_decode(oracle_address), not puzzle hash of the whole oracle puzze!
      let oracle_fee: u64 =
        BigInt::from_signed_bytes_be(&remaining_hints.drain(0..1).next().unwrap())
          .to_u64_digits()
          .1[0];

      let oracle_puzzle =
        DelegatedPuzzle::oracle_layer_full_puzzle(allocator, puzzle_hash.into(), oracle_fee)
          .map_err(|_| ParseError::MissingHint)?;
      let full_puzzle_hash = tree_hash(allocator, oracle_puzzle);

      return Ok(DelegatedPuzzle {
        puzzle_hash: full_puzzle_hash.into(),
        puzzle_info: DelegatedPuzzleInfo::Oracle(puzzle_hash.into(), oracle_fee),
      });
    }

    Err(ParseError::MissingHint)
  }

  pub fn get_full_puzzle(
    self: Self,
    allocator: &mut Allocator,
    inner_puzzle_reveal: NodePtr,
  ) -> Result<NodePtr, ToClvmError> {
    let full_puzzle = match self.puzzle_info {
      DelegatedPuzzleInfo::Admin(_) => Ok(DelegatedPuzzle::admin_layer_full_puzzle(
        allocator,
        inner_puzzle_reveal,
      )?),
      DelegatedPuzzleInfo::Writer(_) => Ok(DelegatedPuzzle::writer_layer_full_puzzle(
        allocator,
        inner_puzzle_reveal,
      )?),
      DelegatedPuzzleInfo::Oracle(oracle_puzzle_hash, oracle_fee) => Ok(
        DelegatedPuzzle::oracle_layer_full_puzzle(allocator, oracle_puzzle_hash, oracle_fee)
          .map_err(|_| ToClvmError::Custom("Could not build oracle puzzle".to_string()))?,
      ),
    }?;

    return Ok(full_puzzle);
  }
}

#[derive(ToClvm, FromClvm, Debug, Clone, PartialEq, Eq)]
#[clvm(list)]
pub struct DLLauncherKVList<M = DataStoreMetadata, T = NodePtr> {
  pub metadata: M,
  pub state_layer_inner_puzzle_hash: Bytes32,
  #[clvm(rest)]
  pub memos: Vec<T>,
}

#[derive(ToClvm, FromClvm, Debug, Clone, PartialEq, Eq)]
#[clvm(list)]
pub struct OldDLLauncherKVList<T = NodePtr> {
  pub root_hash: Bytes32,
  pub state_layer_inner_puzzle_hash: Bytes32,
  #[clvm(rest)]
  pub memos: Vec<T>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct DataStoreMetadataRootHashOnly {
  pub root_hash: Bytes32,
}

#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct DataStoreMetadataWithLabelAndDescription {
  pub root_hash: Bytes32,
  pub label: String,
  pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataStoreMetadata {
  pub root_hash: Bytes32,
  pub label: String,
  pub description: String,
}

impl<N> ToClvm<N> for DataStoreMetadata {
  fn to_clvm(&self, encoder: &mut impl ClvmEncoder<Node = N>) -> Result<N, ToClvmError> {
    if self.label.len() > 0 || self.description.len() > 0 {
      DataStoreMetadataWithLabelAndDescription {
        root_hash: self.root_hash,
        label: self.label.clone(),
        description: self.description.clone(),
      }
      .to_clvm(encoder)
    } else {
      DataStoreMetadataRootHashOnly {
        root_hash: self.root_hash,
      }
      .to_clvm(encoder)
    }
  }
}

impl<N> FromClvm<N> for DataStoreMetadata
where
  N: Clone,
{
  fn from_clvm(decoder: &impl ClvmDecoder<Node = N>, node: N) -> Result<Self, FromClvmError>
  where
    N: Clone,
  {
    if let Ok(metadata) = DataStoreMetadataWithLabelAndDescription::from_clvm(decoder, node.clone())
    {
      return Ok(DataStoreMetadata {
        root_hash: metadata.root_hash,
        label: metadata.label,
        description: metadata.description,
      });
    }

    let metadata = DataStoreMetadataRootHashOnly::from_clvm(decoder, node)?;
    Ok(DataStoreMetadata {
      root_hash: metadata.root_hash,
      label: String::default(),
      description: String::default(),
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct DataStoreInfo {
  pub coin: Coin,
  // singleton layer
  pub launcher_id: Bytes32,
  pub proof: Proof,
  // NFT state layer
  pub metadata: DataStoreMetadata,
  // inner puzzle (either p2 or delegation_layer + p2)
  pub owner_puzzle_hash: Bytes32,
  pub delegated_puzzles: Vec<DelegatedPuzzle>, // if empty, there is no delegation layer
}

#[derive(ToClvm, FromClvm)]
#[apply_constants]
#[derive(Debug, Clone, PartialEq, Eq)]
#[clvm(list)]
pub struct NewMerkleRootCondition<M = NodePtr> {
  #[clvm(constant = -13)]
  pub opcode: i32,
  pub new_merkle_root: Bytes32,
  #[clvm(rest)]
  pub memos: Vec<M>,
}

impl DataStoreInfo {
  pub fn build_datastore_info(
    allocator: &mut Allocator,
    coin: Coin,
    launcher_id: Bytes32,
    proof: Proof,
    metadata: DataStoreMetadata,
    fallback_owner_ph: Bytes32,
    memos: &Vec<Bytes>,
  ) -> Result<DataStoreInfo, ParseError> {
    let mut memos = memos.clone();
    println!("memos clone: {:?}", memos); // todo: debug

    let owner_puzzle_hash: Bytes32 = if memos.len() < 1 {
      fallback_owner_ph
    } else {
      Bytes32::from_bytes(&memos.drain(0..1).next().unwrap())
        .map_err(|_| ParseError::MissingHint)?
    };

    let delegated_puzzles = {
      println!("moar memos: {:?}", memos); // todo: debug
      let mut d_puzz: Vec<DelegatedPuzzle> = vec![];

      while memos.len() > 1 {
        d_puzz.push(DelegatedPuzzle::from_hint(allocator, &mut memos)?);
      }

      Ok(d_puzz)
    }
    .map_err(|_: ParseError| ParseError::MissingHint)?;

    println!("returning datastore info :)"); //todo: debug
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
    prev_delegated_puzzles: &Vec<DelegatedPuzzle>,
  ) -> Result<DataStoreInfo, ParseError>
  where
    // DLLauncherKVList<NodePtr>: FromClvm<NodePtr>, // todo: debug
    NodePtr: ToClvm<NodePtr>,
    NftStateLayerArgs<TreeHash, TreeHash>: ToClvm<TreeHash> + ToTreeHash,
  {
    println!("func start"); // todo: debug
    let Ok(solution_node_ptr) = cs.solution.to_node_ptr(allocator) else {
      println!("err 1"); // todo: debug
      return Err(ParseError::NonStandardLayer);
    };

    if cs.coin.puzzle_hash == SINGLETON_LAUNCHER_PUZZLE_HASH.into() {
      // we're just launching this singleton :)
      // solution is (singleton_full_puzzle_hash amount key_value_list)
      // kv_list is (metadata state_layer_hash)
      let launcher_id = cs.coin.coin_id();

      let proof = Proof::Eve(EveProof {
        parent_coin_info: cs.coin.parent_coin_info,
        amount: cs.coin.amount,
      });

      println!("converting metadata..."); // todo: debug
      let solution = LauncherSolution::<DLLauncherKVList<DataStoreMetadata, Bytes>>::from_clvm(
        allocator,
        solution_node_ptr,
      );

      return match solution {
        Ok(solution) => {
          // store properly hinted
          let metadata = solution.key_value_list.metadata;
          println!("metadata: {:?}", metadata); // todo: debug

          let new_coin = Coin {
            parent_coin_info: launcher_id,
            puzzle_hash: solution.singleton_puzzle_hash,
            amount: solution.amount,
          };

          println!("building datastore info..."); // todo: debug
          println!("memos: {:?}", solution.key_value_list.memos); // todo: debug
          println!("calling build_datastore_info..."); // todo: debug
          match DataStoreInfo::build_datastore_info(
            allocator,
            new_coin,
            launcher_id,
            proof,
            metadata,
            solution.key_value_list.state_layer_inner_puzzle_hash,
            &solution.key_value_list.memos,
          ) {
            Ok(info) => Ok(info),
            Err(err) => Err(err),
          }
        }
        Err(err) => match err {
          FromClvmError::ExpectedPair => {
            println!("expected pair error; datastore might've been launched using old memo format"); // todo: debug
            let solution = LauncherSolution::<OldDLLauncherKVList<Bytes>>::from_clvm(
              allocator,
              solution_node_ptr,
            )?;

            let coin = Coin {
              parent_coin_info: launcher_id,
              puzzle_hash: solution.singleton_puzzle_hash,
              amount: solution.amount,
            };

            Ok(DataStoreInfo::build_datastore_info(
              allocator,
              coin,
              launcher_id,
              proof,
              DataStoreMetadata {
                root_hash: solution.key_value_list.root_hash,
                label: String::default(),
                description: String::default(),
              },
              solution.key_value_list.state_layer_inner_puzzle_hash,
              &solution.key_value_list.memos,
            )?)
          }
          _ => Err(ParseError::FromClvm(err)),
        },
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

    let state_args = NftStateLayerArgs::<NodePtr, DataStoreMetadata>::from_clvm(
      allocator,
      state_layer_puzzle.args,
    )?;

    let solution =
      SingletonSolution::<NftStateLayerSolution<NodePtr>>::from_clvm(allocator, solution_node_ptr)
        .map_err(|err| ParseError::FromClvm(err))?;

    let mut new_metadata = state_args.metadata;

    println!("running inner (state layer) puzzle...");
    // run inner state layer so we also catch -24 conditions
    let inner_inner_output = run_puzzle(
      allocator,
      state_args.inner_puzzle,
      solution.inner_solution.inner_solution,
    )
    .map_err(|err| {
      println!("{:?}", err); // todo: debug
      ParseError::MismatchedOutput
    })?;
    println!("ran state layer's inner puzzle");
    let inner_inner_output_conditions = Vec::<NodePtr>::from_clvm(allocator, inner_inner_output)?;

    inner_inner_output_conditions.iter().for_each(|cond| {
      match NewMetadataCondition::<NodePtr, DataStoreMetadata, NodePtr, NodePtr>::from_clvm(
        allocator, *cond,
      ) {
        Ok(cond) => {
          println!("new metadata condition found and processed!!!"); // todo: debug
          new_metadata = cond.metadata_updater_solution.metadata_part.new_metadata;
        }
        _ => {}
      }
    });
    println!("all ok now :)");

    println!(
      "inner_inner_output: {:?}",
      encode(
        Program::from_node_ptr(&allocator, inner_inner_output)
          .unwrap()
          .to_bytes()
          .unwrap()
      )
    ); // todo: debug
       // coin re-creation
    let odd_create_coin: Condition<NodePtr> = inner_inner_output_conditions
      .iter()
      .map(|cond| Condition::<NodePtr>::from_clvm(allocator, *cond))
      .find(|cond| match cond {
        Ok(Condition::CreateCoin(create_coin)) => create_coin.amount % 2 == 1,
        _ => false,
      })
      .ok_or(ParseError::MissingChild)??;
    println!("odd create coin found"); // todo: debug

    let Condition::CreateCoin(odd_create_coin) = odd_create_coin else {
      return Err(ParseError::MismatchedOutput);
    };
    println!("odd_create_coin: {:?}", odd_create_coin); // todo: debug

    let new_metadata_ptr = new_metadata
      .to_node_ptr(allocator)
      .map_err(|_| ParseError::NonStandardLayer)?;
    let new_metadata_hash = tree_hash(&allocator, new_metadata_ptr);
    let new_coin = Coin {
      parent_coin_info: cs.coin.coin_id(),
      puzzle_hash: SingletonArgs::curry_tree_hash(
        singleton_puzzle.launcher_id,
        CurriedProgram {
          program: NFT_STATE_LAYER_PUZZLE_HASH,
          args: NftStateLayerArgs::<TreeHash, TreeHash> {
            mod_hash: NFT_STATE_LAYER_PUZZLE_HASH.into(),
            metadata: new_metadata_hash,
            metadata_updater_puzzle_hash: DL_METADATA_UPDATER_PUZZLE_HASH.into(),
            inner_puzzle: odd_create_coin.puzzle_hash.into(),
          },
        }
        .tree_hash(),
      )
      .into(),
      amount: odd_create_coin.amount,
    };
    // was the coin re-created with hints?
    if odd_create_coin.memos.len() >= 1 {
      return match DataStoreInfo::build_datastore_info(
        allocator,
        new_coin,
        singleton_puzzle.launcher_id,
        Proof::Lineage(singleton_puzzle.lineage_proof(cs.coin)),
        new_metadata,
        tree_hash(&allocator, state_args.inner_puzzle).into(),
        &odd_create_coin.memos,
      ) {
        Ok(info) => Ok(info),
        Err(err) => Err(err),
      };
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
          coin: new_coin,
          launcher_id: singleton_puzzle.launcher_id,
          proof: Proof::Lineage(singleton_puzzle.lineage_proof(cs.coin)),
          metadata: new_metadata,
          owner_puzzle_hash: deleg_puzzle_hash.inner_puzzle_hash,
          delegated_puzzles: prev_delegated_puzzles.clone(),
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
      coin: new_coin,
      launcher_id: singleton_puzzle.launcher_id,
      proof: Proof::Lineage(singleton_puzzle.lineage_proof(cs.coin)),
      metadata: new_metadata,
      owner_puzzle_hash: owner_puzzle_hash,
      delegated_puzzles: vec![],
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

#[cfg(test)]
mod tests {
  use chia::bls::SecretKey;
  use chia_protocol::Bytes32;
  use chia_puzzles::standard::StandardArgs;
  use chia_sdk_driver::{spend_singleton, Conditions, Launcher, Spend, SpendContext};
  use chia_sdk_test::{test_transaction, Simulator};
  use rstest::rstest;

  use crate::{
    datastore_spend, get_memos, get_new_ownership_inner_condition,
    spend_nft_state_layer_custom_metadata_updated,
    tests::{secret_keys, Description, Hash, Label},
    DataStoreMintInfo, DatastoreInnerSpend, LauncherExt,
  };

  use super::*;

  #[rstest(
    meta_transition => [
      (
        (Hash::ZERO, Hash::ZERO, Hash::ZERO),
        (Label::EMPTY, Label::EMPTY, Label::EMPTY),
        (Description::EMPTY, Description::EMPTY, Description::EMPTY)
      ),
      (
        (Hash::ZERO, Hash::ZERO, Hash::SOME),
        (Label::EMPTY, Label::EMPTY, Label::SOME),
        (Description::EMPTY, Description::EMPTY, Description::SOME)
      ),
      (
        (Hash::ZERO, Hash::SOME, Hash::SOME),
        (Label::EMPTY, Label::SOME, Label::SOME),
        (Description::EMPTY, Description::SOME, Description::SOME)
      ),
      (
        (Hash::SOME, Hash::ZERO, Hash::ZERO),
        (Label::SOME, Label::EMPTY, Label::EMPTY),
        (Description::SOME, Description::EMPTY, Description::EMPTY)
      ),
      (
        (Hash::SOME, Hash::SOME, Hash::ZERO),
        (Label::SOME, Label::SOME, Label::EMPTY),
        (Description::SOME, Description::SOME, Description::EMPTY)
      ),
    ],
    src_with_writer => [true, false],
    src_with_oracle => [true, false],
    dst_with_admin => [true, false],
    dst_with_writer => [true, false],
    dst_with_oracle => [true, false],
  )]
  #[tokio::test]
  async fn test_datastore_admin_empty_root_transition(
    meta_transition: (
      (Hash, Hash, Hash),
      (Label, Label, Label),
      (Description, Description, Description),
    ),
    src_with_writer: bool,
    // src must have admin layer in this scenario
    // and dst does not have any layer
    src_with_oracle: bool,
    dst_with_admin: bool,
    dst_with_writer: bool,
    dst_with_oracle: bool,
  ) -> anyhow::Result<()> {
    let sim = Simulator::new().await?;
    let peer = sim.connect().await?;

    let [owner_sk, admin_sk, writer_sk]: [SecretKey; 3] =
      secret_keys(3).unwrap().try_into().unwrap();

    let owner_pk = owner_sk.public_key();
    let admin_pk = admin_sk.public_key();
    let writer_pk = writer_sk.public_key();

    let oracle_puzzle_hash: Bytes32 = [7; 32].into();
    let oracle_fee = 1000;

    let owner_puzzle_hash = StandardArgs::curry_tree_hash(owner_pk).into();
    let coin = sim.mint_coin(owner_puzzle_hash, 1).await;

    let ctx = &mut SpendContext::new();

    let (admin_delegated_puzzle, admin_inner_puzzle_reveal) =
      DelegatedPuzzle::from_admin_pk(ctx, admin_pk).unwrap();

    let (writer_delegated_puzzle, _) = DelegatedPuzzle::from_writer_pk(ctx, writer_pk).unwrap();

    let oracle_delegated_puzzle =
      DelegatedPuzzle::new_oracle(ctx.allocator_mut(), oracle_puzzle_hash, oracle_fee).unwrap();

    let mut src_delegated_puzzles: Vec<DelegatedPuzzle> = vec![];
    src_delegated_puzzles.push(admin_delegated_puzzle);
    if src_with_writer {
      src_delegated_puzzles.push(writer_delegated_puzzle);
    }
    if src_with_oracle {
      src_delegated_puzzles.push(oracle_delegated_puzzle);
    }

    let (launch_singleton, src_datastore_info) = Launcher::new(coin.coin_id(), 1).mint_datastore(
      ctx,
      DataStoreMintInfo {
        metadata: DataStoreMetadata {
          root_hash: meta_transition.0 .0.value(),
          label: meta_transition.1 .0.value(),
          description: meta_transition.2 .0.value(),
        },
        owner_puzzle_hash: owner_puzzle_hash.into(),
        delegated_puzzles: src_delegated_puzzles.clone(),
      },
    )?;

    ctx.spend_p2_coin(coin, owner_pk, launch_singleton)?;

    // admin: remove all delegated puzzles
    let new_merkle_root = merkle_root_for_delegated_puzzles(&vec![]);

    let new_merkle_root_condition = NewMerkleRootCondition {
      new_merkle_root,
      memos: get_memos(owner_puzzle_hash.into(), vec![].clone()),
    }
    .to_clvm(ctx.allocator_mut())
    .unwrap();

    let mut admin_inner_spend =
      Conditions::new().condition(Condition::Other(new_merkle_root_condition));

    if meta_transition.0 .0 != meta_transition.0 .1
      || meta_transition.1 .0 != meta_transition.1 .1
      || meta_transition.2 .0 != meta_transition.2 .1
    {
      let new_metadata = DataStoreMetadata {
        root_hash: meta_transition.0 .1.value(),
        label: meta_transition.1 .1.value(),
        description: meta_transition.2 .1.value(),
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

      admin_inner_spend = admin_inner_spend.condition(Condition::Other(new_metadata_condition));
    }

    // delegated puzzle info + inner spend
    let inner_datastore_spend = DatastoreInnerSpend::DelegatedPuzzleSpend(
      admin_delegated_puzzle,
      Spend::new(
        admin_inner_puzzle_reveal,
        admin_inner_spend.p2_spend(ctx, admin_pk)?.solution(),
      ),
    );
    let new_spend = datastore_spend(ctx, &src_datastore_info, inner_datastore_spend)?;

    ctx.insert_coin_spend(new_spend.clone());

    let dst_datastore_info = DataStoreInfo::from_spend(
      ctx.allocator_mut(),
      &new_spend,
      &src_datastore_info.delegated_puzzles,
    )
    .unwrap();

    assert!(dst_datastore_info.delegated_puzzles.is_empty());
    assert_eq!(
      dst_datastore_info.metadata.root_hash,
      meta_transition.0 .1.value()
    );
    assert_eq!(
      dst_datastore_info.metadata.label,
      meta_transition.1 .1.value()
    );
    assert_eq!(
      dst_datastore_info.metadata.description,
      meta_transition.2 .1.value()
    );

    // admin left store with []; owner should now re-create the store
    let src_datastore_info = dst_datastore_info;

    let mut dst_delegated_puzzles: Vec<DelegatedPuzzle> = vec![];
    if dst_with_admin {
      dst_delegated_puzzles.push(admin_delegated_puzzle);
    }
    if dst_with_writer {
      dst_delegated_puzzles.push(writer_delegated_puzzle);
    }
    if dst_with_oracle {
      dst_delegated_puzzles.push(oracle_delegated_puzzle);
    }

    let mut owner_output_conds = Conditions::new().condition(get_new_ownership_inner_condition(
      &src_datastore_info.owner_puzzle_hash,
      &dst_delegated_puzzles,
    ));

    if meta_transition.0 .1 != meta_transition.0 .2
      || meta_transition.1 .1 != meta_transition.1 .2
      || meta_transition.2 .1 != meta_transition.2 .2
    {
      let new_metadata = DataStoreMetadata {
        root_hash: meta_transition.0 .2.value(),
        label: meta_transition.1 .2.value(),
        description: meta_transition.2 .2.value(),
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

      owner_output_conds = owner_output_conds.condition(Condition::Other(new_metadata_condition));
    }

    let inner_datastore_spend =
      DatastoreInnerSpend::OwnerPuzzleSpend(owner_output_conds.p2_spend(ctx, owner_pk)?);
    let new_spend = datastore_spend(ctx, &src_datastore_info, inner_datastore_spend)?;
    ctx.insert_coin_spend(new_spend.clone());

    let dst_datastore_info = DataStoreInfo::from_spend(
      ctx.allocator_mut(),
      &new_spend,
      &src_datastore_info.delegated_puzzles,
    )
    .unwrap();

    assert_eq!(
      dst_datastore_info.delegated_puzzles.len(),
      dst_delegated_puzzles.len()
    );
    assert_eq!(dst_datastore_info.delegated_puzzles, dst_delegated_puzzles);
    assert_eq!(
      dst_datastore_info.metadata.root_hash,
      meta_transition.0 .2.value()
    );
    assert_eq!(
      dst_datastore_info.metadata.label,
      meta_transition.1 .2.value()
    );
    assert_eq!(
      dst_datastore_info.metadata.description,
      meta_transition.2 .2.value()
    );

    test_transaction(
      &peer,
      ctx.take_spends(),
      &[owner_sk, admin_sk, writer_sk],
      sim.config().genesis_challenge,
    )
    .await;

    let src_coin_state = sim
      .coin_state(src_datastore_info.coin.coin_id())
      .await
      .expect("expected datastore coin");
    assert_eq!(src_coin_state.coin, src_datastore_info.coin);
    assert!(src_coin_state.spent_height.is_some());
    let dst_coin_state = sim
      .coin_state(dst_datastore_info.coin.coin_id())
      .await
      .expect("expected datastore coin");
    assert_eq!(dst_coin_state.coin, dst_datastore_info.coin);
    assert!(dst_coin_state.created_height.is_some());

    Ok(())
  }

  #[rstest(
    transition => [
      (Hash::ZERO, Hash::ZERO, true),
      (Hash::ZERO, Hash::SOME, false),
      (Hash::ZERO, Hash::SOME, true),
      (Hash::SOME, Hash::SOME, true),
      (Hash::SOME, Hash::ZERO, false),
      (Hash::SOME, Hash::ZERO, true),
    ]
  )]
  #[tokio::test]
  async fn test_old_memo_format(transition: (Hash, Hash, bool)) -> anyhow::Result<()> {
    let sim = Simulator::new().await?;
    let peer = sim.connect().await?;

    let [owner_sk, owner2_sk]: [SecretKey; 2] = secret_keys(2).unwrap().try_into().unwrap();

    let owner_pk = owner_sk.public_key();
    let owner2_pk = owner2_sk.public_key();

    let owner_puzzle_hash = StandardArgs::curry_tree_hash(owner_pk);
    let coin = sim.mint_coin(owner_puzzle_hash.into(), 1).await;

    let owner2_puzzle_hash = StandardArgs::curry_tree_hash(owner2_pk);

    let ctx = &mut SpendContext::new();

    // todo: launch using old memos scheme
    let launcher = Launcher::new(coin.coin_id(), 1);
    let inner_puzzle_hash: TreeHash = owner_puzzle_hash.clone();

    let first_root_hash: Hash = transition.0;
    let metadata_ptr = ctx.alloc(&vec![first_root_hash.value()])?;
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

    // https://github.com/Chia-Network/chia-blockchain/blob/4ffb6dfa6f53f6cd1920bcc775e27377a771fbec/chia/wallet/db_wallet/db_wallet_puzzles.py#L59
    // kv_list = 'memos': (root_hash inner_puzzle_hash)
    let kv_list = vec![first_root_hash.value(), owner_puzzle_hash.into()];

    let launcher_coin = launcher.coin();
    let (launcher_conds, eve_coin) = launcher.spend(ctx, state_layer_hash.into(), kv_list)?;

    ctx.spend_p2_coin(coin, owner_pk, launcher_conds)?;

    let spends = ctx.take_spends();
    spends
      .clone()
      .into_iter()
      .for_each(|spend| ctx.insert_coin_spend(spend));

    let info_from_launcher = spends
      .into_iter()
      .find(|spend| spend.coin.coin_id() == eve_coin.parent_coin_info)
      .map(|spend| {
        DataStoreInfo::from_spend(ctx.allocator_mut(), &spend, &vec![])
          .expect("Could not get info from launcher spend")
      })
      .expect("expected launcher spend");

    assert_eq!(
      info_from_launcher.metadata.root_hash,
      first_root_hash.value()
    );
    assert_eq!(info_from_launcher.metadata.label, Label::EMPTY.value());
    assert_eq!(
      info_from_launcher.metadata.description,
      Description::EMPTY.value()
    );

    assert_eq!(
      info_from_launcher.owner_puzzle_hash,
      owner_puzzle_hash.into()
    );
    assert!(info_from_launcher.delegated_puzzles.is_empty());

    assert_eq!(info_from_launcher.launcher_id, eve_coin.parent_coin_info);
    assert_eq!(info_from_launcher.coin.coin_id(), eve_coin.coin_id());

    match info_from_launcher.proof {
      Proof::Eve(proof) => {
        assert_eq!(proof.parent_coin_info, launcher_coin.parent_coin_info);
        assert_eq!(proof.amount, launcher_coin.amount);
      }
      _ => panic!("expected eve proof for info_from_launcher"),
    }

    // now spend the signleton using old memo format and check that info is parsed correctly

    let mut inner_spend_conditions = Conditions::new();

    let second_root_hash: Hash = transition.1;
    if second_root_hash != first_root_hash {
      inner_spend_conditions = inner_spend_conditions.condition(Condition::Other(
        NewMetadataCondition::<i32, DataStoreMetadata, Bytes32, i32> {
          metadata_updater_reveal: 11,
          metadata_updater_solution: DefaultMetadataSolution {
            metadata_part: DefaultMetadataSolutionMetadataList {
              new_metadata: DataStoreMetadata {
                root_hash: second_root_hash.value(),
                label: Label::EMPTY.value(),
                description: Description::EMPTY.value(),
              },
              new_metadata_updater_ph: DL_METADATA_UPDATER_PUZZLE_HASH.into(),
            },
            conditions: 0,
          },
        }
        .to_clvm(ctx.allocator_mut())
        .unwrap(),
      ));
    }

    let new_owner: bool = transition.2;
    let new_inner_ph: Bytes32 = if new_owner {
      owner2_puzzle_hash.into()
    } else {
      owner_puzzle_hash.into()
    };

    // https://github.com/Chia-Network/chia-blockchain/blob/4ffb6dfa6f53f6cd1920bcc775e27377a771fbec/chia/data_layer/data_layer_wallet.py#L526
    // memos are (launcher_id root_hash inner_puzzle_hash)
    inner_spend_conditions = inner_spend_conditions.condition(Condition::CreateCoin(CreateCoin {
      puzzle_hash: new_inner_ph.clone(),
      amount: 1,
      memos: vec![
        launcher_coin.coin_id().into(),
        second_root_hash.value().into(),
        new_inner_ph.into(),
      ],
    }));

    let inner_spend = inner_spend_conditions.p2_spend(ctx, owner_pk)?;

    let state_layer_spend = spend_nft_state_layer_custom_metadata_updated(
      ctx,
      &info_from_launcher.metadata,
      inner_spend,
    )?;

    let full_spend = spend_singleton(
      ctx,
      info_from_launcher.coin,
      info_from_launcher.launcher_id,
      info_from_launcher.proof,
      state_layer_spend,
    )
    .unwrap();

    let new_info = DataStoreInfo::from_spend(
      ctx.allocator_mut(),
      &full_spend,
      &info_from_launcher.delegated_puzzles,
    )
    .unwrap();

    assert_eq!(new_info.metadata.root_hash, second_root_hash.value());
    assert_eq!(new_info.metadata.label, Label::EMPTY.value());
    assert_eq!(new_info.metadata.description, Description::EMPTY.value());

    assert_eq!(new_info.owner_puzzle_hash, new_inner_ph);
    assert!(new_info.delegated_puzzles.is_empty());

    assert_eq!(new_info.launcher_id, eve_coin.parent_coin_info);

    assert_eq!(
      new_info.coin.parent_coin_info,
      info_from_launcher.coin.coin_id()
    );

    let full_computed_puzzle_ptr = full_spend
      .puzzle_reveal
      .to_node_ptr(ctx.allocator_mut())
      .unwrap();
    assert_eq!(
      new_info.coin.puzzle_hash,
      ctx.tree_hash(full_computed_puzzle_ptr).into()
    );
    assert_eq!(new_info.coin.amount, 1);

    match new_info.proof {
      Proof::Lineage(proof) => {
        assert_eq!(proof.parent_parent_coin_id, eve_coin.parent_coin_info);
        assert_eq!(proof.parent_amount, eve_coin.amount);
        assert_eq!(proof.parent_inner_puzzle_hash, owner_puzzle_hash.into());
      }
      _ => panic!("expected lineage proof for new_info"),
    }

    ctx.insert_coin_spend(full_spend);

    test_transaction(
      &peer,
      ctx.take_spends(),
      &[owner_sk, owner2_sk],
      sim.config().genesis_challenge,
    )
    .await;

    let eve_coin_state = sim
      .coin_state(eve_coin.coin_id())
      .await
      .expect("expected eve coin");
    assert!(eve_coin_state.created_height.is_some());

    Ok(())
  }
}
