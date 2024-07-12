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
pub struct DLLauncherKVList<T = NodePtr> {
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
    hints: &Vec<Bytes>,
  ) -> Result<DataStoreInfo, ParseError> {
    let mut hints = hints.clone();
    println!("hints clone: {:?}", hints); // todo: debug

    let owner_puzzle_hash: Bytes32 = if hints.len() < 1 {
      fallback_owner_ph
    } else {
      Bytes32::from_bytes(&hints.drain(0..1).next().unwrap())
        .map_err(|_| ParseError::MissingHint)?
    };

    let delegated_puzzles = {
      println!("moar hints: {:?}", hints); // todo: debug
      let mut d_puzz: Vec<DelegatedPuzzle> = vec![];

      while hints.len() > 1 {
        d_puzz.push(DelegatedPuzzle::from_hint(allocator, &mut hints)?);
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
    prev_delegated_puzzles: Vec<DelegatedPuzzle>,
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
      let solution =
        LauncherSolution::<DLLauncherKVList<Bytes>>::from_clvm(allocator, solution_node_ptr)
          .map_err(|_| ParseError::NonStandardLayer)?;

      let metadata_info = solution.key_value_list;
      let label: String = if metadata_info.memos.len() >= 1 {
        String::from_utf8(metadata_info.memos[0].to_vec())
          .map_err(|err| {
            println!("err 1023948"); // todo: debug
            println!("metadata_info: {:?}", metadata_info); // todo: debug
            println!("err: {:?}", err); // todo: debug
            return ParseError::MissingHint;
          })
          .unwrap_or_default()
      } else {
        String::default()
      };
      let description: String = if metadata_info.memos.len() >= 2 {
        String::from_utf8(metadata_info.memos[1].to_vec()).unwrap_or_default()
      } else {
        String::default()
      };

      println!("converting metadata..."); // todo: debug
      println!("metadata_info: {:?}", metadata_info); // todo: debug
      let metadata = DataStoreMetadata {
        root_hash: metadata_info.root_hash,
        label,
        description,
      };

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
      println!(
        "hints (first 3 = label/description/inner ph): {:?}",
        metadata_info.memos
      ); // todo: debug
      let hints: Vec<Bytes> = metadata_info.memos.iter().skip(2).cloned().collect();
      println!("calling build_datastore_info..."); // todo: debug
      return match DataStoreInfo::build_datastore_info(
        allocator,
        new_coin,
        launcher_id,
        proof,
        metadata,
        metadata_info.state_layer_inner_puzzle_hash,
        &hints,
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
