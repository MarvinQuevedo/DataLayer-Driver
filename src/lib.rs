#![deny(clippy::all)]

mod debug;
mod drivers;
mod merkle_tree;
mod puzzles;
mod puzzles_info;
mod wallet;

pub use debug::*;
pub use drivers::*;
pub use merkle_tree::*;
use napi::bindgen_prelude::{BigInt, Buffer};
pub use puzzles::*;
pub use puzzles_info::*;
pub use wallet::*;

#[macro_use]
extern crate napi_derive;

type Bytes32 = Buffer;
type Program = Buffer;

#[napi(object)]
#[derive(Clone)]
pub struct Coin {
  pub parent_coin_info: Bytes32,
  pub puzzle_hash: Bytes32,
  pub amount: BigInt,
}

#[napi(object)]
#[derive(Clone)]
pub struct CoinSpend {
  pub coin: Coin,
  pub puzzle_reveal: Program,
  pub solution: Program,
}

#[napi(object)]
#[derive(Clone)]
pub struct LineageProof {
  pub parent_parent_coin_id: Bytes32,
  pub parent_inner_puzzle_hash: Bytes32,
  pub parent_amount: BigInt,
}

#[napi(object)]
#[derive(Clone)]
pub struct EveProof {
  pub parent_coin_info: Bytes32,
  pub amount: BigInt,
}

#[napi(object)]
#[derive(Clone)]
pub struct Proof {
  pub lineage_proof: Option<LineageProof>,
  pub eve_proof: Option<EveProof>,
}

#[napi]
pub fn new_lineage_proof(lineage_proof: LineageProof) -> Proof {
  Proof {
    lineage_proof: Some(lineage_proof),
    eve_proof: None,
  }
}

#[napi]
pub fn new_eve_proof(eve_proof: EveProof) -> Proof {
  Proof {
    lineage_proof: None,
    eve_proof: Some(eve_proof),
  }
}

#[napi(object)]
#[derive(Clone)]
pub struct DataStoreMetadata {
  pub root_hash: Bytes32,
  pub label: String,
  pub description: String,
}

#[napi(object)]
#[derive(Clone)]
pub struct DelegatedPuzzleInfo {
  pub admin_inner_puzzle_hash: Option<Bytes32>,
  pub writer_inner_puzzle_hash: Option<Bytes32>,
  pub oracle_payment_puzzle_hash: Option<Bytes32>,
  pub oracle_fee: Option<BigInt>,
}

#[napi(object)]
#[derive(Clone)]
pub struct DelegatedPuzzle {
  pub puzzle_hash: Bytes32,
  pub puzzle_info: DelegatedPuzzleInfo,
  pub full_puzzle: Option<Program>,
}

#[napi(object)]
#[derive(Clone)]
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

#[napi(object)]
pub struct SuccessResponse {
  pub coin_spends: Vec<CoinSpend>,
  pub new_info: DataStoreInfo,
}
