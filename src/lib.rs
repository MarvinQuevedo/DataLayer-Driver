#![deny(clippy::all)]

mod debug;
mod drivers;
mod merkle_tree;
mod puzzles;
mod puzzles_info;
mod wallet;

use std::sync::Arc;

use chia::client::Peer as RustPeer;
use chia::{bls::PublicKey as RustPublicKey, traits::Streamable};
use chia_protocol::Coin as RustCoin;
use chia_protocol::CoinSpend as RustCoinSpend;
use chia_protocol::Program as RustProgram;
use chia_protocol::{Bytes32 as RustBytes32, NodeType};
use chia_puzzles::EveProof as RustEveProof;
use chia_puzzles::LineageProof as RustLineageProof;
use chia_puzzles::Proof as RustProof;
use chia_wallet_sdk::{connect_peer, create_tls_connector, load_ssl_cert};
pub use debug::*;
pub use drivers::*;
pub use merkle_tree::*;
use napi::bindgen_prelude::*;
use native_tls::TlsConnector;
pub use puzzles::*;
pub use puzzles_info::*;
use puzzles_info::{
  DataStoreInfo as RustDataStoreInfo, DataStoreMetadata as RustDataStoreMetadata,
  DelegatedPuzzle as RustDelegatedPuzzle, DelegatedPuzzleInfo as RustDelegatedPuzzleInfo,
};
use wallet::SuccessResponse as RustSuccessResponse;
pub use wallet::*;

#[macro_use]
extern crate napi_derive;

type Bytes32 = Buffer;
type Program = Buffer;
type PublicKey = Buffer;

pub trait FromJS<T> {
  fn from_js(value: T) -> Self;
}

pub trait ToJS<T> {
  fn to_js(self: &Self) -> T;
}

impl FromJS<Bytes32> for RustBytes32 {
  fn from_js(value: Bytes32) -> Self {
    RustBytes32::from_bytes(&value.to_vec()).unwrap()
  }
}

impl ToJS<Bytes32> for RustBytes32 {
  fn to_js(self: &Self) -> Bytes32 {
    Bytes32::from(self.to_vec())
  }
}

impl FromJS<Program> for RustProgram {
  fn from_js(value: Program) -> Self {
    RustProgram::from(value.to_vec())
  }
}

impl ToJS<Program> for RustProgram {
  fn to_js(self: &Self) -> Program {
    Program::from(self.to_vec())
  }
}

impl FromJS<PublicKey> for RustPublicKey {
  fn from_js(value: PublicKey) -> Self {
    let vec = value.to_vec();
    let bytes: [u8; 48] = vec.try_into().expect("public key should be 48 bytes long");
    RustPublicKey::from_bytes(&bytes).unwrap()
  }
}

impl ToJS<PublicKey> for RustPublicKey {
  fn to_js(self: &Self) -> PublicKey {
    PublicKey::from(self.to_bytes().to_vec())
  }
}

#[napi(object)]
#[derive(Clone)]
pub struct Coin {
  pub parent_coin_info: Bytes32,
  pub puzzle_hash: Bytes32,
  pub amount: BigInt,
}

impl FromJS<BigInt> for u64 {
  fn from_js(value: BigInt) -> Self {
    value.get_u64().1
  }
}

impl ToJS<BigInt> for u64 {
  fn to_js(self: &Self) -> BigInt {
    BigInt::from(*self)
  }
}

impl FromJS<Coin> for RustCoin {
  fn from_js(value: Coin) -> Self {
    RustCoin {
      parent_coin_info: RustBytes32::from_js(value.parent_coin_info),
      puzzle_hash: RustBytes32::from_js(value.puzzle_hash),
      amount: u64::from_js(value.amount),
    }
  }
}

impl ToJS<Coin> for RustCoin {
  fn to_js(self: &Self) -> Coin {
    Coin {
      parent_coin_info: self.parent_coin_info.to_js(),
      puzzle_hash: self.puzzle_hash.to_js(),
      amount: self.amount.to_js(),
    }
  }
}

#[napi(object)]
#[derive(Clone)]
pub struct CoinSpend {
  pub coin: Coin,
  pub puzzle_reveal: Program,
  pub solution: Program,
}

impl FromJS<CoinSpend> for RustCoinSpend {
  fn from_js(value: CoinSpend) -> Self {
    RustCoinSpend {
      coin: RustCoin::from_js(value.coin),
      puzzle_reveal: RustProgram::from_js(value.puzzle_reveal),
      solution: RustProgram::from_js(value.solution),
    }
  }
}

impl ToJS<CoinSpend> for RustCoinSpend {
  fn to_js(self: &Self) -> CoinSpend {
    CoinSpend {
      coin: self.coin.to_js(),
      puzzle_reveal: self.puzzle_reveal.to_js(),
      solution: self.solution.to_js(),
    }
  }
}

#[napi(object)]
#[derive(Clone)]
pub struct LineageProof {
  pub parent_parent_coin_id: Bytes32,
  pub parent_inner_puzzle_hash: Bytes32,
  pub parent_amount: BigInt,
}

impl FromJS<LineageProof> for RustLineageProof {
  fn from_js(value: LineageProof) -> Self {
    RustLineageProof {
      parent_parent_coin_id: RustBytes32::from_js(value.parent_parent_coin_id),
      parent_inner_puzzle_hash: RustBytes32::from_js(value.parent_inner_puzzle_hash),
      parent_amount: u64::from_js(value.parent_amount),
    }
  }
}

impl ToJS<LineageProof> for RustLineageProof {
  fn to_js(self: &Self) -> LineageProof {
    LineageProof {
      parent_parent_coin_id: self.parent_parent_coin_id.to_js(),
      parent_inner_puzzle_hash: self.parent_inner_puzzle_hash.to_js(),
      parent_amount: self.parent_amount.to_js(),
    }
  }
}

#[napi(object)]
#[derive(Clone)]
pub struct EveProof {
  pub parent_coin_info: Bytes32,
  pub amount: BigInt,
}

impl FromJS<EveProof> for RustEveProof {
  fn from_js(value: EveProof) -> Self {
    RustEveProof {
      parent_coin_info: RustBytes32::from_js(value.parent_coin_info),
      amount: u64::from_js(value.amount),
    }
  }
}

impl ToJS<EveProof> for RustEveProof {
  fn to_js(self: &Self) -> EveProof {
    EveProof {
      parent_coin_info: self.parent_coin_info.to_js(),
      amount: self.amount.to_js(),
    }
  }
}

#[napi(object)]
#[derive(Clone)]
pub struct Proof {
  pub lineage_proof: Option<LineageProof>,
  pub eve_proof: Option<EveProof>,
}

impl FromJS<Proof> for RustProof {
  fn from_js(value: Proof) -> Self {
    if value.lineage_proof.is_some() {
      RustProof::Lineage(value.lineage_proof.map(RustLineageProof::from_js).unwrap())
    } else {
      RustProof::Eve(value.eve_proof.map(RustEveProof::from_js).unwrap())
    }
  }
}

impl ToJS<Proof> for RustProof {
  fn to_js(self: &Self) -> Proof {
    match self {
      RustProof::Lineage(lineage_proof) => Proof {
        lineage_proof: Some(lineage_proof.to_js()),
        eve_proof: None,
      },
      RustProof::Eve(eve_proof) => Proof {
        lineage_proof: None,
        eve_proof: Some(eve_proof.to_js()),
      },
    }
  }
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

impl FromJS<DataStoreMetadata> for RustDataStoreMetadata {
  fn from_js(value: DataStoreMetadata) -> Self {
    RustDataStoreMetadata {
      root_hash: RustBytes32::from_js(value.root_hash),
      label: value.label,
      description: value.description,
    }
  }
}

impl ToJS<DataStoreMetadata> for RustDataStoreMetadata {
  fn to_js(self: &Self) -> DataStoreMetadata {
    DataStoreMetadata {
      root_hash: self.root_hash.to_js(),
      label: self.label.clone(),
      description: self.description.clone(),
    }
  }
}

#[napi(object)]
#[derive(Clone)]
pub struct DelegatedPuzzleInfo {
  pub admin_inner_puzzle_hash: Option<Bytes32>,
  pub writer_inner_puzzle_hash: Option<Bytes32>,
  pub oracle_payment_puzzle_hash: Option<Bytes32>,
  pub oracle_fee: Option<BigInt>,
}

impl FromJS<DelegatedPuzzleInfo> for RustDelegatedPuzzleInfo {
  fn from_js(value: DelegatedPuzzleInfo) -> Self {
    if value.admin_inner_puzzle_hash.is_some() {
      RustDelegatedPuzzleInfo::Admin(RustBytes32::from_js(value.admin_inner_puzzle_hash.unwrap()))
    } else if value.writer_inner_puzzle_hash.is_some() {
      RustDelegatedPuzzleInfo::Writer(RustBytes32::from_js(
        value.writer_inner_puzzle_hash.unwrap(),
      ))
    } else {
      RustDelegatedPuzzleInfo::Oracle(
        RustBytes32::from_js(value.oracle_payment_puzzle_hash.unwrap()),
        u64::from_js(value.oracle_fee.unwrap()),
      )
    }
  }
}

impl ToJS<DelegatedPuzzleInfo> for RustDelegatedPuzzleInfo {
  fn to_js(self: &Self) -> DelegatedPuzzleInfo {
    match self {
      RustDelegatedPuzzleInfo::Admin(admin_inner_puzzle_hash) => DelegatedPuzzleInfo {
        admin_inner_puzzle_hash: Some(admin_inner_puzzle_hash.to_js()),
        writer_inner_puzzle_hash: None,
        oracle_payment_puzzle_hash: None,
        oracle_fee: None,
      },
      RustDelegatedPuzzleInfo::Writer(writer_inner_puzzle_hash) => DelegatedPuzzleInfo {
        admin_inner_puzzle_hash: None,
        writer_inner_puzzle_hash: Some(writer_inner_puzzle_hash.to_js()),
        oracle_payment_puzzle_hash: None,
        oracle_fee: None,
      },
      RustDelegatedPuzzleInfo::Oracle(oracle_payment_puzzle_hash, oracle_fee) => {
        DelegatedPuzzleInfo {
          admin_inner_puzzle_hash: None,
          writer_inner_puzzle_hash: None,
          oracle_payment_puzzle_hash: Some(oracle_payment_puzzle_hash.to_js()),
          oracle_fee: Some(oracle_fee.to_js()),
        }
      }
    }
  }
}

#[napi(object)]
#[derive(Clone)]
pub struct DelegatedPuzzle {
  pub puzzle_hash: Bytes32,
  pub puzzle_info: DelegatedPuzzleInfo,
}

impl FromJS<DelegatedPuzzle> for RustDelegatedPuzzle {
  fn from_js(value: DelegatedPuzzle) -> Self {
    let puzzle_info = RustDelegatedPuzzleInfo::from_js(value.puzzle_info);

    RustDelegatedPuzzle {
      puzzle_hash: RustBytes32::from_js(value.puzzle_hash),
      puzzle_info: puzzle_info,
      full_puzzle: None,
    }
  }
}

impl ToJS<DelegatedPuzzle> for RustDelegatedPuzzle {
  fn to_js(self: &Self) -> DelegatedPuzzle {
    DelegatedPuzzle {
      puzzle_hash: self.puzzle_hash.to_js(),
      puzzle_info: self.puzzle_info.to_js(),
    }
  }
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

impl FromJS<DataStoreInfo> for RustDataStoreInfo {
  fn from_js(value: DataStoreInfo) -> Self {
    RustDataStoreInfo {
      coin: RustCoin::from_js(value.coin),
      launcher_id: RustBytes32::from_js(value.launcher_id),
      proof: RustProof::from_js(value.proof),
      metadata: RustDataStoreMetadata::from_js(value.metadata),
      owner_puzzle_hash: RustBytes32::from_js(value.owner_puzzle_hash),
      delegated_puzzles: value
        .delegated_puzzles
        .into_iter()
        .map(RustDelegatedPuzzle::from_js)
        .collect(),
    }
  }
}

impl ToJS<DataStoreInfo> for RustDataStoreInfo {
  fn to_js(self: &Self) -> DataStoreInfo {
    DataStoreInfo {
      coin: self.coin.to_js(),
      launcher_id: self.launcher_id.to_js(),
      proof: self.proof.to_js(),
      metadata: self.metadata.to_js(),
      owner_puzzle_hash: self.owner_puzzle_hash.to_js(),
      delegated_puzzles: self
        .delegated_puzzles
        .iter()
        .map(RustDelegatedPuzzle::to_js)
        .collect(),
    }
  }
}

impl FromJS<SuccessResponse> for RustSuccessResponse {
  fn from_js(value: SuccessResponse) -> Self {
    RustSuccessResponse {
      coin_spends: value
        .coin_spends
        .into_iter()
        .map(RustCoinSpend::from_js)
        .collect(),
      new_info: RustDataStoreInfo::from_js(value.new_info),
    }
  }
}

impl ToJS<SuccessResponse> for RustSuccessResponse {
  fn to_js(self: &Self) -> SuccessResponse {
    SuccessResponse {
      coin_spends: self.coin_spends.iter().map(RustCoinSpend::to_js).collect(),
      new_info: self.new_info.to_js(),
    }
  }
}

#[napi(object)]
pub struct SuccessResponse {
  pub coin_spends: Vec<CoinSpend>,
  pub new_info: DataStoreInfo,
}

#[napi]
pub struct Tls(TlsConnector);

#[napi]
impl Tls {
  #[napi(constructor)]
  pub fn new(cert_path: String, key_path: String) -> napi::Result<Self> {
    let cert = load_ssl_cert(&cert_path, &key_path).map_err(js)?;
    let tls = create_tls_connector(&cert).map_err(js)?;
    Ok(Self(tls))
  }
}

#[napi]
pub struct Peer(Arc<RustPeer>);

#[napi]
impl Peer {
  #[napi(factory)]
  pub async fn new(node_uri: String, network_id: String, tls: &Tls) -> napi::Result<Self> {
    let peer = connect_peer(&node_uri, tls.0.clone()).await.map_err(js)?;

    peer
      .send_handshake(network_id, NodeType::Wallet)
      .await
      .map_err(js)?;

    Ok(Peer(peer.into()))
  }

  #[napi]
  pub async fn mint_store(
    &self,
    minter_synthetic_key: PublicKey,
    minter_ph_min_height: u32,
    root_hash: Bytes32,
    label: String,
    description: String,
    owner_puzzle_hash: Bytes32,
    delegated_puzzles: Vec<DelegatedPuzzle>,
    fee: BigInt,
  ) -> napi::Result<SuccessResponse> {
    let response = mint_store(
      &self.0.clone(),
      RustPublicKey::from_js(minter_synthetic_key),
      minter_ph_min_height,
      RustBytes32::from_js(root_hash),
      label,
      description,
      RustBytes32::from_js(owner_puzzle_hash),
      delegated_puzzles
        .iter()
        .map(|dp| RustDelegatedPuzzle::from_js(dp.clone()))
        .collect(),
      u64::from_js(fee),
    )
    .await
    .map_err(js)?;

    Ok(response.to_js())
  }
}

fn js<T>(error: T) -> napi::Error
where
  T: ToString,
{
  napi::Error::from_reason(error.to_string())
}

// todo: delegated puzzle - rm NodePtr
