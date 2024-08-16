#![deny(clippy::all)]

mod debug;
mod drivers;
mod merkle_tree;
mod puzzles;
mod puzzles_info;
mod wallet;

use std::sync::Arc;

use chia::bls::derive_keys::master_to_wallet_unhardened;
use chia::bls::{SecretKey as RustSecretKey, Signature as RustSignature};
use chia::client::Peer as RustPeer;
use chia::client::Error as ClientError;
use chia::{bls::PublicKey as RustPublicKey, traits::Streamable};
use chia_protocol::Coin as RustCoin;
use chia_protocol::CoinSpend as RustCoinSpend;
use chia_protocol::Program as RustProgram;
use chia_protocol::SpendBundle as RustSpendBundle;
use chia_protocol::{Bytes32 as RustBytes32, NodeType};
use chia_puzzles::standard::StandardArgs;
use chia_puzzles::LineageProof as RustLineageProof;
use chia_puzzles::Proof as RustProof;
use chia_puzzles::{DeriveSynthetic, EveProof as RustEveProof};
use chia_sdk_driver::SpendContext;
use chia_wallet_sdk::{
  connect_peer, create_tls_connector, decode_address, encode_address, load_ssl_cert,
};
use clvmr::Allocator;
pub use debug::*;
pub use drivers::*;
pub use merkle_tree::*;
use napi::bindgen_prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};
pub use puzzles::*;
pub use puzzles_info::*;
use puzzles_info::{
  DataStoreInfo as RustDataStoreInfo, DataStoreMetadata as RustDataStoreMetadata,
  DelegatedPuzzle as RustDelegatedPuzzle, DelegatedPuzzleInfo as RustDelegatedPuzzleInfo,
};
use wallet::SuccessResponse as RustSuccessResponse;
use wallet::SyncStoreResponse as RustSyncStoreResponse;
use wallet::UnspentCoinsResponse as RustUnspentCoinsResponse;
pub use wallet::*;

#[macro_use]
extern crate napi_derive;

pub trait FromJS<T> {
  fn from_js(value: T) -> Self;
}

pub trait ToJS<T> {
  fn to_js(self: &Self) -> T;
}

impl FromJS<Buffer> for RustBytes32 {
  fn from_js(value: Buffer) -> Self {
    RustBytes32::from_bytes(&value.to_vec()).expect("Bytes32 value should be 32 bytes long")
  }
}

impl ToJS<Buffer> for RustBytes32 {
  fn to_js(self: &Self) -> Buffer {
    Buffer::from(self.to_vec())
  }
}

impl FromJS<Buffer> for RustProgram {
  fn from_js(value: Buffer) -> Self {
    RustProgram::from(value.to_vec())
  }
}

impl ToJS<Buffer> for RustProgram {
  fn to_js(self: &Self) -> Buffer {
    Buffer::from(self.to_vec())
  }
}

impl FromJS<Buffer> for RustPublicKey {
  fn from_js(value: Buffer) -> Self {
    let vec = value.to_vec();
    let bytes: [u8; 48] = vec.try_into().expect("public key should be 48 bytes long");
    RustPublicKey::from_bytes(&bytes).expect("error parsing public key")
  }
}

impl ToJS<Buffer> for RustPublicKey {
  fn to_js(self: &Self) -> Buffer {
    Buffer::from(self.to_bytes().to_vec())
  }
}

impl FromJS<Buffer> for RustSecretKey {
  fn from_js(value: Buffer) -> Self {
    let vec = value.to_vec();
    let bytes: [u8; 32] = vec.try_into().expect("secret key should be 32 bytes long");
    RustSecretKey::from_bytes(&bytes).expect("error parsing secret key")
  }
}

impl ToJS<Buffer> for RustSecretKey {
  fn to_js(self: &Self) -> Buffer {
    Buffer::from(self.to_bytes().to_vec())
  }
}

impl FromJS<Buffer> for RustSignature {
  fn from_js(value: Buffer) -> Self {
    let vec = value.to_vec();
    let bytes: [u8; 96] = vec.try_into().expect("signature should be 96 bytes long");
    RustSignature::from_bytes(&bytes).expect("error parsing signature")
  }
}

impl ToJS<Buffer> for RustSignature {
  fn to_js(self: &Self) -> Buffer {
    Buffer::from(self.to_bytes().to_vec())
  }
}

#[napi(object)]
#[derive(Clone)]
/// Represents a coin on the Chia blockchain.
///
/// @property {Buffer} parentCoinInfo - Parent coin name/id.
/// @property {Buffer} puzzleHash - Puzzle hash.
/// @property {BigInt} amount - Coin amount.
pub struct Coin {
  pub parent_coin_info: Buffer,
  pub puzzle_hash: Buffer,
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
/// Represents a coin spend on the Chia blockchain.
///
/// @property {Coin} coin - The coin being spent.
/// @property {Buffer} puzzleReveal - The puzzle of the coin being spent.
/// @property {Buffer} solution - The solution.
pub struct CoinSpend {
  pub coin: Coin,
  pub puzzle_reveal: Buffer,
  pub solution: Buffer,
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
/// Represents a lineage proof that can be used to spend a singleton.
///
/// @property {Buffer} parentParentCoinId - Parent coin's parent coin info/name/ID.
/// @property {Buffer} parentInnerPuzzleHash - Parent coin's inner puzzle hash.
/// @property {BigInt} parentAmount - Parent coin's amount.
pub struct LineageProof {
  pub parent_parent_coin_id: Buffer,
  pub parent_inner_puzzle_hash: Buffer,
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
/// Represents an eve proof that can be used to spend a singleton. Parent coin is the singleton launcher.
///
/// @property {Buffer} parentCoinInfo - Parent coin's name.
/// @property {BigInt} amount - Parent coin's amount.
pub struct EveProof {
  pub parent_coin_info: Buffer,
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
/// Represents a proof (either eve or lineage) that can be used to spend a singleton. Use `new_lineage_proof` or `new_eve_proof` to create a new proof.
///
/// @property {Option<LineageProof>} lineageProof - The lineage proof, if this is a lineage proof.
/// @property {Option<EveProof>} eveProof - The eve proof, if this is an eve proof.
pub struct Proof {
  pub lineage_proof: Option<LineageProof>,
  pub eve_proof: Option<EveProof>,
}

impl FromJS<Proof> for RustProof {
  fn from_js(value: Proof) -> Self {
    if value.lineage_proof.is_some() {
      RustProof::Lineage(
        value
          .lineage_proof
          .map(RustLineageProof::from_js)
          .expect("error parsing lineage proof"),
      )
    } else {
      RustProof::Eve(
        value
          .eve_proof
          .map(RustEveProof::from_js)
          .expect("error parsing eve proof"),
      )
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
/// Creates a new lineage proof.
///
/// @param {LineageProof} lineageProof - The lineage proof.
/// @returns {Proof} The new proof.
pub fn new_lineage_proof(lineage_proof: LineageProof) -> Proof {
  Proof {
    lineage_proof: Some(lineage_proof),
    eve_proof: None,
  }
}

#[napi]
/// Creates a new eve proof.
///
/// @param {EveProof} eveProof - The eve proof.
/// @returns {Proof} The new proof.
pub fn new_eve_proof(eve_proof: EveProof) -> Proof {
  Proof {
    lineage_proof: None,
    eve_proof: Some(eve_proof),
  }
}

#[napi(object)]
#[derive(Clone)]
/// Represents metadata for a data store.
///
/// @property {Buffer} rootHash - Root hash.
/// @property {Option<String>} label - Label (optional).
/// @property {Option<String>} description - Description (optional).
/// @property {Option<BigInt>} bytes - Size of the store in bytes (optional).
pub struct DataStoreMetadata {
  pub root_hash: Buffer,
  pub label: Option<String>,
  pub description: Option<String>,
  pub bytes: Option<BigInt>,
}

impl FromJS<DataStoreMetadata> for RustDataStoreMetadata {
  fn from_js(value: DataStoreMetadata) -> Self {
    RustDataStoreMetadata {
      root_hash: RustBytes32::from_js(value.root_hash),
      label: value.label,
      description: value.description,
      bytes: value.bytes.map(|s| u64::from_js(s)),
    }
  }
}

impl ToJS<DataStoreMetadata> for RustDataStoreMetadata {
  fn to_js(self: &Self) -> DataStoreMetadata {
    DataStoreMetadata {
      root_hash: self.root_hash.to_js(),
      label: self.label.clone(),
      description: self.description.clone(),
      bytes: self.bytes.map(|s| s.to_js()),
    }
  }
}

#[napi(object)]
#[derive(Clone)]
/// Represents information about a delegated puzzle. Note that this struct can represent all three types of delegated puzzles, but only represents one at a time.
///
/// @property {Option<Buffer>} adminInnerPuzzleHash - Admin inner puzzle hash, if this is an admin delegated puzzle.
/// @property {Option<Buffer>} writerInnerPuzzleHash - Writer inner puzzle hash, if this is a writer delegated puzzle.
/// @property {Option<Buffer>} oraclePaymentPuzzleHash - Oracle payment puzzle hash, if this is an oracle delegated puzzle.
/// @property {Option<BigInt>} oracleFee - Oracle fee, if this is an oracle delegated puzzle.
pub struct DelegatedPuzzleInfo {
  pub admin_inner_puzzle_hash: Option<Buffer>,
  pub writer_inner_puzzle_hash: Option<Buffer>,
  pub oracle_payment_puzzle_hash: Option<Buffer>,
  pub oracle_fee: Option<BigInt>,
}

impl FromJS<DelegatedPuzzleInfo> for RustDelegatedPuzzleInfo {
  fn from_js(value: DelegatedPuzzleInfo) -> Self {
    if value.admin_inner_puzzle_hash.is_some() {
      RustDelegatedPuzzleInfo::Admin(RustBytes32::from_js(
        value
          .admin_inner_puzzle_hash
          .expect("error parsing admin inner puzzle hash as Bytes32"),
      ))
    } else if value.writer_inner_puzzle_hash.is_some() {
      RustDelegatedPuzzleInfo::Writer(RustBytes32::from_js(
        value
          .writer_inner_puzzle_hash
          .expect("error parsing writer inner puzzle hash as Bytes32"),
      ))
    } else {
      RustDelegatedPuzzleInfo::Oracle(
        RustBytes32::from_js(
          value
            .oracle_payment_puzzle_hash
            .expect("error parsing oracle payment puzzle hash as Bytes32"),
        ),
        u64::from_js(value.oracle_fee.expect("error parsing oracle fee as u64")),
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
/// Represents a delegated puzzle. Note that utilities such as `admin_delegated_puzzle_from_key` should be used to create this object.
///
/// @property {Buffer} puzzleHash - The full puzzle hash of the delegated puzzle (filter where applicable + inner puzzle).
/// @property {DelegatedPuzzleInfo} puzzleInfo - Delegated puzzle information.
pub struct DelegatedPuzzle {
  pub puzzle_hash: Buffer,
  pub puzzle_info: DelegatedPuzzleInfo,
}

impl FromJS<DelegatedPuzzle> for RustDelegatedPuzzle {
  fn from_js(value: DelegatedPuzzle) -> Self {
    let puzzle_info = RustDelegatedPuzzleInfo::from_js(value.puzzle_info);

    RustDelegatedPuzzle {
      puzzle_hash: RustBytes32::from_js(value.puzzle_hash),
      puzzle_info: puzzle_info,
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
/// Represents information about a data store. This information can be used to spend the store. It is recommended that this struct is stored in a database to avoid syncing it every time.
///
/// @property {Coin} coin - The coin associated with the data store.
/// @property {Buffer} launcherId - The store's launcher/singleton ID.
/// @property {Proof} proof - Proof that can be used to spend this store.
/// @property {DataStoreMetadata} metadata - This store's metadata.
/// @property {Buffer} ownerPuzzleHash - The puzzle hash of the owner puzzle.
/// @property {Vec<DelegatedPuzzle>} delegatedPuzzles - This store's delegated puzzles. An empty list usually indicates a 'vanilla' store.
pub struct DataStoreInfo {
  pub coin: Coin,
  // singleton layer
  pub launcher_id: Buffer,
  pub proof: Proof,
  // NFT state layer
  pub metadata: DataStoreMetadata,
  // inner puzzle (either p2 or delegation_layer + p2)
  pub owner_puzzle_hash: Buffer,
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

#[napi(object)]
// Represents a driver response indicating success.
///
/// @property {Vec<CoinSpend>} coinSpends - Coin spends that can be used to spend the provided store.
/// @property {DataStoreInfo} newInfo - New data store information after the spend is confirmed.
pub struct SuccessResponse {
  pub coin_spends: Vec<CoinSpend>,
  pub new_info: DataStoreInfo,
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
/// Represents a response from synchronizing a store.
///
/// @property {DataStoreInfo} latestInfo - Latest data store information.
/// @property {Option<Vec<Buffer>>} rootHashes - When synced with whistory, this list will contain all of the store's previous root hashes. Otherwise null.
/// @property {Option<Vec<BigInt>>} rootHashesTimestamps - Timestamps of the root hashes (see `rootHashes`).
/// @property {u32} latestHeight - Latest sync height.
pub struct SyncStoreResponse {
  pub latest_info: DataStoreInfo,
  pub root_hashes: Option<Vec<Buffer>>,
  pub root_hashes_timestamps: Option<Vec<BigInt>>,
  pub latest_height: u32,
}

impl FromJS<SyncStoreResponse> for RustSyncStoreResponse {
  fn from_js(value: SyncStoreResponse) -> Self {
    let mut root_hash_history = None;

    if value.root_hashes.is_some() && value.root_hashes_timestamps.is_some() {
      let mut v = vec![];

      for (root_hash, timestamp) in value
        .root_hashes
        .unwrap()
        .into_iter()
        .zip(value.root_hashes_timestamps.unwrap().into_iter())
      {
        v.push((RustBytes32::from_js(root_hash), u64::from_js(timestamp)));
      }

      root_hash_history = Some(v);
    }

    RustSyncStoreResponse {
      latest_info: RustDataStoreInfo::from_js(value.latest_info),
      latest_height: value.latest_height,
      root_hash_history,
    }
  }
}

impl ToJS<SyncStoreResponse> for RustSyncStoreResponse {
  fn to_js(self: &Self) -> SyncStoreResponse {
    SyncStoreResponse {
      latest_info: self.latest_info.to_js(),
      latest_height: self.latest_height,
      root_hashes: self
        .root_hash_history
        .as_ref()
        .map(|v| v.iter().map(|(rh, _)| rh.to_js()).collect()),
      root_hashes_timestamps: self
        .root_hash_history
        .as_ref()
        .map(|v| v.iter().map(|(_, ts)| ts.to_js()).collect()),
    }
  }
}

#[napi(object)]
/// Represents a response containing unspent coins.
///
/// @property {Vec<Coin>} coins - Unspent coins.
/// @property {u32} lastHeight - Last height.
/// @property {Buffer} lastHeaderHash - Last header hash.
pub struct UnspentCoinsResponse {
  pub coins: Vec<Coin>,
  pub last_height: u32,
  pub last_header_hash: Buffer,
}

impl FromJS<UnspentCoinsResponse> for RustUnspentCoinsResponse {
  fn from_js(value: UnspentCoinsResponse) -> Self {
    RustUnspentCoinsResponse {
      coins: value.coins.into_iter().map(RustCoin::from_js).collect(),
      last_height: value.last_height,
      last_header_hash: RustBytes32::from_js(value.last_header_hash),
    }
  }
}

impl ToJS<UnspentCoinsResponse> for RustUnspentCoinsResponse {
  fn to_js(self: &Self) -> UnspentCoinsResponse {
    UnspentCoinsResponse {
      coins: self.coins.iter().map(RustCoin::to_js).collect(),
      last_height: self.last_height,
      last_header_hash: self.last_header_hash.to_js(),
    }
  }
}

#[napi]
pub struct Peer(Arc<RustPeer>);

#[napi]
impl Peer {
  #[napi(factory)]
  /// Creates a new Peer instance.
  ///
  /// @param {String} nodeUri - URI of the node (e.g., '127.0.0.1:58444').
  /// @param {String} networkId - Network ID (e.g., 'testnet11').
  /// @param {String} certPath - Path to the certificate file (usually '~/.chia/mainnet/config/ssl/wallet/wallet_node.crt').
  /// @param {String} keyPath - Path to the key file (usually '~/.chia/mainnet/config/ssl/wallet/wallet_node.key').
  /// @returns {Promise<Peer>} A new Peer instance.
  pub async fn new(
    node_uri: String,
    network_id: String,
    cert_path: String,
    key_path: String,
  ) -> napi::Result<Self> {
    let cert = load_ssl_cert(&cert_path, &key_path).map_err(js)?;
    let tls = create_tls_connector(&cert).map_err(js)?;
    let peer = connect_peer(&node_uri, tls).await.map_err(js)?;

    peer
      .send_handshake(network_id, NodeType::Wallet)
      .await
      .map_err(js)?;

    Ok(Self(Arc::new(peer)))
  }

  #[napi]
  /// Retrieves the fee estimate for a given target time.
  ///
  /// @param {Peer} peer - The peer connection to the Chia node.
  /// @param {BigInt} targetTimeSeconds - The target time in seconds from the current time for the fee estimate.
  /// @returns {Promise<BigInt>} The estimated fee in mojos per CLVM cost.
  pub async fn get_fee_estimate(&self, target_time_seconds: BigInt) -> napi::Result<BigInt> {
      // Convert the target_time_seconds BigInt to u64
      let target_time_seconds_u64: u64 = target_time_seconds.get_u64().1;
  
      // Get the current time as a Unix timestamp in seconds
      let current_time = SystemTime::now().duration_since(UNIX_EPOCH)
          .expect("Time went backwards")
          .as_secs();
  
      // Calculate the target Unix timestamp
      let target_timestamp = current_time + target_time_seconds_u64;
  
      // Call the Rust get_fee_estimate function with the calculated Unix timestamp
      match wallet::get_fee_estimate(&self.0.clone(), target_timestamp).await {
          Ok(fee_estimate) => Ok(BigInt::from(fee_estimate)),
          Err(ClientError::Rejection(error_message)) => {
              Err(napi::Error::from_reason(format!("Fee estimate rejection: {}", error_message)))
          }
          Err(e) => Err(napi::Error::from_reason(format!("Failed to request fee estimates: {:?}", e))),
      }
  }

  #[napi]
  /// Retrieves all coins that are unspent on the chain. Note that coins part of spend bundles that are pending in the mempool will also be included.
  ///
  /// @param {Buffer} puzzleHash - Puzzle hash of the wallet.
  /// @param {Option<u32>} previousHeight - Previous height that was spent. If null, sync will be done from the genesis block.
  /// @param {Buffer} previousHeaderHash - Header hash corresponding to the previous height. If previousHeight is null, this should be the genesis challenge of the current chain.
  /// @returns {Promise<UnspentCoinsResponse>} The unspent coins response.
  pub async fn get_all_unspent_coins(
    &self,
    puzzle_hash: Buffer,
    previous_height: Option<u32>,
    previous_header_hash: Buffer,
  ) -> napi::Result<UnspentCoinsResponse> {
    let resp = get_unspent_coins(
      &self.0.clone(),
      RustBytes32::from_js(puzzle_hash),
      previous_height,
      RustBytes32::from_js(previous_header_hash),
    )
    .await
    .map_err(js)?;

    Ok(resp.to_js())
  }

  #[napi]
  /// Synchronizes a datastore.
  ///
  /// @param {DataStoreInfo} storeInfo - Data store information.
  /// @param {Option<u32>} lastHeight - Min. height to search records from. If null, sync will be done from the genesis block.
  /// @param {Buffer} lastHeaderHash - Header hash corresponding to `lastHeight`. If null, this should be the genesis challenge of the current chain.
  /// @param {bool} withHistory - Whether to return the root hash history of the store.
  /// @returns {Promise<SyncStoreResponse>} The sync store response.
  pub async fn sync_store(
    &self,
    store_info: DataStoreInfo,
    last_height: Option<u32>,
    last_header_hash: Buffer,
    with_history: bool,
  ) -> napi::Result<SyncStoreResponse> {
    let res = sync_store(
      &self.0.clone(),
      &RustDataStoreInfo::from_js(store_info),
      last_height,
      RustBytes32::from_js(last_header_hash),
      with_history,
    )
    .await
    .map_err(js)?;

    Ok(res.to_js())
  }

  #[napi]
  /// Synchronizes a store using its launcher ID.
  ///
  /// @param {Buffer} launcherId - The store's launcher/singleton ID.
  /// @param {Option<u32>} lastHeight - Min. height to search records from. If null, sync will be done from the genesis block.
  /// @param {Buffer} lastHeaderHash - Header hash corresponding to `lastHeight`. If null, this should be the genesis challenge of the current chain.
  /// @param {bool} withHistory - Whether to return the root hash history of the store.
  /// @returns {Promise<SyncStoreResponse>} The sync store response.
  pub async fn sync_store_from_launcher_id(
    &self,
    launcher_id: Buffer,
    last_height: Option<u32>,
    last_header_hash: Buffer,
    with_history: bool,
  ) -> napi::Result<SyncStoreResponse> {
    let res = sync_store_using_launcher_id(
      &self.0.clone(),
      RustBytes32::from_js(launcher_id),
      last_height,
      RustBytes32::from_js(last_header_hash),
      with_history,
    )
    .await
    .map_err(js)?;

    Ok(res.to_js())
  }

  #[napi]
  /// Broadcasts a spend bundle to the mempool.
  ///
  /// @param {Vec<CoinSpend>} coinSpends - The coin spends to be included in the bundle.
  /// @param {Vec<Buffer>} sigs - The signatures to be aggregated and included in the bundle.
  /// @returns {Promise<String>} The broadcast error. If '', the broadcast was successful.
  pub async fn broadcast_spend(
    &self,
    coin_spends: Vec<CoinSpend>,
    sigs: Vec<Buffer>,
  ) -> napi::Result<String> {
    let spend_bundle = RustSpendBundle::new(
      coin_spends
        .into_iter()
        .map(RustCoinSpend::from_js)
        .collect(),
      sigs
        .into_iter()
        .map(|js_sig| RustSignature::from_js(js_sig))
        .fold(RustSignature::default(), |acc, sig| acc + &sig),
    );

    Ok(
      wallet::broadcast_spend_bundle(&self.0.clone(), spend_bundle)
        .await
        .map_err(js)?
        .error
        .unwrap_or(String::default()),
    )
  }

  #[napi]
  /// Checks if a coin is spent on-chain.
  ///
  /// @param {Buffer} coinId - The coin ID.
  /// @param {Option<u32>} lastHeight - Min. height to search records from. If null, sync will be done from the genesis block.
  /// @param {Buffer} headerHash - Header hash corresponding to `lastHeight`. If null, this should be the genesis challenge of the current chain.
  /// @returns {Promise<bool>} Whether the coin is spent on-chain.
  pub async fn is_coin_spent(
    &self,
    coin_id: Buffer,
    last_height: Option<u32>,
    header_hash: Buffer,
  ) -> napi::Result<bool> {
    Ok(
      is_coin_spent(
        &self.0.clone(),
        RustBytes32::from_js(coin_id),
        last_height,
        RustBytes32::from_js(header_hash),
      )
      .await
      .map_err(js)?,
    )
  }

  #[napi]
  /// Retrieves the current header hash corresponding to a given height.
  ///
  /// @param {u32} height - The height.
  /// @returns {Promise<Buffer>} The header hash.
  pub async fn get_header_hash(&self, height: u32) -> napi::Result<Buffer> {
    Ok(
      get_header_hash(&self.0.clone(), height)
        .await
        .map_err(js)?
        .to_js(),
    )
  }
}

/// Selects coins using the knapsack algorithm.
///
/// @param {Vec<Coin>} allCoins - Array of available coins (coins to select from).
/// @param {BigInt} totalAmount - Amount needed for the transaction, including fee.
/// @returns {Vec<Coin>} Array of selected coins.
#[napi]
pub fn select_coins(all_coins: Vec<Coin>, total_amount: BigInt) -> napi::Result<Vec<Coin>> {
  let coins: Vec<RustCoin> = all_coins
    .into_iter()
    .map(|c| RustCoin::from_js(c))
    .collect();
  let selected_coins = wallet::select_coins(coins, u64::from_js(total_amount)).map_err(js)?;

  Ok(selected_coins.into_iter().map(|c| c.to_js()).collect())
}

#[napi]
/// Mints a new datastore.
///
/// @param {Buffer} minterSyntheticKey - Minter synthetic key.
/// @param {Vec<Coin>} selectedCoins - Coins to be used for minting, as retured by `select_coins`. Note that, besides the fee, 1 mojo will be used to create the new store.
/// @param {Buffer} rootHash - Root hash of the store.
/// @param {Option<String>} label - Store label (optional).
/// @param {Option<String>} description - Store description (optional).
/// @param {Option<BigInt>} bytes - Store size in bytes (optional).
/// @param {Buffer} ownerPuzzleHash - Owner puzzle hash.
/// @param {Vec<DelegatedPuzzle>} delegatedPuzzles - Delegated puzzles.
/// @param {BigInt} fee - Fee to use for the transaction. Total amount - 1 - fee will be sent back to the minter.
/// @returns {SuccessResponse} The success response, which includes coin spends and information about the new datastore.
pub fn mint_store(
  minter_synthetic_key: Buffer,
  selected_coins: Vec<Coin>,
  root_hash: Buffer,
  label: Option<String>,
  description: Option<String>,
  bytes: Option<BigInt>,
  owner_puzzle_hash: Buffer,
  delegated_puzzles: Vec<DelegatedPuzzle>,
  fee: BigInt,
) -> napi::Result<SuccessResponse> {
  let response = wallet::mint_store(
    RustPublicKey::from_js(minter_synthetic_key),
    selected_coins
      .into_iter()
      .map(|c| RustCoin::from_js(c))
      .collect(),
    RustBytes32::from_js(root_hash),
    label,
    description,
    bytes.map(|s| u64::from_js(s)),
    RustBytes32::from_js(owner_puzzle_hash),
    delegated_puzzles
      .iter()
      .map(|dp| RustDelegatedPuzzle::from_js(dp.clone()))
      .collect(),
    u64::from_js(fee),
  )
  .map_err(js)?;

  Ok(response.to_js())
}

#[napi]
/// Spends a store in oracle mode.
///
/// @param {Buffer} spenderSyntheticKey - Spender synthetic key.
/// @param {Vec<Coin>} selectedCoins - Selected coins, as returned by `select_coins`.
/// @param {DataStoreInfo} storeInfo - Up-to-daye store information.
/// @param {BigInt} fee - Transaction fee to use.
/// @returns {SuccessResponse} The success response, which includes coin spends and information about the new datastore.
pub fn oracle_spend(
  spender_synthetic_key: Buffer,
  selected_coins: Vec<Coin>,
  store_info: DataStoreInfo,
  fee: BigInt,
) -> napi::Result<SuccessResponse> {
  let response = wallet::oracle_spend(
    RustPublicKey::from_js(spender_synthetic_key),
    selected_coins
      .into_iter()
      .map(|c| RustCoin::from_js(c))
      .collect(),
    &RustDataStoreInfo::from_js(store_info),
    u64::from_js(fee),
  )
  .map_err(js)?;

  Ok(response.to_js())
}

#[napi]
/// Adds a fee to any transaction. Change will be sent to spender.
///
/// @param {Buffer} spenderSyntheticKey - Synthetic key of spender.
/// @param {Vec<Coin>} selectedCoins - Selected coins, as returned by `select_coins`.
/// @param {Vec<Buffer>} assertCoinIds - IDs of coins that need to be spent for the fee to be paid. Usually all coin ids in the original transaction.
/// @param {BigInt} fee - Fee to add.
/// @returns {Vec<CoinSpend>} The coin spends to be added to the original transaction.
pub fn add_fee(
  spender_synthetic_key: Buffer,
  selected_coins: Vec<Coin>,
  assert_coin_ids: Vec<Buffer>,
  fee: BigInt,
) -> napi::Result<Vec<CoinSpend>> {
  let response = wallet::add_fee(
    RustPublicKey::from_js(spender_synthetic_key),
    selected_coins
      .into_iter()
      .map(|c| RustCoin::from_js(c))
      .collect(),
    assert_coin_ids
      .into_iter()
      .map(|cid| RustBytes32::from_js(cid))
      .collect(),
    u64::from_js(fee),
  )
  .map_err(js)?;

  Ok(response.into_iter().map(|cs| cs.to_js()).collect())
}

#[napi]
/// Converts a master public key to a wallet synthetic key.
///
/// @param {Buffer} publicKey - Master public key.
/// @returns {Buffer} The (first) wallet synthetic key.
pub fn master_public_key_to_wallet_synthetic_key(public_key: Buffer) -> Buffer {
  let public_key = RustPublicKey::from_js(public_key);
  let wallet_pk = master_to_wallet_unhardened(&public_key, 0).derive_synthetic();
  wallet_pk.to_js()
}

#[napi]
/// Converts a master public key to the first puzzle hash.
///
/// @param {Buffer} publicKey - Master public key.
/// @returns {Buffer} The first wallet puzzle hash.
pub fn master_public_key_to_first_puzzle_hash(public_key: Buffer) -> Buffer {
  let public_key = RustPublicKey::from_js(public_key);
  let wallet_pk = master_to_wallet_unhardened(&public_key, 0).derive_synthetic();

  let puzzle_hash: RustBytes32 = StandardArgs::curry_tree_hash(wallet_pk).into();

  puzzle_hash.to_js()
}

#[napi]
/// Converts a master secret key to a wallet synthetic secret key.
///
/// @param {Buffer} secretKey - Master secret key.
/// @returns {Buffer} The (first) wallet synthetic secret key.
pub fn master_secret_key_to_wallet_synthetic_secret_key(secret_key: Buffer) -> Buffer {
  let secret_key = RustSecretKey::from_js(secret_key);
  let wallet_sk = master_to_wallet_unhardened(&secret_key, 0).derive_synthetic();
  wallet_sk.to_js()
}

#[napi]
/// Converts a secret key to its corresponding public key.
///
/// @param {Buffer} secretKey - The secret key.
/// @returns {Buffer} The public key.
pub fn secret_key_to_public_key(secret_key: Buffer) -> Buffer {
  let secret_key = RustSecretKey::from_js(secret_key);
  secret_key.public_key().to_js()
}

#[napi]
/// Converts a puzzle hash to an address by encoding it using bech32m.
///
/// @param {Buffer} puzzleHash - The puzzle hash.
/// @param {String} prefix - Address prefix (e.g., 'txch').
/// @returns {Promise<String>} The converted address.
pub fn puzzle_hash_to_address(puzzle_hash: Buffer, prefix: String) -> napi::Result<String> {
  let puzzle_hash = RustBytes32::from_js(puzzle_hash);

  encode_address(puzzle_hash.into(), &prefix).map_err(js)
}

#[napi]
/// Converts an address to a puzzle hash using bech32m.
///
/// @param {String} address - The address.
/// @returns {Promise<Buffer>} The puzzle hash.
pub fn address_to_puzzle_hash(address: String) -> napi::Result<Buffer> {
  let (puzzle_hash, _) = decode_address(&address).map_err(js)?;
  let puzzle_hash: RustBytes32 = RustBytes32::from_bytes(&puzzle_hash).map_err(js)?;

  Ok(puzzle_hash.to_js())
}

#[napi]
/// Creates an admin delegated puzzle for a given key.
///
/// @param {Buffer} syntheticKey - Synthetic key.
/// @returns {Promise<DelegatedPuzzle>} The delegated puzzle.
pub fn admin_delegated_puzzle_from_key(synthetic_key: Buffer) -> napi::Result<DelegatedPuzzle> {
  let synthetic_key = RustPublicKey::from_js(synthetic_key);

  let ctx: &mut SpendContext = &mut SpendContext::new();
  let (admin_dp, _) = RustDelegatedPuzzle::from_admin_pk(ctx, synthetic_key).map_err(js)?;

  Ok(admin_dp.to_js())
}

#[napi]
/// Creates a writer delegated puzzle from a given key.
///
/// @param {Buffer} syntheticKey - Synthetic key.
/// /// @returns {Promise<DelegatedPuzzle>} The delegated puzzle.
pub fn writer_delegated_puzzle_from_key(synthetic_key: Buffer) -> napi::Result<DelegatedPuzzle> {
  let synthetic_key = RustPublicKey::from_js(synthetic_key);

  let ctx: &mut SpendContext = &mut SpendContext::new();
  let (writer_dp, _) = RustDelegatedPuzzle::from_writer_pk(ctx, synthetic_key).map_err(js)?;

  Ok(writer_dp.to_js())
}

#[napi]
// Creates an oracle delegated puzzle.
///
/// @param {Buffer} oraclePuzzleHash - The oracle puzzle hash (corresponding to the wallet where fees should be paid).
/// @param {BigInt} oracleFee - The oracle fee (i.e., XCH amount to be paid for every oracle spend). This amount MUST be even.
/// @returns {Promise<DelegatedPuzzle>} The delegated puzzle.
pub fn oracle_delegated_puzzle(
  oracle_puzzle_hash: Buffer,
  oracle_fee: BigInt,
) -> napi::Result<DelegatedPuzzle> {
  let oracle_puzzle_hash = RustBytes32::from_js(oracle_puzzle_hash);
  let oracle_fee = u64::from_js(oracle_fee);

  let allocator: &mut Allocator = &mut Allocator::new();

  Ok(
    RustDelegatedPuzzle::new_oracle(allocator, oracle_puzzle_hash, oracle_fee)
      .map_err(js)?
      .to_js(),
  )
}

#[napi]
/// Partially or fully signs coin spends using a list of keys.
///
/// @param {Vec<CoinSpend>} coinSpends - The coin spends to sign.
/// @param {Vec<Buffer>} privateKeys - The private/secret keys to be used for signing.
/// @param {Buffer} aggSigData - Aggregated signature data. For testnet11 and mainnet, this is the same as the genesis challenge.
/// @returns {Promise<Buffer>} The signature.
pub fn sign_coin_spends(
  coin_spends: Vec<CoinSpend>,
  private_keys: Vec<Buffer>,
  agg_sig_data: Buffer,
) -> napi::Result<Buffer> {
  let coin_spends = coin_spends
    .iter()
    .map(|cs| RustCoinSpend::from_js(cs.clone()))
    .collect();
  let private_keys = private_keys
    .iter()
    .map(|sk| RustSecretKey::from_js(sk.clone()))
    .collect();
  let agg_sig_data = RustBytes32::from_js(agg_sig_data);

  let sig = wallet::sign_coin_spends(coin_spends, private_keys, agg_sig_data).map_err(js)?;

  Ok(sig.to_js())
}

#[napi]
/// Computes the ID (name) of a coin.
///
/// @param {Coin} coin - The coin.
/// @returns {Buffer} The coin ID.
pub fn get_coin_id(coin: Coin) -> Buffer {
  let coin = RustCoin::from_js(coin);

  coin.coin_id().to_js()
}

#[napi]
/// Updates the metadata of a store. Either the owner, admin, or writer public key must be provided.
///
/// @param {DataStoreInfo} storeInfo - Current store information.
/// @param {Buffer} newRootHash - New root hash.
/// @param {Option<String>} newLabel - New label (optional).
/// @param {Option<String>} newDescription - New description (optional).
/// @param {Option<BigInt>} newBytes - New size in bytes (optional).
/// @param {Option<Buffer>} ownerPublicKey - Owner public key.
/// @param {Option<Buffer>} adminPublicKey - Admin public key.
/// @param {Option<Buffer>} writerPublicKey - Writer public key.
/// @returns {SuccessResponse} The success response, which includes coin spends and information about the new datastore.
pub fn update_store_metadata(
  store_info: DataStoreInfo,
  new_root_hash: Buffer,
  new_label: Option<String>,
  new_description: Option<String>,
  new_bytes: Option<BigInt>,
  owner_public_key: Option<Buffer>,
  admin_public_key: Option<Buffer>,
  writer_public_key: Option<Buffer>,
) -> napi::Result<SuccessResponse> {
  let inner_spend_info = match (owner_public_key, admin_public_key, writer_public_key) {
    (Some(owner_public_key), None, None) => {
      DataStoreInnerSpendInfo::Owner(RustPublicKey::from_js(owner_public_key))
    }
    (None, Some(admin_public_key), None) => {
      DataStoreInnerSpendInfo::Admin(RustPublicKey::from_js(admin_public_key))
    }
    (None, None, Some(writer_public_key)) => {
      DataStoreInnerSpendInfo::Writer(RustPublicKey::from_js(writer_public_key))
    }
    _ => {
      return Err(js(
        "Exactly one of owner_public_key, admin_public_key, writer_public_key must be provided",
      ))
    }
  };

  let res = wallet::update_store_metadata(
    RustDataStoreInfo::from_js(store_info),
    RustBytes32::from_js(new_root_hash),
    new_label,
    new_description,
    new_bytes.map(|s| u64::from_js(s)),
    inner_spend_info,
  )
  .map_err(js)?;

  Ok(res.to_js())
}

#[napi]
/// Updates the ownership of a store. Either the admin or owner public key must be provided.
///
/// @param {DataStoreInfo} storeInfo - Store information.
/// @param {Option<Buffer>} newOwnerPuzzleHash - New owner puzzle hash.
/// @param {Vec<DelegatedPuzzle>} newDelegatedPuzzles - New delegated puzzles.
/// @param {Option<Buffer>} ownerPublicKey - Owner public key.
/// @param {Option<Buffer>} adminPublicKey - Admin public key.
/// @returns {SuccessResponse} The success response, which includes coin spends and information about the new datastore.
pub fn update_store_ownership(
  store_info: DataStoreInfo,
  new_owner_puzzle_hash: Option<Buffer>,
  new_delegated_puzzles: Vec<DelegatedPuzzle>,
  owner_public_key: Option<Buffer>,
  admin_public_key: Option<Buffer>,
) -> napi::Result<SuccessResponse> {
  let new_owner_puzzle_hash =
    new_owner_puzzle_hash.unwrap_or_else(|| store_info.owner_puzzle_hash.clone());

  let inner_spend_info = match (owner_public_key, admin_public_key) {
    (Some(owner_public_key), None) => {
      DataStoreInnerSpendInfo::Owner(RustPublicKey::from_js(owner_public_key))
    }
    (None, Some(admin_public_key)) => {
      DataStoreInnerSpendInfo::Admin(RustPublicKey::from_js(admin_public_key))
    }
    _ => {
      return Err(js(
        "Exactly one of owner_public_key, admin_public_key must be provided",
      ))
    }
  };

  let res = wallet::update_store_ownership(
    RustDataStoreInfo::from_js(store_info),
    RustBytes32::from_js(new_owner_puzzle_hash),
    new_delegated_puzzles
      .into_iter()
      .map(|dp| RustDelegatedPuzzle::from_js(dp))
      .collect(),
    inner_spend_info,
  )
  .map_err(js)?;

  Ok(res.to_js())
}

#[napi]
/// Melts a store. The 1 mojo change will be used as a fee.
///
/// @param {DataStoreInfo} storeInfo - Store information.
/// @param {Buffer} ownerPublicKey - Owner's public key.
/// @returns {Vec<CoinSpend>} The coin spends that the owner can sign to melt the store.
pub fn melt_store(
  store_info: DataStoreInfo,
  owner_public_key: Buffer,
) -> napi::Result<Vec<CoinSpend>> {
  let res = wallet::melt_store(
    &RustDataStoreInfo::from_js(store_info),
    RustPublicKey::from_js(owner_public_key),
  )
  .map_err(js)?;

  Ok(res.into_iter().map(|cs| cs.to_js()).collect())
}

fn js<T>(error: T) -> napi::Error
where
  T: ToString,
{
  napi::Error::from_reason(error.to_string())
}
