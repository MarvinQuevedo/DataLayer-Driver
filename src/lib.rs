mod wallet;

use chia::bls::{master_to_wallet_unhardened, PublicKey as RustPublicKey};
use chia::bls::{SecretKey as RustSecretKey, Signature as RustSignature};
use chia::protocol::Bytes32 as RustBytes32;
use chia::protocol::Program as RustProgram;
use chia::protocol::{Bytes as RustBytes, Coin as RustCoin};
use chia::protocol::{CoinSpend as RustCoinSpend, NewPeakWallet};
use chia::protocol::{ProtocolMessageTypes, SpendBundle as RustSpendBundle};
use chia::puzzles::standard::StandardArgs;
use chia::puzzles::LineageProof as RustLineageProof;
use chia::puzzles::Proof as RustProof;
use chia::puzzles::{DeriveSynthetic, EveProof as RustEveProof};
use chia::traits::Streamable;
use chia_wallet_sdk::Peer as RustPeer;
use chia_wallet_sdk::{
  connect_peer, create_tls_connector, decode_address, encode_address, load_ssl_cert, NetworkId,
};
use chia_wallet_sdk::{
  DataStore as RustDataStore, DataStoreInfo as RustDataStoreInfo,
  DataStoreMetadata as RustDataStoreMetadata, DelegatedPuzzle as RustDelegatedPuzzle,
};
use napi::bindgen_prelude::*;
use std::net::SocketAddr;
use std::result::Result as StdResult;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;
use wallet::SuccessResponse as RustSuccessResponse;
use wallet::SyncStoreResponse as RustSyncStoreResponse;
use wallet::UnspentCoinsResponse as RustUnspentCoinsResponse;
pub use wallet::*;

#[macro_use]
extern crate napi_derive;

#[derive(Error, Debug)]
pub enum ConversionError {
  #[error("Expected different byte length {0}")]
  DifferentLength(u32),

  #[error("Invalid public key")]
  InvalidPublicKey,

  #[error("Invalid private key")]
  InvalidPrivateKey,

  #[error("Invalid signature")]
  InvalidSignature,

  #[error("Missing proof")]
  MissingProof,

  #[error("Missing delegated puzzle info")]
  MissingDelegatedPuzzleInfo,

  #[error("Invalid URI: {0}")]
  InvalidUri(String),
}

pub trait FromJS<T> {
  fn from_js(value: T) -> StdResult<Self, napi::Error>
  where
    Self: Sized;
}

pub trait ToJS<T> {
  fn to_js(&self) -> StdResult<T, napi::Error>;
}

impl FromJS<Buffer> for RustBytes32 {
  fn from_js(value: Buffer) -> StdResult<Self, napi::Error> {
    RustBytes32::try_from(value.as_ref().to_vec())
      .map_err(|_| js(ConversionError::DifferentLength(32)))
  }
}

impl ToJS<Buffer> for RustBytes32 {
  fn to_js(&self) -> StdResult<Buffer, napi::Error> {
    Ok(Buffer::from(self.to_vec()))
  }
}

impl FromJS<Buffer> for RustProgram {
  fn from_js(value: Buffer) -> StdResult<Self, napi::Error> {
    Ok(RustProgram::from(value.to_vec()))
  }
}

impl ToJS<Buffer> for RustProgram {
  fn to_js(&self) -> StdResult<Buffer, napi::Error> {
    Ok(Buffer::from(self.to_vec()))
  }
}

impl FromJS<Buffer> for RustBytes {
  fn from_js(value: Buffer) -> StdResult<Self, napi::Error> {
    Ok(RustBytes::new(value.to_vec()))
  }
}

impl ToJS<Buffer> for RustBytes {
  fn to_js(&self) -> StdResult<Buffer, napi::Error> {
    Ok(Buffer::from(self.to_vec()))
  }
}

impl FromJS<Buffer> for RustPublicKey {
  fn from_js(value: Buffer) -> StdResult<Self, napi::Error> {
    RustPublicKey::from_bytes(
      &<[u8; 48]>::try_from(value.to_vec())
        .map_err(|_| js(ConversionError::DifferentLength(48)))?,
    )
    .map_err(|_| js(ConversionError::InvalidPublicKey))
  }
}

impl ToJS<Buffer> for RustPublicKey {
  fn to_js(&self) -> StdResult<Buffer, napi::Error> {
    Ok(Buffer::from(self.to_bytes().to_vec()))
  }
}

impl FromJS<Buffer> for RustSecretKey {
  fn from_js(value: Buffer) -> StdResult<Self, napi::Error> {
    RustSecretKey::from_bytes(
      &<[u8; 32]>::try_from(value.to_vec())
        .map_err(|_| js(ConversionError::DifferentLength(32)))?,
    )
    .map_err(|_| js(ConversionError::InvalidPrivateKey))
  }
}

impl ToJS<Buffer> for RustSecretKey {
  fn to_js(&self) -> StdResult<Buffer, napi::Error> {
    Ok(Buffer::from(self.to_bytes().to_vec()))
  }
}

impl FromJS<Buffer> for RustSignature {
  fn from_js(value: Buffer) -> StdResult<Self, napi::Error> {
    RustSignature::from_bytes(
      &<[u8; 96]>::try_from(value.to_vec())
        .map_err(|_| js(ConversionError::DifferentLength(96)))?,
    )
    .map_err(|_| js(ConversionError::InvalidSignature))
  }
}

impl ToJS<Buffer> for RustSignature {
  fn to_js(&self) -> StdResult<Buffer, napi::Error> {
    Ok(Buffer::from(self.to_bytes().to_vec()))
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
  fn from_js(value: BigInt) -> StdResult<Self, napi::Error> {
    Ok(value.get_u64().1)
  }
}

impl ToJS<BigInt> for u64 {
  fn to_js(&self) -> StdResult<BigInt, napi::Error> {
    Ok(BigInt::from(*self))
  }
}

impl FromJS<Coin> for RustCoin {
  fn from_js(value: Coin) -> StdResult<Self, napi::Error> {
    Ok(RustCoin {
      parent_coin_info: RustBytes32::from_js(value.parent_coin_info)?,
      puzzle_hash: RustBytes32::from_js(value.puzzle_hash)?,
      amount: u64::from_js(value.amount)?,
    })
  }
}

impl ToJS<Coin> for RustCoin {
  fn to_js(&self) -> StdResult<Coin, napi::Error> {
    Ok(Coin {
      parent_coin_info: self.parent_coin_info.to_js()?,
      puzzle_hash: self.puzzle_hash.to_js()?,
      amount: self.amount.to_js()?,
    })
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
  fn from_js(value: CoinSpend) -> StdResult<Self, napi::Error> {
    Ok(RustCoinSpend {
      coin: RustCoin::from_js(value.coin)?,
      puzzle_reveal: RustProgram::from_js(value.puzzle_reveal)?,
      solution: RustProgram::from_js(value.solution)?,
    })
  }
}

impl ToJS<CoinSpend> for RustCoinSpend {
  fn to_js(&self) -> StdResult<CoinSpend, napi::Error> {
    Ok(CoinSpend {
      coin: self.coin.to_js()?,
      puzzle_reveal: self.puzzle_reveal.to_js()?,
      solution: self.solution.to_js()?,
    })
  }
}

#[napi(object)]
#[derive(Clone)]
/// Represents a lineage proof that can be used to spend a singleton.
///
/// @property {Buffer} parentParentCoinInfo - Parent coin's parent coin info/name/ID.
/// @property {Buffer} parentInnerPuzzleHash - Parent coin's inner puzzle hash.
/// @property {BigInt} parentAmount - Parent coin's amount.
pub struct LineageProof {
  pub parent_parent_coin_info: Buffer,
  pub parent_inner_puzzle_hash: Buffer,
  pub parent_amount: BigInt,
}

impl FromJS<LineageProof> for RustLineageProof {
  fn from_js(value: LineageProof) -> StdResult<Self, napi::Error> {
    Ok(RustLineageProof {
      parent_parent_coin_info: RustBytes32::from_js(value.parent_parent_coin_info)?,
      parent_inner_puzzle_hash: RustBytes32::from_js(value.parent_inner_puzzle_hash)?,
      parent_amount: u64::from_js(value.parent_amount)?,
    })
  }
}

impl ToJS<LineageProof> for RustLineageProof {
  fn to_js(&self) -> StdResult<LineageProof, napi::Error> {
    Ok(LineageProof {
      parent_parent_coin_info: self.parent_parent_coin_info.to_js()?,
      parent_inner_puzzle_hash: self.parent_inner_puzzle_hash.to_js()?,
      parent_amount: self.parent_amount.to_js()?,
    })
  }
}

#[napi(object)]
#[derive(Clone)]
/// Represents an eve proof that can be used to spend a singleton. Parent coin is the singleton launcher.
///
/// @property {Buffer} parentParentCoinInfo - Parent coin's name.
/// @property {BigInt} parentAmount - Parent coin's amount.
pub struct EveProof {
  pub parent_parent_coin_info: Buffer,
  pub parent_amount: BigInt,
}

impl FromJS<EveProof> for RustEveProof {
  fn from_js(value: EveProof) -> StdResult<Self, napi::Error> {
    Ok(RustEveProof {
      parent_parent_coin_info: RustBytes32::from_js(value.parent_parent_coin_info)?,
      parent_amount: u64::from_js(value.parent_amount)?,
    })
  }
}

impl ToJS<EveProof> for RustEveProof {
  fn to_js(&self) -> StdResult<EveProof, napi::Error> {
    Ok(EveProof {
      parent_parent_coin_info: self.parent_parent_coin_info.to_js()?,
      parent_amount: self.parent_amount.to_js()?,
    })
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
  fn from_js(value: Proof) -> StdResult<Self, napi::Error> {
    if let Some(lineage_proof) = value.lineage_proof {
      Ok(RustProof::Lineage(RustLineageProof::from_js(
        lineage_proof,
      )?))
    } else if let Some(eve_proof) = value.eve_proof {
      Ok(RustProof::Eve(RustEveProof::from_js(eve_proof)?))
    } else {
      Err(js(ConversionError::MissingProof))
    }
  }
}

impl ToJS<Proof> for RustProof {
  fn to_js(&self) -> StdResult<Proof, napi::Error> {
    Ok(match self {
      RustProof::Lineage(lineage_proof) => Proof {
        lineage_proof: Some(lineage_proof.to_js()?),
        eve_proof: None,
      },
      RustProof::Eve(eve_proof) => Proof {
        lineage_proof: None,
        eve_proof: Some(eve_proof.to_js()?),
      },
    })
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
  fn from_js(value: DataStoreMetadata) -> StdResult<Self, napi::Error> {
    Ok(RustDataStoreMetadata {
      root_hash: RustBytes32::from_js(value.root_hash)?,
      label: value.label,
      description: value.description,
      bytes: if let Some(bytes) = value.bytes {
        Some(u64::from_js(bytes)?)
      } else {
        None
      },
    })
  }
}

impl ToJS<DataStoreMetadata> for RustDataStoreMetadata {
  fn to_js(&self) -> StdResult<DataStoreMetadata, napi::Error> {
    Ok(DataStoreMetadata {
      root_hash: self.root_hash.to_js()?,
      label: self.label.clone(),
      description: self.description.clone(),
      bytes: if let Some(bytes) = self.bytes {
        Some(bytes.to_js()?)
      } else {
        None
      },
    })
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
pub struct DelegatedPuzzle {
  pub admin_inner_puzzle_hash: Option<Buffer>,
  pub writer_inner_puzzle_hash: Option<Buffer>,
  pub oracle_payment_puzzle_hash: Option<Buffer>,
  pub oracle_fee: Option<BigInt>,
}

impl FromJS<DelegatedPuzzle> for RustDelegatedPuzzle {
  fn from_js(value: DelegatedPuzzle) -> StdResult<Self, napi::Error> {
    Ok(
      if let Some(admin_inner_puzzle_hash) = value.admin_inner_puzzle_hash {
        RustDelegatedPuzzle::Admin(RustBytes32::from_js(admin_inner_puzzle_hash)?.into())
      } else if let Some(writer_inner_puzzle_hash) = value.writer_inner_puzzle_hash {
        RustDelegatedPuzzle::Writer(RustBytes32::from_js(writer_inner_puzzle_hash)?.into())
      } else if let (Some(oracle_payment_puzzle_hash), Some(oracle_fee)) =
        (value.oracle_payment_puzzle_hash, value.oracle_fee)
      {
        RustDelegatedPuzzle::Oracle(
          RustBytes32::from_js(oracle_payment_puzzle_hash)?,
          u64::from_js(oracle_fee)?,
        )
      } else {
        return Err(js(ConversionError::MissingDelegatedPuzzleInfo));
      },
    )
  }
}

impl ToJS<DelegatedPuzzle> for RustDelegatedPuzzle {
  fn to_js(&self) -> StdResult<DelegatedPuzzle, napi::Error> {
    match self {
      RustDelegatedPuzzle::Admin(admin_inner_puzzle_hash) => {
        let admin_inner_puzzle_hash: RustBytes32 = (*admin_inner_puzzle_hash).into();

        Ok(DelegatedPuzzle {
          admin_inner_puzzle_hash: Some(admin_inner_puzzle_hash.to_js()?),
          writer_inner_puzzle_hash: None,
          oracle_payment_puzzle_hash: None,
          oracle_fee: None,
        })
      }
      RustDelegatedPuzzle::Writer(writer_inner_puzzle_hash) => {
        let writer_inner_puzzle_hash: RustBytes32 = (*writer_inner_puzzle_hash).into();

        Ok(DelegatedPuzzle {
          admin_inner_puzzle_hash: None,
          writer_inner_puzzle_hash: Some(writer_inner_puzzle_hash.to_js()?),
          oracle_payment_puzzle_hash: None,
          oracle_fee: None,
        })
      }
      RustDelegatedPuzzle::Oracle(oracle_payment_puzzle_hash, oracle_fee) => {
        let oracle_payment_puzzle_hash: RustBytes32 = *oracle_payment_puzzle_hash;

        Ok(DelegatedPuzzle {
          admin_inner_puzzle_hash: None,
          writer_inner_puzzle_hash: None,
          oracle_payment_puzzle_hash: Some(oracle_payment_puzzle_hash.to_js()?),
          oracle_fee: Some(oracle_fee.to_js()?),
        })
      }
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
pub struct DataStore {
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

impl FromJS<DataStore> for RustDataStore {
  fn from_js(value: DataStore) -> StdResult<Self, napi::Error> {
    Ok(RustDataStore {
      coin: RustCoin::from_js(value.coin)?,
      proof: RustProof::from_js(value.proof)?,

      info: RustDataStoreInfo {
        launcher_id: RustBytes32::from_js(value.launcher_id)?,
        metadata: RustDataStoreMetadata::from_js(value.metadata)?,
        owner_puzzle_hash: RustBytes32::from_js(value.owner_puzzle_hash)?,
        delegated_puzzles: value
          .delegated_puzzles
          .into_iter()
          .map(RustDelegatedPuzzle::from_js)
          .collect::<StdResult<Vec<RustDelegatedPuzzle>, napi::Error>>()?,
      },
    })
  }
}

impl ToJS<DataStore> for RustDataStore {
  fn to_js(&self) -> StdResult<DataStore, napi::Error> {
    Ok(DataStore {
      coin: self.coin.to_js()?,
      proof: self.proof.to_js()?,

      launcher_id: self.info.launcher_id.to_js()?,
      metadata: self.info.metadata.to_js()?,
      owner_puzzle_hash: self.info.owner_puzzle_hash.to_js()?,
      delegated_puzzles: self
        .info
        .delegated_puzzles
        .iter()
        .map(RustDelegatedPuzzle::to_js)
        .collect::<StdResult<Vec<DelegatedPuzzle>, napi::Error>>()?,
    })
  }
}

#[napi(object)]
// Represents a driver response indicating success.
///
/// @property {Vec<CoinSpend>} coinSpends - Coin spends that can be used to spend the provided store.
/// @property {DataStore} newStore - New data store information after the spend is confirmed.
pub struct SuccessResponse {
  pub coin_spends: Vec<CoinSpend>,
  pub new_store: DataStore,
}

impl FromJS<SuccessResponse> for RustSuccessResponse {
  fn from_js(value: SuccessResponse) -> StdResult<Self, napi::Error> {
    Ok(RustSuccessResponse {
      coin_spends: value
        .coin_spends
        .into_iter()
        .map(RustCoinSpend::from_js)
        .collect::<StdResult<Vec<RustCoinSpend>, napi::Error>>()?,
      new_datastore: RustDataStore::from_js(value.new_store)?,
    })
  }
}

impl ToJS<SuccessResponse> for RustSuccessResponse {
  fn to_js(&self) -> StdResult<SuccessResponse, napi::Error> {
    Ok(SuccessResponse {
      coin_spends: self
        .coin_spends
        .iter()
        .map(RustCoinSpend::to_js)
        .collect::<StdResult<Vec<CoinSpend>, napi::Error>>()?,
      new_store: self.new_datastore.to_js()?,
    })
  }
}

#[napi(object)]
/// Represents a response from synchronizing a store.
///
/// @property {DataStore} latestStore - Latest data store information.
/// @property {Option<Vec<Buffer>>} rootHashes - When synced with whistory, this list will contain all of the store's previous root hashes. Otherwise null.
/// @property {Option<Vec<BigInt>>} rootHashesTimestamps - Timestamps of the root hashes (see `rootHashes`).
/// @property {u32} latestHeight - Latest sync height.
pub struct SyncStoreResponse {
  pub latest_store: DataStore,
  pub root_hashes: Option<Vec<Buffer>>,
  pub root_hashes_timestamps: Option<Vec<BigInt>>,
  pub latest_height: u32,
}

impl FromJS<SyncStoreResponse> for RustSyncStoreResponse {
  fn from_js(value: SyncStoreResponse) -> StdResult<Self, napi::Error> {
    let mut root_hash_history = None;

    if let (Some(root_hashes), Some(root_hashes_timestamps)) =
      (value.root_hashes, value.root_hashes_timestamps)
    {
      let mut v = vec![];

      for (root_hash, timestamp) in root_hashes
        .into_iter()
        .zip(root_hashes_timestamps.into_iter())
      {
        v.push((RustBytes32::from_js(root_hash)?, u64::from_js(timestamp)?));
      }

      root_hash_history = Some(v);
    }

    Ok(RustSyncStoreResponse {
      latest_store: RustDataStore::from_js(value.latest_store)?,
      latest_height: value.latest_height,
      root_hash_history,
    })
  }
}
impl ToJS<SyncStoreResponse> for RustSyncStoreResponse {
  fn to_js(&self) -> StdResult<SyncStoreResponse, napi::Error> {
    let root_hashes = self
      .root_hash_history
      .as_ref()
      .map(|v| {
        v.iter()
          .map(|(rh, _)| rh.to_js())
          .collect::<StdResult<Vec<Buffer>, napi::Error>>()
      })
      .transpose()?;

    let root_hashes_timestamps = self
      .root_hash_history
      .as_ref()
      .map(|v| {
        v.iter()
          .map(|(_, ts)| ts.to_js())
          .collect::<StdResult<Vec<BigInt>, napi::Error>>()
      })
      .transpose()?;

    Ok(SyncStoreResponse {
      latest_store: self.latest_store.to_js()?,
      latest_height: self.latest_height,
      root_hashes,
      root_hashes_timestamps,
    })
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
  fn from_js(value: UnspentCoinsResponse) -> StdResult<Self, napi::Error> {
    Ok(RustUnspentCoinsResponse {
      coins: value
        .coins
        .into_iter()
        .map(RustCoin::from_js)
        .collect::<StdResult<Vec<RustCoin>, napi::Error>>()?,
      last_height: value.last_height,
      last_header_hash: RustBytes32::from_js(value.last_header_hash)?,
    })
  }
}

impl ToJS<UnspentCoinsResponse> for RustUnspentCoinsResponse {
  fn to_js(&self) -> StdResult<UnspentCoinsResponse, napi::Error> {
    Ok(UnspentCoinsResponse {
      coins: self
        .coins
        .iter()
        .map(RustCoin::to_js)
        .collect::<StdResult<Vec<Coin>, napi::Error>>()?,
      last_height: self.last_height,
      last_header_hash: self.last_header_hash.to_js()?,
    })
  }
}

#[napi]
pub struct Peer {
  inner: Arc<RustPeer>,
  peak: Arc<Mutex<Option<NewPeakWallet>>>,
}

#[napi]
impl Peer {
  #[napi(factory)]
  /// Creates a new Peer instance.
  ///
  /// @param {String} nodeUri - URI of the node (e.g., '127.0.0.1:58444').
  /// @param {bool} testnet - True for connecting to testnet11, false for mainnet.
  /// @param {String} certPath - Path to the certificate file (usually '~/.chia/mainnet/config/ssl/wallet/wallet_node.crt').
  /// @param {String} keyPath - Path to the key file (usually '~/.chia/mainnet/config/ssl/wallet/wallet_node.key').
  /// @returns {Promise<Peer>} A new Peer instance.
  pub async fn new(
    node_uri: String,
    tesntet: bool,
    cert_path: String,
    key_path: String,
  ) -> napi::Result<Self> {
    let cert = load_ssl_cert(&cert_path, &key_path).map_err(js)?;
    let tls = create_tls_connector(&cert).map_err(js)?;
    let (peer, mut receiver) = connect_peer(
      if tesntet {
        NetworkId::Testnet11
      } else {
        NetworkId::Mainnet
      },
      tls,
      if let Ok(socket_addr) = node_uri.parse::<SocketAddr>() {
        socket_addr
      } else {
        return Err(js(ConversionError::InvalidUri(node_uri)));
      },
    )
    .await
    .map_err(js)?;

    let inner = Arc::new(peer);
    let peak = Arc::new(Mutex::new(None));

    let peak_clone = peak.clone();
    tokio::spawn(async move {
      while let Some(message) = receiver.recv().await {
        if message.msg_type == ProtocolMessageTypes::NewPeakWallet {
          if let Ok(new_peak) = NewPeakWallet::from_bytes(&message.data) {
            let mut peak_guard = peak_clone.lock().await;
            *peak_guard = Some(new_peak);
          }
        }
      }
    });

    Ok(Self { inner, peak })
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
      &self.inner.clone(),
      RustBytes32::from_js(puzzle_hash)?,
      previous_height,
      RustBytes32::from_js(previous_header_hash)?,
    )
    .await
    .map_err(js)?;

    resp.to_js()
  }

  #[napi]
  /// Synchronizes a datastore.
  ///
  /// @param {DataStore} store - Data store.
  /// @param {Option<u32>} lastHeight - Min. height to search records from. If null, sync will be done from the genesis block.
  /// @param {Buffer} lastHeaderHash - Header hash corresponding to `lastHeight`. If null, this should be the genesis challenge of the current chain.
  /// @param {bool} withHistory - Whether to return the root hash history of the store.
  /// @returns {Promise<SyncStoreResponse>} The sync store response.
  pub async fn sync_store(
    &self,
    store: DataStore,
    last_height: Option<u32>,
    last_header_hash: Buffer,
    with_history: bool,
  ) -> napi::Result<SyncStoreResponse> {
    let res = sync_store(
      &self.inner.clone(),
      &RustDataStore::from_js(store)?,
      last_height,
      RustBytes32::from_js(last_header_hash)?,
      with_history,
    )
    .await
    .map_err(js)?;

    res.to_js()
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
      &self.inner.clone(),
      RustBytes32::from_js(launcher_id)?,
      last_height,
      RustBytes32::from_js(last_header_hash)?,
      with_history,
    )
    .await
    .map_err(js)?;

    res.to_js()
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
    let mut agg_sig = RustSignature::default();
    for sig in sigs.into_iter() {
      agg_sig += &RustSignature::from_js(sig)?;
    }

    let spend_bundle = RustSpendBundle::new(
      coin_spends
        .into_iter()
        .map(RustCoinSpend::from_js)
        .collect::<StdResult<Vec<RustCoinSpend>, napi::Error>>()?,
      agg_sig,
    );

    Ok(
      wallet::broadcast_spend_bundle(&self.inner.clone(), spend_bundle)
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
    is_coin_spent(
      &self.inner.clone(),
      RustBytes32::from_js(coin_id)?,
      last_height,
      RustBytes32::from_js(header_hash)?,
    )
    .await
    .map_err(js)
  }

  #[napi]
  /// Retrieves the current header hash corresponding to a given height.
  ///
  /// @param {u32} height - The height.
  /// @returns {Promise<Buffer>} The header hash.
  pub async fn get_header_hash(&self, height: u32) -> napi::Result<Buffer> {
    get_header_hash(&self.inner.clone(), height)
      .await
      .map_err(js)?
      .to_js()
  }

  #[napi]
  /// Retrieves the fee estimate for a given target time.
  ///
  /// @param {Peer} peer - The peer connection to the Chia node.
  /// @param {BigInt} targetTimeSeconds - Time delta: The target time in seconds from the current time for the fee estimate.
  /// @returns {Promise<BigInt>} The estimated fee in mojos per CLVM cost.
  pub async fn get_fee_estimate(&self, target_time_seconds: BigInt) -> napi::Result<BigInt> {
    wallet::get_fee_estimate(&self.inner.clone(), u64::from_js(target_time_seconds)?)
      .await
      .map_err(js)?
      .to_js()
  }

  #[napi]
  /// Retrieves the peer's peak.
  ///
  /// @returns {Option<u32>} A tuple consiting of the latest synced block's height, as reported by the peer. Null if the peer has not yet reported a peak.
  pub async fn get_peak(&self) -> napi::Result<Option<u32>> {
    let peak_guard = self.peak.lock().await;
    let peak: Option<NewPeakWallet> = peak_guard.clone();
    Ok(peak.map(|p| p.height))
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
    .map(RustCoin::from_js)
    .collect::<StdResult<Vec<RustCoin>, napi::Error>>()?;
  let selected_coins = wallet::select_coins(coins, u64::from_js(total_amount)?).map_err(js)?;

  selected_coins
    .into_iter()
    .map(|c| c.to_js())
    .collect::<StdResult<Vec<Coin>, napi::Error>>()
}

#[allow(clippy::too_many_arguments)]
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
    RustPublicKey::from_js(minter_synthetic_key)?,
    selected_coins
      .into_iter()
      .map(RustCoin::from_js)
      .collect::<StdResult<Vec<RustCoin>, napi::Error>>()?,
    RustBytes32::from_js(root_hash)?,
    label,
    description,
    if let Some(bytes) = bytes {
      Some(u64::from_js(bytes)?)
    } else {
      None
    },
    RustBytes32::from_js(owner_puzzle_hash)?,
    delegated_puzzles
      .into_iter()
      .map(RustDelegatedPuzzle::from_js)
      .collect::<StdResult<Vec<RustDelegatedPuzzle>, napi::Error>>()?,
    u64::from_js(fee).map_err(js)?,
  )
  .map_err(js)?;

  response.to_js()
}

#[napi]
/// Spends a store in oracle mode.
///
/// @param {Buffer} spenderSyntheticKey - Spender synthetic key.
/// @param {Vec<Coin>} selectedCoins - Selected coins, as returned by `select_coins`.
/// @param {DataStore} store - Up-to-daye store information.
/// @param {BigInt} fee - Transaction fee to use.
/// @returns {SuccessResponse} The success response, which includes coin spends and information about the new datastore.
pub fn oracle_spend(
  spender_synthetic_key: Buffer,
  selected_coins: Vec<Coin>,
  store: DataStore,
  fee: BigInt,
) -> napi::Result<SuccessResponse> {
  let response = wallet::oracle_spend(
    RustPublicKey::from_js(spender_synthetic_key)?,
    selected_coins
      .into_iter()
      .map(RustCoin::from_js)
      .collect::<StdResult<Vec<RustCoin>, napi::Error>>()?,
    RustDataStore::from_js(store)?,
    u64::from_js(fee)?,
  )
  .map_err(js)?;

  response.to_js()
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
    RustPublicKey::from_js(spender_synthetic_key)?,
    selected_coins
      .into_iter()
      .map(RustCoin::from_js)
      .collect::<StdResult<Vec<RustCoin>, napi::Error>>()?,
    assert_coin_ids
      .into_iter()
      .map(RustBytes32::from_js)
      .collect::<StdResult<Vec<RustBytes32>, napi::Error>>()?,
    u64::from_js(fee)?,
  )
  .map_err(js)?;

  response
    .into_iter()
    .map(|cs| cs.to_js())
    .collect::<StdResult<Vec<CoinSpend>, napi::Error>>()
}

#[napi]
/// Converts a master public key to a wallet synthetic key.
///
/// @param {Buffer} publicKey - Master public key.
/// @returns {Buffer} The (first) wallet synthetic key.
pub fn master_public_key_to_wallet_synthetic_key(public_key: Buffer) -> napi::Result<Buffer> {
  let public_key = RustPublicKey::from_js(public_key)?;
  let wallet_pk = master_to_wallet_unhardened(&public_key, 0).derive_synthetic();
  wallet_pk.to_js()
}

#[napi]
/// Converts a master public key to the first puzzle hash.
///
/// @param {Buffer} publicKey - Master public key.
/// @returns {Buffer} The first wallet puzzle hash.
pub fn master_public_key_to_first_puzzle_hash(public_key: Buffer) -> napi::Result<Buffer> {
  let public_key = RustPublicKey::from_js(public_key)?;
  let wallet_pk = master_to_wallet_unhardened(&public_key, 0).derive_synthetic();

  let puzzle_hash: RustBytes32 = StandardArgs::curry_tree_hash(wallet_pk).into();

  puzzle_hash.to_js()
}

#[napi]
/// Converts a master secret key to a wallet synthetic secret key.
///
/// @param {Buffer} secretKey - Master secret key.
/// @returns {Buffer} The (first) wallet synthetic secret key.
pub fn master_secret_key_to_wallet_synthetic_secret_key(
  secret_key: Buffer,
) -> napi::Result<Buffer> {
  let secret_key = RustSecretKey::from_js(secret_key)?;
  let wallet_sk = master_to_wallet_unhardened(&secret_key, 0).derive_synthetic();
  wallet_sk.to_js()
}

#[napi]
/// Converts a secret key to its corresponding public key.
///
/// @param {Buffer} secretKey - The secret key.
/// @returns {Buffer} The public key.
pub fn secret_key_to_public_key(secret_key: Buffer) -> napi::Result<Buffer> {
  let secret_key = RustSecretKey::from_js(secret_key)?;
  secret_key.public_key().to_js()
}

#[napi]
/// Converts a puzzle hash to an address by encoding it using bech32m.
///
/// @param {Buffer} puzzleHash - The puzzle hash.
/// @param {String} prefix - Address prefix (e.g., 'txch').
/// @returns {Promise<String>} The converted address.
pub fn puzzle_hash_to_address(puzzle_hash: Buffer, prefix: String) -> napi::Result<String> {
  let puzzle_hash = RustBytes32::from_js(puzzle_hash)?;

  encode_address(puzzle_hash.into(), &prefix).map_err(js)
}

#[napi]
/// Converts an address to a puzzle hash using bech32m.
///
/// @param {String} address - The address.
/// @returns {Promise<Buffer>} The puzzle hash.
pub fn address_to_puzzle_hash(address: String) -> napi::Result<Buffer> {
  let (puzzle_hash, _) = decode_address(&address).map_err(js)?;
  let puzzle_hash: RustBytes32 = RustBytes32::new(puzzle_hash);

  puzzle_hash.to_js()
}

#[napi]
/// Creates an admin delegated puzzle for a given key.
///
/// @param {Buffer} syntheticKey - Synthetic key.
/// @returns {Promise<DelegatedPuzzle>} The delegated puzzle.
pub fn admin_delegated_puzzle_from_key(synthetic_key: Buffer) -> napi::Result<DelegatedPuzzle> {
  let synthetic_key = RustPublicKey::from_js(synthetic_key)?;

  RustDelegatedPuzzle::Admin(StandardArgs::curry_tree_hash(synthetic_key)).to_js()
}

#[napi]
/// Creates a writer delegated puzzle from a given key.
///
/// @param {Buffer} syntheticKey - Synthetic key.
/// /// @returns {Promise<DelegatedPuzzle>} The delegated puzzle.
pub fn writer_delegated_puzzle_from_key(synthetic_key: Buffer) -> napi::Result<DelegatedPuzzle> {
  let synthetic_key = RustPublicKey::from_js(synthetic_key)?;

  RustDelegatedPuzzle::Writer(StandardArgs::curry_tree_hash(synthetic_key)).to_js()
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
  let oracle_puzzle_hash = RustBytes32::from_js(oracle_puzzle_hash)?;
  let oracle_fee = u64::from_js(oracle_fee)?;

  RustDelegatedPuzzle::Oracle(oracle_puzzle_hash, oracle_fee).to_js()
}

#[napi]
/// Partially or fully signs coin spends using a list of keys.
///
/// @param {Vec<CoinSpend>} coinSpends - The coin spends to sign.
/// @param {Vec<Buffer>} privateKeys - The private/secret keys to be used for signing.
/// @param {Buffer} forTestnet - Set to true to sign spends for testnet11, false for mainnet.
/// @returns {Promise<Buffer>} The signature.
pub fn sign_coin_spends(
  coin_spends: Vec<CoinSpend>,
  private_keys: Vec<Buffer>,
  for_testnet: bool,
) -> napi::Result<Buffer> {
  let coin_spends = coin_spends
    .iter()
    .map(|cs| RustCoinSpend::from_js(cs.clone()))
    .collect::<StdResult<Vec<RustCoinSpend>, napi::Error>>()?;
  let private_keys = private_keys
    .iter()
    .map(|sk| RustSecretKey::from_js(sk.clone()))
    .collect::<StdResult<Vec<RustSecretKey>, napi::Error>>()?;

  let sig = wallet::sign_coin_spends(
    coin_spends,
    private_keys,
    if for_testnet {
      TargetNetwork::Testnet11
    } else {
      TargetNetwork::Mainnet
    },
  )
  .map_err(js)?;

  sig.to_js()
}

#[napi]
/// Computes the ID (name) of a coin.
///
/// @param {Coin} coin - The coin.
/// @returns {Buffer} The coin ID.
pub fn get_coin_id(coin: Coin) -> napi::Result<Buffer> {
  RustCoin::from_js(coin)?.coin_id().to_js()
}

#[allow(clippy::too_many_arguments)]
#[napi]
/// Updates the metadata of a store. Either the owner, admin, or writer public key must be provided.
///
/// @param {DataStore} store - Current store information.
/// @param {Buffer} newRootHash - New root hash.
/// @param {Option<String>} newLabel - New label (optional).
/// @param {Option<String>} newDescription - New description (optional).
/// @param {Option<BigInt>} newBytes - New size in bytes (optional).
/// @param {Option<Buffer>} ownerPublicKey - Owner public key.
/// @param {Option<Buffer>} adminPublicKey - Admin public key.
/// @param {Option<Buffer>} writerPublicKey - Writer public key.
/// @returns {SuccessResponse} The success response, which includes coin spends and information about the new datastore.
pub fn update_store_metadata(
  store: DataStore,
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
      DataStoreInnerSpend::Owner(RustPublicKey::from_js(owner_public_key)?)
    }
    (None, Some(admin_public_key), None) => {
      DataStoreInnerSpend::Admin(RustPublicKey::from_js(admin_public_key)?)
    }
    (None, None, Some(writer_public_key)) => {
      DataStoreInnerSpend::Writer(RustPublicKey::from_js(writer_public_key)?)
    }
    _ => {
      return Err(js(
        "Exactly one of owner_public_key, admin_public_key, writer_public_key must be provided",
      ))
    }
  };

  let res = wallet::update_store_metadata(
    RustDataStore::from_js(store)?,
    RustBytes32::from_js(new_root_hash)?,
    new_label,
    new_description,
    if let Some(bytes) = new_bytes {
      Some(u64::from_js(bytes)?)
    } else {
      None
    },
    inner_spend_info,
  )
  .map_err(js)?;

  res.to_js()
}

#[napi]
/// Updates the ownership of a store. Either the admin or owner public key must be provided.
///
/// @param {DataStore} store - Store information.
/// @param {Option<Buffer>} newOwnerPuzzleHash - New owner puzzle hash.
/// @param {Vec<DelegatedPuzzle>} newDelegatedPuzzles - New delegated puzzles.
/// @param {Option<Buffer>} ownerPublicKey - Owner public key.
/// @param {Option<Buffer>} adminPublicKey - Admin public key.
/// @returns {SuccessResponse} The success response, which includes coin spends and information about the new datastore.
pub fn update_store_ownership(
  store: DataStore,
  new_owner_puzzle_hash: Option<Buffer>,
  new_delegated_puzzles: Vec<DelegatedPuzzle>,
  owner_public_key: Option<Buffer>,
  admin_public_key: Option<Buffer>,
) -> napi::Result<SuccessResponse> {
  let store = RustDataStore::from_js(store)?;
  let new_owner_puzzle_hash = new_owner_puzzle_hash
    .map(RustBytes32::from_js)
    .unwrap_or_else(|| Ok(store.info.owner_puzzle_hash))?;

  let inner_spend_info = match (owner_public_key, admin_public_key) {
    (Some(owner_public_key), None) => {
      DataStoreInnerSpend::Owner(RustPublicKey::from_js(owner_public_key)?)
    }
    (None, Some(admin_public_key)) => {
      DataStoreInnerSpend::Admin(RustPublicKey::from_js(admin_public_key)?)
    }
    _ => {
      return Err(js(
        "Exactly one of owner_public_key, admin_public_key must be provided",
      ))
    }
  };

  let res = wallet::update_store_ownership(
    store,
    new_owner_puzzle_hash,
    new_delegated_puzzles
      .into_iter()
      .map(RustDelegatedPuzzle::from_js)
      .collect::<StdResult<Vec<RustDelegatedPuzzle>, napi::Error>>()?,
    inner_spend_info,
  )
  .map_err(js)?;

  res.to_js()
}

#[napi]
/// Melts a store. The 1 mojo change will be used as a fee.
///
/// @param {DataStore} store - Store information.
/// @param {Buffer} ownerPublicKey - Owner's public key.
/// @returns {Vec<CoinSpend>} The coin spends that the owner can sign to melt the store.
pub fn melt_store(store: DataStore, owner_public_key: Buffer) -> napi::Result<Vec<CoinSpend>> {
  let res = wallet::melt_store(
    RustDataStore::from_js(store)?,
    RustPublicKey::from_js(owner_public_key)?,
  )
  .map_err(js)?;

  res
    .into_iter()
    .map(|cs| cs.to_js())
    .collect::<StdResult<Vec<CoinSpend>, napi::Error>>()
}

#[napi]
/// Signs a message using the provided private key.
///
/// @param {Buffer} message - Message to sign, as bytes. "Chia Signed Message" will be prepended automatically, as per CHIP-2 - no need to add it before calling this function.
/// @param {Buffer} private_key - Private key to sign the message with. No derivation is done.
/// @returns {Buffer} The signature.
pub fn sign_message(message: Buffer, private_key: Buffer) -> napi::Result<Buffer> {
  wallet::sign_message(
    RustBytes::from_js(message)?,
    RustSecretKey::from_js(private_key)?,
  )
  .map_err(js)?
  .to_js()
}

#[napi]
/// Verifies a signed message using the provided public key.
///
/// @param {Buffer} signature - Th signature to be verified.
/// @param {Buffer} public_key - Public key corresponding to the private key that was used to sign the message.
/// @param {Buffer} message - Message that was signed, as bytes. "Chia Signed Message" will be prepended automatically, as per CHIP-2 - no need to add it before calling this function.
/// @returns {Buffer} Boolean - true indicates that the signature is valid, while false indicates that it is not.
pub fn verify_signed_message(
  signature: Buffer,
  public_key: Buffer,
  message: Buffer,
) -> napi::Result<bool> {
  wallet::verify_signature(
    RustBytes::from_js(message)?,
    RustPublicKey::from_js(public_key)?,
    RustSignature::from_js(signature)?,
  )
  .map_err(js)
}

#[napi]
/// Converts a synthetic key to its corresponding standard puzzle hash.
///
/// @param {Buffer} syntheticKey - Synthetic key.
/// @returns {Buffer} The standard puzzle (puzzle) hash.
pub fn synthetic_key_to_puzzle_hash(synthetic_key: Buffer) -> napi::Result<Buffer> {
  let puzzle_hash: RustBytes32 =
    StandardArgs::curry_tree_hash(RustPublicKey::from_js(synthetic_key)?).into();

  puzzle_hash.to_js()
}

#[napi]
/// Calculates the total cost of a given array of coin spends/
///
/// @param {Vec<CoinSpend>} CoinSpend - Coin spends.
/// @returns {BigInt} The cost of the coin spends.
pub fn get_cost(coin_spends: Vec<CoinSpend>) -> napi::Result<BigInt> {
  wallet::get_cost(
    coin_spends
      .into_iter()
      .map(RustCoinSpend::from_js)
      .collect::<StdResult<Vec<RustCoinSpend>, napi::Error>>()?,
  )
  .map_err(js)?
  .to_js()
}

fn js<T>(error: T) -> napi::Error
where
  T: ToString,
{
  napi::Error::from_reason(error.to_string())
}
