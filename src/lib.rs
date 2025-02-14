#![allow(unexpected_cfgs)]

mod conversions;
mod js;
mod rust;
mod server_coin;
mod wallet;

use chia::bls::{
    master_to_wallet_unhardened, PublicKey as RustPublicKey, SecretKey as RustSecretKey,
    Signature as RustSignature,
};
use chia::protocol::{
    Bytes as RustBytes, Bytes32 as RustBytes32, Coin as RustCoin, CoinSpend as RustCoinSpend,
    CoinStateUpdate, NewPeakWallet, ProtocolMessageTypes, SpendBundle as RustSpendBundle,
};
use chia::puzzles::nft::NftMetadata as RustNftMetadata;
use chia::puzzles::{standard::StandardArgs, DeriveSynthetic, Proof as RustProof};
use chia::traits::Streamable;
use chia_wallet_sdk::{
    connect_peer, create_native_tls_connector, decode_address, encode_address, load_ssl_cert,
    Connector, DataStore as RustDataStore, DataStoreInfo as RustDataStoreInfo,
    DataStoreMetadata as RustDataStoreMetadata, DelegatedPuzzle as RustDelegatedPuzzle,
    Did as RustDid, Nft, Peer as RustPeer, PeerOptions, MAINNET_CONSTANTS, TESTNET11_CONSTANTS,
};
use conversions::{ConversionError, FromJs, ToJs};
use js::{Coin, CoinSpend, CoinState, EveProof, Proof, ServerCoin};
use napi::bindgen_prelude::*;
use napi::Result;
use std::collections::HashMap;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::Mutex;
use wallet::{
    PossibleLaunchersResponse as RustPossibleLaunchersResponse,
    SuccessResponse as RustSuccessResponse, SyncStoreResponse as RustSyncStoreResponse,
};

pub use wallet::*;

#[macro_use]
extern crate napi_derive;

#[napi]
/// Creates a new lineage proof.
///
/// @param {LineageProof} lineageProof - The lineage proof.
/// @returns {Proof} The new proof.
pub fn new_lineage_proof(lineage_proof: js::LineageProof) -> js::Proof {
    js::Proof {
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

impl FromJs<DataStoreMetadata> for RustDataStoreMetadata {
    fn from_js(value: DataStoreMetadata) -> Result<Self> {
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

impl ToJs<DataStoreMetadata> for RustDataStoreMetadata {
    fn to_js(&self) -> Result<DataStoreMetadata> {
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

impl FromJs<DelegatedPuzzle> for RustDelegatedPuzzle {
    fn from_js(value: DelegatedPuzzle) -> Result<Self> {
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
                return Err(js::err(ConversionError::MissingDelegatedPuzzleInfo));
            },
        )
    }
}

impl ToJs<DelegatedPuzzle> for RustDelegatedPuzzle {
    fn to_js(&self) -> Result<DelegatedPuzzle> {
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

impl FromJs<DataStore> for RustDataStore {
    fn from_js(value: DataStore) -> Result<Self> {
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
                    .collect::<Result<Vec<RustDelegatedPuzzle>>>()?,
            },
        })
    }
}

impl ToJs<DataStore> for RustDataStore {
    fn to_js(&self) -> Result<DataStore> {
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
                .collect::<Result<Vec<DelegatedPuzzle>>>()?,
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

impl FromJs<SuccessResponse> for RustSuccessResponse {
    fn from_js(value: SuccessResponse) -> Result<Self> {
        Ok(RustSuccessResponse {
            coin_spends: value
                .coin_spends
                .into_iter()
                .map(RustCoinSpend::from_js)
                .collect::<Result<Vec<RustCoinSpend>>>()?,
            new_datastore: RustDataStore::from_js(value.new_store)?,
        })
    }
}

impl ToJs<SuccessResponse> for RustSuccessResponse {
    fn to_js(&self) -> Result<SuccessResponse> {
        Ok(SuccessResponse {
            coin_spends: self
                .coin_spends
                .iter()
                .map(RustCoinSpend::to_js)
                .collect::<Result<Vec<CoinSpend>>>()?,
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

impl FromJs<SyncStoreResponse> for RustSyncStoreResponse {
    fn from_js(value: SyncStoreResponse) -> Result<Self> {
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
impl ToJs<SyncStoreResponse> for RustSyncStoreResponse {
    fn to_js(&self) -> Result<SyncStoreResponse> {
        let root_hashes = self
            .root_hash_history
            .as_ref()
            .map(|v| {
                v.iter()
                    .map(|(rh, _)| rh.to_js())
                    .collect::<Result<Vec<Buffer>>>()
            })
            .transpose()?;

        let root_hashes_timestamps = self
            .root_hash_history
            .as_ref()
            .map(|v| {
                v.iter()
                    .map(|(_, ts)| ts.to_js())
                    .collect::<Result<Vec<BigInt>>>()
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

impl FromJs<UnspentCoinsResponse> for rust::UnspentCoinsResponse {
    fn from_js(value: UnspentCoinsResponse) -> Result<Self> {
        Ok(rust::UnspentCoinsResponse {
            coins: value
                .coins
                .into_iter()
                .map(RustCoin::from_js)
                .collect::<Result<Vec<RustCoin>>>()?,
            last_height: value.last_height,
            last_header_hash: RustBytes32::from_js(value.last_header_hash)?,
        })
    }
}

impl ToJs<UnspentCoinsResponse> for rust::UnspentCoinsResponse {
    fn to_js(&self) -> Result<UnspentCoinsResponse> {
        Ok(UnspentCoinsResponse {
            coins: self
                .coins
                .iter()
                .map(RustCoin::to_js)
                .collect::<Result<Vec<Coin>>>()?,
            last_height: self.last_height,
            last_header_hash: self.last_header_hash.to_js()?,
        })
    }
}

#[napi(object)]
/// Represents a response containing possible launcher ids for datastores.
///
/// @property {Vec<Buffer>} launcher_ids - Launcher ids of coins that might be datastores.
/// @property {u32} lastHeight - Last height.
/// @property {Buffer} lastHeaderHash - Last header hash.
pub struct PossibleLaunchersResponse {
    pub launcher_ids: Vec<Buffer>,
    pub last_height: u32,
    pub last_header_hash: Buffer,
}

impl FromJs<PossibleLaunchersResponse> for RustPossibleLaunchersResponse {
    fn from_js(value: PossibleLaunchersResponse) -> Result<Self> {
        Ok(RustPossibleLaunchersResponse {
            last_header_hash: RustBytes32::from_js(value.last_header_hash)?,
            last_height: value.last_height,
            launcher_ids: value
                .launcher_ids
                .into_iter()
                .map(RustBytes32::from_js)
                .collect::<Result<Vec<RustBytes32>>>()?,
        })
    }
}

impl ToJs<PossibleLaunchersResponse> for RustPossibleLaunchersResponse {
    fn to_js(&self) -> Result<PossibleLaunchersResponse> {
        Ok(PossibleLaunchersResponse {
            last_header_hash: self.last_header_hash.to_js()?,
            last_height: self.last_height,
            launcher_ids: self
                .launcher_ids
                .iter()
                .map(RustBytes32::to_js)
                .collect::<Result<Vec<Buffer>>>()?,
        })
    }
}

#[napi]
pub struct Tls(Connector);

#[napi]
impl Tls {
    #[napi(constructor)]
    /// Creates a new TLS connector.
    ///
    /// @param {String} certPath - Path to the certificate file (usually '~/.chia/mainnet/config/ssl/wallet/wallet_node.crt').
    /// @param {String} keyPath - Path to the key file (usually '~/.chia/mainnet/config/ssl/wallet/wallet_node.key').
    pub fn new(cert_path: String, key_path: String) -> napi::Result<Self> {
        let cert = load_ssl_cert(&cert_path, &key_path).map_err(js::err)?;
        let tls = create_native_tls_connector(&cert).map_err(js::err)?;
        Ok(Self(tls))
    }
}

#[napi]
pub struct Peer {
    inner: Arc<RustPeer>,
    peak: Arc<Mutex<Option<NewPeakWallet>>>,
    coin_listeners: Arc<Mutex<HashMap<RustBytes32, UnboundedSender<()>>>>,
}

#[napi]
impl Peer {
    #[napi(factory)]
    /// Creates a new Peer instance.
    ///
    /// @param {String} nodeUri - URI of the node (e.g., '127.0.0.1:58444').
    /// @param {bool} testnet - True for connecting to testnet11, false for mainnet.
    /// @param {Tls} tls - TLS connector.
    /// @returns {Promise<Peer>} A new Peer instance.
    pub async fn new(node_uri: String, testnet: bool, tls: &Tls) -> napi::Result<Self> {
        let (peer, mut receiver) = connect_peer(
            if testnet {
                "testnet11".to_string()
            } else {
                "mainnet".to_string()
            },
            tls.0.clone(),
            if let Ok(socket_addr) = node_uri.parse::<SocketAddr>() {
                socket_addr
            } else {
                return Err(js::err(ConversionError::InvalidUri(node_uri)));
            },
            PeerOptions::default(),
        )
        .await
        .map_err(js::err)?;

        let inner = Arc::new(peer);
        let peak = Arc::new(Mutex::new(None));
        let coin_listeners = Arc::new(Mutex::new(
            HashMap::<RustBytes32, UnboundedSender<()>>::new(),
        ));

        let peak_clone = peak.clone();
        let coin_listeners_clone = coin_listeners.clone();
        tokio::spawn(async move {
            while let Some(message) = receiver.recv().await {
                if message.msg_type == ProtocolMessageTypes::NewPeakWallet {
                    if let Ok(new_peak) = NewPeakWallet::from_bytes(&message.data) {
                        let mut peak_guard = peak_clone.lock().await;
                        *peak_guard = Some(new_peak);
                    }
                }

                if message.msg_type == ProtocolMessageTypes::CoinStateUpdate {
                    if let Ok(coin_state_update) = CoinStateUpdate::from_bytes(&message.data) {
                        let mut listeners = coin_listeners_clone.lock().await;

                        for coin_state_update_item in coin_state_update.items {
                            if coin_state_update_item.spent_height.is_none() {
                                continue;
                            }

                            if let Some(listener) =
                                listeners.get(&coin_state_update_item.coin.coin_id())
                            {
                                let _ = listener.send(());
                                listeners.remove(&coin_state_update_item.coin.coin_id());
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            inner,
            peak,
            coin_listeners,
        })
    }

    #[napi(js_name = "getCoinChildren")]
    /// Gets all children of a given coin.
    ///
    /// @param {Buffer} coinId - ID of the coin to get children for.
    /// @returns {Promise<Vec<Coin>>} The coin's children.
    pub async fn get_coin_children(&self, coin_id: Buffer) -> napi::Result<Vec<CoinState>> {
        let coin_id = RustBytes32::from_js(coin_id)?;
        let resp = self
            .inner
            .request_children(coin_id)
            .await
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;

        resp.coin_states
            .into_iter()
            .map(|c| c.to_js())
            .collect::<Result<Vec<CoinState>>>()
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
        let resp: rust::UnspentCoinsResponse = get_unspent_coin_states(
            &self.inner.clone(),
            RustBytes32::from_js(puzzle_hash)?,
            previous_height,
            RustBytes32::from_js(previous_header_hash)?,
            false,
        )
        .await
        .map_err(js::err)?
        .into();

        resp.to_js()
    }

    #[napi]
    /// Retrieves all hinted coin states that are unspent on the chain. Note that coins part of spend bundles that are pending in the mempool will also be included.
    ///
    /// @param {Buffer} puzzleHash - Puzzle hash to lookup hinted coins for.
    /// @param {bool} forTestnet - True for testnet, false for mainnet.
    /// @returns {Promise<Vec<Coin>>} The unspent coins response.
    pub async fn get_hinted_coin_states(
        &self,
        puzzle_hash: Buffer,
        for_testnet: bool,
    ) -> napi::Result<Vec<CoinState>> {
        let resp = get_unspent_coin_states(
            &self.inner.clone(),
            RustBytes32::from_js(puzzle_hash)?,
            None,
            if for_testnet {
                TESTNET11_CONSTANTS.genesis_challenge
            } else {
                MAINNET_CONSTANTS.genesis_challenge
            },
            true,
        )
        .await
        .map_err(js::err)?;

        resp.coin_states
            .into_iter()
            .map(|c| c.to_js())
            .collect::<Result<Vec<CoinState>>>()
    }

    #[napi]
    /// Fetches the server coin from a given coin state.
    ///
    /// @param {CoinState} coinState - The coin state.
    /// @param {BigInt} maxCost - The maximum cost to use when parsing the coin. For example, `11_000_000_000`.
    /// @returns {Promise<ServerCoin>} The server coin.
    pub async fn fetch_server_coin(
        &self,
        coin_state: CoinState,
        max_cost: BigInt,
    ) -> napi::Result<js::ServerCoin> {
        let coin = wallet::fetch_server_coin(
            &self.inner.clone(),
            rust::CoinState::from_js(coin_state)?,
            u64::from_js(max_cost)?,
        )
        .await
        .map_err(js::err)?;

        coin.to_js()
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
        .map_err(js::err)?;

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
        .map_err(js::err)?;

        res.to_js()
    }

    #[napi]
    /// Fetch a store's creation height.
    ///
    /// @param {Buffer} launcherId - The store's launcher/singleton ID.
    /// @param {Option<u32>} lastHeight - Min. height to search records from. If null, sync will be done from the genesis block.
    /// @param {Buffer} lastHeaderHash - Header hash corresponding to `lastHeight`. If null, this should be the genesis challenge of the current chain.
    /// @returns {Promise<BigInt>} The store's creation height.
    pub async fn get_store_creation_height(
        &self,
        launcher_id: Buffer,
        last_height: Option<u32>,
        last_header_hash: Buffer,
    ) -> napi::Result<BigInt> {
        let res = wallet::get_store_creation_height(
            &self.inner.clone(),
            RustBytes32::from_js(launcher_id)?,
            last_height,
            RustBytes32::from_js(last_header_hash)?,
        )
        .await
        .map_err(js::err)?;

        (res as u64).to_js()
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
                .collect::<Result<Vec<RustCoinSpend>>>()?,
            agg_sig,
        );

        Ok(
            wallet::broadcast_spend_bundle(&self.inner.clone(), spend_bundle)
                .await
                .map_err(js::err)?
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
        .map_err(js::err)
    }

    #[napi]
    /// Retrieves the current header hash corresponding to a given height.
    ///
    /// @param {u32} height - The height.
    /// @returns {Promise<Buffer>} The header hash.
    pub async fn get_header_hash(&self, height: u32) -> napi::Result<Buffer> {
        get_header_hash(&self.inner.clone(), height)
            .await
            .map_err(js::err)?
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
            .map_err(js::err)?
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

    /// Spends the mirror coins to make them unusable in the future.
    ///
    /// @param {Buffer} syntheticKey - The synthetic key used by the wallet.
    /// @param {Vec<Coin>} selectedCoins - Coins to be used for minting, as retured by `select_coins`. Note that the server coins will count towards the fee.
    /// @param {BigInt} fee - The fee to use for the transaction.
    /// @param {bool} forTestnet - True for testnet, false for mainnet.
    #[napi]
    pub async fn lookup_and_spend_server_coins(
        &self,
        synthetic_key: Buffer,
        selected_coins: Vec<Coin>,
        fee: BigInt,
        for_testnet: bool,
    ) -> napi::Result<Vec<CoinSpend>> {
        let coin = wallet::spend_server_coins(
            &self.inner,
            RustPublicKey::from_js(synthetic_key)?,
            selected_coins
                .into_iter()
                .map(RustCoin::from_js)
                .collect::<Result<Vec<RustCoin>>>()?,
            u64::from_js(fee)?,
            if for_testnet {
                TargetNetwork::Testnet11
            } else {
                TargetNetwork::Mainnet
            },
        )
        .await
        .map_err(js::err)?;

        coin.into_iter()
            .map(|c| c.to_js())
            .collect::<Result<Vec<CoinSpend>>>()
    }

    #[napi]
    /// Looks up possible datastore launchers by searching for singleton launchers created with a DL-specific hint.
    ///
    /// @param {Option<u32>} lastHeight - Min. height to search records from. If null, sync will be done from the genesis block.
    /// @param {Buffer} headerHash - Header hash corresponding to `lastHeight`. If null, this should be the genesis challenge of the current chain.
    /// @returns {Promise<PossibleLaunchersResponse>} Possible launcher ids for datastores, as well as a height + header hash combo to use for the next call.
    pub async fn look_up_possible_launchers(
        &self,
        last_height: Option<u32>,
        header_hash: Buffer,
    ) -> napi::Result<PossibleLaunchersResponse> {
        wallet::look_up_possible_launchers(
            &self.inner.clone(),
            last_height,
            RustBytes32::from_js(header_hash)?,
        )
        .await
        .map_err(js::err)?
        .to_js()
    }

    #[napi]
    /// Waits for a coin to be spent on-chain.
    ///
    /// @param {Buffer} coin_id - Id of coin to track.
    /// @param {Option<u32>} lastHeight - Min. height to search records from. If null, sync will be done from the genesis block.
    /// @param {Buffer} headerHash - Header hash corresponding to `lastHeight`. If null, this should be the genesis challenge of the current chain.
    /// @returns {Promise<Buffer>} Promise that resolves when the coin is spent (returning the coin id).
    pub async fn wait_for_coin_to_be_spent(
        &self,
        coin_id: Buffer,
        last_height: Option<u32>,
        header_hash: Buffer,
    ) -> napi::Result<Buffer> {
        let rust_coin_id = RustBytes32::from_js(coin_id)?;
        let spent_height = wallet::subscribe_to_coin_states(
            &self.inner.clone(),
            rust_coin_id,
            last_height,
            RustBytes32::from_js(header_hash)?,
        )
        .await
        .map_err(js::err)?;

        if spent_height.is_none() {
            let (sender, mut receiver) = unbounded_channel::<()>();

            {
                let mut listeners = self.coin_listeners.lock().await;
                listeners.insert(rust_coin_id, sender);
            }

            receiver
                .recv()
                .await
                .ok_or_else(|| js::err("Failed to receive spent notification"))?;
        }

        wallet::unsubscribe_from_coin_states(&self.inner.clone(), rust_coin_id)
            .await
            .map_err(js::err)?;

        rust_coin_id.to_js()
    }

    #[napi]
    /// Gets the last spendable DID coin in the chain
    ///
    /// @param {Buffer} didId - The DID ID to look up
    /// @param {Buffer} spenderSyntheticKey - The synthetic public key of the spender
    /// @param {bool} forTestnet - True for testnet, false for mainnet
    /// @returns {Promise<Option<Did>>} The last spendable DID coin, if found
    pub async fn get_last_spendable_did_coin(
        &self,
        did_id: Buffer,
        spender_synthetic_key: Buffer,
        for_testnet: bool,
    ) -> napi::Result<Option<js::Did>> {
        let result = wallet::get_last_spendable_did_coin(
            &self.inner.clone(),
            RustBytes32::from_js(did_id)?,
            if for_testnet {
                TargetNetwork::Testnet11
            } else {
                TargetNetwork::Mainnet
            },
            RustPublicKey::from_js(spender_synthetic_key)?,
        )
        .await
        .map_err(js::err)?;

        result.map(|did| did.to_js()).transpose()
    }

    #[napi]
    /// Requests the state of specific coins from the network.
    ///
    /// @param {Vec<Buffer>} coinIds - IDs of the coins to look up.
    /// @param {Option<u32>} previousHeight - Previous height that was spent. If null, sync will be done from the genesis block.
    /// @param {Buffer} headerHash - Header hash corresponding to the previous height.
    /// @param {bool} subscribe - Whether to subscribe to updates for these coins.
    /// @returns {Promise<Vec<CoinState>>} The coin states.
    pub async fn request_coin_state(
        &self,
        coin_ids: Vec<Buffer>,
        previous_height: Option<u32>,
        header_hash: Buffer,
        subscribe: bool,
    ) -> napi::Result<Vec<CoinState>> {
        wallet::request_coin_state(
            &self.inner,
            coin_ids
                .into_iter()
                .map(RustBytes32::from_js)
                .collect::<Result<Vec<RustBytes32>>>()?,
            previous_height,
            RustBytes32::from_js(header_hash)?,
            subscribe,
        )
        .await
        .map_err(|e| napi::Error::from_reason(e.to_string()))?
        .into_iter()
        .map(|c| c.to_js())
        .collect()
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
        .collect::<Result<Vec<RustCoin>>>()?;
    let selected_coins =
        wallet::select_coins(coins, u64::from_js(total_amount)?).map_err(js::err)?;

    selected_coins
        .into_iter()
        .map(|c| c.to_js())
        .collect::<Result<Vec<Coin>>>()
}

/// An output puzzle hash and amount.
#[napi(object)]
pub struct Output {
    pub puzzle_hash: Buffer,
    pub amount: BigInt,
    pub memos: Vec<Buffer>,
}

/// Sends XCH to a given set of puzzle hashes.
///
/// @param {Buffer} syntheticKey - The synthetic key used by the wallet.
/// @param {Vec<Coin>} selectedCoins - Coins to be spent, as retured by `select_coins`.
/// @param {Vec<Output>} outputs - The output amounts to create.
/// @param {BigInt} fee - The fee to use for the transaction.
#[napi]
pub fn send_xch(
    synthetic_key: Buffer,
    selected_coins: Vec<Coin>,
    outputs: Vec<Output>,
    fee: BigInt,
) -> napi::Result<Vec<CoinSpend>> {
    let mut items = Vec::new();

    for output in outputs {
        items.push((
            RustBytes32::from_js(output.puzzle_hash)?,
            u64::from_js(output.amount)?,
            output
                .memos
                .into_iter()
                .map(RustBytes::from_js)
                .collect::<Result<Vec<RustBytes>>>()?,
        ));
    }

    let coin_spends = wallet::send_xch(
        RustPublicKey::from_js(synthetic_key)?,
        &selected_coins
            .into_iter()
            .map(RustCoin::from_js)
            .collect::<Result<Vec<RustCoin>>>()?,
        &items,
        u64::from_js(fee)?,
    )
    .map_err(js::err)?;

    coin_spends
        .into_iter()
        .map(|c| c.to_js())
        .collect::<Result<Vec<CoinSpend>>>()
}

/// Adds an offset to a launcher id to make it deterministically unique from the original.
///
/// @param {Buffer} launcherId - The original launcher id.
/// @param {BigInt} offset - The offset to add.
#[napi]
pub fn morph_launcher_id(launcher_id: Buffer, offset: BigInt) -> napi::Result<Buffer> {
    server_coin::morph_launcher_id(
        RustBytes32::from_js(launcher_id)?,
        &u64::from_js(offset)?.into(),
    )
    .to_js()
}

/// The new server coin and coin spends to create it.
#[napi(object)]
pub struct NewServerCoin {
    pub server_coin: ServerCoin,
    pub coin_spends: Vec<CoinSpend>,
}

/// Creates a new mirror coin with the given URLs.
///
/// @param {Buffer} syntheticKey - The synthetic key used by the wallet.
/// @param {Vec<Coin>} selectedCoins - Coins to be used for minting, as retured by `select_coins`. Note that, besides the fee, 1 mojo will be used to create the mirror coin.
/// @param {Buffer} hint - The hint for the mirror coin, usually the original or morphed launcher id.
/// @param {Vec<String>} uris - The URIs of the mirrors.
/// @param {BigInt} amount - The amount to use for the created coin.
/// @param {BigInt} fee - The fee to use for the transaction.
#[napi]
pub fn create_server_coin(
    synthetic_key: Buffer,
    selected_coins: Vec<Coin>,
    hint: Buffer,
    uris: Vec<String>,
    amount: BigInt,
    fee: BigInt,
) -> napi::Result<NewServerCoin> {
    let (coin_spends, server_coin) = wallet::create_server_coin(
        RustPublicKey::from_js(synthetic_key)?,
        selected_coins
            .into_iter()
            .map(RustCoin::from_js)
            .collect::<Result<Vec<RustCoin>>>()?,
        RustBytes32::from_js(hint)?,
        uris,
        u64::from_js(amount)?,
        u64::from_js(fee)?,
    )
    .map_err(js::err)?;

    Ok(NewServerCoin {
        coin_spends: coin_spends
            .into_iter()
            .map(|c| c.to_js())
            .collect::<Result<Vec<CoinSpend>>>()?,
        server_coin: server_coin.to_js()?,
    })
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
            .collect::<Result<Vec<RustCoin>>>()?,
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
            .collect::<Result<Vec<RustDelegatedPuzzle>>>()?,
        u64::from_js(fee).map_err(js::err)?,
    )
    .map_err(js::err)?;

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
            .collect::<Result<Vec<RustCoin>>>()?,
        RustDataStore::from_js(store)?,
        u64::from_js(fee)?,
    )
    .map_err(js::err)?;

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
            .collect::<Result<Vec<RustCoin>>>()?,
        assert_coin_ids
            .into_iter()
            .map(RustBytes32::from_js)
            .collect::<Result<Vec<RustBytes32>>>()?,
        u64::from_js(fee)?,
    )
    .map_err(js::err)?;

    response
        .into_iter()
        .map(|cs| cs.to_js())
        .collect::<Result<Vec<CoinSpend>>>()
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

    encode_address(puzzle_hash.into(), &prefix).map_err(js::err)
}

#[napi]
/// Converts an address to a puzzle hash using bech32m.
///
/// @param {String} address - The address.
/// @returns {Promise<Buffer>} The puzzle hash.
pub fn address_to_puzzle_hash(address: String) -> napi::Result<Buffer> {
    let (puzzle_hash, _) = decode_address(&address).map_err(js::err)?;
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
        .collect::<Result<Vec<RustCoinSpend>>>()?;
    let private_keys = private_keys
        .iter()
        .map(|sk| RustSecretKey::from_js(sk.clone()))
        .collect::<Result<Vec<RustSecretKey>>>()?;

    let sig = wallet::sign_coin_spends(
        coin_spends,
        private_keys,
        if for_testnet {
            TargetNetwork::Testnet11
        } else {
            TargetNetwork::Mainnet
        },
    )
    .map_err(js::err)?;

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
        _ => return Err(js::err(
            "Exactly one of owner_public_key, admin_public_key, writer_public_key must be provided",
        )),
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
    .map_err(js::err)?;

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
            return Err(js::err(
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
            .collect::<Result<Vec<RustDelegatedPuzzle>>>()?,
        inner_spend_info,
    )
    .map_err(js::err)?;

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
    .map_err(js::err)?;

    res.into_iter()
        .map(|cs| cs.to_js())
        .collect::<Result<Vec<CoinSpend>>>()
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
    .map_err(js::err)?
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
    .map_err(js::err)
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
            .collect::<Result<Vec<RustCoinSpend>>>()?,
    )
    .map_err(js::err)?
    .to_js()
}

#[napi]
/// Returns the mainnet genesis challenge.
///
/// @returns {Buffer} The mainnet genesis challenge.
pub fn get_mainnet_genesis_challenge() -> napi::Result<Buffer> {
    MAINNET_CONSTANTS.genesis_challenge.to_js()
}

#[napi]
/// Returns the testnet11 genesis challenge.
///
/// @returns {Buffer} The testnet11 genesis challenge.
pub fn get_testnet11_genesis_challenge() -> napi::Result<Buffer> {
    TESTNET11_CONSTANTS.genesis_challenge.to_js()
}

#[napi(object)]
/// NFT metadata structure
pub struct NftMetadata {
    /// Data URL or hex string containing the metadata
    pub data_uris: Vec<String>,
    /// Data hash of the metadata
    pub data_hash: Option<Buffer>,
    /// License URL or hex string
    pub license_uris: Vec<String>,
    /// License hash
    pub license_hash: Option<Buffer>,
    /// NFT metadata URL or hex string
    pub metadata_uris: Vec<String>,
    /// NFT metadata hash
    pub metadata_hash: Option<Buffer>,
    /// Edition number
    pub edition_number: u32,
    /// Maximum number of editions
    pub edition_total: u32,
}

impl FromJs<NftMetadata> for RustNftMetadata {
    fn from_js(value: NftMetadata) -> Result<Self> {
        Ok(RustNftMetadata {
            data_uris: value.data_uris,
            data_hash: if value.data_hash.is_some() {
                Some(RustBytes32::from_js(value.data_hash.unwrap())?)
            } else {
                None
            },
            license_uris: value.license_uris,
            license_hash: if value.license_hash.is_some() {
                Some(RustBytes32::from_js(value.license_hash.unwrap())?)
            } else {
                None
            },
            metadata_uris: value.metadata_uris,
            metadata_hash: if value.metadata_hash.is_some() {
                Some(RustBytes32::from_js(value.metadata_hash.unwrap())?)
            } else {
                None
            },
            edition_number: value.edition_number as u64,
            edition_total: value.edition_total as u64,
        })
    }
}

impl ToJs<NftMetadata> for RustNftMetadata {
    fn to_js(&self) -> Result<NftMetadata> {
        Ok(NftMetadata {
            data_uris: self.data_uris.clone(),
            data_hash: self.data_hash.map(|hash| hash.to_js()).transpose()?,
            license_uris: self.license_uris.clone(),
            license_hash: self.license_hash.map(|hash| hash.to_js()).transpose()?,
            metadata_uris: self.metadata_uris.clone(),
            metadata_hash: self.metadata_hash.map(|hash| hash.to_js()).transpose()?,
            edition_number: self.edition_number as u32,
            edition_total: self.edition_total as u32,
        })
    }
}

#[napi(object)]
/// Configuration for minting a single NFT in a bulk operation
pub struct WalletNftMint {
    /// Metadata for the NFT
    pub metadata: NftMetadata,
    /// Optional royalty puzzle hash - defaults to target address if None
    pub royalty_puzzle_hash: Option<Buffer>,
    /// Royalty percentage in basis points (1/10000)
    pub royalty_ten_thousandths: u16,
    /// Optional p2 puzzle hash - defaults to target address if None
    pub p2_puzzle_hash: Option<Buffer>,
}

impl FromJs<WalletNftMint> for wallet::WalletNftMint {
    fn from_js(value: WalletNftMint) -> Result<Self> {
        Ok(wallet::WalletNftMint {
            metadata: RustNftMetadata::from_js(value.metadata)?,
            royalty_puzzle_hash: value
                .royalty_puzzle_hash
                .map(RustBytes32::from_js)
                .transpose()?,
            royalty_ten_thousandths: value.royalty_ten_thousandths,
            p2_puzzle_hash: value.p2_puzzle_hash.map(RustBytes32::from_js).transpose()?,
        })
    }
}

impl ToJs<WalletNftMint> for wallet::WalletNftMint {
    fn to_js(&self) -> Result<WalletNftMint> {
        Ok(WalletNftMint {
            metadata: self.metadata.to_js()?,
            royalty_puzzle_hash: self.royalty_puzzle_hash.map(|ph| ph.to_js()).transpose()?,
            royalty_ten_thousandths: self.royalty_ten_thousandths,
            p2_puzzle_hash: self.p2_puzzle_hash.map(|ph| ph.to_js()).transpose()?,
        })
    }
}

#[napi(object)]
/// Response from creating a DID
pub struct CreateDidResponse {
    pub coin_spends: Vec<CoinSpend>,
    pub did_id: Buffer,
}

impl<T> ToJs<CreateDidResponse> for (Vec<RustCoinSpend>, RustDid<T>) {
    fn to_js(&self) -> Result<CreateDidResponse> {
        Ok(CreateDidResponse {
            coin_spends: self
                .0
                .iter()
                .map(RustCoinSpend::to_js)
                .collect::<Result<Vec<CoinSpend>>>()?,
            did_id: self.1.coin.coin_id().to_js()?,
        })
    }
}

#[napi(object)]
/// Response from bulk minting NFTs
pub struct BulkMintNftsResponse {
    pub coin_spends: Vec<CoinSpend>,
    pub nft_launcher_ids: Vec<Buffer>,
    pub log_list: Vec<String>,
}

impl ToJs<BulkMintNftsResponse> for (Vec<RustCoinSpend>, Vec<Nft<RustNftMetadata>>, Vec<String>) {
    fn to_js(&self) -> Result<BulkMintNftsResponse> {
        Ok(BulkMintNftsResponse {
            coin_spends: self
                .0
                .iter()
                .map(RustCoinSpend::to_js)
                .collect::<Result<Vec<CoinSpend>>>()?,
            nft_launcher_ids: self
                .1
                .iter()
                .map(|nft| nft.coin.coin_id().to_js())
                .collect::<Result<Vec<Buffer>>>()?,
            log_list: self.2.clone(),
        })
    }
}

// Now we can update the NAPI functions to use these conversions:

#[napi]
/// Creates a new Decentralized Identity (DID)
///
/// @param {Buffer} spenderSyntheticKey - The synthetic public key of the spender
/// @param {Vec<Coin>} selectedCoins - Coins to use for the creation
/// @param {BigInt} fee - Transaction fee in mojos
/// @returns {Promise<CreateDidResponse>} The coin spends and DID ID
pub fn create_did(
    spender_synthetic_key: Buffer,
    selected_coins: Vec<Coin>,
    fee: BigInt,
) -> napi::Result<js::CreateDidResponse> {
    let result = wallet::create_did(
        RustPublicKey::from_js(spender_synthetic_key)?,
        selected_coins
            .into_iter()
            .map(RustCoin::from_js)
            .collect::<Result<Vec<RustCoin>>>()?,
        u64::from_js(fee)?,
    )
    .map_err(js::err)?;

    result.to_js()
}

#[napi]
/// Mints multiple NFTs in a single transaction
///
/// @param {Buffer} spenderSyntheticKey - The synthetic public key of the spender
/// @param {Vec<Coin>} selectedCoins - Coins to use for minting
/// @param {Vec<WalletNftMint>} mints - Vector of NFT configurations to mint
/// @param {Option<Did>} did - Optional DID to associate with the NFTs
/// @param {Buffer} targetAddress - Default address for royalties and ownership
/// @param {BigInt} fee - Transaction fee in mojos
/// @param {bool} forTestnet - True for testnet, false for mainnet
/// @returns {Promise<BulkMintNftsResponse>} The coin spends and NFT launcher IDs
pub async fn bulk_mint_nfts(
    spender_synthetic_key: Buffer,
    selected_coins: Vec<js::Coin>,
    mints: Vec<WalletNftMint>,
    did: js::Did,
    target_address: Buffer,
    fee: BigInt,
) -> napi::Result<BulkMintNftsResponse> {
    let result = wallet::bulk_mint_nfts(
        RustPublicKey::from_js(spender_synthetic_key)?,
        selected_coins
            .into_iter()
            .map(RustCoin::from_js)
            .collect::<Result<Vec<RustCoin>>>()?,
        mints
            .into_iter()
            .map(wallet::WalletNftMint::from_js)
            .collect::<Result<Vec<wallet::WalletNftMint>>>()?,
        RustDid::from_js(did)?,
        RustBytes32::from_js(target_address)?,
        u64::from_js(fee)?,
    )
    .await
    .map_err(js::err)?;

    Ok(BulkMintNftsResponse {
        coin_spends: result
            .0
            .iter()
            .map(RustCoinSpend::to_js)
            .collect::<Result<Vec<CoinSpend>>>()?,
        nft_launcher_ids: result
            .1
            .iter()
            .map(|nft| nft.coin.coin_id().to_js())
            .collect::<Result<Vec<Buffer>>>()?,
        log_list: result.3.clone(),
    })
}
