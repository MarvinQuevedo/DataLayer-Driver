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
use chia::{bls::PublicKey as RustPublicKey, traits::Streamable};
use chia_protocol::CoinSpend as RustCoinSpend;
use chia_protocol::Program as RustProgram;
use chia_protocol::SpendBundle as RustSpendBundle;
use chia_protocol::{Bytes32 as RustBytes32, NodeType};
use chia_protocol::{Coin as RustCoin, CoinState};
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
use native_tls::TlsConnector;
pub use puzzles::*;
pub use puzzles_info::*;
use puzzles_info::{
  DataStoreInfo as RustDataStoreInfo, DataStoreMetadata as RustDataStoreMetadata,
  DelegatedPuzzle as RustDelegatedPuzzle, DelegatedPuzzleInfo as RustDelegatedPuzzleInfo,
};
use wallet::SuccessResponse as RustSuccessResponse;
use wallet::SyncStoreResponse as RustSyncStoreResponse;
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
    RustBytes32::from_bytes(&value.to_vec()).unwrap()
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
    RustPublicKey::from_bytes(&bytes).unwrap()
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
    RustSecretKey::from_bytes(&bytes).unwrap()
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
    RustSignature::from_bytes(&bytes).unwrap()
  }
}

impl ToJS<Buffer> for RustSignature {
  fn to_js(self: &Self) -> Buffer {
    Buffer::from(self.to_bytes().to_vec())
  }
}

#[napi(object)]
#[derive(Clone)]
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
pub struct SpendBundle {
  pub coin_spends: Vec<CoinSpend>,
  pub aggregated_signature: Buffer,
}

impl FromJS<SpendBundle> for RustSpendBundle {
  fn from_js(value: SpendBundle) -> Self {
    RustSpendBundle::new(
      value
        .coin_spends
        .into_iter()
        .map(|cs| RustCoinSpend::from_js(cs))
        .collect(),
      RustSignature::from_js(value.aggregated_signature),
    )
  }
}

impl ToJS<SpendBundle> for RustSpendBundle {
  fn to_js(self: &Self) -> SpendBundle {
    SpendBundle {
      coin_spends: self.coin_spends.iter().map(RustCoinSpend::to_js).collect(),
      aggregated_signature: self.aggregated_signature.to_js(),
    }
  }
}

#[napi(object)]
#[derive(Clone)]
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
  pub root_hash: Buffer,
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
  pub admin_inner_puzzle_hash: Option<Buffer>,
  pub writer_inner_puzzle_hash: Option<Buffer>,
  pub oracle_payment_puzzle_hash: Option<Buffer>,
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
pub struct SyncStoreResponse {
  pub latest_info: DataStoreInfo,
  pub latest_height: u32,
}

impl FromJS<SyncStoreResponse> for RustSyncStoreResponse {
  fn from_js(value: SyncStoreResponse) -> Self {
    RustSyncStoreResponse {
      latest_info: RustDataStoreInfo::from_js(value.latest_info),
      latest_height: value.latest_height,
    }
  }
}

impl ToJS<SyncStoreResponse> for RustSyncStoreResponse {
  fn to_js(self: &Self) -> SyncStoreResponse {
    SyncStoreResponse {
      latest_info: self.latest_info.to_js(),
      latest_height: self.latest_height,
    }
  }
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

    Ok(Self(Arc::new(peer)))
  }

  #[napi]
  pub async fn get_coins(&self, puzzle_hash: Buffer, min_height: u32) -> napi::Result<Vec<Coin>> {
    let coins = get_coins(
      &self.0.clone(),
      RustBytes32::from_js(puzzle_hash),
      min_height,
    )
    .await
    .map_err(js)?;

    Ok(coins.iter().map(RustCoin::to_js).collect())
  }

  #[napi]
  pub async fn mint_store(
    &self,
    minter_synthetic_key: Buffer,
    minter_ph_min_height: u32,
    root_hash: Buffer,
    label: String,
    description: String,
    owner_puzzle_hash: Buffer,
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

  #[napi]
  pub async fn sync_store(
    &self,
    store_info: DataStoreInfo,
    min_height: u32,
  ) -> napi::Result<SyncStoreResponse> {
    let res = sync_store(
      &self.0.clone(),
      &RustDataStoreInfo::from_js(store_info),
      min_height,
    )
    .await
    .map_err(js)?;

    Ok(res.to_js())
  }

  // returns error
  #[napi]
  pub async fn broadcast_spend_bundle(&self, spend_bundle: SpendBundle) -> napi::Result<String> {
    let spend_bundle = RustSpendBundle::from_js(spend_bundle);

    Ok(
      wallet::broadcast_spend_bundle(&self.0.clone(), spend_bundle)
        .await
        .map_err(js)?
        .error
        .unwrap_or(String::default()),
    )
  }

  #[napi]
  pub async fn is_coin_spent(&self, coin_id: Buffer) -> napi::Result<bool> {
    let p: &RustPeer = &self.0.clone();
    let states: Vec<CoinState> = p
      .register_for_coin_updates(vec![RustBytes32::from_js(coin_id)], 0)
      .await
      .map_err(js)?;

    Ok(states.len() == 1 && states[0].spent_height.is_some())
  }

  #[napi]
  pub async fn oracle_spend(
    &self,
    spender_synthetic_key: Buffer,
    spender_ph_min_height: u32,
    store_info: DataStoreInfo,
    fee: BigInt,
  ) -> napi::Result<SuccessResponse> {
    let response = wallet::oracle_spend(
      &self.0.clone(),
      RustPublicKey::from_js(spender_synthetic_key),
      spender_ph_min_height,
      &RustDataStoreInfo::from_js(store_info),
      u64::from_js(fee),
    )
    .await
    .map_err(js)?;

    Ok(response.to_js())
  }

  #[napi]
  pub async fn add_fee(
    &self,
    spender_synthetic_key: Buffer,
    spender_ph_min_height: u32,
    coin_ids: Vec<Buffer>,
    fee: BigInt,
  ) -> napi::Result<Vec<CoinSpend>> {
    let response = wallet::add_fee(
      &self.0.clone(),
      RustPublicKey::from_js(spender_synthetic_key),
      spender_ph_min_height,
      coin_ids
        .into_iter()
        .map(|cid| RustBytes32::from_js(cid))
        .collect(),
      u64::from_js(fee),
    )
    .await
    .map_err(js)?;

    Ok(response.into_iter().map(|cs| cs.to_js()).collect())
  }
}

#[napi]
pub fn master_public_key_to_wallet_synthetic_key(public_key: Buffer) -> Buffer {
  let public_key = RustPublicKey::from_js(public_key);
  let wallet_pk = master_to_wallet_unhardened(&public_key, 0).derive_synthetic();
  wallet_pk.to_js()
}

#[napi]
pub fn master_public_key_to_first_puzzle_hash(public_key: Buffer) -> Buffer {
  let public_key = RustPublicKey::from_js(public_key);
  let wallet_pk = master_to_wallet_unhardened(&public_key, 0).derive_synthetic();

  let puzzle_hash: RustBytes32 = StandardArgs::curry_tree_hash(wallet_pk).into();

  puzzle_hash.to_js()
}

#[napi]
pub fn master_secret_key_to_wallet_synthetic_secret_key(secret_key: Buffer) -> Buffer {
  let secret_key = RustSecretKey::from_js(secret_key);
  let wallet_sk = master_to_wallet_unhardened(&secret_key, 0).derive_synthetic();
  wallet_sk.to_js()
}

#[napi]
pub fn secret_key_to_public_key(secret_key: Buffer) -> Buffer {
  let secret_key = RustSecretKey::from_js(secret_key);
  secret_key.public_key().to_js()
}

#[napi]
pub fn puzzle_hash_to_address(puzzle_hash: Buffer, prefix: String) -> napi::Result<String> {
  let puzzle_hash = RustBytes32::from_js(puzzle_hash);

  encode_address(puzzle_hash.into(), &prefix).map_err(js)
}

#[napi]
pub fn address_to_puzzle_hash(address: String) -> napi::Result<Buffer> {
  let (puzzle_hash, _) = decode_address(&address).map_err(js)?;
  let puzzle_hash: RustBytes32 = RustBytes32::from_bytes(&puzzle_hash).map_err(js)?;

  Ok(puzzle_hash.to_js())
}

#[napi]
pub fn admin_delegated_puzzle_from_key(synthetic_key: Buffer) -> napi::Result<DelegatedPuzzle> {
  let synthetic_key = RustPublicKey::from_js(synthetic_key);

  let ctx: &mut SpendContext = &mut SpendContext::new();
  let (admin_dp, _) = RustDelegatedPuzzle::from_admin_pk(ctx, synthetic_key).map_err(js)?;

  Ok(admin_dp.to_js())
}

#[napi]
pub fn writer_delegated_puzzle_from_key(synthetic_key: Buffer) -> napi::Result<DelegatedPuzzle> {
  let synthetic_key = RustPublicKey::from_js(synthetic_key);

  let ctx: &mut SpendContext = &mut SpendContext::new();
  let (writer_dp, _) = RustDelegatedPuzzle::from_writer_pk(ctx, synthetic_key).map_err(js)?;

  Ok(writer_dp.to_js())
}

#[napi]
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
pub fn get_coin_id(coin: Coin) -> Buffer {
  let coin = RustCoin::from_js(coin);

  coin.coin_id().to_js()
}

#[napi]
pub fn update_store_metadata(
  store_info: DataStoreInfo,
  new_root_hash: Buffer,
  new_label: String,
  new_description: String,
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
    inner_spend_info,
  )
  .map_err(js)?;

  Ok(res.to_js())
}

#[napi]
pub fn update_store_ownership(
  store_info: DataStoreInfo,
  new_owner_puzzle_hash: Buffer,
  new_delegated_puzzles: Vec<DelegatedPuzzle>,
  owner_public_key: Option<Buffer>,
  admin_public_key: Option<Buffer>,
) -> napi::Result<SuccessResponse> {
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
