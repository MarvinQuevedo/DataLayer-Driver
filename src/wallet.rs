use chia::client::Error as ClientError;
use chia::client::Peer;
use chia_protocol::{Bytes32, CoinSpend};
use thiserror::Error;

use crate::{DataStoreInfo, DelegatedPuzzle};

#[derive(Clone, Debug)]

pub struct SuccessResponse {
    pub coin_spends: Vec<CoinSpend>,
    pub new_info: DataStoreInfo,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0:?}")]
    WalletError(#[from] ClientError<()>),
}

pub async fn mint_store(
    peer: &Peer,
    minter_puzzle_hash: Bytes32,
    minter_ph_min_height: u32,
    root_hash: Bytes32,
    label: String,
    description: String,
    owner_puzzle_hash: Bytes32,
    delegated_puzzles: Vec<DelegatedPuzzle>,
    fee: u64,
) -> Result<SuccessResponse, Error> {
    let coins = peer
        .register_for_ph_updates(vec![minter_puzzle_hash], minter_ph_min_height)
        .await
        .map_err(|e| Error::WalletError(e))?;

    let totalAmount = fee + 1;
    // select_coins

    todo!()
}

pub fn sync_store(peer: &Peer, store_info: &DataStoreInfo) -> Result<SuccessResponse, Error> {
    todo!()
}

pub fn burn_store(peer: &Peer, store_info: &DataStoreInfo) -> Result<SuccessResponse, Error> {
    todo!()
}

pub fn update_store(
    peer: &Peer,
    store_info: &DataStoreInfo,
    new_owner_address: &str,
    new_delegated_puzzles: Option<Vec<DelegatedPuzzle>>,
) -> Result<SuccessResponse, Error> {
    todo!()
}

pub fn update_metadata(
    peer: &Peer,
    store_info: &DataStoreInfo,
    new_root_hash: Bytes32,
    new_label: &str,
    new_description: &str,
) -> Result<SuccessResponse, Error> {
    todo!()
}

pub fn oracle_spend(peer: &Peer, store_info: &DataStoreInfo) -> Result<SuccessResponse, Error> {
    todo!()
}

// also need to be implemented/exposed:
// - puzzle for pk
// - puzzle hash for puzzle
// - DelegatedPuzzle (from puzzle hash & type etc.)
// - sign coin spends using sk
// - address to puzzle hash
