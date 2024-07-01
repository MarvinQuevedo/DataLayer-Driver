use chia::client::Peer;
use chia_protocol::{Bytes32, CoinSpend};
use serde::de::value::Error;

use crate::{DataStoreInfo, DelegatedPuzzle};

#[derive(Clone, Debug)]

pub struct SuccessResponse {
    pub coin_spends: Vec<CoinSpend>,
    pub new_info: DataStoreInfo,
}

pub fn mint_store_to_address(
    peer: &Peer,
    minter_address: &str,
    root_hash: Bytes32,
    label: &str,
    description: &str,
    address: &str,
    delegated_puzzles: Option<Vec<DelegatedPuzzle>>,
) -> Result<SuccessResponse, Error> {
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
