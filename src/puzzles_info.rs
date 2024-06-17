use chia_protocol::{Bytes32, Coin};
use chia_puzzles::Proof;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum DelegatedPuzzle {
    Admin(Bytes32),
    Writer(Bytes32),
    NoFilter(Bytes32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct DataStoreInfo<M> {
    pub launcher_id: Bytes32,
    pub coin: Coin,
    pub proof: Proof,
    pub metadata: M,
    pub owner_puzzle_hash: Bytes32,
    pub oracle_address: Option<Bytes32>,
    pub oracle_fee: Option<u64>,
    pub delegated_puzzles_metkle_root: Option<Bytes32>,
}
