use chia_protocol::{Bytes32, Coin};
use chia_puzzles::Proof;
use clvmr::NodePtr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum DelegatedPuzzleHash {
    Admin(Bytes32),
    Writer(Bytes32),
    Oracle(Bytes32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum DelegatedPuzzle {
    Admin(NodePtr),
    Writer(NodePtr),
    Oracle(Bytes32, u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct DataStoreInfo<M> {
    pub coin: Coin,
    // singleton layer
    pub launcher_id: Bytes32,
    pub proof: Proof,
    // NFT state layer
    pub metadata: M,
    // inner puzzle (either p2 or delegation_layer + p2)
    pub owner_puzzle_hash: Bytes32,
    pub delegated_puzzle_hashes: Option<Vec<DelegatedPuzzleHash>>,
}
