pub use crate::server_coin::ServerCoin;
use crate::UnspentCoinStates;
pub use chia::protocol::*;
pub use chia::puzzles::{EveProof, LineageProof, Proof};

pub struct UnspentCoinsResponse {
    pub coins: Vec<Coin>,
    pub last_height: u32,
    pub last_header_hash: Bytes32,
}

impl From<UnspentCoinStates> for UnspentCoinsResponse {
    fn from(unspent_coin_states: UnspentCoinStates) -> Self {
        Self {
            coins: unspent_coin_states
                .coin_states
                .into_iter()
                .map(|cs| cs.coin)
                .collect(),
            last_height: unspent_coin_states.last_height,
            last_header_hash: unspent_coin_states.last_header_hash,
        }
    }
}
