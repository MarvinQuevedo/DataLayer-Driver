use chia::bls::G2Element;
use chia_protocol::{Coin, CoinSpend, SpendBundle};
use hex::encode;
use serde::Serialize;

#[derive(Serialize)]
struct SerializableCoin {
    parent_coin_info: String,
    puzzle_hash: String,
    amount: u64,
}

#[derive(Serialize)]
struct SerializableCoinSpend {
    coin: SerializableCoin,
    puzzle_reveal: String,
    solution: String,
}

#[derive(Serialize)]
struct SerializableSpendBundle {
    coin_spends: Vec<SerializableCoinSpend>,
    aggregated_signature: String,
}

impl From<&Coin> for SerializableCoin {
    fn from(coin: &Coin) -> Self {
        SerializableCoin {
            parent_coin_info: encode(coin.parent_coin_info),
            puzzle_hash: encode(coin.puzzle_hash),
            amount: coin.amount,
        }
    }
}

impl From<&CoinSpend> for SerializableCoinSpend {
    fn from(coin_spend: &CoinSpend) -> Self {
        SerializableCoinSpend {
            coin: SerializableCoin::from(&coin_spend.coin),
            puzzle_reveal: encode(coin_spend.puzzle_reveal.clone().into_bytes()),
            solution: encode(coin_spend.solution.clone().into_bytes()),
        }
    }
}

impl From<&SpendBundle> for SerializableSpendBundle {
    fn from(spend_bundle: &SpendBundle) -> Self {
        SerializableSpendBundle {
            coin_spends: spend_bundle
                .coin_spends
                .iter()
                .map(SerializableCoinSpend::from)
                .collect(),
            aggregated_signature: encode(spend_bundle.aggregated_signature.to_bytes()),
        }
    }
}

pub fn print_spend_bundle(spends: Vec<CoinSpend>, agg_sig: G2Element) {
    let spend_bundle = SpendBundle {
        coin_spends: spends,
        aggregated_signature: agg_sig,
    };

    let serializable_bundle = SerializableSpendBundle::from(&spend_bundle);
    let json = serde_json::to_string(&serializable_bundle).expect("Serialization failed");
    println!("{}", json);
}
