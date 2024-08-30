use chia::{
    bls::{PublicKey, SecretKey, Signature},
    protocol::{Bytes, Bytes32, Program},
};
use napi::bindgen_prelude::*;
use napi::Result;
use thiserror::Error;

use crate::{js, rust};

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

pub trait FromJs<T> {
    fn from_js(value: T) -> Result<Self>
    where
        Self: Sized;
}

pub trait ToJs<T> {
    fn to_js(&self) -> Result<T>;
}

impl FromJs<Buffer> for Bytes32 {
    fn from_js(value: Buffer) -> Result<Self> {
        Self::try_from(value.as_ref().to_vec())
            .map_err(|_| js::err(ConversionError::DifferentLength(32)))
    }
}

impl ToJs<Buffer> for Bytes32 {
    fn to_js(&self) -> Result<Buffer> {
        Ok(Buffer::from(self.to_vec()))
    }
}

impl FromJs<Buffer> for Program {
    fn from_js(value: Buffer) -> Result<Self> {
        Ok(Self::from(value.to_vec()))
    }
}

impl ToJs<Buffer> for Program {
    fn to_js(&self) -> Result<Buffer> {
        Ok(Buffer::from(self.to_vec()))
    }
}

impl FromJs<Buffer> for Bytes {
    fn from_js(value: Buffer) -> Result<Self> {
        Ok(Self::new(value.to_vec()))
    }
}

impl ToJs<Buffer> for Bytes {
    fn to_js(&self) -> Result<Buffer> {
        Ok(Buffer::from(self.to_vec()))
    }
}

impl FromJs<Buffer> for PublicKey {
    fn from_js(value: Buffer) -> Result<Self> {
        Self::from_bytes(
            &<[u8; 48]>::try_from(value.to_vec())
                .map_err(|_| js::err(ConversionError::DifferentLength(48)))?,
        )
        .map_err(|_| js::err(ConversionError::InvalidPublicKey))
    }
}

impl ToJs<Buffer> for PublicKey {
    fn to_js(&self) -> Result<Buffer> {
        Ok(Buffer::from(self.to_bytes().to_vec()))
    }
}

impl FromJs<Buffer> for SecretKey {
    fn from_js(value: Buffer) -> Result<Self> {
        Self::from_bytes(
            &<[u8; 32]>::try_from(value.to_vec())
                .map_err(|_| js::err(ConversionError::DifferentLength(32)))?,
        )
        .map_err(|_| js::err(ConversionError::InvalidPrivateKey))
    }
}

impl ToJs<Buffer> for SecretKey {
    fn to_js(&self) -> Result<Buffer> {
        Ok(Buffer::from(self.to_bytes().to_vec()))
    }
}

impl FromJs<Buffer> for Signature {
    fn from_js(value: Buffer) -> Result<Self> {
        Self::from_bytes(
            &<[u8; 96]>::try_from(value.to_vec())
                .map_err(|_| js::err(ConversionError::DifferentLength(96)))?,
        )
        .map_err(|_| js::err(ConversionError::InvalidSignature))
    }
}

impl ToJs<Buffer> for Signature {
    fn to_js(&self) -> Result<Buffer> {
        Ok(Buffer::from(self.to_bytes().to_vec()))
    }
}

impl FromJs<BigInt> for u64 {
    fn from_js(value: BigInt) -> Result<Self> {
        Ok(value.get_u64().1)
    }
}

impl ToJs<BigInt> for u64 {
    fn to_js(&self) -> Result<BigInt> {
        Ok(BigInt::from(*self))
    }
}

impl FromJs<js::Coin> for rust::Coin {
    fn from_js(value: js::Coin) -> Result<Self> {
        Ok(Self {
            parent_coin_info: Bytes32::from_js(value.parent_coin_info)?,
            puzzle_hash: Bytes32::from_js(value.puzzle_hash)?,
            amount: u64::from_js(value.amount)?,
        })
    }
}

impl ToJs<js::Coin> for rust::Coin {
    fn to_js(&self) -> Result<js::Coin> {
        Ok(js::Coin {
            parent_coin_info: self.parent_coin_info.to_js()?,
            puzzle_hash: self.puzzle_hash.to_js()?,
            amount: self.amount.to_js()?,
        })
    }
}

impl FromJs<js::CoinSpend> for rust::CoinSpend {
    fn from_js(value: js::CoinSpend) -> Result<Self> {
        Ok(Self {
            coin: rust::Coin::from_js(value.coin)?,
            puzzle_reveal: Program::from_js(value.puzzle_reveal)?,
            solution: Program::from_js(value.solution)?,
        })
    }
}

impl ToJs<js::CoinSpend> for rust::CoinSpend {
    fn to_js(&self) -> Result<js::CoinSpend> {
        Ok(js::CoinSpend {
            coin: self.coin.to_js()?,
            puzzle_reveal: self.puzzle_reveal.to_js()?,
            solution: self.solution.to_js()?,
        })
    }
}

impl FromJs<js::LineageProof> for rust::LineageProof {
    fn from_js(value: js::LineageProof) -> Result<Self> {
        Ok(Self {
            parent_parent_coin_info: Bytes32::from_js(value.parent_parent_coin_info)?,
            parent_inner_puzzle_hash: Bytes32::from_js(value.parent_inner_puzzle_hash)?,
            parent_amount: u64::from_js(value.parent_amount)?,
        })
    }
}

impl ToJs<js::LineageProof> for rust::LineageProof {
    fn to_js(&self) -> Result<js::LineageProof> {
        Ok(js::LineageProof {
            parent_parent_coin_info: self.parent_parent_coin_info.to_js()?,
            parent_inner_puzzle_hash: self.parent_inner_puzzle_hash.to_js()?,
            parent_amount: self.parent_amount.to_js()?,
        })
    }
}

impl FromJs<js::EveProof> for rust::EveProof {
    fn from_js(value: js::EveProof) -> Result<Self> {
        Ok(rust::EveProof {
            parent_parent_coin_info: Bytes32::from_js(value.parent_parent_coin_info)?,
            parent_amount: u64::from_js(value.parent_amount)?,
        })
    }
}

impl ToJs<js::EveProof> for rust::EveProof {
    fn to_js(&self) -> Result<js::EveProof> {
        Ok(js::EveProof {
            parent_parent_coin_info: self.parent_parent_coin_info.to_js()?,
            parent_amount: self.parent_amount.to_js()?,
        })
    }
}

impl FromJs<js::Proof> for rust::Proof {
    fn from_js(value: js::Proof) -> Result<Self> {
        if let Some(lineage_proof) = value.lineage_proof {
            Ok(rust::Proof::Lineage(rust::LineageProof::from_js(
                lineage_proof,
            )?))
        } else if let Some(eve_proof) = value.eve_proof {
            Ok(rust::Proof::Eve(rust::EveProof::from_js(eve_proof)?))
        } else {
            Err(js::err(ConversionError::MissingProof))
        }
    }
}

impl ToJs<js::Proof> for rust::Proof {
    fn to_js(&self) -> Result<js::Proof> {
        Ok(match self {
            rust::Proof::Lineage(lineage_proof) => js::Proof {
                lineage_proof: Some(lineage_proof.to_js()?),
                eve_proof: None,
            },
            rust::Proof::Eve(eve_proof) => js::Proof {
                lineage_proof: None,
                eve_proof: Some(eve_proof.to_js()?),
            },
        })
    }
}
