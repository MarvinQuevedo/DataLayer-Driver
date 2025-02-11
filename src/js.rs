use crate::conversions::{FromJs, ToJs};
use crate::wallet;

use chia::protocol::{Bytes32 as RustBytes32, CoinSpend as RustCoinSpend};
use chia::puzzles::nft::NftMetadata as RustNftMetadata;
use chia_wallet_sdk::{Did as RustDid, Nft as RustNft};
use napi::bindgen_prelude::*;

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

#[napi(object)]
#[derive(Clone)]
/// Represents a full coin state on the Chia blockchain.
///
/// @property {Coin} coin - The coin.
/// @property {Buffer} spentHeight - The height the coin was spent at, if it was spent.
/// @property {Buffer} createdHeight - The height the coin was created at.
pub struct CoinState {
    pub coin: Coin,
    pub spent_height: Option<BigInt>,
    pub created_height: Option<BigInt>,
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

#[napi(object)]
/// Represents a mirror coin with a potentially morphed launcher id.
///
/// @property {Coin} coin - The coin.
/// @property {Buffer} p2PuzzleHash - The puzzle hash that owns the server coin.
/// @property {Array<string>} memoUrls - The memo URLs that serve the data store being mirrored.
pub struct ServerCoin {
    pub coin: Coin,
    pub p2_puzzle_hash: Buffer,
    pub memo_urls: Vec<String>,
}

pub fn err<T>(error: T) -> napi::Error
where
    T: ToString,
{
    napi::Error::from_reason(error.to_string())
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
            data_hash: if self.data_hash.is_some() {
                Some(self.data_hash.unwrap().to_js()?)
            } else {
                None
            },
            license_uris: self.license_uris.clone(),
            license_hash: if self.license_hash.is_some() {
                Some(self.license_hash.unwrap().to_js()?)
            } else {
                None
            },
            metadata_hash: self.metadata_hash.map(|hash| hash.to_js()).transpose()?,
            metadata_uris: self.metadata_uris.clone(),
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
            did_id: self.1.info.launcher_id.to_js()?,
        })
    }
}

#[napi(object)]
/// Response from bulk minting NFTs
pub struct BulkMintNftsResponse {
    pub coin_spends: Vec<CoinSpend>,
    pub nft_launcher_ids: Vec<Buffer>,
}

impl ToJs<BulkMintNftsResponse> for (Vec<RustCoinSpend>, Vec<RustNft<RustNftMetadata>>) {
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
        })
    }
}
