/* tslint:disable */
/* eslint-disable */

/* auto-generated by NAPI-RS */

/**
 * Represents a coin on the Chia blockchain.
 *
 * @property {Buffer} parentCoinInfo - Parent coin name/id.
 * @property {Buffer} puzzleHash - Puzzle hash.
 * @property {BigInt} amount - Coin amount.
 */
export interface Coin {
  parentCoinInfo: Buffer
  puzzleHash: Buffer
  amount: bigint
}
/**
 * Represents a full coin state on the Chia blockchain.
 *
 * @property {Coin} coin - The coin.
 * @property {Buffer} spentHeight - The height the coin was spent at, if it was spent.
 * @property {Buffer} createdHeight - The height the coin was created at.
 */
export interface CoinState {
  coin: Coin
  spentHeight?: bigint
  createdHeight?: bigint
}
/**
 * Represents a coin spend on the Chia blockchain.
 *
 * @property {Coin} coin - The coin being spent.
 * @property {Buffer} puzzleReveal - The puzzle of the coin being spent.
 * @property {Buffer} solution - The solution.
 */
export interface CoinSpend {
  coin: Coin
  puzzleReveal: Buffer
  solution: Buffer
}
/**
 * Represents a lineage proof that can be used to spend a singleton.
 *
 * @property {Buffer} parentParentCoinInfo - Parent coin's parent coin info/name/ID.
 * @property {Buffer} parentInnerPuzzleHash - Parent coin's inner puzzle hash.
 * @property {BigInt} parentAmount - Parent coin's amount.
 */
export interface LineageProof {
  parentParentCoinInfo: Buffer
  parentInnerPuzzleHash: Buffer
  parentAmount: bigint
}
/**
 * Represents an eve proof that can be used to spend a singleton. Parent coin is the singleton launcher.
 *
 * @property {Buffer} parentParentCoinInfo - Parent coin's name.
 * @property {BigInt} parentAmount - Parent coin's amount.
 */
export interface EveProof {
  parentParentCoinInfo: Buffer
  parentAmount: bigint
}
/**
 * Represents a proof (either eve or lineage) that can be used to spend a singleton. Use `new_lineage_proof` or `new_eve_proof` to create a new proof.
 *
 * @property {Option<LineageProof>} lineageProof - The lineage proof, if this is a lineage proof.
 * @property {Option<EveProof>} eveProof - The eve proof, if this is an eve proof.
 */
export interface Proof {
  lineageProof?: LineageProof
  eveProof?: EveProof
}
/**
 * Represents a mirror coin with a potentially morphed launcher id.
 *
 * @property {Coin} coin - The coin.
 * @property {Buffer} p2PuzzleHash - The puzzle hash that owns the server coin.
 * @property {Array<string>} memoUrls - The memo URLs that serve the data store being mirrored.
 */
export interface ServerCoin {
  coin: Coin
  p2PuzzleHash: Buffer
  memoUrls: Array<string>
}
/** NFT metadata structure */
export interface NftMetadata {
  /** Data URL or hex string containing the metadata */
  dataUris: Array<string>
  /** Data hash of the metadata */
  dataHash?: Buffer
  /** License URL or hex string */
  licenseUris: Array<string>
  /** License hash */
  licenseHash?: Buffer
  /** NFT metadata URL or hex string */
  metadataUris: Array<string>
  /** NFT metadata hash */
  metadataHash?: Buffer
  /** Edition number */
  editionNumber: number
  /** Maximum number of editions */
  editionTotal: number
}
/** Configuration for minting a single NFT in a bulk operation */
export interface WalletNftMint {
  /** Metadata for the NFT */
  metadata: NftMetadata
  /** Optional royalty puzzle hash - defaults to target address if None */
  royaltyPuzzleHash?: Buffer
  /** Royalty percentage in basis points (1/10000) */
  royaltyTenThousandths: number
  /** Optional p2 puzzle hash - defaults to target address if None */
  p2PuzzleHash?: Buffer
}
/** Response from creating a DID */
export interface CreateDidResponse {
  coinSpends: Array<CoinSpend>
  didId: Buffer
}
/** Response from bulk minting NFTs */
export interface BulkMintNftsResponse {
  coinSpends: Array<CoinSpend>
  nftLauncherIds: Array<Buffer>
}
/**
 * Creates a new lineage proof.
 *
 * @param {LineageProof} lineageProof - The lineage proof.
 * @returns {Proof} The new proof.
 */
export declare function newLineageProof(lineageProof: LineageProof): Proof
/**
 * Creates a new eve proof.
 *
 * @param {EveProof} eveProof - The eve proof.
 * @returns {Proof} The new proof.
 */
export declare function newEveProof(eveProof: EveProof): Proof
/**
 * Represents metadata for a data store.
 *
 * @property {Buffer} rootHash - Root hash.
 * @property {Option<String>} label - Label (optional).
 * @property {Option<String>} description - Description (optional).
 * @property {Option<BigInt>} bytes - Size of the store in bytes (optional).
 */
export interface DataStoreMetadata {
  rootHash: Buffer
  label?: string
  description?: string
  bytes?: bigint
}
/**
 * Represents information about a delegated puzzle. Note that this struct can represent all three types of delegated puzzles, but only represents one at a time.
 *
 * @property {Option<Buffer>} adminInnerPuzzleHash - Admin inner puzzle hash, if this is an admin delegated puzzle.
 * @property {Option<Buffer>} writerInnerPuzzleHash - Writer inner puzzle hash, if this is a writer delegated puzzle.
 * @property {Option<Buffer>} oraclePaymentPuzzleHash - Oracle payment puzzle hash, if this is an oracle delegated puzzle.
 * @property {Option<BigInt>} oracleFee - Oracle fee, if this is an oracle delegated puzzle.
 */
export interface DelegatedPuzzle {
  adminInnerPuzzleHash?: Buffer
  writerInnerPuzzleHash?: Buffer
  oraclePaymentPuzzleHash?: Buffer
  oracleFee?: bigint
}
/**
 * Represents information about a data store. This information can be used to spend the store. It is recommended that this struct is stored in a database to avoid syncing it every time.
 *
 * @property {Coin} coin - The coin associated with the data store.
 * @property {Buffer} launcherId - The store's launcher/singleton ID.
 * @property {Proof} proof - Proof that can be used to spend this store.
 * @property {DataStoreMetadata} metadata - This store's metadata.
 * @property {Buffer} ownerPuzzleHash - The puzzle hash of the owner puzzle.
 * @property {Vec<DelegatedPuzzle>} delegatedPuzzles - This store's delegated puzzles. An empty list usually indicates a 'vanilla' store.
 */
export interface DataStore {
  coin: Coin
  launcherId: Buffer
  proof: Proof
  metadata: DataStoreMetadata
  ownerPuzzleHash: Buffer
  delegatedPuzzles: Array<DelegatedPuzzle>
}
/**
 *
 * @property {Vec<CoinSpend>} coinSpends - Coin spends that can be used to spend the provided store.
 * @property {DataStore} newStore - New data store information after the spend is confirmed.
 */
export interface SuccessResponse {
  coinSpends: Array<CoinSpend>
  newStore: DataStore
}
/**
 * Represents a response from synchronizing a store.
 *
 * @property {DataStore} latestStore - Latest data store information.
 * @property {Option<Vec<Buffer>>} rootHashes - When synced with whistory, this list will contain all of the store's previous root hashes. Otherwise null.
 * @property {Option<Vec<BigInt>>} rootHashesTimestamps - Timestamps of the root hashes (see `rootHashes`).
 * @property {u32} latestHeight - Latest sync height.
 */
export interface SyncStoreResponse {
  latestStore: DataStore
  rootHashes?: Array<Buffer>
  rootHashesTimestamps?: Array<bigint>
  latestHeight: number
}
/**
 * Represents a response containing unspent coins.
 *
 * @property {Vec<Coin>} coins - Unspent coins.
 * @property {u32} lastHeight - Last height.
 * @property {Buffer} lastHeaderHash - Last header hash.
 */
export interface UnspentCoinsResponse {
  coins: Array<Coin>
  lastHeight: number
  lastHeaderHash: Buffer
}
/**
 * Represents a response containing possible launcher ids for datastores.
 *
 * @property {Vec<Buffer>} launcher_ids - Launcher ids of coins that might be datastores.
 * @property {u32} lastHeight - Last height.
 * @property {Buffer} lastHeaderHash - Last header hash.
 */
export interface PossibleLaunchersResponse {
  launcherIds: Array<Buffer>
  lastHeight: number
  lastHeaderHash: Buffer
}
/**
 * Selects coins using the knapsack algorithm.
 *
 * @param {Vec<Coin>} allCoins - Array of available coins (coins to select from).
 * @param {BigInt} totalAmount - Amount needed for the transaction, including fee.
 * @returns {Vec<Coin>} Array of selected coins.
 */
export declare function selectCoins(allCoins: Array<Coin>, totalAmount: bigint): Array<Coin>
/** An output puzzle hash and amount. */
export interface Output {
  puzzleHash: Buffer
  amount: bigint
  memos: Array<Buffer>
}
/**
 * Sends XCH to a given set of puzzle hashes.
 *
 * @param {Buffer} syntheticKey - The synthetic key used by the wallet.
 * @param {Vec<Coin>} selectedCoins - Coins to be spent, as retured by `select_coins`.
 * @param {Vec<Output>} outputs - The output amounts to create.
 * @param {BigInt} fee - The fee to use for the transaction.
 */
export declare function sendXch(syntheticKey: Buffer, selectedCoins: Array<Coin>, outputs: Array<Output>, fee: bigint): Array<CoinSpend>
/**
 * Adds an offset to a launcher id to make it deterministically unique from the original.
 *
 * @param {Buffer} launcherId - The original launcher id.
 * @param {BigInt} offset - The offset to add.
 */
export declare function morphLauncherId(launcherId: Buffer, offset: bigint): Buffer
/** The new server coin and coin spends to create it. */
export interface NewServerCoin {
  serverCoin: ServerCoin
  coinSpends: Array<CoinSpend>
}
/**
 * Creates a new mirror coin with the given URLs.
 *
 * @param {Buffer} syntheticKey - The synthetic key used by the wallet.
 * @param {Vec<Coin>} selectedCoins - Coins to be used for minting, as retured by `select_coins`. Note that, besides the fee, 1 mojo will be used to create the mirror coin.
 * @param {Buffer} hint - The hint for the mirror coin, usually the original or morphed launcher id.
 * @param {Vec<String>} uris - The URIs of the mirrors.
 * @param {BigInt} amount - The amount to use for the created coin.
 * @param {BigInt} fee - The fee to use for the transaction.
 */
export declare function createServerCoin(syntheticKey: Buffer, selectedCoins: Array<Coin>, hint: Buffer, uris: Array<string>, amount: bigint, fee: bigint): NewServerCoin
/**
 * Mints a new datastore.
 *
 * @param {Buffer} minterSyntheticKey - Minter synthetic key.
 * @param {Vec<Coin>} selectedCoins - Coins to be used for minting, as retured by `select_coins`. Note that, besides the fee, 1 mojo will be used to create the new store.
 * @param {Buffer} rootHash - Root hash of the store.
 * @param {Option<String>} label - Store label (optional).
 * @param {Option<String>} description - Store description (optional).
 * @param {Option<BigInt>} bytes - Store size in bytes (optional).
 * @param {Buffer} ownerPuzzleHash - Owner puzzle hash.
 * @param {Vec<DelegatedPuzzle>} delegatedPuzzles - Delegated puzzles.
 * @param {BigInt} fee - Fee to use for the transaction. Total amount - 1 - fee will be sent back to the minter.
 * @returns {SuccessResponse} The success response, which includes coin spends and information about the new datastore.
 */
export declare function mintStore(minterSyntheticKey: Buffer, selectedCoins: Array<Coin>, rootHash: Buffer, label: string | undefined | null, description: string | undefined | null, bytes: bigint | undefined | null, ownerPuzzleHash: Buffer, delegatedPuzzles: Array<DelegatedPuzzle>, fee: bigint): SuccessResponse
/**
 * Spends a store in oracle mode.
 *
 * @param {Buffer} spenderSyntheticKey - Spender synthetic key.
 * @param {Vec<Coin>} selectedCoins - Selected coins, as returned by `select_coins`.
 * @param {DataStore} store - Up-to-daye store information.
 * @param {BigInt} fee - Transaction fee to use.
 * @returns {SuccessResponse} The success response, which includes coin spends and information about the new datastore.
 */
export declare function oracleSpend(spenderSyntheticKey: Buffer, selectedCoins: Array<Coin>, store: DataStore, fee: bigint): SuccessResponse
/**
 * Adds a fee to any transaction. Change will be sent to spender.
 *
 * @param {Buffer} spenderSyntheticKey - Synthetic key of spender.
 * @param {Vec<Coin>} selectedCoins - Selected coins, as returned by `select_coins`.
 * @param {Vec<Buffer>} assertCoinIds - IDs of coins that need to be spent for the fee to be paid. Usually all coin ids in the original transaction.
 * @param {BigInt} fee - Fee to add.
 * @returns {Vec<CoinSpend>} The coin spends to be added to the original transaction.
 */
export declare function addFee(spenderSyntheticKey: Buffer, selectedCoins: Array<Coin>, assertCoinIds: Array<Buffer>, fee: bigint): Array<CoinSpend>
/**
 * Converts a master public key to a wallet synthetic key.
 *
 * @param {Buffer} publicKey - Master public key.
 * @returns {Buffer} The (first) wallet synthetic key.
 */
export declare function masterPublicKeyToWalletSyntheticKey(publicKey: Buffer): Buffer
/**
 * Converts a master public key to the first puzzle hash.
 *
 * @param {Buffer} publicKey - Master public key.
 * @returns {Buffer} The first wallet puzzle hash.
 */
export declare function masterPublicKeyToFirstPuzzleHash(publicKey: Buffer): Buffer
/**
 * Converts a master secret key to a wallet synthetic secret key.
 *
 * @param {Buffer} secretKey - Master secret key.
 * @returns {Buffer} The (first) wallet synthetic secret key.
 */
export declare function masterSecretKeyToWalletSyntheticSecretKey(secretKey: Buffer): Buffer
/**
 * Converts a secret key to its corresponding public key.
 *
 * @param {Buffer} secretKey - The secret key.
 * @returns {Buffer} The public key.
 */
export declare function secretKeyToPublicKey(secretKey: Buffer): Buffer
/**
 * Converts a puzzle hash to an address by encoding it using bech32m.
 *
 * @param {Buffer} puzzleHash - The puzzle hash.
 * @param {String} prefix - Address prefix (e.g., 'txch').
 * @returns {Promise<String>} The converted address.
 */
export declare function puzzleHashToAddress(puzzleHash: Buffer, prefix: string): string
/**
 * Converts an address to a puzzle hash using bech32m.
 *
 * @param {String} address - The address.
 * @returns {Promise<Buffer>} The puzzle hash.
 */
export declare function addressToPuzzleHash(address: string): Buffer
/**
 * Creates an admin delegated puzzle for a given key.
 *
 * @param {Buffer} syntheticKey - Synthetic key.
 * @returns {Promise<DelegatedPuzzle>} The delegated puzzle.
 */
export declare function adminDelegatedPuzzleFromKey(syntheticKey: Buffer): DelegatedPuzzle
/**
 * Creates a writer delegated puzzle from a given key.
 *
 * @param {Buffer} syntheticKey - Synthetic key.
 * /// @returns {Promise<DelegatedPuzzle>} The delegated puzzle.
 */
export declare function writerDelegatedPuzzleFromKey(syntheticKey: Buffer): DelegatedPuzzle
/**
 *
 * @param {Buffer} oraclePuzzleHash - The oracle puzzle hash (corresponding to the wallet where fees should be paid).
 * @param {BigInt} oracleFee - The oracle fee (i.e., XCH amount to be paid for every oracle spend). This amount MUST be even.
 * @returns {Promise<DelegatedPuzzle>} The delegated puzzle.
 */
export declare function oracleDelegatedPuzzle(oraclePuzzleHash: Buffer, oracleFee: bigint): DelegatedPuzzle
/**
 * Partially or fully signs coin spends using a list of keys.
 *
 * @param {Vec<CoinSpend>} coinSpends - The coin spends to sign.
 * @param {Vec<Buffer>} privateKeys - The private/secret keys to be used for signing.
 * @param {Buffer} forTestnet - Set to true to sign spends for testnet11, false for mainnet.
 * @returns {Promise<Buffer>} The signature.
 */
export declare function signCoinSpends(coinSpends: Array<CoinSpend>, privateKeys: Array<Buffer>, forTestnet: boolean): Buffer
/**
 * Computes the ID (name) of a coin.
 *
 * @param {Coin} coin - The coin.
 * @returns {Buffer} The coin ID.
 */
export declare function getCoinId(coin: Coin): Buffer
/**
 * Updates the metadata of a store. Either the owner, admin, or writer public key must be provided.
 *
 * @param {DataStore} store - Current store information.
 * @param {Buffer} newRootHash - New root hash.
 * @param {Option<String>} newLabel - New label (optional).
 * @param {Option<String>} newDescription - New description (optional).
 * @param {Option<BigInt>} newBytes - New size in bytes (optional).
 * @param {Option<Buffer>} ownerPublicKey - Owner public key.
 * @param {Option<Buffer>} adminPublicKey - Admin public key.
 * @param {Option<Buffer>} writerPublicKey - Writer public key.
 * @returns {SuccessResponse} The success response, which includes coin spends and information about the new datastore.
 */
export declare function updateStoreMetadata(store: DataStore, newRootHash: Buffer, newLabel?: string | undefined | null, newDescription?: string | undefined | null, newBytes?: bigint | undefined | null, ownerPublicKey?: Buffer | undefined | null, adminPublicKey?: Buffer | undefined | null, writerPublicKey?: Buffer | undefined | null): SuccessResponse
/**
 * Updates the ownership of a store. Either the admin or owner public key must be provided.
 *
 * @param {DataStore} store - Store information.
 * @param {Option<Buffer>} newOwnerPuzzleHash - New owner puzzle hash.
 * @param {Vec<DelegatedPuzzle>} newDelegatedPuzzles - New delegated puzzles.
 * @param {Option<Buffer>} ownerPublicKey - Owner public key.
 * @param {Option<Buffer>} adminPublicKey - Admin public key.
 * @returns {SuccessResponse} The success response, which includes coin spends and information about the new datastore.
 */
export declare function updateStoreOwnership(store: DataStore, newOwnerPuzzleHash: Buffer | undefined | null, newDelegatedPuzzles: Array<DelegatedPuzzle>, ownerPublicKey?: Buffer | undefined | null, adminPublicKey?: Buffer | undefined | null): SuccessResponse
/**
 * Melts a store. The 1 mojo change will be used as a fee.
 *
 * @param {DataStore} store - Store information.
 * @param {Buffer} ownerPublicKey - Owner's public key.
 * @returns {Vec<CoinSpend>} The coin spends that the owner can sign to melt the store.
 */
export declare function meltStore(store: DataStore, ownerPublicKey: Buffer): Array<CoinSpend>
/**
 * Signs a message using the provided private key.
 *
 * @param {Buffer} message - Message to sign, as bytes. "Chia Signed Message" will be prepended automatically, as per CHIP-2 - no need to add it before calling this function.
 * @param {Buffer} private_key - Private key to sign the message with. No derivation is done.
 * @returns {Buffer} The signature.
 */
export declare function signMessage(message: Buffer, privateKey: Buffer): Buffer
/**
 * Verifies a signed message using the provided public key.
 *
 * @param {Buffer} signature - Th signature to be verified.
 * @param {Buffer} public_key - Public key corresponding to the private key that was used to sign the message.
 * @param {Buffer} message - Message that was signed, as bytes. "Chia Signed Message" will be prepended automatically, as per CHIP-2 - no need to add it before calling this function.
 * @returns {Buffer} Boolean - true indicates that the signature is valid, while false indicates that it is not.
 */
export declare function verifySignedMessage(signature: Buffer, publicKey: Buffer, message: Buffer): boolean
/**
 * Converts a synthetic key to its corresponding standard puzzle hash.
 *
 * @param {Buffer} syntheticKey - Synthetic key.
 * @returns {Buffer} The standard puzzle (puzzle) hash.
 */
export declare function syntheticKeyToPuzzleHash(syntheticKey: Buffer): Buffer
/**
 * Calculates the total cost of a given array of coin spends/
 *
 * @param {Vec<CoinSpend>} CoinSpend - Coin spends.
 * @returns {BigInt} The cost of the coin spends.
 */
export declare function getCost(coinSpends: Array<CoinSpend>): bigint
/**
 * Returns the mainnet genesis challenge.
 *
 * @returns {Buffer} The mainnet genesis challenge.
 */
export declare function getMainnetGenesisChallenge(): Buffer
/**
 * Returns the testnet11 genesis challenge.
 *
 * @returns {Buffer} The testnet11 genesis challenge.
 */
export declare function getTestnet11GenesisChallenge(): Buffer
/**
 * Creates a new Decentralized Identity (DID)
 *
 * @param {Buffer} spenderSyntheticKey - The synthetic public key of the spender
 * @param {Vec<Coin>} selectedCoins - Coins to use for the creation
 * @param {BigInt} fee - Transaction fee in mojos
 * @returns {Promise<CreateDidResponse>} The coin spends and DID ID
 */
export declare function createDid(spenderSyntheticKey: Buffer, selectedCoins: Array<Coin>, fee: bigint): CreateDidResponse
/**
 * Mints multiple NFTs in a single transaction
 *
 * @param {Buffer} spenderSyntheticKey - The synthetic public key of the spender
 * @param {Vec<Coin>} selectedCoins - Coins to use for minting
 * @param {Vec<WalletNftMint>} mints - Vector of NFT configurations to mint
 * @param {Option<Buffer>} didId - Optional DID to associate with the NFTs
 * @param {Buffer} targetAddress - Default address for royalties and ownership
 * @param {BigInt} fee - Transaction fee in mojos
 * @returns {Promise<BulkMintNftsResponse>} The coin spends and NFT launcher IDs
 */
export declare function bulkMintNfts(spenderSyntheticKey: Buffer, selectedCoins: Array<Coin>, mints: Array<WalletNftMint>, didId: Buffer | undefined | null, targetAddress: Buffer, fee: bigint): Promise<BulkMintNftsResponse>
export declare class Tls {
  /**
   * Creates a new TLS connector.
   *
   * @param {String} certPath - Path to the certificate file (usually '~/.chia/mainnet/config/ssl/wallet/wallet_node.crt').
   * @param {String} keyPath - Path to the key file (usually '~/.chia/mainnet/config/ssl/wallet/wallet_node.key').
   */
  constructor(certPath: string, keyPath: string)
}
export declare class Peer {
  /**
   * Creates a new Peer instance.
   *
   * @param {String} nodeUri - URI of the node (e.g., '127.0.0.1:58444').
   * @param {bool} testnet - True for connecting to testnet11, false for mainnet.
   * @param {Tls} tls - TLS connector.
   * @returns {Promise<Peer>} A new Peer instance.
   */
  static new(nodeUri: string, tesntet: boolean, tls: Tls): Promise<Peer>
  /**
   * Gets all children of a given coin.
   *
   * @param {Buffer} coinId - ID of the coin to get children for.
   * @returns {Promise<Vec<Coin>>} The coin's children.
   */
  getCoinChildren(coinId: Buffer): Promise<Array<CoinState>>
  /**
   * Retrieves all coins that are unspent on the chain. Note that coins part of spend bundles that are pending in the mempool will also be included.
   *
   * @param {Buffer} puzzleHash - Puzzle hash of the wallet.
   * @param {Option<u32>} previousHeight - Previous height that was spent. If null, sync will be done from the genesis block.
   * @param {Buffer} previousHeaderHash - Header hash corresponding to the previous height. If previousHeight is null, this should be the genesis challenge of the current chain.
   * @returns {Promise<UnspentCoinsResponse>} The unspent coins response.
   */
  getAllUnspentCoins(puzzleHash: Buffer, previousHeight: number | undefined | null, previousHeaderHash: Buffer): Promise<UnspentCoinsResponse>
  /**
   * Retrieves all hinted coin states that are unspent on the chain. Note that coins part of spend bundles that are pending in the mempool will also be included.
   *
   * @param {Buffer} puzzleHash - Puzzle hash to lookup hinted coins for.
   * @param {bool} forTestnet - True for testnet, false for mainnet.
   * @returns {Promise<Vec<Coin>>} The unspent coins response.
   */
  getHintedCoinStates(puzzleHash: Buffer, forTestnet: boolean): Promise<Array<CoinState>>
  /**
   * Fetches the server coin from a given coin state.
   *
   * @param {CoinState} coinState - The coin state.
   * @param {BigInt} maxCost - The maximum cost to use when parsing the coin. For example, `11_000_000_000`.
   * @returns {Promise<ServerCoin>} The server coin.
   */
  fetchServerCoin(coinState: CoinState, maxCost: bigint): Promise<ServerCoin>
  /**
   * Synchronizes a datastore.
   *
   * @param {DataStore} store - Data store.
   * @param {Option<u32>} lastHeight - Min. height to search records from. If null, sync will be done from the genesis block.
   * @param {Buffer} lastHeaderHash - Header hash corresponding to `lastHeight`. If null, this should be the genesis challenge of the current chain.
   * @param {bool} withHistory - Whether to return the root hash history of the store.
   * @returns {Promise<SyncStoreResponse>} The sync store response.
   */
  syncStore(store: DataStore, lastHeight: number | undefined | null, lastHeaderHash: Buffer, withHistory: boolean): Promise<SyncStoreResponse>
  /**
   * Synchronizes a store using its launcher ID.
   *
   * @param {Buffer} launcherId - The store's launcher/singleton ID.
   * @param {Option<u32>} lastHeight - Min. height to search records from. If null, sync will be done from the genesis block.
   * @param {Buffer} lastHeaderHash - Header hash corresponding to `lastHeight`. If null, this should be the genesis challenge of the current chain.
   * @param {bool} withHistory - Whether to return the root hash history of the store.
   * @returns {Promise<SyncStoreResponse>} The sync store response.
   */
  syncStoreFromLauncherId(launcherId: Buffer, lastHeight: number | undefined | null, lastHeaderHash: Buffer, withHistory: boolean): Promise<SyncStoreResponse>
  /**
   * Fetch a store's creation height.
   *
   * @param {Buffer} launcherId - The store's launcher/singleton ID.
   * @param {Option<u32>} lastHeight - Min. height to search records from. If null, sync will be done from the genesis block.
   * @param {Buffer} lastHeaderHash - Header hash corresponding to `lastHeight`. If null, this should be the genesis challenge of the current chain.
   * @returns {Promise<BigInt>} The store's creation height.
   */
  getStoreCreationHeight(launcherId: Buffer, lastHeight: number | undefined | null, lastHeaderHash: Buffer): Promise<bigint>
  /**
   * Broadcasts a spend bundle to the mempool.
   *
   * @param {Vec<CoinSpend>} coinSpends - The coin spends to be included in the bundle.
   * @param {Vec<Buffer>} sigs - The signatures to be aggregated and included in the bundle.
   * @returns {Promise<String>} The broadcast error. If '', the broadcast was successful.
   */
  broadcastSpend(coinSpends: Array<CoinSpend>, sigs: Array<Buffer>): Promise<string>
  /**
   * Checks if a coin is spent on-chain.
   *
   * @param {Buffer} coinId - The coin ID.
   * @param {Option<u32>} lastHeight - Min. height to search records from. If null, sync will be done from the genesis block.
   * @param {Buffer} headerHash - Header hash corresponding to `lastHeight`. If null, this should be the genesis challenge of the current chain.
   * @returns {Promise<bool>} Whether the coin is spent on-chain.
   */
  isCoinSpent(coinId: Buffer, lastHeight: number | undefined | null, headerHash: Buffer): Promise<boolean>
  /**
   * Retrieves the current header hash corresponding to a given height.
   *
   * @param {u32} height - The height.
   * @returns {Promise<Buffer>} The header hash.
   */
  getHeaderHash(height: number): Promise<Buffer>
  /**
   * Retrieves the fee estimate for a given target time.
   *
   * @param {Peer} peer - The peer connection to the Chia node.
   * @param {BigInt} targetTimeSeconds - Time delta: The target time in seconds from the current time for the fee estimate.
   * @returns {Promise<BigInt>} The estimated fee in mojos per CLVM cost.
   */
  getFeeEstimate(targetTimeSeconds: bigint): Promise<bigint>
  /**
   * Retrieves the peer's peak.
   *
   * @returns {Option<u32>} A tuple consiting of the latest synced block's height, as reported by the peer. Null if the peer has not yet reported a peak.
   */
  getPeak(): Promise<number | null>
  /**
   * Spends the mirror coins to make them unusable in the future.
   *
   * @param {Buffer} syntheticKey - The synthetic key used by the wallet.
   * @param {Vec<Coin>} selectedCoins - Coins to be used for minting, as retured by `select_coins`. Note that the server coins will count towards the fee.
   * @param {BigInt} fee - The fee to use for the transaction.
   * @param {bool} forTestnet - True for testnet, false for mainnet.
   */
  lookupAndSpendServerCoins(syntheticKey: Buffer, selectedCoins: Array<Coin>, fee: bigint, forTestnet: boolean): Promise<Array<CoinSpend>>
  /**
   * Looks up possible datastore launchers by searching for singleton launchers created with a DL-specific hint.
   *
   * @param {Option<u32>} lastHeight - Min. height to search records from. If null, sync will be done from the genesis block.
   * @param {Buffer} headerHash - Header hash corresponding to `lastHeight`. If null, this should be the genesis challenge of the current chain.
   * @returns {Promise<PossibleLaunchersResponse>} Possible launcher ids for datastores, as well as a height + header hash combo to use for the next call.
   */
  lookUpPossibleLaunchers(lastHeight: number | undefined | null, headerHash: Buffer): Promise<PossibleLaunchersResponse>
  /**
   * Waits for a coin to be spent on-chain.
   *
   * @param {Buffer} coin_id - Id of coin to track.
   * @param {Option<u32>} lastHeight - Min. height to search records from. If null, sync will be done from the genesis block.
   * @param {Buffer} headerHash - Header hash corresponding to `lastHeight`. If null, this should be the genesis challenge of the current chain.
   * @returns {Promise<Buffer>} Promise that resolves when the coin is spent (returning the coin id).
   */
  waitForCoinToBeSpent(coinId: Buffer, lastHeight: number | undefined | null, headerHash: Buffer): Promise<Buffer>
}
