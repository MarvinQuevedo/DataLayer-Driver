# DataLayer-Driver

## Description

A collection of functions that can be used to interact with datastores on the Chia blockchain.

## Functions

This library offers the following functions:
- wallet: `selectCoins`, `addFee`, `signCoinSpends`
- drivers: `mintStore`, `adminDelegatedPuzzleFromKey`, `writerDelegatedPuzzleFromKey`, `oracleDelegatedPuzzle`, `oracleSpend`, `updateStoreMetadata`, `updateStoreOwnership`, `meltStore`
- utils: `getCoinId`, `masterPublicKeyToWalletSyntheticKey`, `masterPublicKeyToFirstPuzzleHash`, `masterSecretKeyToWalletSyntheticSecretKey`, `secretKeyToPublicKey`, `puzzleHashToAddress`, `addressToPuzzleHash`, `newLineageProof`, `newEveProof`

The `Peer` class also exposes the following methods: `getAllUnspentCoins`, `syncStore`, `syncStoreFromLauncherId`, `broadcastSpend`, `isCoinSpent`.

Note that all functions come with detailed JSDoc comments.

## Example

This example will assume that you want to use a server-side wallet to mint & update the store. You can also send unsigned coin spends to the client and ask them to sign via a wallet such as Goby, but this scenario will not be covered here.

First, you'll need to generate new keys for the server wallet. You can do that by running `chia keys generate`, followed by `chia keys show --show-mnemonic-seed -f [FINGERPRINT]` (fingerprint is present in the output of the first command). The server signing transactions will need the `Master private key (m)` printed by the second command. The server wallet will be single-address, meaning that you can only send XCH to `First wallet address` to fund it (i.e., don't use `get_address` to obtain the wallet address!).

The synthetic public and private keys corresponding to the first address can simply be obtain as follows:

```js
export const getPublicSyntheticKey = (): Buffer => {
  const master_sk = Buffer.from(process.env.SERVER_SK as string, 'hex');
  const master_pk = secretKeyToPublicKey(master_sk);

  return masterPublicKeyToWalletSyntheticKey(master_pk);
}

export const getPrivateSyntheticKey = (): Buffer => {
  const master_sk = Buffer.from(process.env.SERVER_SK as string, 'hex');

  return masterSecretKeyToWalletSyntheticSecretKey(master_sk);
}
```

To get the wallet's address, you can simply do:

```js
export const getServerPuzzleHash = (): Buffer => {
  const master_sk = Buffer.from(process.env.SERVER_SK as string, 'hex');
  const master_pk = secretKeyToPublicKey(master_sk);

  return masterPublicKeyToFirstPuzzleHash(master_pk);
}

// other part of the code
const ph = getServerPuzzleHash();
const address = puzzleHashToAddress(ph, NETWORK_PREFIX);
```

Where `NETWORK_PREFIX` is `xch` for mainnet and `txch` for testnet.

To 'talk' with the wallet, you will need to initialize a `Peer` object like in the example below:

```js
const peer = await Peer.new('127.0.0.1:58444', 'testnet11', CHIA_CRT, CHIA_KEY)
```

The example above connects to a `tesntet11` full node. Note that `CHIA_CRT` is usually `~/.chia/mainnet/config/ssl/wallet/wallet_node.crt` and `CHIA_KEY` is usually `~/.chia/mainnet/config/ssl/wallet/wallet_node.key`. For mainnet, the port is usually `8444`, and the network id is `mainnet`.

Making any transaction will require finding available (unspent) coins in the server wallet and selecting them before calling any drivers:

```js
const ph = getServerPuzzleHash();
const coinsResp = await peer.getAllUnspentCoins(ph, MIN_HEIGHT, MIN_HEIGHT_HEADER_HASH);
const coins = selectCoins(coinsResp.coins, feeBigInt + BigInt(1));
```

You can speed up coin lookup by setting `MIN_HEIGHT` and `MIN_HEIGHT_HEADER_HASH` to point to a block just before wallet creation (or before the first fund tx was confirmed). Alternatively, you can set them to `null` and the network's genesis challenge. When selecting coins, make sure to include the fee in the total amount.

The next step is to generate coin spends using drivers:
```js
const successResponse = await mintStore(
    getPublicSyntheticKey(),
    coins,
    rootHash,
    label,
    description,
    ownerPuzzleHash,
    [
      adminDelegatedPuzzleFromKey(serverKey),
      writerDelegatedPuzzleFromKey(serverKey),
      oracleDelegatedPuzzle(ownerPuzzleHash, oracleFeeBigInt)
    ],
    feeBigInt
  );
 ```
 
 The code above is used to mint stores. Note that a success response not only contains unsigned coin spends, but also returns a new `DataStoreInfo` object that can be used to sync or spend the store in the future. Note that some drivers will not require coins, only the information of the store being spent:
 
 ```js
 const resp = meltStore(
    parseDataStoreInfo(info),
    ownerPublicKey
  );
```

In that case, the 'basic' transaction only spends the store - to add fees, you'll need to call `addFee` and make sure to include the returned coin spends in the final bundle:

```js
const resp = await addFee(getPublicSyntheticKey(), selectedCoins, coin_ids, BigInt(fee));
```

Before broadcasting transactions, you'll usually need to sign the coin spends. The `signCoinSpends` function was created for that purpose:

```js
const sig = signCoinSpends(coinSpends, [getPrivateSyntheticKey()], NETWORK_AGG_SIG_DATA);
```

Broadcasting a bundle is as easy as:

```js
const err = await peer.broadcastSpend(
    coinSpends,
    [sig]
  );
```

To confirm the transaction, you can just confirm that the datastore coin was spent on-chain:

```js
const confirmed = await peer.isCoinSpent(getCoinId(info.coin), MIN_HEIGHT, MIN_HEIGHT_HEADER_HASH);
```

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/Datalayer-Storage/DataLayer-Driver/blob/HEAD/LICENSE) file for details.
