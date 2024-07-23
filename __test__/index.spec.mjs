import test from 'ava'

import { newLineageProof, newEveProof, Peer, selectCoins, mintStore, oracleSpend, addFee, masterPublicKeyToWalletSyntheticKey, masterPublicKeyToFirstPuzzleHash, masterSecretKeyToWalletSyntheticSecretKey, secretKeyToPublicKey, puzzleHashToAddress, addressToPuzzleHash, adminDelegatedPuzzleFromKey, writerDelegatedPuzzleFromKey, oracleDelegatedPuzzle, signCoinSpends, getCoinId, updateStoreMetadata, updateStoreOwnership, meltStore } from '../index.js';


test('exports', (t) => {
  t.assert(newLineageProof);
  t.assert(newEveProof);
  t.assert(selectCoins);
  t.assert(mintStore);
  t.assert(oracleSpend);
  t.assert(addFee);
  t.assert(masterPublicKeyToWalletSyntheticKey);
  t.assert(masterPublicKeyToFirstPuzzleHash);
  t.assert(masterSecretKeyToWalletSyntheticSecretKey);
  t.assert(secretKeyToPublicKey);
  t.assert(puzzleHashToAddress);
  t.assert(addressToPuzzleHash);
  t.assert(adminDelegatedPuzzleFromKey);
  t.assert(writerDelegatedPuzzleFromKey);
  t.assert(oracleDelegatedPuzzle);
  t.assert(signCoinSpends);
  t.assert(getCoinId);
  t.assert(updateStoreMetadata);
  t.assert(updateStoreOwnership);
  t.assert(meltStore);
  t.assert(Peer);
})
