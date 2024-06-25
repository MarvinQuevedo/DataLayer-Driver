use std::collections::HashMap;

use chia_protocol::Bytes32;
use sha2::{Digest, Sha256};

const HASH_TREE_PREFIX: &[u8] = &[2];
const HASH_LEAF_PREFIX: &[u8] = &[1];

pub struct MerkleTree {
    root: Bytes32,
    proofs: HashMap<Bytes32, (u32, Vec<Bytes32>)>,
}

impl MerkleTree {
    pub fn new(leaves: &[Bytes32]) -> Self {
        let (root, proofs) = MerkleTree::build_merkle_tree(leaves);
        Self { root, proofs }
    }

    fn build_merkle_tree(leaves: &[Bytes32]) -> (Bytes32, HashMap<Bytes32, (u32, Vec<Bytes32>)>) {
        let binary_tree = MerkleTree::list_to_binary_tree(leaves);
        println!("{:?}", binary_tree);
        MerkleTree::build_merkle_tree_from_binary_tree(&binary_tree)
    }

    fn sha256(args: Vec<&[u8]>) -> Bytes32 {
        let mut hasher = Sha256::new();
        args.iter().for_each(|arg| hasher.update(arg));

        let result = hasher.finalize();
        let result: [u8; 32] = result.into();
        Bytes32::from(result)
    }

    fn list_to_binary_tree(leaves: &[Bytes32]) -> Vec<Vec<Bytes32>> {
        let mut tree = vec![leaves
            .to_vec()
            .iter()
            .map(|leaf| MerkleTree::sha256(vec![HASH_LEAF_PREFIX, leaf]))
            .collect::<Vec<Bytes32>>()];
        while tree.last().unwrap().len() > 1 {
            let current_level = tree.last().unwrap();
            let mut next_level = vec![];
            for pair in current_level.chunks(2) {
                if pair.len() == 2 {
                    next_level.push(MerkleTree::sha256(vec![
                        HASH_TREE_PREFIX,
                        &pair[0],
                        &pair[1],
                    ]));
                } else {
                    next_level.push(pair[0]);
                }
            }
            tree.push(next_level);
        }
        tree
    }

    fn build_merkle_tree_from_binary_tree(
        tree: &[Vec<Bytes32>],
    ) -> (Bytes32, HashMap<Bytes32, (u32, Vec<Bytes32>)>) {
        let mut proofs = HashMap::new();
        for level in (1..tree.len()).rev() {
            let current_level = &tree[level];
            for (i, chunk) in current_level.chunks(2).enumerate() {
                let (left, right) = if chunk.len() == 2 {
                    (&chunk[0], &chunk[1])
                } else {
                    (&chunk[0], &chunk[0])
                };
                let parent = &tree[level - 1][i];
                proofs
                    .entry(*left)
                    .or_insert_with(|| (0, vec![]))
                    .1
                    .push(*right);
                proofs
                    .entry(*right)
                    .or_insert_with(|| (0, vec![]))
                    .1
                    .push(*left);
                proofs.entry(*left).and_modify(|e| e.0 = i as u32);
                proofs
                    .entry(*right)
                    .and_modify(|e| e.0 = (i as u32) | (1 << e.1.len()));
            }
        }
        (tree.last().unwrap()[0], proofs)
    }

    pub fn generate_proof_for_leaf(&self, leaf: Bytes32) -> Option<(u32, Vec<Bytes32>)> {
        self.proofs.get(&leaf).cloned()
    }

    pub fn generate_proof(&self, leaf_hash: Bytes32) -> Option<(u32, Vec<Bytes32>)> {
        let key = MerkleTree::sha256(vec![HASH_LEAF_PREFIX, &leaf_hash]);
        println!("key for generate proof: {:?}", key); // todo: debug
        println!("proofs: {:?}", self.proofs); // todo: debug
        self.generate_proof_for_leaf(key)
    }

    pub fn verify_proof(root: Bytes32, leaf: Bytes32, proof: (u32, Vec<Bytes32>)) -> bool {
        let (mut path, nodes) = proof;
        let mut current_hash = MerkleTree::sha256(vec![HASH_LEAF_PREFIX, &leaf]);

        for node in nodes {
            if path & 1 == 1 {
                current_hash = MerkleTree::sha256(vec![HASH_TREE_PREFIX, &node, &current_hash]);
            } else {
                current_hash = MerkleTree::sha256(vec![HASH_TREE_PREFIX, &current_hash, &node]);
            }
            path >>= 1;
        }

        root == current_hash
    }

    pub fn get_root(&self) -> Bytes32 {
        self.root
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[tokio::test]
    async fn test_merkle_tree_basic() -> anyhow::Result<()> {
        let leaf1 = Bytes32::from([1; 32]);
        let leaf2 = Bytes32::from([2; 32]);

        let leaves = vec![leaf1, leaf2];
        let merkle_tree = MerkleTree::new(&leaves);

        /*
                >>> from chia.wallet.util.merkle_utils import build_merkle_tree
        >>> build_merkle_tree([b'\x01' * 32, b'\x02' * 32])
        (<bytes32: 00f2e7e0bc3ee77f0b5aa330406f69bfbd5c2e3b8a4338dba49f64bb3f0247c4>, {<bytes32: 0101010101010101010101010101010101010101010101010101010101010101>: (0, [<bytes32: f1386fff8b06ac98d347997ff5d0abad3b977514b1b7cfe0689f45f3f1393497>]), <bytes32: 0202020202020202020202020202020202020202020202020202020202020202>: (1, [<bytes32: ce041765675ad4d93378e20bd3a7d0d97ddcf3385fb6341581b21d4bc9e3e69e>])})
                 */
        assert_eq!(
            merkle_tree.get_root(),
            Bytes32::from(hex!(
                "00f2e7e0bc3ee77f0b5aa330406f69bfbd5c2e3b8a4338dba49f64bb3f0247c4"
            ))
        );

        assert_eq!(
            merkle_tree.generate_proof(leaf1),
            Some((
                0,
                vec![Bytes32::from(hex!(
                    "f1386fff8b06ac98d347997ff5d0abad3b977514b1b7cfe0689f45f3f1393497"
                ))]
            ))
        );
        Ok(())
    }
}
