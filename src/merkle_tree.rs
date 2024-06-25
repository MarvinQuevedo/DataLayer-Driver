use std::collections::HashMap;

use chia_protocol::Bytes32;
use sha2::{Digest, Sha256};

const HASH_TREE_PREFIX: &[u8] = &[2];
const HASH_LEAF_PREFIX: &[u8] = &[1];

pub struct MerkleTree {
    root: Bytes32,
    proofs: HashMap<Bytes32, (u32, Vec<Bytes32>)>,
}

use std::fmt::Debug;

#[derive(Debug, Clone)]
pub enum BinaryTree<T> {
    Leaf(T),
    Node(Box<BinaryTree<T>>, Box<BinaryTree<T>>),
}

impl MerkleTree {
    pub fn new(leaves: &[Bytes32]) -> Self {
        let (root, proofs) = MerkleTree::build_merkle_tree(leaves);
        Self { root, proofs }
    }

    fn build_merkle_tree(leaves: &[Bytes32]) -> (Bytes32, HashMap<Bytes32, (u32, Vec<Bytes32>)>) {
        let binary_tree = MerkleTree::list_to_binary_tree(leaves).unwrap();
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

    fn list_to_binary_tree<T: Clone + Debug>(objects: &[T]) -> Result<BinaryTree<T>, &'static str> {
        let size = objects.len();
        if size == 0 {
            return Err("Cannot build a tree out of 0 objects");
        }
        if size == 1 {
            return Ok(BinaryTree::Leaf(objects[0].clone()));
        }
        let midpoint = (size + 1) >> 1;
        let first_half = &objects[..midpoint];
        let last_half = &objects[midpoint..];
        let left_tree = MerkleTree::list_to_binary_tree(first_half)?;
        let right_tree = MerkleTree::list_to_binary_tree(last_half)?;
        Ok(BinaryTree::Node(Box::new(left_tree), Box::new(right_tree)))
    }

    fn build_merkle_tree_from_binary_tree(
        tuples: &BinaryTree<Bytes32>,
    ) -> (Bytes32, HashMap<Bytes32, (u32, Vec<Bytes32>)>) {
        match tuples {
            BinaryTree::Leaf(t) => {
                let hash = MerkleTree::sha256(vec![HASH_LEAF_PREFIX, t]);
                let mut proof = HashMap::new();
                proof.insert(*t, (0, vec![]));
                (hash, proof)
            }
            BinaryTree::Node(left, right) => {
                let (left_root, left_proofs) = MerkleTree::build_merkle_tree_from_binary_tree(left);
                let (right_root, right_proofs) =
                    MerkleTree::build_merkle_tree_from_binary_tree(right);

                let new_root = MerkleTree::sha256(vec![HASH_TREE_PREFIX, &left_root, &right_root]);
                let mut new_proofs = HashMap::new();

                for (name, (path, mut proof)) in left_proofs {
                    proof.push(right_root);
                    new_proofs.insert(name, (path, proof));
                }

                for (name, (path, mut proof)) in right_proofs {
                    let path = path | (1 << proof.len());
                    proof.push(left_root);
                    new_proofs.insert(name, (path, proof));
                }

                (new_root, new_proofs)
            }
        }
    }

    pub fn get_root(&self) -> Bytes32 {
        self.root
    }

    pub fn generate_proof(&self, leaf: Bytes32) -> Option<(u32, Vec<Bytes32>)> {
        self.proofs.get(&leaf).cloned()
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

        assert_eq!(
            merkle_tree.generate_proof(leaf2),
            Some((
                1,
                vec![Bytes32::from(hex!(
                    "ce041765675ad4d93378e20bd3a7d0d97ddcf3385fb6341581b21d4bc9e3e69e"
                ))]
            ))
        );
        Ok(())
    }
}
