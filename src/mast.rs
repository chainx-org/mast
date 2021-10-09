#![allow(dead_code)]
#![allow(clippy::module_inception)]

use core::ops::AddAssign;

use super::error::MastError;
use super::XOnly;
use super::{
    error::Result, pmt::PartialMerkleTree, serialize, LeafNode, MerkleNode, TapBranchHash,
    TapLeafHash, TapTweakHash, VarInt,
};
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use hashes::{
    hex::{FromHex, ToHex},
    Hash,
};
use schnorrkel::musig::{aggregate_public_key_from_slice, AggregatePublicKey};
use schnorrkel::PublicKey;

use std::convert::TryFrom;
use std::ops::Deref;

/// Data structure that represents a partial mast tree
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Mast {
    /// The threshold aggregate public key
    pubkeys: Vec<XOnly>,
    /// The pubkey of all person
    inner_pubkey: XOnly,
}

impl Mast {
    /// Create a mast instance
    pub fn new(mut person_pubkeys: Vec<PublicKey>, threshold: usize) -> Result<Self> {
        let inner_pubkey = XOnly::try_from(
            aggregate_public_key_from_slice(&mut person_pubkeys)
                .ok_or(MastError::MastBuildError)?
                .public_key()
                .to_bytes()
                .to_vec(),
        )?;
        Ok(Mast {
            pubkeys: generate_combine_pubkey(person_pubkeys, threshold)?,
            inner_pubkey,
        })
    }

    /// calculate merkle root
    pub fn calc_root(&self) -> Result<MerkleNode> {
        let leaf_nodes = self
            .pubkeys
            .iter()
            .map(|s| tagged_leaf(s))
            .collect::<Result<Vec<_>>>()?;

        let mut matches = vec![true];

        if self.pubkeys.len() < 2 {
            return Err(MastError::MastBuildError);
        }
        matches.extend(&vec![false; self.pubkeys.len() - 1]);
        let pmt = PartialMerkleTree::from_leaf_nodes(&leaf_nodes, &matches)?;
        let mut matches_vec: Vec<LeafNode> = vec![];
        let mut indexes_vec: Vec<u32> = vec![];
        pmt.extract_matches(&mut matches_vec, &mut indexes_vec)
    }

    /// generate merkle proof
    pub fn generate_merkle_proof(&self, pubkey: &PublicKey) -> Result<Vec<MerkleNode>> {
        let pubkey = &XOnly::try_from(pubkey.to_bytes().to_vec())?;
        let proof = {
            assert!(self.pubkeys.iter().any(|s| *s == *pubkey));
            let mut matches = vec![];
            let mut index = 9999;
            for (i, s) in self.pubkeys.iter().enumerate() {
                if *s == *pubkey {
                    matches.push(true);
                    index = i;
                } else {
                    matches.push(false)
                }
            }
            let leaf_nodes = self
                .pubkeys
                .iter()
                .map(|s| tagged_leaf(s))
                .collect::<Result<Vec<_>>>()?;
            let filter_proof = MerkleNode::from_inner(leaf_nodes[index].into_inner());
            Ok(PartialMerkleTree::from_leaf_nodes(&leaf_nodes, &matches)?
                .collected_hashes(filter_proof))
        };

        if proof.is_err() {
            Err(MastError::MastGenProofError)
        } else {
            proof
        }
    }

    /// generate threshold signature address
    pub fn generate_tweak_pubkey(&self) -> Result<Vec<u8>> {
        let root = self.calc_root()?;
        tweak_pubkey(&self.inner_pubkey, &root)
    }
}

/// Calculate the leaf nodes from the pubkey
///
/// tagged_hash("TapLeaf", bytes([leaf_version]) + ser_size(pubkey))
pub fn tagged_leaf(pubkey: &XOnly) -> Result<LeafNode> {
    let mut x: Vec<u8> = vec![];
    x.extend(hex::decode("c0")?.iter());
    let ser_len = serialize(&VarInt(32u64))?;
    x.extend(&ser_len);
    x.extend(pubkey.deref());
    Ok(LeafNode::from_hex(&TapLeafHash::hash(&x).to_hex())?)
}

/// Calculate branch nodes from left and right children
///
/// tagged_hash("TapBranch", left + right)). The left and right nodes are lexicographic order
pub fn tagged_branch(left_node: MerkleNode, right_node: MerkleNode) -> Result<MerkleNode> {
    // If the hash of the left and right leaves is the same, it means that the total number of leaves is odd
    //
    // In this case, the parent hash is computed without copying
    // Note: `TapLeafHash` will replace the `TapBranchHash`
    if left_node != right_node {
        let mut x: Vec<u8> = vec![];
        let (left_node, right_node) = lexicographical_compare(left_node, right_node);
        x.extend(left_node.to_vec().iter());
        x.extend(right_node.to_vec().iter());

        Ok(MerkleNode::from_hex(&TapBranchHash::hash(&x).to_hex())?)
    } else {
        Ok(left_node)
    }
}

/// Lexicographic order of left and right nodes
fn lexicographical_compare(
    left_node: MerkleNode,
    right_node: MerkleNode,
) -> (MerkleNode, MerkleNode) {
    if right_node.to_vec() < left_node.to_vec() {
        (right_node, left_node)
    } else {
        (left_node, right_node)
    }
}

/// Compute tweak public key
pub fn tweak_pubkey(inner_pubkey: &[u8; 32], root: &MerkleNode) -> Result<Vec<u8>> {
    // P + hash_tweak(P||root)G
    let mut x: Vec<u8> = vec![];
    x.extend(inner_pubkey);
    x.extend(&root.to_vec());
    let tweak_key = TapTweakHash::hash(&x);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&tweak_key[..]);

    let scalar = Scalar::from_bytes_mod_order(bytes);
    let base_point = RISTRETTO_BASEPOINT_POINT;

    let mut point = base_point * scalar;

    let inner_pubkey = PublicKey::from_bytes(inner_pubkey)?;
    point.add_assign(inner_pubkey.as_point());
    Ok(point.compress().as_bytes().to_vec())
}

fn generate_combine_index(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut temp: Vec<usize> = vec![];
    let mut ans: Vec<Vec<usize>> = vec![];
    for i in 1..=k {
        temp.push(i)
    }
    temp.push(n + 1);

    let mut j: usize = 0;
    while j < k {
        ans.push(temp[..k as usize].to_vec());
        j = 0;

        while j < k && temp[j] + 1 == temp[j + 1] {
            temp[j] = j + 1;
            j += 1;
        }
        temp[j] += 1;
    }
    ans
}

fn generate_combine_pubkey(pubkeys: Vec<PublicKey>, k: usize) -> Result<Vec<XOnly>> {
    let all_indexs = generate_combine_index(pubkeys.len(), k);
    let mut output: Vec<PublicKey> = vec![];
    for indexs in all_indexs {
        let mut temp: Vec<PublicKey> = vec![];
        for index in indexs {
            temp.push(pubkeys[index - 1])
        }
        output.push(
            aggregate_public_key_from_slice(&mut temp)
                .ok_or(MastError::MastBuildError)?
                .public_key(),
        )
    }
    output.sort_unstable();
    output
        .iter()
        .map(|p| XOnly::try_from(p.to_bytes().to_vec()))
        .collect::<Result<Vec<XOnly>>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashes::hex::ToHex;

    #[test]
    fn test_generate_combine_pubkey() {
        // test data: https://github.com/chainx-org/threshold_signature/issues/1#issuecomment-909896156
        let pubkey_a = PublicKey::from_bytes(
            &hex::decode("005431ba274d567440f1da2fc4b8bc37e90d8155bf158966907b3f67a9e13b2d")
                .unwrap(),
        )
        .unwrap();
        let pubkey_b = PublicKey::from_bytes(
            &hex::decode("90b0ae8d9be3dab2f61595eb357846e98c185483aff9fa211212a87ad18ae547")
                .unwrap(),
        )
        .unwrap();
        let pubkey_c = PublicKey::from_bytes(
            &hex::decode("66768a820dd1e686f28167a572f5ea1acb8c3162cb33f0d4b2b6bee287742415")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            generate_combine_pubkey(vec![pubkey_a, pubkey_b, pubkey_c], 2)
                .unwrap()
                .iter()
                .map(|p| hex::encode(&p.0))
                .collect::<Vec<_>>(),
            vec![
                "7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861",
                "a20c839d955cb10e58c6cbc75812684ad3a1a8f24a503e1c07f5e4944d974d3b",
                "b69af178463918a181a8549d2cfbe77884852ace9d8b299bddf69bedc33f6356"
            ]
        );
    }

    #[test]
    fn mast_generate_root_should_work() {
        let pubkey_a = PublicKey::from_bytes(
            &hex::decode("005431ba274d567440f1da2fc4b8bc37e90d8155bf158966907b3f67a9e13b2d")
                .unwrap(),
        )
        .unwrap();
        let pubkey_b = PublicKey::from_bytes(
            &hex::decode("90b0ae8d9be3dab2f61595eb357846e98c185483aff9fa211212a87ad18ae547")
                .unwrap(),
        )
        .unwrap();
        let pubkey_c = PublicKey::from_bytes(
            &hex::decode("66768a820dd1e686f28167a572f5ea1acb8c3162cb33f0d4b2b6bee287742415")
                .unwrap(),
        )
        .unwrap();
        let person_pubkeys = vec![pubkey_a, pubkey_b, pubkey_c];
        let mast = Mast::new(person_pubkeys, 2).unwrap();
        let root = mast.calc_root().unwrap();

        assert_eq!(
            "41e3435f56ea7d09ee7450ccad226920bb656ce67b4888d0577eb45d02fa6e42",
            root.to_hex()
        );
    }

    #[test]
    fn mast_generate_merkle_proof_should_work() {
        let pubkey_a = PublicKey::from_bytes(
            &hex::decode("005431ba274d567440f1da2fc4b8bc37e90d8155bf158966907b3f67a9e13b2d")
                .unwrap(),
        )
        .unwrap();
        let pubkey_b = PublicKey::from_bytes(
            &hex::decode("90b0ae8d9be3dab2f61595eb357846e98c185483aff9fa211212a87ad18ae547")
                .unwrap(),
        )
        .unwrap();
        let pubkey_c = PublicKey::from_bytes(
            &hex::decode("66768a820dd1e686f28167a572f5ea1acb8c3162cb33f0d4b2b6bee287742415")
                .unwrap(),
        )
        .unwrap();
        let person_pubkeys = vec![pubkey_a, pubkey_b, pubkey_c];
        let mast = Mast::new(person_pubkeys, 2).unwrap();
        let pubkey_ab = PublicKey::from_bytes(
            &hex::decode("7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861")
                .unwrap(),
        )
        .unwrap();

        let proof = mast.generate_merkle_proof(&pubkey_ab).unwrap();

        assert_eq!(
            proof.iter().map(|p| p.to_hex()).collect::<Vec<_>>(),
            vec![
                "0fa86e461c886db2edfa52a7eb11a96620e0bbdfd677c43b22f9ec2e3621ac0b",
                "ddc014704d52a8c50371151848f2c521dd4ec1f7e98c21f4b26d6f0f05237ae1",
            ]
        )
    }

    #[test]
    fn test_final_addr() {
        let pubkey_a = PublicKey::from_bytes(
            &hex::decode("005431ba274d567440f1da2fc4b8bc37e90d8155bf158966907b3f67a9e13b2d")
                .unwrap(),
        )
        .unwrap();
        let pubkey_b = PublicKey::from_bytes(
            &hex::decode("90b0ae8d9be3dab2f61595eb357846e98c185483aff9fa211212a87ad18ae547")
                .unwrap(),
        )
        .unwrap();
        let pubkey_c = PublicKey::from_bytes(
            &hex::decode("66768a820dd1e686f28167a572f5ea1acb8c3162cb33f0d4b2b6bee287742415")
                .unwrap(),
        )
        .unwrap();
        let person_pubkeys = vec![pubkey_a, pubkey_b, pubkey_c];
        let mast = Mast::new(person_pubkeys, 2).unwrap();

        let addr = mast.generate_tweak_pubkey().unwrap();
        assert_eq!(
            "d637ab113200c61d0188b6039de9738baa65d3e4f0d9f463a7aef8038c964021",
            hex::encode(addr)
        );
    }
}
