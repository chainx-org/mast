#![allow(dead_code)]
#![allow(clippy::module_inception)]

use bech32::{self, u5, ToBase32, Variant};

use super::{
    error::{MastError, Result},
    pmt::PartialMerkleTree,
    serialize, LeafNode, MerkleNode, TapBranchHash, TapLeafHash, TapTweakHash, VarInt,
};
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};
use hashes::{
    hex::{FromHex, ToHex},
    Hash,
};
use musig2::{
    key::{PrivateKey, PublicKey},
    musig2::KeyAgg,
};

/// Data structure that represents a partial mast tree
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Mast {
    /// The threshold aggregate public key
    pubkeys: Vec<PublicKey>,
    /// The pubkey of all person
    inner_pubkey: PublicKey,
}

impl Mast {
    /// Create a mast instance
    pub fn new(person_pubkeys: Vec<PublicKey>, threshold: usize) -> Result<Self> {
        let inner_pubkey = KeyAgg::key_aggregation_n(&person_pubkeys)?.X_tilde;
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
    pub fn generate_merkle_proof(&self, pubkey: &PublicKey) -> Result<Vec<u8>> {
        if !self.pubkeys.iter().any(|s| *s == *pubkey) {
            return Err(MastError::MastGenProofError);
        }

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
        Ok([
            self.inner_pubkey.x_coor().to_vec(),
            PartialMerkleTree::from_leaf_nodes(&leaf_nodes, &matches)?
                .collected_hashes(filter_proof)
                .concat(),
        ]
        .concat())
    }

    /// generate threshold signature address
    pub fn generate_tweak_pubkey(&self) -> Result<String> {
        let root = self.calc_root()?;
        tweak_pubkey(&self.inner_pubkey, &root)
    }
}

/// Calculate the leaf nodes from the pubkey
///
/// tagged_hash("TapLeaf", bytes([leaf_version]) + ser_size(pubkey))
pub fn tagged_leaf(pubkey: &PublicKey) -> Result<LeafNode> {
    let mut x: Vec<u8> = vec![];
    x.extend(hex::decode("c0")?.iter());
    let ser_len = serialize(&VarInt(32u64))?;
    x.extend(&ser_len);
    x.extend(&pubkey.x_coor());
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

pub fn bench32m(p: &PublicKey) -> Result<String> {
    // https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#Test_vectors_for_Bech32m
    let mut data = vec![u5::try_from_u8(1).expect("It will definitely be converted to u5")];
    data.extend(p.x_coor().to_vec().to_base32());
    Ok(bech32::encode("bc", data, Variant::Bech32m)?)
}

/// Compute tweak public key
pub fn tweak_pubkey(inner_pubkey: &PublicKey, root: &MerkleNode) -> Result<String> {
    // P + hash_tweak(P||root)G
    let mut x: Vec<u8> = vec![];
    x.extend(&inner_pubkey.x_coor());
    x.extend(&root.to_vec());
    let tweak_key = TapTweakHash::hash(&x);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&tweak_key[..]);
    let point = PublicKey::create_from_private_key(&PrivateKey::parse(&bytes)?);

    let tweak_pubkey = point.add_point(inner_pubkey)?;
    bench32m(&tweak_pubkey)
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

fn generate_combine_pubkey(pubkeys: Vec<PublicKey>, k: usize) -> Result<Vec<PublicKey>> {
    let all_indexs = generate_combine_index(pubkeys.len(), k);
    let mut output: Vec<PublicKey> = vec![];
    for indexs in all_indexs {
        let mut temp: Vec<PublicKey> = vec![];
        for index in indexs {
            temp.push(pubkeys[index - 1].clone())
        }
        output.push(KeyAgg::key_aggregation_n(&temp)?.X_tilde)
    }
    output.sort_by_key(|a| a.x_coor());
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashes::hex::ToHex;

    fn convert_hex_to_pubkey(p: &str) -> PublicKey {
        let mut key = [0u8; 65];
        key.copy_from_slice(&hex::decode(p).unwrap());
        PublicKey::parse(&key).unwrap()
    }

    #[test]
    fn test_generate_combine_pubkey() {
        let pubkey_a = convert_hex_to_pubkey("04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");
        let pubkey_b = convert_hex_to_pubkey("04dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba6592ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898");
        let pubkey_c = convert_hex_to_pubkey("04dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8f594bb5f72b37faae396a4259ea64ed5e6fdeb2a51c6467582b275925fab1394");
        assert_eq!(
            generate_combine_pubkey(vec![pubkey_a, pubkey_b, pubkey_c], 2)
                .unwrap()
                .iter()
                .map(|p| hex::encode(&p.serialize()))
                .collect::<Vec<_>>(),
            vec![
                "0443498bc300426635cd1876077e3993bec1168d6c6fa1138f893ce41a5f51bf0a22a2a7a85830e1f9facf02488328be04ece354730e19ce2766d5dca1478483cd",
                "04be1979e5e167d216a1229315844990606c2aba2d582472492a9eec7c9466460a286a71973e72f8d057235855253707ba73b5436d6170e702edf2ed5df46722b2",
                "04e7c92d2ef4294389c385fedd5387fba806687f5aba1c7ba285093dacd69354d9b4f9ea87450c75954ade455677475e92fb5e303db36753c2ea20e47d3e939662",
            ]
        );
    }

    #[test]
    fn mast_generate_root_should_work() {
        let pubkey_a = convert_hex_to_pubkey("04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");
        let pubkey_b = convert_hex_to_pubkey("04dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba6592ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898");
        let pubkey_c = convert_hex_to_pubkey("04dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8f594bb5f72b37faae396a4259ea64ed5e6fdeb2a51c6467582b275925fab1394");
        let person_pubkeys = vec![pubkey_a, pubkey_b, pubkey_c];
        let mast = Mast::new(person_pubkeys, 2).unwrap();
        let root = mast.calc_root().unwrap();

        assert_eq!(
            "d215b815fd05016c6bdf980a61249c71c5d8fa327908c01183db2a6eb1f758e0",
            root.to_hex()
        );
    }

    #[test]
    fn mast_generate_merkle_proof_should_work() {
        let pubkey_a = convert_hex_to_pubkey("04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");
        let pubkey_b = convert_hex_to_pubkey("04dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba6592ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898");
        let pubkey_c = convert_hex_to_pubkey("04dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8f594bb5f72b37faae396a4259ea64ed5e6fdeb2a51c6467582b275925fab1394");
        let person_pubkeys = vec![pubkey_a, pubkey_b, pubkey_c];
        let mast = Mast::new(person_pubkeys, 2).unwrap();
        let pubkey_ab = convert_hex_to_pubkey("04e7c92d2ef4294389c385fedd5387fba806687f5aba1c7ba285093dacd69354d9b4f9ea87450c75954ade455677475e92fb5e303db36753c2ea20e47d3e939662");

        let proof = mast.generate_merkle_proof(&pubkey_ab).unwrap();

        assert_eq!(
            hex::encode(&proof),
            "f4152c91b2c78a3524e7858c72ffa360da59e7c3c4d67d6787cf1e3bfe1684c10bd30ee53bc06cba243e9467d6fc04a0416fbd86d68d167b66b05315a5a89d4d",
        )
    }

    #[test]
    fn test_final_addr() {
        let pubkey_a = convert_hex_to_pubkey("04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");
        let pubkey_b = convert_hex_to_pubkey("04dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba6592ce19b946c4ee58546f5251d441a065ea50735606985e5b228788bec4e582898");
        let pubkey_c = convert_hex_to_pubkey("04dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8f594bb5f72b37faae396a4259ea64ed5e6fdeb2a51c6467582b275925fab1394");
        let person_pubkeys = vec![pubkey_a, pubkey_b, pubkey_c];
        let mast = Mast::new(person_pubkeys, 2).unwrap();

        let addr = mast.generate_tweak_pubkey().unwrap();
        assert_eq!(
            "bc1pxrtzfy85sl0hm6ym8w6f0qy46jznz7d256m5csdrqdgkepafk96sahp6jf",
            addr
        );
    }
}
