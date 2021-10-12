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
        let inner_pubkey = KeyAgg::key_aggregation_n(&person_pubkeys, 0)?.X_tilde;
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
        output.push(KeyAgg::key_aggregation_n(&temp, 0)?.X_tilde)
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
        // test data: https://github.com/chainx-org/threshold_signature/issues/1#issuecomment-909024631
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
                "04828b16587113846bc89ab67058fb521dbacc32660b312688e9b270fe4eacc2a20dce48305985e1b2c635396122c4972f2429f1721b4fd020f7a228ca18cff905",
                "04b5d07008e94b393759e7a8fdc1ade682cf6a1c11187e5f90b16a3cf9a11a9fe5ea54cef7fbdace8f69d881d43b3250f0638eb9f9f05d5fc462377ba40175de35",
                "04ed8758a53267babe6cd44d62dc7cafb5454995254ed86cda657d29fab413fde82c87d05dfa89cb6f7bdd39ad1c835f141bfc8e4191c43a1caa84b5a1357339e4",
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
            "0ef8fda7b8183fff400f9a9ebba33f86035e9f765339b3de15f3422dba5f8559",
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
        let pubkey_ab = convert_hex_to_pubkey("04b5d07008e94b393759e7a8fdc1ade682cf6a1c11187e5f90b16a3cf9a11a9fe5ea54cef7fbdace8f69d881d43b3250f0638eb9f9f05d5fc462377ba40175de35");

        let proof = mast.generate_merkle_proof(&pubkey_ab).unwrap();

        assert_eq!(
            hex::encode(&proof),
            "5f3b1b4ed3e06bbc9f63f872ea77798cad288bffa76344d527837481083b633715e6085165adc8b3654c747799e109071517384d696e4bd2ebecfd2182ab8baaaabc7ff37edf6e47a876490d6ff2c9479ba2ab2958749a8c5c012f5e7b78d298",
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
            "bc1pgmgdvc77nt4pml77zpg3t77duppgk3nuhclc2avhm3dur2cf7plq66ark5",
            addr
        );
    }
}
