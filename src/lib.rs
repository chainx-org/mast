#![feature(test)]

#[macro_use]
pub extern crate bitcoin_hashes as hashes;

pub mod encode;
pub mod error;
pub mod mast;
pub mod pmt;
pub mod tagged;

pub use crate::mast::*;
pub use encode::*;
pub use tagged::*;

#[cfg(feature = "std")]
use std::io;

#[cfg(not(feature = "std"))]
use core2::io;

#[cfg(not(feature = "std"))]
use alloc::{
    borrow::ToOwned,
    fmt, format,
    prelude::v1::Box,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use hashes::{hash_newtype, sha256d, Hash};

hash_newtype!(
    LeafNode,
    sha256d::Hash,
    32,
    doc = "The leaf node of Merkle tree.",
    false
);
hash_newtype!(
    MerkleNode,
    sha256d::Hash,
    32,
    doc = "The node of Merkle tree, include leaf node.",
    false
);
