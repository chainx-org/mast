#[macro_use]
pub extern crate bitcoin_hashes as hashes;

pub mod encode;
pub mod pmt;
// pub mod merkle_root;
pub mod error;
pub mod hash_types;
pub mod mast;

pub use encode::*;
pub use hash_types::*;
pub use mast::*;

#[cfg(feature = "std")]
use std::{convert::TryFrom, io, ops::Deref};

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

use error::MastError;

/// XOnly is used to represent a public key with only x coordinates
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct XOnly([u8; 32]);

impl TryFrom<Vec<u8>> for XOnly {
    type Error = MastError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() == 32 {
            let mut x = [0u8; 32];
            x.copy_from_slice(&value);
            Ok(XOnly(x))
        } else {
            Err(MastError::KeyPairError("Invalid XOnly Length".to_owned()))
        }
    }
}

impl Deref for XOnly {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
