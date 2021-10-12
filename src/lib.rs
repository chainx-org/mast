#[macro_use]
pub extern crate bitcoin_hashes as hashes;

pub mod encode;
pub mod pmt;
// pub mod merkle_root;
pub mod error;
pub mod hash_types;
pub mod mast;

pub use crate::mast::*;
pub use encode::*;
pub use hash_types::*;

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
