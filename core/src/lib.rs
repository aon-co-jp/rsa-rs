//! `rsa-rs-core`: ハッシュ・乱数の版に依存しない RSA コア (RFC 8017)。
//!
//! 互換層 (`compat-0.9` / `compat-0.10`) が `rsa` クレート互換の API をこの上に載せる。
//! 第三者監査は受けていない。README の「限界」を参照。
#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod ct;
pub mod error;
pub mod hash;
pub mod key;
pub mod keygen;
pub mod mgf;
pub mod oaep;
pub mod pkcs1v15;

pub use crypto_bigint::BoxedUint;
pub use error::{Error, Result};
pub use hash::{FillBytes, HashFn};
pub use key::{PrivateKey, PublicKey};
