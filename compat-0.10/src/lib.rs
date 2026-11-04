//! `rsa` 0.10.0-rc.18 の API のうち、ssh-key / russh が使う範囲の互換実装。
//!
//! 実体は `rsa-rs-core` (RFC 8017)。RUSTSEC-2023-0071 (Marvin Attack) を避けるため、
//! 秘密鍵演算は定数時間のモンゴメリ演算 + CRT + ブラインディング + 結果検証で行う。
//!
//! 未実装 (呼ぶとコンパイルエラーになる): PSS、PKCS#1 v1.5 暗号化、multi-prime 鍵、serde、
//! `hazmat`。第三者監査は受けていない。詳細は README / PORTING.md。
#![no_std]
#![warn(missing_docs)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub use crypto_bigint::BoxedUint;
pub use rand_core;
pub use signature;

pub mod errors;
mod hashadapt;
mod key;
pub mod oaep;
pub mod pkcs1v15;
pub mod traits;

#[cfg(feature = "encoding")]
mod encoding;
#[cfg(feature = "encoding")]
pub use pkcs1;
#[cfg(feature = "encoding")]
pub use pkcs8;
#[cfg(feature = "sha2")]
pub use sha2;

pub use crate::{
    errors::{Error, Result},
    key::{RsaPrivateKey, RsaPublicKey},
    oaep::Oaep,
    pkcs1v15::Pkcs1v15Sign,
    traits::CrtValue,
};
