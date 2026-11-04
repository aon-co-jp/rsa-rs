//! `rsa` 0.9.10 の API のうち、sqlx-mysql 0.8.x が使う範囲 (公開鍵の読み込みと OAEP 暗号化)
//! の互換実装。実体は `rsa-rs-core` (RFC 8017)。
//!
//! 秘密鍵・署名・PSS・PKCS#1 v1.5 暗号化は **実装していない** (呼ぶとコンパイルエラー)。
//! 公開鍵のみの用途なので RUSTSEC-2023-0071 (秘密鍵演算の Marvin Attack) の影響範囲外になる。
//! 第三者監査は受けていない。詳細は README / PORTING.md。
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

pub use num_bigint::BigUint;
pub use rand_core;

pub mod errors;
mod key;
pub mod oaep;
pub mod traits;

pub use pkcs1;
pub use pkcs8;

pub use crate::{
    errors::{Error, Result},
    key::RsaPublicKey,
    oaep::Oaep,
};
