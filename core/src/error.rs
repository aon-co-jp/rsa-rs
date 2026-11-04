//! エラー型。復号/検証系は呼び出し側に原因を区別させない (Bleichenbacher/Marvin 対策)。

use core::fmt;

/// 失敗理由。`Decryption`/`Verification` は意図的に粗い。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// 復号失敗 (原因は区別しない)。
    Decryption,
    /// 署名検証失敗 (原因は区別しない)。
    Verification,
    /// メッセージが長すぎる。
    MessageTooLong,
    /// ハッシュ長が想定と違う。
    InputNotHashed,
    /// ラベルが長すぎる。
    LabelTooLong,
    /// 鍵が不正 (n, e, d, p, q の整合性)。
    InvalidKey,
    /// 公開指数が範囲外。
    InvalidExponent,
    /// 法が小さすぎる。
    ModulusTooSmall,
    /// 法が大きすぎる。
    ModulusTooLarge,
    /// 乱数源の失敗。
    Rng,
    /// 内部の不整合 (フォールト検出を含む)。
    Internal,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Decryption => "decryption error",
            Error::Verification => "verification error",
            Error::MessageTooLong => "message too long",
            Error::InputNotHashed => "input must be hashed",
            Error::LabelTooLong => "label too long",
            Error::InvalidKey => "invalid key",
            Error::InvalidExponent => "invalid exponent",
            Error::ModulusTooSmall => "modulus too small",
            Error::ModulusTooLarge => "modulus too large",
            Error::Rng => "rng error",
            Error::Internal => "internal error",
        })
    }
}

impl core::error::Error for Error {}

/// `Result` の別名。
pub type Result<T> = core::result::Result<T, Error>;
