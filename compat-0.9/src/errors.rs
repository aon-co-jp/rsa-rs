//! エラー型 (`rsa` 0.9 と同じ名前・形)。

use core::fmt;

/// `rsa` クレートの `Result`。
pub type Result<T> = core::result::Result<T, Error>;

/// エラー。
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// 不正なパディング方式。
    InvalidPaddingScheme,
    /// 復号失敗 (原因は区別しない)。
    Decryption,
    /// 検証失敗。
    Verification,
    /// メッセージが長すぎる。
    MessageTooLong,
    /// 入力がハッシュ済みでない。
    InputNotHashed,
    /// 素数の個数が少なすぎる。
    NprimesTooSmall,
    /// 素数が足りない。
    TooFewPrimes,
    /// 素数が不正。
    InvalidPrime,
    /// 法が不正。
    InvalidModulus,
    /// 指数が不正。
    InvalidExponent,
    /// 係数が不正。
    InvalidCoefficient,
    /// 法が小さすぎる。
    ModulusTooSmall,
    /// 法が大きすぎる。
    ModulusTooLarge,
    /// 公開指数が小さすぎる。
    PublicExponentTooSmall,
    /// 公開指数が大きすぎる。
    PublicExponentTooLarge,
    /// PKCS#1 のエラー。
    Pkcs1(pkcs1::Error),
    /// PKCS#8 のエラー。
    Pkcs8(pkcs8::Error),
    /// 内部エラー。
    Internal,
    /// ラベルが長すぎる。
    LabelTooLong,
    /// パディング長が不正。
    InvalidPadLen,
    /// 引数が不正。
    InvalidArguments,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidPaddingScheme => write!(f, "invalid padding scheme"),
            Error::Decryption => write!(f, "decryption error"),
            Error::Verification => write!(f, "verification error"),
            Error::MessageTooLong => write!(f, "message too long"),
            Error::InputNotHashed => write!(f, "input must be hashed"),
            Error::NprimesTooSmall => write!(f, "nprimes must be >= 2"),
            Error::TooFewPrimes => {
                write!(f, "too few primes of given length to generate an RSA key")
            }
            Error::InvalidPrime => write!(f, "invalid prime value"),
            Error::InvalidModulus => write!(f, "invalid modulus"),
            Error::InvalidExponent => write!(f, "invalid exponent"),
            Error::InvalidCoefficient => write!(f, "invalid coefficient"),
            Error::ModulusTooSmall => write!(f, "modulus too small"),
            Error::ModulusTooLarge => write!(f, "modulus too large"),
            Error::PublicExponentTooSmall => write!(f, "public exponent too small"),
            Error::PublicExponentTooLarge => write!(f, "public exponent too large"),
            Error::Pkcs1(err) => write!(f, "{}", err),
            Error::Pkcs8(err) => write!(f, "{}", err),
            Error::Internal => write!(f, "internal error"),
            Error::LabelTooLong => write!(f, "label too long"),
            Error::InvalidPadLen => write!(f, "invalid padding length"),
            Error::InvalidArguments => write!(f, "invalid arguments"),
        }
    }
}

impl From<pkcs1::Error> for Error {
    fn from(err: pkcs1::Error) -> Error {
        Error::Pkcs1(err)
    }
}

impl From<pkcs8::Error> for Error {
    fn from(err: pkcs8::Error) -> Error {
        Error::Pkcs8(err)
    }
}

impl From<rsa_rs_core::Error> for Error {
    fn from(e: rsa_rs_core::Error) -> Error {
        use rsa_rs_core::Error as C;
        match e {
            C::Decryption => Error::Decryption,
            C::Verification => Error::Verification,
            C::MessageTooLong => Error::MessageTooLong,
            C::InputNotHashed => Error::InputNotHashed,
            C::LabelTooLong => Error::LabelTooLong,
            C::InvalidKey => Error::InvalidModulus,
            C::InvalidExponent => Error::InvalidExponent,
            C::ModulusTooSmall => Error::ModulusTooSmall,
            C::ModulusTooLarge => Error::ModulusTooLarge,
            _ => Error::Internal,
        }
    }
}
