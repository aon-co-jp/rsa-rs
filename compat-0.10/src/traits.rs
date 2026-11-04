//! 鍵の構成要素とパディングのトレイト (rsa 0.10 互換)。

use alloc::{boxed::Box, vec::Vec};
use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, NonZero,
};
use rand_core::TryCryptoRng;
use zeroize::Zeroize;

use crate::errors::Result;
use crate::key::{RsaPrivateKey, RsaPublicKey};

/// 公開鍵の構成要素。
pub trait PublicKeyParts {
    /// 法 n。
    fn n(&self) -> &NonZero<BoxedUint>;

    /// 公開指数 e。
    fn e(&self) -> &BoxedUint;

    /// 法のバイト長。
    fn size(&self) -> usize {
        (self.n().bits() as usize).div_ceil(8)
    }

    /// n のモンゴメリパラメータ。
    fn n_params(&self) -> &BoxedMontyParams;

    /// n の精度 (ビット)。
    fn n_bits_precision(&self) -> u32 {
        self.n().bits_precision()
    }

    /// n のビッグエンディアン表現 (先頭のゼロを除く)。
    fn n_bytes(&self) -> Box<[u8]> {
        self.n().to_be_bytes_trimmed_vartime()
    }

    /// e のビッグエンディアン表現 (先頭のゼロを除く)。
    fn e_bytes(&self) -> Box<[u8]> {
        self.e().to_be_bytes_trimmed_vartime()
    }
}

/// 秘密鍵の構成要素。
pub trait PrivateKeyParts: PublicKeyParts {
    /// 秘密指数 d。
    fn d(&self) -> &BoxedUint;

    /// 素因数。
    fn primes(&self) -> &[BoxedUint];

    /// d mod (p-1)。
    fn dp(&self) -> Option<&BoxedUint>;

    /// d mod (q-1)。
    fn dq(&self) -> Option<&BoxedUint>;

    /// q^-1 mod p。
    fn qinv(&self) -> Option<&BoxedMontyForm>;

    /// 3 素数目以降の CRT 値 (本実装は multi-prime 未対応のため常に `None`)。
    fn crt_values(&self) -> Option<&[CrtValue]>;

    /// p のパラメータ。
    fn p_params(&self) -> Option<&BoxedMontyParams>;

    /// q のパラメータ。
    fn q_params(&self) -> Option<&BoxedMontyParams>;
}

/// multi-prime 用 CRT 値 (互換のための型。本実装では生成されない)。
#[derive(Debug, Clone)]
pub struct CrtValue {
    pub(crate) exp: BoxedUint,
    pub(crate) coeff: BoxedUint,
    pub(crate) r: BoxedUint,
}

impl Zeroize for CrtValue {
    fn zeroize(&mut self) {
        self.exp.zeroize();
        self.coeff.zeroize();
        self.r.zeroize();
    }
}

impl Drop for CrtValue {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// 暗号化パディング方式。
pub trait PaddingScheme {
    /// 復号。`rng` が `None` でもブラインディングは OS 乱数で行う。
    fn decrypt<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &RsaPrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>>;

    /// 暗号化。
    fn encrypt<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: &mut Rng,
        pub_key: &RsaPublicKey,
        msg: &[u8],
    ) -> Result<Vec<u8>>;
}

/// 署名方式。
pub trait SignatureScheme {
    /// 署名。`rng` が `None` でもブラインディングは OS 乱数で行う。
    fn sign<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &RsaPrivateKey,
        hashed: &[u8],
    ) -> Result<Vec<u8>>;

    /// 検証。
    fn verify(self, pub_key: &RsaPublicKey, hashed: &[u8], sig: &[u8]) -> Result<()>;
}
