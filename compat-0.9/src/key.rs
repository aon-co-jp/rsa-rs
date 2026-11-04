//! `RsaPublicKey` (rsa 0.9 互換の範囲)。

use alloc::vec::Vec;
use core::convert::TryFrom;
use crypto_bigint::BoxedUint;
use num_bigint::BigUint;
use pkcs8::{der::Decode, spki};
use rand_core::CryptoRngCore;

use crate::errors::{Error, Result};
use crate::traits::{PaddingScheme, PublicKeyParts};

/// RSA 公開鍵。
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    pub(crate) inner: rsa_rs_core::PublicKey,
    n: BigUint,
    e: BigUint,
}

impl PartialEq for RsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n && self.e == other.e
    }
}
impl Eq for RsaPublicKey {}

impl PublicKeyParts for RsaPublicKey {
    fn n(&self) -> &BigUint {
        &self.n
    }
    fn e(&self) -> &BigUint {
        &self.e
    }
}

impl RsaPublicKey {
    /// e の下限。
    pub const MIN_PUB_EXPONENT: u64 = rsa_rs_core::key::MIN_PUB_EXPONENT;
    /// e の上限。
    pub const MAX_PUB_EXPONENT: u64 = rsa_rs_core::key::MAX_PUB_EXPONENT;
    /// 法の最大ビット数。
    pub const MAX_SIZE: usize = rsa_rs_core::key::MAX_SIZE;

    /// n, e から作る (検査付き。法は 4096 ビットまで... 上流は 4096。ここでは 8192 まで許す)。
    pub fn new(n: BigUint, e: BigUint) -> Result<Self> {
        Self::new_with_max_size(n, e, Self::MAX_SIZE)
    }

    /// 法の上限ビット数を指定して作る。
    pub fn new_with_max_size(n: BigUint, e: BigUint, max_size: usize) -> Result<Self> {
        let inner = rsa_rs_core::PublicKey::new_with_max_size(
            BoxedUint::from_be_slice_vartime(&n.to_bytes_be()),
            BoxedUint::from_be_slice_vartime(&e.to_bytes_be()),
            max_size,
        )
        .map_err(|e| match e {
            rsa_rs_core::Error::InvalidExponent => Error::InvalidExponent,
            rsa_rs_core::Error::ModulusTooLarge => Error::ModulusTooLarge,
            _ => Error::InvalidModulus,
        })?;
        Ok(Self { inner, n, e })
    }

    /// 公開鍵でパディング付き暗号化する。
    pub fn encrypt<R: CryptoRngCore, P: PaddingScheme>(
        &self,
        rng: &mut R,
        padding: P,
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        padding.encrypt(rng, self, msg)
    }
}

// ---- PKCS#1 / SPKI -------------------------------------------------------

impl TryFrom<pkcs1::RsaPublicKey<'_>> for RsaPublicKey {
    type Error = pkcs1::Error;

    fn try_from(k: pkcs1::RsaPublicKey<'_>) -> pkcs1::Result<Self> {
        let n = BigUint::from_bytes_be(k.modulus.as_bytes());
        let e = BigUint::from_bytes_be(k.public_exponent.as_bytes());
        RsaPublicKey::new(n, e).map_err(|_| pkcs1::Error::Crypto)
    }
}

impl TryFrom<spki::SubjectPublicKeyInfoRef<'_>> for RsaPublicKey {
    type Error = spki::Error;

    fn try_from(spki: spki::SubjectPublicKeyInfoRef<'_>) -> spki::Result<Self> {
        // rsaEncryption の AlgorithmIdentifier (パラメータは NULL) のみ受理する。
        spki.algorithm.assert_algorithm_oid(pkcs1::ALGORITHM_OID)?;
        if spki.algorithm.parameters_any()? != pkcs8::der::asn1::Null.into() {
            return Err(spki::Error::KeyMalformed);
        }
        let bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or(spki::Error::KeyMalformed)?;
        let k = pkcs1::RsaPublicKey::from_der(bytes).map_err(|_| spki::Error::KeyMalformed)?;
        RsaPublicKey::try_from(k).map_err(|_| spki::Error::KeyMalformed)
    }
}
