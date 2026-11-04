//! RSASSA-PKCS1-v1_5 署名 (RFC 8017 §8.2)。PKCS#1 v1.5 *暗号化* は意図的に未実装。

use alloc::{boxed::Box, vec::Vec};
use const_oid::AssociatedOid;
use core::fmt::{self, Debug, Display, LowerHex, UpperHex};
use core::marker::PhantomData;
use crypto_bigint::BoxedUint;
use digest::{Digest, FixedOutput, HashMarker, Update};
use rand_core::TryCryptoRng;
use signature::{
    hazmat::{PrehashSigner, PrehashVerifier},
    DigestSigner, DigestVerifier, Keypair, MultipartSigner, RandomizedDigestSigner,
    RandomizedMultipartSigner, RandomizedSigner, SignatureEncoding, Signer, Verifier,
};
use zeroize::ZeroizeOnDrop;

use crate::errors::{Error, Result};
use crate::hashadapt::DigestFn;
use crate::key::{with_fill, OsRng, RsaPrivateKey, RsaPublicKey};
use crate::traits::{PublicKeyParts, SignatureScheme};

/// 署名方式 `Pkcs1v15Sign` (ハッシュ済みの入力に対する署名/検証)。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pkcs1v15Sign {
    /// ハッシュ長 (`None` ならハッシュ長を検査しない)。
    pub hash_len: Option<usize>,
    /// DigestInfo の DER 接頭辞。
    pub prefix: Box<[u8]>,
}

impl Pkcs1v15Sign {
    /// ハッシュ `D` 用。
    pub fn new<D>() -> Self
    where
        D: Digest + AssociatedOid,
    {
        Self {
            hash_len: Some(<D as Digest>::output_size()),
            prefix: prefix_for::<D>().into_boxed_slice(),
        }
    }

    /// DigestInfo を付けない (生のハッシュ値のみ)。
    pub fn new_unprefixed() -> Self {
        Self {
            hash_len: None,
            prefix: Box::new([]),
        }
    }
}

pub(crate) fn prefix_for<D: Digest + AssociatedOid>() -> Vec<u8> {
    rsa_rs_core::pkcs1v15::digest_info_prefix(D::OID.as_bytes(), <D as Digest>::output_size())
}

fn do_sign<R: rand_core::TryRng + ?Sized>(
    rng: Option<&mut R>,
    key: &RsaPrivateKey,
    prefix: &[u8],
    hashed: &[u8],
) -> Result<Vec<u8>> {
    with_fill(rng, |f| {
        rsa_rs_core::pkcs1v15::sign(&key.inner, f, prefix, hashed)
    })
    .map_err(Into::into)
}

fn do_verify(key: &RsaPublicKey, prefix: &[u8], hashed: &[u8], sig: &Signature) -> Result<()> {
    let bytes = sig.inner.to_be_bytes();
    // 署名は k バイトでなければならない。整数表現を k バイトに左ゼロ詰めして渡す。
    let k = key.size();
    let bytes = if bytes.len() <= k {
        let mut v = alloc::vec![0u8; k - bytes.len()];
        v.extend_from_slice(&bytes);
        v
    } else {
        // 先頭が 0 のバイトだけが余剰なら切り詰める。非 0 なら不正 (n 以上)。
        let (extra, rest) = bytes.split_at(bytes.len() - k);
        if extra.iter().any(|&b| b != 0) {
            return Err(Error::Verification);
        }
        rest.to_vec()
    };
    rsa_rs_core::pkcs1v15::verify(&key.inner, prefix, hashed, &bytes)
        .map_err(|_| Error::Verification)
}

impl SignatureScheme for Pkcs1v15Sign {
    fn sign<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &RsaPrivateKey,
        hashed: &[u8],
    ) -> Result<Vec<u8>> {
        if let Some(l) = self.hash_len {
            if hashed.len() != l {
                return Err(Error::InputNotHashed);
            }
        }
        do_sign(rng, priv_key, &self.prefix, hashed)
    }

    fn verify(self, pub_key: &RsaPublicKey, hashed: &[u8], sig: &[u8]) -> Result<()> {
        if let Some(l) = self.hash_len {
            if hashed.len() != l {
                return Err(Error::InputNotHashed);
            }
        }
        let sig = Signature {
            inner: BoxedUint::from_be_slice_vartime(sig),
        };
        do_verify(pub_key, &self.prefix, hashed, &sig)
    }
}

/// `RSASSA-PKCS1-v1_5` 署名。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub(crate) inner: BoxedUint,
}

impl SignatureEncoding for Signature {
    type Repr = Box<[u8]>;
}

impl TryFrom<&[u8]> for Signature {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> signature::Result<Self> {
        Ok(Self {
            inner: BoxedUint::from_be_slice_vartime(bytes),
        })
    }
}

impl From<Signature> for Box<[u8]> {
    fn from(signature: Signature) -> Box<[u8]> {
        signature.inner.to_be_bytes()
    }
}

impl LowerHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.to_bytes().iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl UpperHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.to_bytes().iter() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self)
    }
}

/// 署名鍵 `SigningKey<D>`。
#[derive(Debug, Clone)]
pub struct SigningKey<D>
where
    D: Digest,
{
    inner: RsaPrivateKey,
    prefix: Vec<u8>,
    phantom: PhantomData<D>,
}

impl<D> SigningKey<D>
where
    D: Digest + AssociatedOid,
{
    /// 鍵から作る (DigestInfo 付き)。
    pub fn new(key: RsaPrivateKey) -> Self {
        Self {
            inner: key,
            prefix: prefix_for::<D>(),
            phantom: PhantomData,
        }
    }

    /// 乱数で鍵を生成する。
    pub fn random<R: rand_core::CryptoRng + ?Sized>(rng: &mut R, bit_size: usize) -> Result<Self> {
        Ok(Self::new(RsaPrivateKey::new(rng, bit_size)?))
    }
}

impl<D> SigningKey<D>
where
    D: Digest,
{
    /// DigestInfo を付けない署名鍵。
    pub fn new_unprefixed(key: RsaPrivateKey) -> Self {
        Self {
            inner: key,
            prefix: Vec::new(),
            phantom: PhantomData,
        }
    }

    /// DigestInfo を付けない署名鍵を乱数で生成する。
    pub fn random_unprefixed<R: rand_core::CryptoRng + ?Sized>(
        rng: &mut R,
        bit_size: usize,
    ) -> Result<Self> {
        Ok(Self::new_unprefixed(RsaPrivateKey::new(rng, bit_size)?))
    }

    fn sign_hashed<R: rand_core::TryRng + ?Sized>(
        &self,
        rng: Option<&mut R>,
        hashed: &[u8],
    ) -> signature::Result<Signature> {
        let bytes = do_sign(rng, &self.inner, &self.prefix, hashed)?;
        Signature::try_from(bytes.as_slice())
    }
}

impl<D> DigestSigner<D, Signature> for SigningKey<D>
where
    D: Default + FixedOutput + HashMarker + Update,
{
    fn try_sign_digest<F: Fn(&mut D) -> signature::Result<()>>(
        &self,
        f: F,
    ) -> signature::Result<Signature> {
        let mut digest = D::default();
        f(&mut digest)?;
        self.sign_hashed(Option::<&mut OsRng>::None, &digest.finalize_fixed())
    }
}

impl<D> PrehashSigner<Signature> for SigningKey<D>
where
    D: Digest,
{
    fn sign_prehash(&self, prehash: &[u8]) -> signature::Result<Signature> {
        self.sign_hashed(Option::<&mut OsRng>::None, prehash)
    }
}

impl<D> RandomizedDigestSigner<D, Signature> for SigningKey<D>
where
    D: Default + FixedOutput + HashMarker + Update,
{
    fn try_sign_digest_with_rng<
        R: TryCryptoRng + ?Sized,
        F: Fn(&mut D) -> signature::Result<()>,
    >(
        &self,
        rng: &mut R,
        f: F,
    ) -> signature::Result<Signature> {
        let mut digest = D::default();
        f(&mut digest)?;
        self.sign_hashed(Some(rng), &digest.finalize_fixed())
    }
}

impl<D> RandomizedSigner<Signature> for SigningKey<D>
where
    D: Digest,
{
    fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> signature::Result<Signature> {
        self.try_multipart_sign_with_rng(rng, &[msg])
    }
}

impl<D> RandomizedMultipartSigner<Signature> for SigningKey<D>
where
    D: Digest,
{
    fn try_multipart_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[&[u8]],
    ) -> signature::Result<Signature> {
        self.sign_hashed(Some(rng), &DigestFn::<D>::digest(msg))
    }
}

impl<D> Signer<Signature> for SigningKey<D>
where
    D: Digest,
{
    fn try_sign(&self, msg: &[u8]) -> signature::Result<Signature> {
        self.try_multipart_sign(&[msg])
    }
}

impl<D> MultipartSigner<Signature> for SigningKey<D>
where
    D: Digest,
{
    fn try_multipart_sign(&self, msg: &[&[u8]]) -> signature::Result<Signature> {
        self.sign_hashed(Option::<&mut OsRng>::None, &DigestFn::<D>::digest(msg))
    }
}

impl<D> AsRef<RsaPrivateKey> for SigningKey<D>
where
    D: Digest,
{
    fn as_ref(&self) -> &RsaPrivateKey {
        &self.inner
    }
}

impl<D> Keypair for SigningKey<D>
where
    D: Digest + Clone,
{
    type VerifyingKey = VerifyingKey<D>;
    fn verifying_key(&self) -> Self::VerifyingKey {
        VerifyingKey {
            inner: self.inner.to_public_key(),
            prefix: self.prefix.clone(),
            phantom: PhantomData,
        }
    }
}

impl<D> From<RsaPrivateKey> for SigningKey<D>
where
    D: Digest + AssociatedOid,
{
    fn from(key: RsaPrivateKey) -> Self {
        Self::new(key)
    }
}

impl<D> From<SigningKey<D>> for RsaPrivateKey
where
    D: Digest,
{
    fn from(key: SigningKey<D>) -> Self {
        key.inner.clone()
    }
}

impl<D> ZeroizeOnDrop for SigningKey<D> where D: Digest {}

/// 検証鍵 `VerifyingKey<D>`。
#[derive(Debug)]
pub struct VerifyingKey<D>
where
    D: Digest,
{
    pub(crate) inner: RsaPublicKey,
    pub(crate) prefix: Vec<u8>,
    pub(crate) phantom: PhantomData<D>,
}

impl<D> VerifyingKey<D>
where
    D: Digest + AssociatedOid,
{
    /// 公開鍵から作る (DigestInfo 付き)。
    pub fn new(key: RsaPublicKey) -> Self {
        Self {
            inner: key,
            prefix: prefix_for::<D>(),
            phantom: PhantomData,
        }
    }
}

impl<D> VerifyingKey<D>
where
    D: Digest,
{
    /// DigestInfo を付けない検証鍵。
    pub fn new_unprefixed(key: RsaPublicKey) -> Self {
        Self {
            inner: key,
            prefix: Vec::new(),
            phantom: PhantomData,
        }
    }
}

impl<D> DigestVerifier<D, Signature> for VerifyingKey<D>
where
    D: Default + FixedOutput + HashMarker + Update,
{
    fn verify_digest<F: Fn(&mut D) -> signature::Result<()>>(
        &self,
        f: F,
        signature: &Signature,
    ) -> signature::Result<()> {
        let mut digest = D::default();
        f(&mut digest)?;
        do_verify(
            &self.inner,
            &self.prefix,
            &digest.finalize_fixed(),
            signature,
        )
        .map_err(Into::into)
    }
}

impl<D> PrehashVerifier<Signature> for VerifyingKey<D>
where
    D: Digest,
{
    fn verify_prehash(&self, prehash: &[u8], signature: &Signature) -> signature::Result<()> {
        do_verify(&self.inner, &self.prefix, prehash, signature).map_err(Into::into)
    }
}

impl<D> Verifier<Signature> for VerifyingKey<D>
where
    D: Digest,
{
    fn verify(&self, msg: &[u8], signature: &Signature) -> signature::Result<()> {
        do_verify(
            &self.inner,
            &self.prefix,
            &DigestFn::<D>::digest(&[msg]),
            signature,
        )
        .map_err(Into::into)
    }
}

impl<D> AsRef<RsaPublicKey> for VerifyingKey<D>
where
    D: Digest,
{
    fn as_ref(&self) -> &RsaPublicKey {
        &self.inner
    }
}

impl<D> Clone for VerifyingKey<D>
where
    D: Digest,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            prefix: self.prefix.clone(),
            phantom: PhantomData,
        }
    }
}

impl<D> From<RsaPublicKey> for VerifyingKey<D>
where
    D: Digest + AssociatedOid,
{
    fn from(key: RsaPublicKey) -> Self {
        Self::new(key)
    }
}

impl<D> From<VerifyingKey<D>> for RsaPublicKey
where
    D: Digest,
{
    fn from(key: VerifyingKey<D>) -> Self {
        key.inner
    }
}
