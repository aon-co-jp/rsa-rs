//! RSAES-OAEP (RFC 8017 §7.1)。

use alloc::{boxed::Box, vec::Vec};
use core::fmt;
use digest::{Digest, FixedOutputReset};
use rand_core::TryCryptoRng;

use crate::errors::Result;
use crate::hashadapt::DigestFn;
use crate::key::{with_fill, RsaPrivateKey, RsaPublicKey};
use crate::traits::PaddingScheme;

/// OAEP 暗号化/復号の設定。`D` が OAEP のハッシュ、`MGD` が MGF1 のハッシュ。
pub struct Oaep<D, MGD = D> {
    /// OAEP のハッシュ。
    pub digest: D,
    /// MGF1 のハッシュ。
    pub mgf_digest: MGD,
    /// ラベル (省略時は空)。
    pub label: Option<Box<[u8]>>,
}

impl<D> Default for Oaep<D>
where
    D: Digest + FixedOutputReset,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<D> Oaep<D>
where
    D: Digest + FixedOutputReset,
{
    /// ハッシュと MGF1 に同じ `D` を使う。
    pub fn new() -> Self {
        Self {
            digest: D::new(),
            mgf_digest: D::new(),
            label: None,
        }
    }

    /// ラベル付き。
    pub fn new_with_label<S: Into<Box<[u8]>>>(label: S) -> Self {
        Self {
            digest: D::new(),
            mgf_digest: D::new(),
            label: Some(label.into()),
        }
    }
}

impl<D, MGD> Oaep<D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    /// MGF1 のハッシュを別にする。
    pub fn new_with_mgf_hash() -> Self {
        Self {
            digest: D::new(),
            mgf_digest: MGD::new(),
            label: None,
        }
    }

    /// MGF1 のハッシュを別にしてラベルも付ける。
    pub fn new_with_mgf_hash_and_label<S: Into<Box<[u8]>>>(label: S) -> Self {
        Self {
            digest: D::new(),
            mgf_digest: MGD::new(),
            label: Some(label.into()),
        }
    }
}

impl<D, MGD> PaddingScheme for Oaep<D, MGD>
where
    D: Digest,
    MGD: Digest + FixedOutputReset,
{
    fn decrypt<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: Option<&mut Rng>,
        priv_key: &RsaPrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let label = self.label.as_deref().unwrap_or(&[]);
        let (h, g) = (DigestFn::<D>::new(), DigestFn::<MGD>::new());
        with_fill(rng, |f| {
            rsa_rs_core::oaep::decrypt(&priv_key.inner, f, &h, &g, label, ciphertext)
        })
        .map_err(|_| crate::errors::Error::Decryption)
    }

    fn encrypt<Rng: TryCryptoRng + ?Sized>(
        self,
        rng: &mut Rng,
        pub_key: &RsaPublicKey,
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        let label = self.label.as_deref().unwrap_or(&[]);
        let (h, g) = (DigestFn::<D>::new(), DigestFn::<MGD>::new());
        rsa_rs_core::oaep::encrypt(
            &pub_key.inner,
            &mut crate::key::RngFill(rng),
            &h,
            &g,
            label,
            msg,
        )
        .map_err(Into::into)
    }
}

impl<D, MGD> fmt::Debug for Oaep<D, MGD> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAEP")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}
