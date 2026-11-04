//! RSAES-OAEP 暗号化 (RFC 8017 §7.1.1)。

use alloc::{boxed::Box, string::String, vec::Vec};
use core::fmt;
use digest::{Digest, DynDigest};
use rand_core::CryptoRngCore;
use rsa_rs_core::{FillBytes, HashFn};

use crate::errors::Result;
use crate::key::RsaPublicKey;
use crate::traits::PaddingScheme;

/// OAEP の設定。
pub struct Oaep {
    /// OAEP のハッシュ。
    pub digest: Box<dyn DynDigest + Send + Sync>,
    /// MGF1 のハッシュ。
    pub mgf_digest: Box<dyn DynDigest + Send + Sync>,
    /// ラベル (省略時は空)。
    pub label: Option<String>,
}

impl Oaep {
    /// ハッシュと MGF1 に同じ `T` を使う (ラベルは空)。
    pub fn new<T: 'static + Digest + DynDigest + Send + Sync>() -> Self {
        Self {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(T::new()),
            label: None,
        }
    }

    /// ラベル付き。
    pub fn new_with_label<T: 'static + Digest + DynDigest + Send + Sync, S: AsRef<str>>(
        label: S,
    ) -> Self {
        Self {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(T::new()),
            label: Some(label.as_ref().into()),
        }
    }

    /// MGF1 のハッシュを別にする。
    pub fn new_with_mgf_hash<
        T: 'static + Digest + DynDigest + Send + Sync,
        U: 'static + Digest + DynDigest + Send + Sync,
    >() -> Self {
        Self {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(U::new()),
            label: None,
        }
    }

    /// MGF1 のハッシュを別にしてラベルも付ける。
    pub fn new_with_mgf_hash_and_label<
        T: 'static + Digest + DynDigest + Send + Sync,
        U: 'static + Digest + DynDigest + Send + Sync,
        S: AsRef<str>,
    >(
        label: S,
    ) -> Self {
        Self {
            digest: Box::new(T::new()),
            mgf_digest: Box::new(U::new()),
            label: Some(label.as_ref().into()),
        }
    }
}

impl fmt::Debug for Oaep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAEP")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// `DynDigest` を core の `HashFn` に見せる (毎回クローンして状態を初期化)。
struct Dyn<'a>(&'a (dyn DynDigest + Send + Sync));

impl HashFn for Dyn<'_> {
    fn output_len(&self) -> usize {
        self.0.output_size()
    }
    fn hash(&self, parts: &[&[u8]]) -> Vec<u8> {
        let mut d = self.0.box_clone();
        d.reset();
        for p in parts {
            d.update(p);
        }
        d.finalize_reset().into_vec()
    }
}

/// rand_core 0.6 の乱数を core の乱数源に見せる。
struct Fill06<'a, R: ?Sized>(&'a mut R);

impl<R: CryptoRngCore + ?Sized> FillBytes for Fill06<'_, R> {
    fn fill(&mut self, dest: &mut [u8]) -> rsa_rs_core::Result<()> {
        self.0
            .try_fill_bytes(dest)
            .map_err(|_| rsa_rs_core::Error::Rng)
    }
}

impl PaddingScheme for Oaep {
    fn encrypt<Rng: CryptoRngCore>(
        self,
        rng: &mut Rng,
        pub_key: &RsaPublicKey,
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        let label = self.label.as_deref().unwrap_or("").as_bytes();
        let (h, g) = (Dyn(&*self.digest), Dyn(&*self.mgf_digest));
        rsa_rs_core::oaep::encrypt(&pub_key.inner, &mut Fill06(rng), &h, &g, label, msg)
            .map_err(Into::into)
    }
}
