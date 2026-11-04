//! `RsaPublicKey` / `RsaPrivateKey` (rsa 0.10 互換の範囲)。実体は `rsa-rs-core`。

use alloc::vec::Vec;
use core::fmt;
use core::hash::{Hash, Hasher};
use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, NonZero,
};
use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use rsa_rs_core::hash::{FillBytes, OsFill};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{Error, Result};
use crate::traits::{PaddingScheme, PrivateKeyParts, PublicKeyParts, SignatureScheme};

/// `TryCryptoRng` を core の乱数源に見せる。
pub(crate) struct RngFill<'a, R: ?Sized>(pub &'a mut R);

impl<R: TryRng + ?Sized> FillBytes for RngFill<'_, R> {
    fn fill(&mut self, dest: &mut [u8]) -> rsa_rs_core::Result<()> {
        self.0
            .try_fill_bytes(dest)
            .map_err(|_| rsa_rs_core::Error::Rng)
    }
}

/// RSA 公開鍵。
#[derive(Clone)]
pub struct RsaPublicKey {
    pub(crate) inner: rsa_rs_core::PublicKey,
}

impl fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPublicKey")
            .field("n", self.inner.n())
            .field("e", self.inner.e())
            .finish()
    }
}

impl Eq for RsaPublicKey {}
impl PartialEq for RsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.n() == other.inner.n() && self.inner.e() == other.inner.e()
    }
}

impl Hash for RsaPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.n().to_be_bytes_trimmed_vartime().hash(state);
        self.inner.e().to_be_bytes_trimmed_vartime().hash(state);
    }
}

impl PublicKeyParts for RsaPublicKey {
    fn n(&self) -> &NonZero<BoxedUint> {
        self.inner.n()
    }
    fn e(&self) -> &BoxedUint {
        self.inner.e()
    }
    fn n_params(&self) -> &BoxedMontyParams {
        self.inner.n_params()
    }
}

impl RsaPublicKey {
    /// e の下限。
    pub const MIN_PUB_EXPONENT: u64 = rsa_rs_core::key::MIN_PUB_EXPONENT;
    /// e の上限。
    pub const MAX_PUB_EXPONENT: u64 = rsa_rs_core::key::MAX_PUB_EXPONENT;
    /// 法の最大ビット数。
    pub const MAX_SIZE: usize = rsa_rs_core::key::MAX_SIZE;

    /// n, e から作る (検査付き。法は 8192 ビットまで)。
    pub fn new(n: BoxedUint, e: BoxedUint) -> Result<Self> {
        Self::new_with_max_size(n, e, Self::MAX_SIZE)
    }

    /// 法の上限を指定して作る。
    pub fn new_with_max_size(n: BoxedUint, e: BoxedUint, max_size: usize) -> Result<Self> {
        let inner =
            rsa_rs_core::PublicKey::new_with_max_size(n, e, max_size).map_err(map_pub_err)?;
        Ok(Self { inner })
    }

    /// 検査なしで作る (n は奇数であること)。
    pub fn new_unchecked(n: BoxedUint, e: BoxedUint) -> Self {
        Self {
            inner: rsa_rs_core::PublicKey::new_unchecked(n, e),
        }
    }

    /// 公開鍵でパディング付き暗号化する。
    pub fn encrypt<R: CryptoRng + ?Sized, P: PaddingScheme>(
        &self,
        rng: &mut R,
        padding: P,
        msg: &[u8],
    ) -> Result<Vec<u8>> {
        padding.encrypt(rng, self, msg)
    }

    /// 署名を検証する。
    pub fn verify<S: SignatureScheme>(&self, scheme: S, hashed: &[u8], sig: &[u8]) -> Result<()> {
        scheme.verify(self, hashed, sig)
    }
}

fn map_pub_err(e: rsa_rs_core::Error) -> Error {
    use rsa_rs_core::Error as C;
    match e {
        C::InvalidExponent => Error::InvalidExponent,
        C::ModulusTooLarge => Error::ModulusTooLarge,
        C::InvalidKey => Error::InvalidModulus,
        other => other.into(),
    }
}

/// RSA 秘密鍵 (2 素数)。
#[derive(Clone)]
pub struct RsaPrivateKey {
    pub(crate) inner: rsa_rs_core::PrivateKey,
    public: RsaPublicKey,
    primes: Vec<BoxedUint>,
}

impl fmt::Debug for RsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPrivateKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl Eq for RsaPrivateKey {}
impl PartialEq for RsaPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Hash for RsaPrivateKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.public.hash(state);
    }
}

impl AsRef<RsaPublicKey> for RsaPrivateKey {
    fn as_ref(&self) -> &RsaPublicKey {
        &self.public
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        for p in self.primes.iter_mut() {
            p.zeroize();
        }
    }
}

impl ZeroizeOnDrop for RsaPrivateKey {}

impl From<RsaPrivateKey> for RsaPublicKey {
    fn from(private_key: RsaPrivateKey) -> Self {
        (&private_key).into()
    }
}

impl From<&RsaPrivateKey> for RsaPublicKey {
    fn from(private_key: &RsaPrivateKey) -> Self {
        private_key.public.clone()
    }
}

impl PublicKeyParts for RsaPrivateKey {
    fn n(&self) -> &NonZero<BoxedUint> {
        self.inner.public().n()
    }
    fn e(&self) -> &BoxedUint {
        self.inner.public().e()
    }
    fn n_params(&self) -> &BoxedMontyParams {
        self.inner.public().n_params()
    }
}

impl PrivateKeyParts for RsaPrivateKey {
    fn d(&self) -> &BoxedUint {
        self.inner.d()
    }
    fn primes(&self) -> &[BoxedUint] {
        &self.primes
    }
    fn dp(&self) -> Option<&BoxedUint> {
        Some(self.inner.dp())
    }
    fn dq(&self) -> Option<&BoxedUint> {
        Some(self.inner.dq())
    }
    fn qinv(&self) -> Option<&BoxedMontyForm> {
        Some(self.inner.qinv())
    }
    fn crt_values(&self) -> Option<&[crate::traits::CrtValue]> {
        // multi-prime 用。2 素数鍵では上流でも空なので None。
        None
    }
    fn p_params(&self) -> Option<&BoxedMontyParams> {
        Some(self.inner.p_params())
    }
    fn q_params(&self) -> Option<&BoxedMontyParams> {
        Some(self.inner.q_params())
    }
}

impl RsaPrivateKey {
    pub(crate) fn from_core(inner: rsa_rs_core::PrivateKey) -> Self {
        let public = RsaPublicKey {
            inner: inner.public().clone(),
        };
        let primes = alloc::vec![inner.p().clone(), inner.q().clone()];
        Self {
            inner,
            public,
            primes,
        }
    }

    /// 65537 を公開指数として `bit_size` ビットの鍵を生成する。
    pub fn new<R: CryptoRng + ?Sized>(rng: &mut R, bit_size: usize) -> Result<Self> {
        Self::new_with_exp(rng, bit_size, BoxedUint::from(65537u64))
    }

    /// 公開指数を指定して鍵を生成する。
    pub fn new_with_exp<R: CryptoRng + ?Sized>(
        rng: &mut R,
        bit_size: usize,
        exp: BoxedUint,
    ) -> Result<Self> {
        if exp < BoxedUint::from(RsaPublicKey::MIN_PUB_EXPONENT) {
            return Err(Error::PublicExponentTooSmall);
        }
        if exp > BoxedUint::from(RsaPublicKey::MAX_PUB_EXPONENT) {
            return Err(Error::PublicExponentTooLarge);
        }
        let key = rsa_rs_core::keygen::generate(&mut RngFill(rng), bit_size, &exp)?;
        Ok(Self::from_core(key))
    }

    /// 構成要素から作る。素数は 2 個のみ対応 (multi-prime は `Error::InvalidPrime`)。
    pub fn from_components(
        n: BoxedUint,
        e: BoxedUint,
        d: BoxedUint,
        primes: Vec<BoxedUint>,
    ) -> Result<Self> {
        if primes.len() < 2 {
            return Err(Error::NprimesTooSmall);
        }
        if primes.len() > 2 {
            return Err(Error::InvalidPrime);
        }
        let key =
            rsa_rs_core::PrivateKey::from_components(n, e, d, &primes).map_err(|e| match e {
                rsa_rs_core::Error::InvalidExponent => Error::InvalidExponent,
                rsa_rs_core::Error::ModulusTooLarge => Error::ModulusTooLarge,
                _ => Error::InvalidModulus,
            })?;
        Ok(Self::from_core(key))
    }

    /// 公開鍵への参照。
    pub fn as_public_key(&self) -> &RsaPublicKey {
        &self.public
    }

    /// 公開鍵のコピー。
    pub fn to_public_key(&self) -> RsaPublicKey {
        self.public.clone()
    }

    /// CRT 係数 q^-1 mod p。
    pub fn crt_coefficient(&self) -> Option<BoxedUint> {
        Some(self.inner.qinv().retrieve())
    }

    /// 鍵の整合性を検査する (構築時に検査済みなので常に Ok)。
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }

    /// パディング付き復号 (ブラインディングは常に有効)。
    pub fn decrypt<P: PaddingScheme>(&self, padding: P, ciphertext: &[u8]) -> Result<Vec<u8>> {
        padding.decrypt(Option::<&mut OsRng>::None, self, ciphertext)
    }

    /// 乱数源を指定して復号する。
    pub fn decrypt_blinded<R: TryCryptoRng + ?Sized, P: PaddingScheme>(
        &self,
        rng: &mut R,
        padding: P,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        padding.decrypt(Some(rng), self, ciphertext)
    }

    /// 署名する (ブラインディングは常に有効)。
    pub fn sign<S: SignatureScheme>(&self, padding: S, digest_in: &[u8]) -> Result<Vec<u8>> {
        padding.sign(Option::<&mut OsRng>::None, self, digest_in)
    }

    /// 乱数源を指定して署名する。
    pub fn sign_with_rng<R: TryCryptoRng + ?Sized, S: SignatureScheme>(
        &self,
        rng: &mut R,
        padding: S,
        digest_in: &[u8],
    ) -> Result<Vec<u8>> {
        padding.sign(Some(rng), self, digest_in)
    }
}

/// `Option::None` の型引数用の空の乱数型 (呼ばれない)。
pub(crate) struct OsRng;
impl TryRng for OsRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        let _ = OsFill.fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        let _ = OsFill.fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        let _ = OsFill.fill(dst);
        Ok(())
    }
}
impl TryCryptoRng for OsRng {}

/// 乱数源の `Option` から core の `FillBytes` を作る (None なら OS 乱数)。
pub(crate) fn with_fill<R: TryRng + ?Sized, T>(
    rng: Option<&mut R>,
    f: impl FnOnce(&mut dyn FillBytes) -> T,
) -> T {
    match rng {
        Some(r) => f(&mut RngFill(r)),
        None => f(&mut OsFill),
    }
}
