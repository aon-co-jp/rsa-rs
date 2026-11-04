//! 鍵生成 (素数は `crypto-primes`。構成は RFC 8017 §3.2 / FIPS 186-5 B.3 の要件に沿う)。

use alloc::vec::Vec;
use core::convert::Infallible;
use crate::key::Rs;
use crypto_bigint::{BoxedUint, NonZero};
use crypto_primes::{
    hazmat::{SetBits, SmallFactorsSieveFactory},
    is_prime, sieve_and_find, Flavor,
};
use rand_core::{TryCryptoRng, TryRng};

use crate::error::{Error, Result};
use crate::hash::FillBytes;
use crate::key::PrivateKey;

/// `FillBytes` を rand_core の乱数に見せる。失敗は記録して 0 を返し、呼び出し側が検出する。
struct FillRng<'a> {
    inner: &'a mut dyn FillBytes,
    failed: bool,
}

impl TryRng for FillRng<'_> {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> core::result::Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> core::result::Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Infallible> {
        if self.inner.fill(dst).is_err() {
            self.failed = true;
            dst.fill(0);
        }
        Ok(())
    }
}
impl TryCryptoRng for FillRng<'_> {}

fn gen_prime(rng: &mut FillRng<'_>, bits: u32) -> Result<BoxedUint> {
    let factory = SmallFactorsSieveFactory::new(Flavor::Any, bits, SetBits::TwoMsb)
        .map_err(|_| Error::InvalidKey)?;
    let p = sieve_and_find(rng, factory, |_r, c| is_prime(Flavor::Any, c))
        .map_err(|_| Error::Rng)?
        .ok_or(Error::Rng)?;
    if rng.failed {
        return Err(Error::Rng);
    }
    Ok(p)
}

/// `bits` ビットの 2 素数鍵を生成する。`e` は奇数 (通常 65537)。
pub fn generate(rng: &mut dyn FillBytes, bits: usize, e: &BoxedUint) -> Result<PrivateKey> {
    if bits < 128 || bits > crate::key::MAX_SIZE {
        return Err(Error::InvalidKey);
    }
    let mut r = FillRng { inner: rng, failed: false };
    let (pb, qb) = ((bits / 2) as u32, (bits - bits / 2) as u32);
    loop {
        let p = gen_prime(&mut r, pb)?;
        let q = gen_prime(&mut r, qb)?;
        if p == q {
            continue;
        }
        let wide = (bits as u32).div_ceil(64) * 64 + 64;
        let pw = p.rs(wide).ok_or(Error::Internal)?;
        let qw = q.rs(wide).ok_or(Error::Internal)?;
        let n = pw.wrapping_mul(&qw);
        if n.bits_vartime() as usize != bits {
            continue;
        }
        // |p - q| が小さすぎる鍵 (Fermat 法で割れる) を避ける: > 2^(bits/2 - 100)
        let diff = if pw > qw { pw.wrapping_sub(&qw) } else { qw.wrapping_sub(&pw) };
        if bits >= 1024 && (diff.bits_vartime() as usize) <= bits / 2 - 100 {
            continue;
        }
        let one = BoxedUint::one_with_precision(wide);
        let phi = pw.wrapping_sub(&one).wrapping_mul(&qw.wrapping_sub(&one));
        let e_w = e.rs(wide).ok_or(Error::Internal)?;
        // d = e^-1 mod φ(n)。逆元が無ければ (gcd(e, φ) != 1) やり直し。
        let phi_nz = NonZero::new(phi).into_option().ok_or(Error::Internal)?;
        let d = match Option::<BoxedUint>::from(e_w.invert_mod(&phi_nz)) {
            Some(d) => d,
            None => continue,
        };
        // d > 2^(bits/2) (FIPS 186-5 B.3.1)
        if bits >= 1024 && (d.bits_vartime() as usize) <= bits / 2 {
            continue;
        }
        if r.failed {
            return Err(Error::Rng);
        }
        let primes: Vec<BoxedUint> = alloc::vec![p, q];
        return PrivateKey::from_components(n, e.clone(), d, &primes);
    }
}
