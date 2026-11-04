//! 鍵型と素のRSA演算 (RFC 8017 §3, §5.1)。
//!
//! 秘密鍵演算 (RSADP) は次の防御を常に有効にする:
//! * ブラインディング (c' = c · r^e mod n。r は毎回新規)
//! * CRT (Garner) — 定数時間のモンゴメリ演算 (`crypto-bigint` 0.7.10 以上)
//! * 結果検証 — ブラインド後の値 m' について m'^e ≡ c' (mod n) を確認し、
//!   不一致 (フォールト) なら値を一切返さない
//!
//! 公開指数 e と公開値だけを使う演算 (RSAEP, 検証) は可変時間でよい。

use alloc::vec::Vec;
use crypto_bigint::{Integer, 
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, NonZero, Odd, Resize,
};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::hash::FillBytes;

/// e の下限 (RFC 8017 は 3 以上の奇数。`rsa` 互換のため 2 以上の奇数 = 3 以上)。
pub const MIN_PUB_EXPONENT: u64 = 2;
/// e の上限 (`rsa` 0.10 と同じ 2^33-1)。
pub const MAX_PUB_EXPONENT: u64 = (1 << 33) - 1;
/// 法の最大ビット数。
pub const MAX_SIZE: usize = 8192;

fn round_up_64(bits: u32) -> u32 {
    bits.div_ceil(64).max(1) * 64
}

/// 値を、その実ビット長を収める最小の 64 ビット倍数精度に正規化する (公開情報のみに使う)。
fn normalize(x: &BoxedUint) -> BoxedUint {
    let prec = round_up_64(x.bits_vartime());
    x.rs(prec).unwrap_or_else(|| x.clone())
}

/// RSA 公開鍵。
#[derive(Clone)]
pub struct PublicKey {
    n: NonZero<BoxedUint>,
    e: BoxedUint,
    n_params: BoxedMontyParams,
}

impl PublicKey {
    /// 検査付きで作る。`max_size` ビットを超える法は拒否。
    pub fn new_with_max_size(n: BoxedUint, e: BoxedUint, max_size: usize) -> Result<Self> {
        let n = normalize(&n);
        let e = normalize(&e);
        if n.bits_vartime() as usize > max_size {
            return Err(Error::ModulusTooLarge);
        }
        if bool::from(n.is_even()) || bool::from(n.is_zero()) || e >= n {
            return Err(Error::InvalidKey);
        }
        if bool::from(e.is_even()) {
            return Err(Error::InvalidExponent);
        }
        if e < BoxedUint::from(MIN_PUB_EXPONENT) || e > BoxedUint::from(MAX_PUB_EXPONENT) {
            return Err(Error::InvalidExponent);
        }
        Ok(Self::new_unchecked(n, e))
    }

    /// 既定の上限 [`MAX_SIZE`] で作る。
    pub fn new(n: BoxedUint, e: BoxedUint) -> Result<Self> {
        Self::new_with_max_size(n, e, MAX_SIZE)
    }

    /// 検査なしで作る (n は奇数であること)。
    pub fn new_unchecked(n: BoxedUint, e: BoxedUint) -> Self {
        let n = normalize(&n);
        let odd = Odd::new(n.clone()).expect("n must be odd");
        let n_params = BoxedMontyParams::new(odd);
        let n = NonZero::new(n).expect("odd is non-zero");
        Self { n, e, n_params }
    }

    /// 法 n。
    pub fn n(&self) -> &NonZero<BoxedUint> {
        &self.n
    }

    /// 公開指数 e。
    pub fn e(&self) -> &BoxedUint {
        &self.e
    }

    /// n のモンゴメリパラメータ。
    pub fn n_params(&self) -> &BoxedMontyParams {
        &self.n_params
    }

    /// 法のバイト長 k (RFC 8017 の k)。
    pub fn size(&self) -> usize {
        (self.n.bits_vartime() as usize).div_ceil(8)
    }

    /// RSAEP (§5.1.1): m^e mod n。0 <= m < n が必要。
    pub fn rsaep(&self, m: &BoxedUint) -> Result<BoxedUint> {
        if m.bits_precision() != self.n.bits_precision() || m >= self.n.as_ref() {
            return Err(Error::MessageTooLong);
        }
        Ok(self.pow_e(m))
    }

    fn pow_e(&self, m: &BoxedUint) -> BoxedUint {
        let m = BoxedMontyForm::new(m.clone(), &self.n_params);
        m.pow_bounded_exp(&self.e, self.e.bits_vartime()).retrieve()
    }

    /// 署名値などのバイト列を n と同じ精度の整数にする (長さが k を超えるなら `None`)。
    pub fn int_from_be(&self, bytes: &[u8]) -> Option<BoxedUint> {
        let k = self.size();
        // 先頭の 0 を許容するのは k までに限る (RFC 8017: 署名長は k と等しくなければならない)。
        if bytes.len() != k {
            return None;
        }
        BoxedUint::from_be_slice(bytes, self.n.bits_precision()).ok()
    }

    /// 整数を k バイトに左ゼロ詰めして出力する (I2OSP)。
    pub fn int_to_be(&self, x: &BoxedUint) -> Vec<u8> {
        i2osp(x, self.size())
    }
}

/// I2OSP: 整数を長さ `len` のバイト列へ (呼び出し側が収まることを保証する)。
pub fn i2osp(x: &BoxedUint, len: usize) -> Vec<u8> {
    let full = x.to_be_bytes();
    if full.len() >= len {
        full[full.len() - len..].to_vec()
    } else {
        let mut out = alloc::vec![0u8; len - full.len()];
        out.extend_from_slice(&full);
        out
    }
}

/// RSA 秘密鍵 (2 素数)。
#[derive(Clone)]
pub struct PrivateKey {
    public: PublicKey,
    d: BoxedUint,
    p: BoxedUint,
    q: BoxedUint,
    dp: BoxedUint,
    dq: BoxedUint,
    qinv: BoxedMontyForm,
    p_params: BoxedMontyParams,
    q_params: BoxedMontyParams,
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.d.zeroize();
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for PrivateKey {}

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey").finish_non_exhaustive()
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.public.n == other.public.n
            && self.public.e == other.public.e
            && self.d == other.d
            && self.p == other.p
            && self.q == other.q
    }
}
impl Eq for PrivateKey {}

fn is_one(x: &BoxedUint) -> bool {
    x.bits_vartime() == 1
}

impl PrivateKey {
    /// 構成要素から作る。n = p·q、de ≡ 1 (mod p-1)、de ≡ 1 (mod q-1)、p≠q を検査する。
    ///
    /// 3 素数以上 (multi-prime) は未対応で `InvalidKey`。
    pub fn from_components(
        n: BoxedUint,
        e: BoxedUint,
        d: BoxedUint,
        primes: &[BoxedUint],
    ) -> Result<Self> {
        if primes.len() != 2 {
            return Err(Error::InvalidKey);
        }
        let public = PublicKey::new(n, e)?;
        let (p, q) = (normalize(&primes[0]), normalize(&primes[1]));
        let one = BoxedUint::one();
        if p <= one || q <= one || bool::from(p.is_even()) || bool::from(q.is_even()) || p == q {
            return Err(Error::InvalidKey);
        }
        // n == p*q (幅を n の 2 倍に取って溢れを防ぐ)
        let wide = public.n.bits_precision() * 2;
        let pw = p.rs(wide).ok_or(Error::Internal)?;
        let qw = q.rs(wide).ok_or(Error::Internal)?;
        let nw = public.n.as_ref().rs(wide).ok_or(Error::Internal)?;
        if pw.wrapping_mul(&qw) != nw {
            return Err(Error::InvalidKey);
        }
        let d = normalize(&d);
        // e·d ≡ 1 (mod p-1), (mod q-1)
        let ed = d
            .rs(wide)
            .ok_or(Error::Internal)?
            .wrapping_mul(&public.e.rs(wide).ok_or(Error::Internal)?);
        for prime in [&pw, &qw] {
            let pm1 = NonZero::new(prime.wrapping_sub(&BoxedUint::one_with_precision(wide)))
                .into_option()
                .ok_or(Error::InvalidKey)?;
            if !is_one(&ed.rem_vartime(&pm1)) {
                return Err(Error::InvalidKey);
            }
        }
        Self::assemble(public, d, p, q)
    }

    /// 検査済みの要素から CRT 値を前計算して組み立てる。
    fn assemble(public: PublicKey, d: BoxedUint, p: BoxedUint, q: BoxedUint) -> Result<Self> {
        // p, q は同じ精度にそろえる (小さい方を拡張)。
        let prec = round_up_64(p.bits_vartime().max(q.bits_vartime()));
        let p = p.rs(prec).ok_or(Error::Internal)?;
        let q = q.rs(prec).ok_or(Error::Internal)?;
        let p_params = BoxedMontyParams::new(Odd::new(p.clone()).into_option().ok_or(Error::InvalidKey)?);
        let q_params = BoxedMontyParams::new(Odd::new(q.clone()).into_option().ok_or(Error::InvalidKey)?);

        let dprec = d.bits_precision().max(prec);
        let dw = d.rs(dprec).ok_or(Error::Internal)?;
        let one = BoxedUint::one_with_precision(prec);
        let dp = {
            let m = NonZero::new((&p).wrapping_sub(&one)).into_option().ok_or(Error::InvalidKey)?;
            dw.rem_vartime(&NonZero::new(m.as_ref().rs(dprec).ok_or(Error::Internal)?).into_option().ok_or(Error::Internal)?)
                .rs(prec)
                .ok_or(Error::Internal)?
        };
        let dq = {
            let m = NonZero::new((&q).wrapping_sub(&one)).into_option().ok_or(Error::InvalidKey)?;
            dw.rem_vartime(&NonZero::new(m.as_ref().rs(dprec).ok_or(Error::Internal)?).into_option().ok_or(Error::Internal)?)
                .rs(prec)
                .ok_or(Error::Internal)?
        };
        // qinv = q^-1 mod p
        let q_mod_p = q.rem_vartime(&NonZero::new(p.clone()).into_option().ok_or(Error::InvalidKey)?);
        let qinv = BoxedMontyForm::new(q_mod_p, &p_params)
            .invert()
            .into_option()
            .ok_or(Error::InvalidKey)?;
        Ok(Self {
            public,
            d: dw,
            p,
            q,
            dp,
            dq,
            qinv,
            p_params,
            q_params,
        })
    }

    /// 公開鍵。
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// 私有指数 d。
    pub fn d(&self) -> &BoxedUint {
        &self.d
    }

    /// 素数 p。
    pub fn p(&self) -> &BoxedUint {
        &self.p
    }

    /// 素数 q。
    pub fn q(&self) -> &BoxedUint {
        &self.q
    }

    /// d mod (p-1)。
    pub fn dp(&self) -> &BoxedUint {
        &self.dp
    }

    /// d mod (q-1)。
    pub fn dq(&self) -> &BoxedUint {
        &self.dq
    }

    /// q^-1 mod p (モンゴメリ形式)。
    pub fn qinv(&self) -> &BoxedMontyForm {
        &self.qinv
    }

    /// p のパラメータ。
    pub fn p_params(&self) -> &BoxedMontyParams {
        &self.p_params
    }

    /// q のパラメータ。
    pub fn q_params(&self) -> &BoxedMontyParams {
        &self.q_params
    }

    /// RSADP (§5.1.2、CRT 形式) をブラインディングと結果検証付きで行う。
    pub fn rsadp(&self, rng: &mut dyn FillBytes, c: &BoxedUint) -> Result<BoxedUint> {
        let n = &self.public.n;
        let n_params = &self.public.n_params;
        if c.bits_precision() != n.bits_precision() || c >= n.as_ref() {
            return Err(Error::Decryption);
        }

        // ブラインド値 r (n と互換な逆元を持つもの) を選ぶ。
        let (r, r_inv) = loop {
            let r = random_below(rng, n)?;
            if bool::from(r.is_zero()) {
                continue;
            }
            let rm = BoxedMontyForm::new(r, n_params);
            if let Some(inv) = Option::<BoxedMontyForm>::from(rm.invert()) {
                break (rm, inv);
            }
        };
        // c' = c · r^e mod n
        let re = r.pow_bounded_exp(&self.public.e, self.public.e.bits_vartime());
        let cb = BoxedMontyForm::new(c.clone(), n_params).mul(&re).retrieve();

        let mb = self.crt(&cb)?;

        // フォールト検出: m'^e ≡ c' (mod n)
        if self.public.pow_e(&mb) != cb {
            return Err(Error::Internal);
        }

        // アンブラインド: m = m' · r^-1 mod n
        Ok(BoxedMontyForm::new(mb, n_params).mul(&r_inv).retrieve())
    }

    /// CRT (Garner): 入力 c' を c'^d mod n に写す。
    fn crt(&self, c: &BoxedUint) -> Result<BoxedUint> {
        let prec = self.p.bits_precision();
        let nprec = self.public.n.bits_precision();

        let reduce = |x: &BoxedUint, m: &BoxedUint| -> Result<BoxedUint> {
            let wide = x.bits_precision().max(prec);
            let xw = x.rs(wide).ok_or(Error::Internal)?;
            let mw = NonZero::new(m.rs(wide).ok_or(Error::Internal)?)
                .into_option()
                .ok_or(Error::Internal)?;
            xw.rem(&mw).rs(prec).ok_or(Error::Internal)
        };

        // m1 = c^dp mod p, m2 = c^dq mod q
        let cp = BoxedMontyForm::new(reduce(c, &self.p)?, &self.p_params);
        let m1 = cp.pow(&self.dp);
        let cq = BoxedMontyForm::new(reduce(c, &self.q)?, &self.q_params);
        let m2 = cq.pow(&self.dq).retrieve();

        // h = qinv · (m1 - m2) mod p
        let m2p = BoxedMontyForm::new(reduce(&m2, &self.p)?, &self.p_params);
        let h = (self.qinv.mul(&(m1 - m2p))).retrieve();

        // m = m2 + h·q  (n の幅で)
        let hq = h
            .rs(nprec)
            .ok_or(Error::Internal)?
            .wrapping_mul(&self.q.rs(nprec).ok_or(Error::Internal)?);
        Ok(m2.rs(nprec).ok_or(Error::Internal)?.wrapping_add(&hq))
    }
}

/// [0, n) の整数を乱数で選ぶ。ブラインド用なので小さな偏りは問題ない (64 ビット余分に引いて剰余)。
fn random_below(rng: &mut dyn FillBytes, n: &NonZero<BoxedUint>) -> Result<BoxedUint> {
    let prec = n.bits_precision();
    let wide = prec + 64;
    let mut buf = alloc::vec![0u8; (wide / 8) as usize];
    rng.fill(&mut buf)?;
    let x = BoxedUint::from_be_slice(&buf, wide).map_err(|_| Error::Internal);
    buf.zeroize();
    let x = x?;
    let nw = NonZero::new(n.as_ref().rs(wide).ok_or(Error::Internal)?)
        .into_option()
        .ok_or(Error::Internal)?;
    x.rem(&nw).rs(prec).ok_or(Error::Internal)
}

/// 参照から精度変更するための小さな拡張 (`Resize` は値渡しのため)。
pub trait Rs {
    /// 精度を `bits` に変更する (値が収まらなければ `None`)。
    fn rs(&self, bits: u32) -> Option<BoxedUint>;
}

impl Rs for BoxedUint {
    fn rs(&self, bits: u32) -> Option<BoxedUint> {
        Resize::try_resize(self, bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::OsFill;

    fn key1024() -> PrivateKey {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/key1024.txt");
        let txt = std::fs::read_to_string(p).unwrap();
        let get = |k: &str| {
            let l = txt.lines().find(|l| l.starts_with(&alloc::format!("{k}="))).unwrap();
            let s = &l[2..];
            let s = if s.len() % 2 == 1 { alloc::format!("0{s}") } else { s.into() };
            BoxedUint::from_be_slice_vartime(&hex::decode(s).unwrap())
        };
        PrivateKey::from_components(get("n"), get("e"), get("d"), &[get("p"), get("q")]).unwrap()
    }

    /// CRT の途中値が壊れた (フォールト) 場合、誤った値を出さずエラーにする。
    #[test]
    fn faulty_crt_value_is_detected_not_returned() {
        let good = key1024();
        let c = BoxedUint::from_be_slice(&[0x42u8; 100], good.public().n().bits_precision()).unwrap();
        let ok = good.rsadp(&mut OsFill, &c).unwrap();
        // 正しい鍵では rsaep(rsadp(c)) == c
        assert_eq!(good.public().rsaep(&ok).unwrap(), c);

        let mut bad = good.clone();
        bad.dp = bad.dp.wrapping_add(&BoxedUint::from_be_slice(&[2], bad.dp.bits_precision()).unwrap());
        assert_eq!(bad.rsadp(&mut OsFill, &c), Err(Error::Internal));

        let mut bad = good.clone();
        bad.dq = bad.dq.wrapping_add(&BoxedUint::from_be_slice(&[2], bad.dq.bits_precision()).unwrap());
        assert_eq!(bad.rsadp(&mut OsFill, &c), Err(Error::Internal));
    }
}
