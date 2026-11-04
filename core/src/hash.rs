//! ハッシュ関数の抽象。互換層が各 `digest` 版に合わせて実装する。

use alloc::vec::Vec;

/// RFC 8017 §B.1 の Hash。複数の断片を連結してハッシュする。
pub trait HashFn {
    /// 出力長 (hLen)。
    fn output_len(&self) -> usize;
    /// `parts` を連結した入力のダイジェスト。
    fn hash(&self, parts: &[&[u8]]) -> Vec<u8>;
}

/// 乱数源。`fill` が全バイトを埋められなければ `Err`。
pub trait FillBytes {
    /// `dest` を乱数で埋める。
    fn fill(&mut self, dest: &mut [u8]) -> crate::Result<()>;
}

impl<F: FnMut(&mut [u8]) -> crate::Result<()>> FillBytes for F {
    fn fill(&mut self, dest: &mut [u8]) -> crate::Result<()> {
        self(dest)
    }
}

/// OS の乱数 (`os-rng` feature)。
#[cfg(feature = "os-rng")]
pub struct OsFill;

#[cfg(feature = "os-rng")]
impl FillBytes for OsFill {
    fn fill(&mut self, dest: &mut [u8]) -> crate::Result<()> {
        getrandom::fill(dest).map_err(|_| crate::Error::Rng)
    }
}
