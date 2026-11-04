//! `digest` 0.11 の `Digest` を core の `HashFn` に見せる。

use alloc::vec::Vec;
use core::marker::PhantomData;
use digest::Digest;
use rsa_rs_core::HashFn;

pub(crate) struct DigestFn<D>(PhantomData<D>);

impl<D> DigestFn<D> {
    pub(crate) fn new() -> Self {
        Self(PhantomData)
    }
}

impl<D: Digest> DigestFn<D> {
    /// 断片を連結してハッシュする。
    pub(crate) fn digest(parts: &[&[u8]]) -> Vec<u8> {
        let mut d = D::new();
        for p in parts {
            d.update(p);
        }
        d.finalize().iter().copied().collect()
    }
}

impl<D: Digest> HashFn for DigestFn<D> {
    fn output_len(&self) -> usize {
        <D as Digest>::output_size()
    }
    fn hash(&self, parts: &[&[u8]]) -> Vec<u8> {
        Self::digest(parts)
    }
}
