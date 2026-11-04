//! MGF1 (RFC 8017 §B.2.1)。

use alloc::vec::Vec;

use crate::hash::HashFn;

/// `seed` から `len` バイトのマスクを作る。`len` は 2^32·hLen 以下 (§B.2.1)。
pub fn mgf1(hash: &dyn HashFn, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + hash.output_len());
    let mut counter: u32 = 0;
    while out.len() < len {
        let c = counter.to_be_bytes();
        out.extend_from_slice(&hash.hash(&[seed, &c]));
        counter += 1;
    }
    out.truncate(len);
    out
}

/// `buf ^= mask`。
pub fn xor_in_place(buf: &mut [u8], mask: &[u8]) {
    for (b, m) in buf.iter_mut().zip(mask.iter()) {
        *b ^= m;
    }
}
