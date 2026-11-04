//! 秘密依存の分岐を避けるための小さなバイト列ヘルパ。
//!
//! `black_box` で最適化による分岐化を抑えるが、命令列の保証はしない (README の限界を参照)。

use core::hint::black_box;

/// `x == 0` のとき 0xFF、それ以外は 0x00。
#[inline]
pub fn is_zero_mask(x: u8) -> u8 {
    let x = black_box(x) as u32;
    // x==0 のとき (x-1) の最上位ビットが立つ。
    ((x.wrapping_sub(1) >> 8) & 0xFF) as u8
}

/// `a == b` のとき 0xFF、違うとき 0x00。
#[inline]
pub fn eq_mask(a: u8, b: u8) -> u8 {
    is_zero_mask(a ^ b)
}

/// 長さが等しい前提のバイト列比較。等しければ 0xFF、違えば 0x00。長さ不一致は 0x00。
pub fn bytes_eq_mask(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    is_zero_mask(acc)
}

/// usize の `a == b` を 0xFF/0x00 で。
#[inline]
pub fn usize_eq_mask(a: usize, b: usize) -> u8 {
    let d = (black_box(a) ^ black_box(b)) as u64;
    // d==0 → 0xFF
    let nz = ((d | d.wrapping_neg()) >> 63) as u8; // 非0なら1
    (nz ^ 1).wrapping_neg()
}

/// `a < b` を 0xFF/0x00 で (どちらも 2^63 未満を想定)。
#[inline]
pub fn usize_lt_mask(a: usize, b: usize) -> u8 {
    let r = (black_box(a) as u64).wrapping_sub(black_box(b) as u64) >> 63;
    (r as u8).wrapping_neg()
}

/// mask==0xFF なら a、0x00 なら b。
#[inline]
pub fn select_u8(mask: u8, a: u8, b: u8) -> u8 {
    (mask & a) | (!mask & b)
}

/// mask==0xFF なら a、0x00 なら b (usize)。
#[inline]
pub fn select_usize(mask: u8, a: usize, b: usize) -> usize {
    // mask は 0x00 か 0xFF のみ。0xFF * (MAX/255) = MAX。
    let m = (mask as usize).wrapping_mul(usize::MAX / 255);
    (m & a) | (!m & b)
}
