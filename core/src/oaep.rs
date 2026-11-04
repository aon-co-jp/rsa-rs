//! RSAES-OAEP (RFC 8017 §7.1, EME-OAEP §7.1.1 / §7.1.2)。
//!
//! 復号は §7.1.2 の注意 (Manger 攻撃) に従い、全ての失敗を 1 種類のエラーにまとめ、
//! EM の検査 (Y, lHash, PS/0x01 の探索) を秘密依存の分岐なしで行う。
//! 返す平文の *長さ* だけは API 上避けられず、呼び出し側に見える。

use alloc::vec::Vec;
use zeroize::Zeroize;

use crate::ct::*;
use crate::error::{Error, Result};
use crate::hash::{FillBytes, HashFn};
use crate::key::{PrivateKey, PublicKey};
use crate::mgf::{mgf1, xor_in_place};
use crypto_bigint::BoxedUint;

/// RSAES-OAEP-ENCRYPT。`hash` が OAEP のハッシュ、`mgf_hash` が MGF1 のハッシュ。
pub fn encrypt(
    key: &PublicKey,
    rng: &mut dyn FillBytes,
    hash: &dyn HashFn,
    mgf_hash: &dyn HashFn,
    label: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>> {
    let k = key.size();
    let h_len = hash.output_len();
    if k < 2 * h_len + 2 || msg.len() > k - 2 * h_len - 2 {
        return Err(Error::MessageTooLong);
    }
    if (label.len() as u64) >= (1u64 << 61) {
        return Err(Error::LabelTooLong);
    }
    let l_hash = hash.hash(&[label]);

    let mut em = alloc::vec![0u8; k];
    let (_, rest) = em.split_at_mut(1);
    let (seed, db) = rest.split_at_mut(h_len);
    db[..h_len].copy_from_slice(&l_hash);
    let db_len = db.len();
    db[db_len - msg.len() - 1] = 0x01;
    db[db_len - msg.len()..].copy_from_slice(msg);
    rng.fill(seed)?;

    let db_mask = mgf1(mgf_hash, seed, db.len());
    xor_in_place(db, &db_mask);
    let seed_mask = mgf1(mgf_hash, db, h_len);
    xor_in_place(seed, &seed_mask);

    let m = BoxedUint::from_be_slice(&em, key.n().bits_precision()).map_err(|_| Error::Internal)?;
    let c = key.rsaep(&m)?;
    Ok(key.int_to_be(&c))
}

/// RSAES-OAEP-DECRYPT。
pub fn decrypt(
    key: &PrivateKey,
    rng: &mut dyn FillBytes,
    hash: &dyn HashFn,
    mgf_hash: &dyn HashFn,
    label: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    let pk = key.public();
    let k = pk.size();
    let h_len = hash.output_len();
    if k < 2 * h_len + 2 {
        return Err(Error::Decryption);
    }
    let c = pk.int_from_be(ct).ok_or(Error::Decryption)?;
    let m = key.rsadp(rng, &c).map_err(|_| Error::Decryption)?;
    let mut em = pk.int_to_be(&m);

    let l_hash = hash.hash(&[label]);

    let y = em[0];
    let (_, rest) = em.split_at_mut(1);
    let (masked_seed, masked_db) = rest.split_at_mut(h_len);
    let seed_mask = mgf1(mgf_hash, masked_db, h_len);
    xor_in_place(masked_seed, &seed_mask);
    let db_mask = mgf1(mgf_hash, masked_seed, masked_db.len());
    xor_in_place(masked_db, &db_mask);
    let db: &[u8] = masked_db;

    // 検査: Y == 0、lHash 一致、PS の後に 0x01。全て分岐なしで集約する。
    let mut ok = is_zero_mask(y);
    ok &= bytes_eq_mask(&db[..h_len], &l_hash);

    // db[h_len..] は 00..00 01 M。最初の非ゼロバイトが 0x01 であること。
    let mut looking = 0xFFu8;
    let mut idx = 0usize;
    let mut found_one = 0u8;
    let mut bad = 0u8;
    for (i, &b) in db[h_len..].iter().enumerate() {
        let nz = !is_zero_mask(b);
        let first = looking & nz;
        idx = select_usize(first, i, idx);
        let is_one = eq_mask(b, 0x01);
        found_one |= first & is_one;
        bad |= first & !is_one;
        looking &= !nz;
    }
    ok &= found_one & !bad;

    let start = h_len + idx + 1;
    let result = if ok == 0xFF {
        Ok(db[start..].to_vec())
    } else {
        Err(Error::Decryption)
    };
    em.zeroize();
    result
}
