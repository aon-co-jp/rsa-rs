//! RSASSA-PKCS1-v1_5 (RFC 8017 §8.2, EMSA-PKCS1-v1_5 §9.2)。
//!
//! 検証は §8.2.2 の注記どおり「期待される EM を再構成してバイト列を比較」する方式で、
//! 復号した EM を構文解析しない (Bleichenbacher 型の解析の穴を作らない)。
//! PKCS#1 v1.5 *暗号化* (RSAES) は Bleichenbacher/Marvin の温床なので実装しない。

use alloc::vec::Vec;

use crate::ct::bytes_eq_mask;
use crate::error::{Error, Result};
use crate::hash::FillBytes;
use crate::key::{PrivateKey, PublicKey};
use crypto_bigint::BoxedUint;

fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
}

/// DigestInfo の、ハッシュ値の直前までの DER 接頭辞 (§9.2 注記 1)。
///
/// `oid_content` は OID の内容バイト (タグ・長さを含まない)。パラメータは NULL (`05 00`)。
pub fn digest_info_prefix(oid_content: &[u8], hash_len: usize) -> Vec<u8> {
    // AlgorithmIdentifier ::= SEQUENCE { OID, NULL }
    let mut alg_body = Vec::new();
    alg_body.push(0x06);
    der_len(oid_content.len(), &mut alg_body);
    alg_body.extend_from_slice(oid_content);
    alg_body.extend_from_slice(&[0x05, 0x00]);
    let mut inner = Vec::new();
    inner.push(0x30);
    der_len(alg_body.len(), &mut inner);
    inner.extend_from_slice(&alg_body);
    // DigestInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }
    inner.push(0x04);
    der_len(hash_len, &mut inner);
    let total = inner.len() + hash_len;
    let mut out = Vec::new();
    out.push(0x30);
    der_len(total, &mut out);
    out.extend_from_slice(&inner);
    out
}

/// EMSA-PKCS1-v1_5-ENCODE。`prefix` が空なら T = hashed。
fn emsa_encode(prefix: &[u8], hashed: &[u8], k: usize) -> Result<Vec<u8>> {
    let t_len = prefix.len() + hashed.len();
    if k < t_len + 11 {
        return Err(Error::MessageTooLong);
    }
    let mut em = alloc::vec![0xFFu8; k];
    em[0] = 0x00;
    em[1] = 0x01;
    em[k - t_len - 1] = 0x00;
    em[k - t_len..k - hashed.len()].copy_from_slice(prefix);
    em[k - hashed.len()..].copy_from_slice(hashed);
    Ok(em)
}

/// RSASSA-PKCS1-v1_5-SIGN。`prefix` は [`digest_info_prefix`] の結果。
pub fn sign(
    key: &PrivateKey,
    rng: &mut dyn FillBytes,
    prefix: &[u8],
    hashed: &[u8],
) -> Result<Vec<u8>> {
    let pk = key.public();
    let em = emsa_encode(prefix, hashed, pk.size())?;
    let m = BoxedUint::from_be_slice(&em, pk.n().bits_precision()).map_err(|_| Error::Internal)?;
    let s = key.rsadp(rng, &m)?;
    Ok(pk.int_to_be(&s))
}

/// RSASSA-PKCS1-v1_5-VERIFY。原因は区別せず `Verification` のみ返す。
pub fn verify(key: &PublicKey, prefix: &[u8], hashed: &[u8], sig: &[u8]) -> Result<()> {
    let k = key.size();
    let s = key.int_from_be(sig).ok_or(Error::Verification)?;
    let m = key.rsaep(&s).map_err(|_| Error::Verification)?;
    let em = key.int_to_be(&m);
    let expected = emsa_encode(prefix, hashed, k).map_err(|_| Error::Verification)?;
    if bytes_eq_mask(&em, &expected) == 0xFF {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}
