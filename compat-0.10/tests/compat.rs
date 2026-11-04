//! rsa 0.10 互換 API の検証。期待値は OpenSSL 生成のフィクスチャ (core/tests/fixtures)。

use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    signature::{Keypair, SignatureEncoding, Signer, Verifier},
    traits::{PrivateKeyParts, PublicKeyParts},
    BoxedUint, Oaep, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{fs, path::PathBuf};

fn fx(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../core/tests/fixtures")
        .join(name);
    fs::read(p).unwrap()
}

fn key(bits: u32) -> RsaPrivateKey {
    RsaPrivateKey::from_pkcs8_pem(std::str::from_utf8(&fx(&format!("key{bits}.pem"))).unwrap())
        .unwrap()
}

fn sign_matches<D: Digest>(bits: u32, name: &str)
where
    D: const_oid::AssociatedOid + Clone,
{
    let msg = fx("msg.bin");
    let sk = SigningKey::<D>::new(key(bits));
    let sig = sk.try_sign(&msg).unwrap();
    let want = fx(&format!("sig{bits}_{name}.bin"));
    assert_eq!(sig.to_vec(), want, "{bits} {name}");
    let vk: VerifyingKey<D> = Keypair::verifying_key(&sk);
    vk.verify(&msg, &sig).unwrap();
    vk.verify(&msg, &Signature::try_from(want.as_slice()).unwrap())
        .unwrap();
    assert!(vk.verify(b"tampered", &sig).is_err());
}

#[test]
fn signing_key_matches_openssl_bytes() {
    for bits in [1024, 2048] {
        sign_matches::<Sha1>(bits, "sha1");
        sign_matches::<Sha256>(bits, "sha256");
        sign_matches::<Sha384>(bits, "sha384");
        sign_matches::<Sha512>(bits, "sha512");
    }
}

#[test]
fn pkcs1v15sign_scheme_api() {
    let k = key(2048);
    let hashed = Sha256::digest(fx("msg.bin"));
    let sig = k.sign(Pkcs1v15Sign::new::<Sha256>(), &hashed).unwrap();
    assert_eq!(sig, fx("sig2048_sha256.bin"));
    k.to_public_key()
        .verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, &sig)
        .unwrap();
    // 長さ違いのハッシュは InputNotHashed
    assert_eq!(
        k.sign(Pkcs1v15Sign::new::<Sha256>(), &hashed[..31]),
        Err(rsa::Error::InputNotHashed)
    );
    // 別ハッシュ用の方式では検証できない
    assert!(k
        .to_public_key()
        .verify(
            Pkcs1v15Sign::new::<Sha512>(),
            &Sha512::digest(fx("msg.bin")),
            &sig
        )
        .is_err());
}

#[test]
fn oaep_roundtrip_and_openssl() {
    let k = key(2048);
    let pt = fx("oaep_pt.bin");
    // OpenSSL が作った暗号文を復号
    assert_eq!(
        k.decrypt(Oaep::<Sha1>::new(), &fx("oaep2048_sha1.bin"))
            .unwrap(),
        pt
    );
    assert_eq!(
        k.decrypt(Oaep::<Sha256>::new(), &fx("oaep2048_sha256.bin"))
            .unwrap(),
        pt
    );
    // 往復・MGF ハッシュ違い・ラベル
    let mut rng = chacha_like();
    let ct = k
        .to_public_key()
        .encrypt(
            &mut rng,
            Oaep::<Sha256, Sha1>::new_with_mgf_hash_and_label(&b"L"[..]),
            &pt,
        )
        .unwrap();
    assert_eq!(
        k.decrypt(
            Oaep::<Sha256, Sha1>::new_with_mgf_hash_and_label(&b"L"[..]),
            &ct
        )
        .unwrap(),
        pt
    );
    assert!(k
        .decrypt(Oaep::<Sha256, Sha1>::new_with_mgf_hash(), &ct)
        .is_err());
    assert!(k.decrypt(Oaep::<Sha256>::new(), &ct).is_err());
}

/// テスト用の簡易 CryptoRng (OS 乱数)。
fn chacha_like() -> impl rand_core::CryptoRng {
    struct Os;
    impl rand_core::TryRng for Os {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut b = [0u8; 4];
            getrandom::fill(&mut b).unwrap();
            Ok(u32::from_le_bytes(b))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut b = [0u8; 8];
            getrandom::fill(&mut b).unwrap();
            Ok(u64::from_le_bytes(b))
        }
        fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), Self::Error> {
            getrandom::fill(d).unwrap();
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for Os {}
    Os
}

use rsa::rand_core;

#[test]
fn pkcs_encodings_roundtrip_and_match_openssl_public_der() {
    let k = key(2048);
    // 公開鍵 SPKI は OpenSSL の PEM と同一
    let pem = String::from_utf8(fx("pub2048.pem")).unwrap();
    let p = RsaPublicKey::from_public_key_pem(&pem).unwrap();
    assert_eq!(p, k.to_public_key());
    assert_eq!(
        p.to_public_key_pem(Default::default()).unwrap().trim(),
        pem.trim()
    );
    // 秘密鍵の PKCS#8 / PKCS#1 DER 往復
    let der8 = k.to_pkcs8_der().unwrap();
    assert_eq!(RsaPrivateKey::from_pkcs8_der(der8.as_bytes()).unwrap(), k);
    let der1 = k.to_pkcs1_der().unwrap();
    assert_eq!(RsaPrivateKey::from_pkcs1_der(der1.as_bytes()).unwrap(), k);
    let _ = k.to_public_key().to_pkcs1_der().unwrap();
    // 構成要素
    assert_eq!(k.primes().len(), 2);
    assert_eq!(k.size(), 256);
    assert_eq!(k.e(), &BoxedUint::from(65537u64));
    let qinv = k.crt_coefficient().unwrap();
    assert!(!bool::from(qinv.is_zero()));
}

#[test]
fn generated_key_signs_and_interoperates_with_encoding() {
    let mut rng = chacha_like();
    let k = RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let sk = SigningKey::<Sha256>::new(k.clone());
    let sig = sk.sign(b"hello");
    sk.verifying_key().verify(b"hello", &sig).unwrap();
    let k2 = RsaPrivateKey::from_pkcs8_der(k.to_pkcs8_der().unwrap().as_bytes()).unwrap();
    assert_eq!(k, k2);
}

#[test]
fn from_components_validates() {
    let k = key(1024);
    let n = k.n().as_ref().clone();
    let e = k.e().clone();
    let d = k.d().clone();
    let primes = k.primes().to_vec();
    assert!(
        RsaPrivateKey::from_components(n.clone(), e.clone(), d.clone(), primes.clone()).is_ok()
    );
    assert!(RsaPrivateKey::from_components(
        n.clone(),
        e.clone(),
        d.wrapping_add(&BoxedUint::one()),
        primes.clone()
    )
    .is_err());
    assert!(RsaPrivateKey::from_components(n, e, d, vec![primes[0].clone()]).is_err());
}
