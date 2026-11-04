//! 既知回答テスト。期待値は OpenSSL が生成したもの (scripts/gen-fixtures.sh)。
//! PKCS#1 v1.5 署名は決定的なので、自前の出力が OpenSSL とバイト一致することを確認する。

use std::fs;
use std::path::PathBuf;

use rsa_rs_core::hash::OsFill;
use rsa_rs_core::{oaep, pkcs1v15, BoxedUint, Error, HashFn, PrivateKey};
use sha2::Digest;

fn fx(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn load_key(bits: u32) -> PrivateKey {
    let txt = String::from_utf8(fx(&format!("key{bits}.txt"))).unwrap();
    let get = |k: &str| -> BoxedUint {
        let line = txt
            .lines()
            .find(|l| l.starts_with(&format!("{k}=")))
            .unwrap();
        hex_uint(&line[2..])
    };
    PrivateKey::from_components(get("n"), get("e"), get("d"), &[get("p"), get("q")]).unwrap()
}

struct H(&'static str);
impl HashFn for H {
    fn output_len(&self) -> usize {
        match self.0 {
            "sha1" => 20,
            "sha256" => 32,
            "sha384" => 48,
            _ => 64,
        }
    }
    fn hash(&self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            for p in parts {
                d.update(p);
            }
            d.finalize().to_vec()
        }
        match self.0 {
            "sha1" => run::<sha1::Sha1>(parts),
            "sha256" => run::<sha2::Sha256>(parts),
            "sha384" => run::<sha2::Sha384>(parts),
            _ => run::<sha2::Sha512>(parts),
        }
    }
}

/// DigestAlgorithm の OID 内容バイト (RFC 8017 §9.2 注記 1)。
fn oid(h: &str) -> &'static [u8] {
    match h {
        "sha1" => &[0x2B, 0x0E, 0x03, 0x02, 0x1A],
        "sha256" => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
        "sha384" => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
        _ => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
    }
}

const HASHES: [&str; 4] = ["sha1", "sha256", "sha384", "sha512"];

#[test]
fn digest_info_prefix_matches_rfc8017_9_2() {
    // RFC 8017 §9.2 注記 1 の SHA-256 の DigestInfo 接頭辞。
    let want = hex::decode("3031300d060960864801650304020105000420").unwrap();
    assert_eq!(pkcs1v15::digest_info_prefix(oid("sha256"), 32), want);
    // SHA-1: 3021300906052b0e03021a05000414
    let want = hex::decode("3021300906052b0e03021a05000414").unwrap();
    assert_eq!(pkcs1v15::digest_info_prefix(oid("sha1"), 20), want);
    // SHA-512: 3051300d060960864801650304020305000440
    let want = hex::decode("3051300d060960864801650304020305000440").unwrap();
    assert_eq!(pkcs1v15::digest_info_prefix(oid("sha512"), 64), want);
}

#[test]
fn pkcs1v15_sign_is_byte_identical_to_openssl() {
    let msg = fx("msg.bin");
    for bits in [1024u32, 2048] {
        let key = load_key(bits);
        for h in HASHES {
            let hf = H(h);
            let hashed = hf.hash(&[&msg]);
            let prefix = pkcs1v15::digest_info_prefix(oid(h), hashed.len());
            let ours = pkcs1v15::sign(&key, &mut OsFill, &prefix, &hashed).unwrap();
            assert_eq!(ours, fx(&format!("sig{bits}_{h}.bin")), "{bits} {h}");
            // OpenSSL の署名を我々が検証できる
            pkcs1v15::verify(
                key.public(),
                &prefix,
                &hashed,
                &fx(&format!("sig{bits}_{h}.bin")),
            )
            .unwrap();
        }
    }
}

#[test]
fn pkcs1v15_verify_rejects_bad_input() {
    let msg = fx("msg.bin");
    let key = load_key(2048);
    let hf = H("sha256");
    let hashed = hf.hash(&[&msg]);
    let prefix = pkcs1v15::digest_info_prefix(oid("sha256"), 32);
    let good = fx("sig2048_sha256.bin");
    pkcs1v15::verify(key.public(), &prefix, &hashed, &good).unwrap();

    // 1 ビット反転
    for i in [0usize, 100, 255] {
        let mut bad = good.clone();
        bad[i] ^= 1;
        assert_eq!(
            pkcs1v15::verify(key.public(), &prefix, &hashed, &bad),
            Err(Error::Verification)
        );
    }
    // 長さ違い (短い・長い・先頭ゼロ付加)
    assert!(pkcs1v15::verify(key.public(), &prefix, &hashed, &good[1..]).is_err());
    let mut longer = vec![0u8];
    longer.extend_from_slice(&good);
    assert!(pkcs1v15::verify(key.public(), &prefix, &hashed, &longer).is_err());
    // 別メッセージ
    let other = hf.hash(&[b"other"]);
    assert!(pkcs1v15::verify(key.public(), &prefix, &other, &good).is_err());
    // 別ハッシュの接頭辞
    let p512 = pkcs1v15::digest_info_prefix(oid("sha512"), 32);
    assert!(pkcs1v15::verify(key.public(), &p512, &hashed, &good).is_err());
    // s >= n (n 自身)
    let n_bytes = key.public().int_to_be(key.public().n());
    assert!(pkcs1v15::verify(key.public(), &prefix, &hashed, &n_bytes).is_err());
    // 全ゼロ・全 0xFF
    assert!(pkcs1v15::verify(key.public(), &prefix, &hashed, &[0u8; 256]).is_err());
    assert!(pkcs1v15::verify(key.public(), &prefix, &hashed, &[0xFFu8; 256]).is_err());
}

#[test]
fn oaep_decrypts_openssl_ciphertexts() {
    let key = load_key(2048);
    let pt = fx("oaep_pt.bin");
    for h in ["sha1", "sha256"] {
        let hf = H(h);
        let got = oaep::decrypt(
            &key,
            &mut OsFill,
            &hf,
            &hf,
            b"",
            &fx(&format!("oaep2048_{h}.bin")),
        )
        .unwrap();
        assert_eq!(got, pt, "{h}");
        // ラベル違いは失敗
        assert_eq!(
            oaep::decrypt(
                &key,
                &mut OsFill,
                &hf,
                &hf,
                b"x",
                &fx(&format!("oaep2048_{h}.bin"))
            ),
            Err(Error::Decryption)
        );
        // ハッシュ違いは失敗
        let other = H("sha512");
        assert!(oaep::decrypt(
            &key,
            &mut OsFill,
            &other,
            &other,
            b"",
            &fx(&format!("oaep2048_{h}.bin"))
        )
        .is_err());
    }
}

#[test]
fn oaep_roundtrip_and_tamper() {
    let key = load_key(2048);
    for h in ["sha1", "sha256", "sha512"] {
        let hf = H(h);
        let max = 256 - 2 * hf.output_len() - 2;
        for len in [0usize, 1, 16, max] {
            let msg: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
            let ct = oaep::encrypt(key.public(), &mut OsFill, &hf, &hf, b"lbl", &msg).unwrap();
            assert_eq!(ct.len(), 256);
            assert_eq!(
                oaep::decrypt(&key, &mut OsFill, &hf, &hf, b"lbl", &ct).unwrap(),
                msg
            );
            let mut bad = ct.clone();
            bad[10] ^= 0x40;
            assert_eq!(
                oaep::decrypt(&key, &mut OsFill, &hf, &hf, b"lbl", &bad),
                Err(Error::Decryption)
            );
        }
        // 長すぎる平文
        let too_long = vec![1u8; max + 1];
        assert_eq!(
            oaep::encrypt(key.public(), &mut OsFill, &hf, &hf, b"", &too_long),
            Err(Error::MessageTooLong)
        );
    }
    // MGF1 のハッシュを OAEP のハッシュと別にできる
    let (a, b) = (H("sha256"), H("sha1"));
    let ct = oaep::encrypt(key.public(), &mut OsFill, &a, &b, b"", b"mixed").unwrap();
    assert_eq!(
        oaep::decrypt(&key, &mut OsFill, &a, &b, b"", &ct).unwrap(),
        b"mixed"
    );
    assert!(oaep::decrypt(&key, &mut OsFill, &a, &a, b"", &ct).is_err());
}

#[test]
fn oaep_ciphertext_not_below_modulus_is_rejected() {
    let key = load_key(1024);
    let hf = H("sha1");
    let n = key.public().int_to_be(key.public().n());
    assert_eq!(
        oaep::decrypt(&key, &mut OsFill, &hf, &hf, b"", &n),
        Err(Error::Decryption)
    );
    assert!(oaep::decrypt(&key, &mut OsFill, &hf, &hf, b"", &[0u8; 128]).is_err());
    assert!(oaep::decrypt(&key, &mut OsFill, &hf, &hf, b"", &[1u8; 5]).is_err());
}

#[test]
fn key_validation() {
    let txt = String::from_utf8(fx("key1024.txt")).unwrap();
    let get = |k: &str| -> BoxedUint {
        let line = txt
            .lines()
            .find(|l| l.starts_with(&format!("{k}=")))
            .unwrap();
        hex_uint(&line[2..])
    };
    let (n, e, d, p, q) = (get("n"), get("e"), get("d"), get("p"), get("q"));
    PrivateKey::from_components(n.clone(), e.clone(), d.clone(), &[p.clone(), q.clone()]).unwrap();
    // d を 1 ずらす
    let bad_d = d.wrapping_add(&BoxedUint::one());
    assert!(
        PrivateKey::from_components(n.clone(), e.clone(), bad_d, &[p.clone(), q.clone()]).is_err()
    );
    // p と q を入れ替えても同じ鍵として受理される
    PrivateKey::from_components(n.clone(), e.clone(), d.clone(), &[q.clone(), p.clone()]).unwrap();
    // 素数が 1 個 / 3 個
    assert!(PrivateKey::from_components(n.clone(), e.clone(), d.clone(), &[p.clone()]).is_err());
    assert!(PrivateKey::from_components(
        n.clone(),
        e.clone(),
        d.clone(),
        &[p.clone(), q.clone(), p.clone()]
    )
    .is_err());
    // p == q
    assert!(
        PrivateKey::from_components(n.clone(), e.clone(), d.clone(), &[p.clone(), p.clone()])
            .is_err()
    );
    // e が偶数 / 範囲外
    assert!(PrivateKey::from_components(
        n.clone(),
        BoxedUint::from(4u64),
        d.clone(),
        &[p.clone(), q.clone()]
    )
    .is_err());
    assert!(PrivateKey::from_components(n, BoxedUint::from(1u64 << 40 | 1), d, &[p, q]).is_err());
}

#[test]
fn generated_keys_work() {
    let e = BoxedUint::from(65537u64);
    for bits in [512usize, 1024] {
        let key = rsa_rs_core::keygen::generate(&mut OsFill, bits, &e).unwrap();
        assert_eq!(key.public().n().bits_vartime() as usize, bits);
        let hf = H("sha256");
        let hashed = hf.hash(&[b"hello"]);
        let prefix = pkcs1v15::digest_info_prefix(oid("sha256"), 32);
        let sig = pkcs1v15::sign(&key, &mut OsFill, &prefix, &hashed).unwrap();
        pkcs1v15::verify(key.public(), &prefix, &hashed, &sig).unwrap();
    }
}

/// 16 進文字列 (奇数桁可) を整数にする。
fn hex_uint(s: &str) -> BoxedUint {
    let s = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    BoxedUint::from_be_slice_vartime(&hex::decode(s).unwrap())
}
