//! Project Wycheproof (C2SP/wycheproof, testvectors_v1) の RSA 署名検証と OAEP 復号ベクタ。
//! 方針: valid は必ず成功、invalid は必ず失敗、acceptable は結果を数えるだけ (どちらでも可)。

use std::{fs, path::PathBuf};

use rsa_rs_core::{hash::OsFill, oaep, pkcs1v15, BoxedUint, HashFn, PrivateKey, PublicKey};
use serde_json::Value;
use sha2::Digest;

struct H(&'static str);
impl HashFn for H {
    fn output_len(&self) -> usize {
        match self.0 {
            "SHA-1" => 20,
            "SHA-256" => 32,
            "SHA-384" => 48,
            _ => 64,
        }
    }
    fn hash(&self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(p: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            for x in p {
                d.update(x);
            }
            d.finalize().to_vec()
        }
        match self.0 {
            "SHA-1" => run::<sha1::Sha1>(parts),
            "SHA-256" => run::<sha2::Sha256>(parts),
            "SHA-384" => run::<sha2::Sha384>(parts),
            _ => run::<sha2::Sha512>(parts),
        }
    }
}

fn oid(h: &str) -> &'static [u8] {
    match h {
        "SHA-1" => &[0x2B, 0x0E, 0x03, 0x02, 0x1A],
        "SHA-256" => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
        "SHA-384" => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
        _ => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
    }
}

fn load(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/wycheproof").join(name);
    serde_json::from_slice(&fs::read(p).unwrap()).unwrap()
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn uint(v: &Value) -> BoxedUint {
    BoxedUint::from_be_slice_vartime(&hx(v))
}

fn sha_name(g: &Value) -> &'static str {
    match g["sha"].as_str().unwrap() {
        "SHA-1" => "SHA-1",
        "SHA-256" => "SHA-256",
        "SHA-384" => "SHA-384",
        "SHA-512" => "SHA-512",
        other => panic!("unsupported {other}"),
    }
}

fn signature_file(name: &str) {
    let v = load(name);
    let (mut valid, mut invalid, mut acceptable, mut skipped) = (0, 0, 0, 0);
    for g in v["testGroups"].as_array().unwrap() {
        let key = PublicKey::new(uint(&g["publicKey"]["modulus"]), uint(&g["publicKey"]["publicExponent"]));
        let sha = sha_name(g);
        let h = H(sha);
        for t in g["tests"].as_array().unwrap() {
            let id = t["tcId"].as_u64().unwrap();
            let Ok(key) = &key else {
                // 鍵自体が拒否される場合、そのグループの valid は無いはず
                assert_ne!(t["result"], "valid", "tc {id}: key rejected but vector valid");
                skipped += 1;
                continue;
            };
            let hashed = h.hash(&[&hx(&t["msg"])]);
            let prefix = pkcs1v15::digest_info_prefix(oid(sha), hashed.len());
            let r = pkcs1v15::verify(key, &prefix, &hashed, &hx(&t["sig"]));
            match t["result"].as_str().unwrap() {
                "valid" => {
                    r.unwrap_or_else(|e| panic!("{name} tc {id} valid but rejected: {e}"));
                    valid += 1;
                }
                "invalid" => {
                    assert!(r.is_err(), "{name} tc {id} ({}) invalid but accepted", t["comment"]);
                    invalid += 1;
                }
                _ => acceptable += 1,
            }
        }
    }
    println!("{name}: valid={valid} invalid={invalid} acceptable={acceptable} skipped={skipped}");
    assert!(valid > 0 && invalid > 0);
}

#[test]
fn signatures() {
    for f in [
        "rsa_signature_2048_sha256_test.json",
        "rsa_signature_2048_sha512_test.json",
        "rsa_signature_3072_sha256_test.json",
    ] {
        signature_file(f);
    }
}

fn oaep_file(name: &str, hash: &'static str) {
    let v = load(name);
    let (mut valid, mut invalid, mut acceptable) = (0, 0, 0);
    for g in v["testGroups"].as_array().unwrap() {
        let k = &g["privateKey"];
        let key = PrivateKey::from_components(
            uint(&k["modulus"]),
            uint(&k["publicExponent"]),
            uint(&k["privateExponent"]),
            &[uint(&k["prime1"]), uint(&k["prime2"])],
        )
        .expect("wycheproof key");
        let h = H(hash);
        for t in g["tests"].as_array().unwrap() {
            let id = t["tcId"].as_u64().unwrap();
            let r = oaep::decrypt(&key, &mut OsFill, &h, &h, &hx(&t["label"]), &hx(&t["ct"]));
            match t["result"].as_str().unwrap() {
                "valid" => {
                    assert_eq!(r.unwrap_or_else(|e| panic!("{name} tc {id}: {e}")), hx(&t["msg"]), "tc {id}");
                    valid += 1;
                }
                "invalid" => {
                    assert!(r.is_err(), "{name} tc {id} ({}) invalid but decrypted", t["comment"]);
                    invalid += 1;
                }
                _ => acceptable += 1,
            }
        }
    }
    println!("{name}: valid={valid} invalid={invalid} acceptable={acceptable}");
    assert!(valid > 0 && invalid > 0);
}

#[test]
fn oaep() {
    oaep_file("rsa_oaep_2048_sha256_mgf1sha256_test.json", "SHA-256");
    oaep_file("rsa_oaep_2048_sha1_mgf1sha1_test.json", "SHA-1");
}
