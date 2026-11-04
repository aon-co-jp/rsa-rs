//! sqlx-mysql 0.8.6 と同じ使い方 (PEM 公開鍵 → Oaep::new::<Sha1>() → encrypt) の検証。
//! 暗号文は core の秘密鍵で復号して往復を確認し、`RSA_RS_OUT` があればファイルにも書く
//! (scripts/interop.sh が openssl で復号して突き合わせる)。

use rsa::{pkcs8::DecodePublicKey, Oaep, RsaPublicKey};
use rsa_rs_core::{hash::OsFill, oaep, BoxedUint, HashFn, PrivateKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

fn fx(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../core/tests/fixtures")
        .join(name);
    fs::read(p).unwrap()
}

fn hex_uint(s: &str) -> BoxedUint {
    let s = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    BoxedUint::from_be_slice_vartime(&hex::decode(s).unwrap())
}

fn core_key() -> PrivateKey {
    let txt = String::from_utf8(fx("key2048.txt")).unwrap();
    let get = |k: &str| {
        hex_uint(
            &txt.lines()
                .find(|l| l.starts_with(&format!("{k}=")))
                .unwrap()[2..],
        )
    };
    PrivateKey::from_components(get("n"), get("e"), get("d"), &[get("p"), get("q")]).unwrap()
}

struct H<D>(std::marker::PhantomData<D>);
impl<D: Digest> HashFn for H<D> {
    fn output_len(&self) -> usize {
        <D as Digest>::output_size()
    }
    fn hash(&self, parts: &[&[u8]]) -> Vec<u8> {
        let mut d = D::new();
        for p in parts {
            d.update(p);
        }
        d.finalize().to_vec()
    }
}

#[test]
fn mysql_style_encrypt_roundtrip_and_export() {
    let pem = String::from_utf8(fx("pub2048.pem")).unwrap();
    let pkey = RsaPublicKey::from_public_key_pem(&pem).unwrap();
    // MySQL: パスワード + NUL を nonce と XOR したもの (ここでは固定のダミー)
    let pass: Vec<u8> = b"correct horse\0"
        .iter()
        .zip(b"nonce".iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect();
    let mut rng = rand::thread_rng();
    let ct = pkey
        .encrypt(&mut rng, Oaep::new::<Sha1>(), &pass[..])
        .unwrap();
    assert_eq!(ct.len(), 256);
    let h = H::<Sha1>(Default::default());
    assert_eq!(
        oaep::decrypt(&core_key(), &mut OsFill, &h, &h, b"", &ct).unwrap(),
        pass
    );
    // 乱数入りなので同じ平文でも暗号文は毎回違う
    let ct2 = pkey
        .encrypt(&mut rng, Oaep::new::<Sha1>(), &pass[..])
        .unwrap();
    assert_ne!(ct, ct2);
    if let Ok(dir) = std::env::var("RSA_RS_OUT") {
        fs::write(format!("{dir}/mysql_oaep_sha1.bin"), &ct).unwrap();
        fs::write(format!("{dir}/mysql_oaep_sha1.pt"), &pass).unwrap();
        let ct256 = pkey
            .encrypt(&mut rng, Oaep::new::<Sha256>(), &pass[..])
            .unwrap();
        fs::write(format!("{dir}/mysql_oaep_sha256.bin"), ct256).unwrap();
        let lbl = pkey
            .encrypt(
                &mut rng,
                Oaep::new_with_label::<Sha256, _>("lbl"),
                &pass[..],
            )
            .unwrap();
        fs::write(format!("{dir}/mysql_oaep_sha256_lbl.bin"), lbl).unwrap();
    }
}

#[test]
fn too_long_message_and_bad_keys_are_rejected() {
    let pem = String::from_utf8(fx("pub2048.pem")).unwrap();
    let pkey = RsaPublicKey::from_public_key_pem(&pem).unwrap();
    let mut rng = rand::thread_rng();
    // 2048 ビット鍵・SHA-1: 最大 256-2*20-2 = 214 バイト
    assert!(pkey
        .encrypt(&mut rng, Oaep::new::<Sha1>(), &[0u8; 214])
        .is_ok());
    assert_eq!(
        pkey.encrypt(&mut rng, Oaep::new::<Sha1>(), &[0u8; 215]),
        Err(rsa::Error::MessageTooLong)
    );
    // 壊れた PEM / RSA でない鍵は読み込みに失敗する
    assert!(RsaPublicKey::from_public_key_pem(
        "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
    )
    .is_err());
    assert!(RsaPublicKey::from_public_key_pem("not pem").is_err());
    // 偶数の法・偶数の指数は拒否
    use rsa::BigUint;
    assert!(RsaPublicKey::new(BigUint::from(1u8) << 2048usize, BigUint::from(65537u32)).is_err());
    assert!(RsaPublicKey::new(
        (BigUint::from(1u8) << 2048usize) + 1u8,
        BigUint::from(65536u32)
    )
    .is_err());
}
