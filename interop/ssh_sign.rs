//! 相互運用: ssh-keygen が作った RSA 秘密鍵で SSHSIG 署名し、`ssh-keygen -Y verify` に検証させる。
//! scripts/interop.sh が work-ssh-key に配置して実行する (環境変数 INTEROP_DIR)。
use ssh_key::{HashAlg, LineEnding, PrivateKey};
use chacha20::rand_core::SeedableRng;
use std::{env, fs};

#[test]
fn sign_with_ssh_keygen_key_for_ssh_keygen_verify() {
    let dir = env::var("INTEROP_DIR").expect("INTEROP_DIR");
    let key = PrivateKey::from_openssh(fs::read_to_string(format!("{dir}/id_rsa")).unwrap()).unwrap();
    assert!(key.algorithm().is_rsa());
    let msg = fs::read(format!("{dir}/msg.txt")).unwrap();
    for (alg, name) in [(HashAlg::Sha256, "sha256"), (HashAlg::Sha512, "sha512")] {
        let sig = key.sign("rsa-rs-interop", alg, &msg).unwrap();
        let pem = sig.to_pem(LineEnding::LF).unwrap();
        fs::write(format!("{dir}/msg.{name}.sig"), pem).unwrap();
    }
    // 自分で作った鍵 (keygen 経由) でも署名して OpenSSH 形式で書き出す
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let mut rng = chacha20::ChaCha8Rng::from_seed(seed);
    let k2 = PrivateKey::random(&mut rng, ssh_key::Algorithm::Rsa { hash: None }).unwrap();
    fs::write(format!("{dir}/gen_rsa"), k2.to_openssh(LineEnding::LF).unwrap()).unwrap();
    fs::write(format!("{dir}/gen_rsa.pub"), k2.public_key().to_openssh().unwrap()).unwrap();
    let sig = k2.sign("rsa-rs-interop", HashAlg::Sha512, &msg).unwrap();
    fs::write(format!("{dir}/msg.gen.sig"), sig.to_pem(LineEnding::LF).unwrap()).unwrap();
}

#[test]
fn verify_ssh_keygen_signature() {
    let dir = env::var("INTEROP_DIR").expect("INTEROP_DIR");
    let pubkey = ssh_key::PublicKey::from_openssh(&fs::read_to_string(format!("{dir}/id_rsa.pub")).unwrap()).unwrap();
    let msg = fs::read(format!("{dir}/msg.txt")).unwrap();
    for name in ["sha256", "sha512"] {
        let p = format!("{dir}/ossh.{name}.sig");
        let sig = ssh_key::SshSig::from_pem(fs::read_to_string(&p).unwrap()).unwrap();
        pubkey.verify("rsa-rs-interop", &msg, &sig).unwrap_or_else(|e| panic!("{name}: {e}"));
        // 改ざんメッセージは失敗する
        assert!(pubkey.verify("rsa-rs-interop", b"tampered", &sig).is_err());
    }
}
