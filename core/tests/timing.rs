//! dudect 風の簡易タイミング計測 (実測の入口。**証明ではない**)。
//!
//! 2 クラスの入力で処理時間を交互に計測し、外れ値を落として Welch の t 値を出す。
//! |t| が大きい (経験則で > 10) ならクラス間で時間差がある疑い。小さいことは「この環境・この
//! サンプル数では検出できなかった」だけで、定数時間性の保証にはならない。
//! 実行: cargo test --release -p rsa-rs-core --test timing -- --ignored --nocapture

use std::{fs, hint::black_box, path::PathBuf, time::Instant};

use rsa_rs_core::{hash::OsFill, oaep, BoxedUint, HashFn, PrivateKey};
use sha2::Digest;

struct Sha256;
impl HashFn for Sha256 {
    fn output_len(&self) -> usize {
        32
    }
    fn hash(&self, parts: &[&[u8]]) -> Vec<u8> {
        let mut d = sha2::Sha256::new();
        for p in parts {
            d.update(p);
        }
        d.finalize().to_vec()
    }
}

fn key() -> PrivateKey {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/key2048.txt");
    let txt = fs::read_to_string(p).unwrap();
    let get = |k: &str| {
        let s = &txt
            .lines()
            .find(|l| l.starts_with(&format!("{k}=")))
            .unwrap()[2..];
        let s = if s.len() % 2 == 1 {
            format!("0{s}")
        } else {
            s.to_string()
        };
        BoxedUint::from_be_slice_vartime(&hex::decode(s).unwrap())
    };
    PrivateKey::from_components(get("n"), get("e"), get("d"), &[get("p"), get("q")]).unwrap()
}

fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let m = |x: &[f64]| x.iter().sum::<f64>() / x.len() as f64;
    let v = |x: &[f64], mu: f64| {
        x.iter().map(|y| (y - mu).powi(2)).sum::<f64>() / (x.len() as f64 - 1.0)
    };
    let (ma, mb) = (m(a), m(b));
    (ma - mb) / (v(a, ma) / a.len() as f64 + v(b, mb) / b.len() as f64).sqrt()
}

/// 下位 `keep` 割だけ残す (上側の外れ値を落とす)。
fn crop(mut x: Vec<f64>, keep: f64) -> Vec<f64> {
    x.sort_by(|a, b| a.partial_cmp(b).unwrap());
    x.truncate((x.len() as f64 * keep) as usize);
    x
}

fn run(name: &str, n: usize, mut f0: impl FnMut(), mut f1: impl FnMut()) {
    let (mut t0, mut t1) = (Vec::with_capacity(n), Vec::with_capacity(n));
    for i in 0..n {
        // 順序バイアスを避けるため交互に先攻を入れ替える
        for which in if i % 2 == 0 { [0, 1] } else { [1, 0] } {
            let s = Instant::now();
            if which == 0 {
                f0()
            } else {
                f1()
            }
            let e = s.elapsed().as_nanos() as f64;
            if which == 0 {
                t0.push(e)
            } else {
                t1.push(e)
            }
        }
    }
    let raw = welch_t(&t0, &t1);
    let (c0, c1) = (crop(t0, 0.8), crop(t1, 0.8));
    let cropped = welch_t(&c0, &c1);
    let med = |x: &[f64]| x[x.len() / 2];
    println!(
        "{name:<44} n={n}  t(raw)={raw:+7.2}  t(crop80%)={cropped:+7.2}  median {:.0}ns vs {:.0}ns",
        med(&c0),
        med(&c1)
    );
}

#[test]
#[ignore]
fn timing_oaep_decrypt_valid_vs_invalid() {
    let k = key();
    let h = Sha256;
    let valid = oaep::encrypt(k.public(), &mut OsFill, &h, &h, b"", b"secret message").unwrap();
    // 不正クラス: 毎回ランダムな暗号文 (復号後のパディング検査が必ず失敗する)
    let mut junk = valid.clone();
    junk[0] = 0x01;
    let mut n_ok = 0u32;
    run(
        "OAEP decrypt: valid vs random-invalid",
        1500,
        || {
            n_ok += oaep::decrypt(&k, &mut OsFill, &h, &h, b"", black_box(&valid)).is_ok() as u32;
        },
        || {
            let mut c = junk.clone();
            let mut r = [0u8; 8];
            getrandom::fill(&mut r).unwrap();
            c[8..16].copy_from_slice(&r);
            let _ = black_box(oaep::decrypt(&k, &mut OsFill, &h, &h, b"", black_box(&c)));
        },
    );
    assert!(n_ok > 0);
}

#[test]
#[ignore]
fn timing_rsadp_fixed_vs_random_input() {
    let k = key();
    let prec = k.public().n().bits_precision();
    let small = BoxedUint::from_be_slice(&[0, 0, 0, 2], prec).unwrap(); // 小さい入力
    run(
        "RSADP: c=2 vs random c",
        600,
        || {
            let _ = black_box(k.rsadp(&mut OsFill, black_box(&small)));
        },
        || {
            let mut b = vec![0u8; 255];
            getrandom::fill(&mut b).unwrap();
            let c = BoxedUint::from_be_slice(&b, prec).unwrap();
            let _ = black_box(k.rsadp(&mut OsFill, black_box(&c)));
        },
    );
}
