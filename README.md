# rsa-rs

**日本語** | [English](#english)

`rsa` クレートの **互換置き換え** (RUSTSEC-2023-0071 / Marvin Attack 対策)。aon-co-jp 配下のリポジトリが
依存経由で使っている範囲だけを、RFC 8017 に基づき自前で実装したものです。非公開リポジトリ。crates.io には公開しません。

> ⚠️ **第三者監査は受けていません。** 自前の暗号実装です。「定数時間性」「Marvin 非脆弱」を保証するものではありません。
> 下の「限界」を必ず読んでください。

## 構成

| ディレクトリ | 内容 |
|---|---|
| `core/` (`rsa-rs-core`) | ハッシュ・乱数の版に依存しない RSA コア。鍵、RSADP(CRT+ブラインディング+結果検証)、PKCS#1 v1.5 署名、OAEP、鍵生成 |
| `compat-0.10/` (crate 名 `rsa` 0.10.0-rc.18) | `ssh-key 0.7.0-rc.11` / `russh 0.62・0.63` 向け。署名(PKCS#1 v1.5)・OAEP・PKCS#1/#8/SPKI 入出力 |
| `compat-0.9/` (crate 名 `rsa` 0.9.10) | `sqlx-mysql 0.8.x` 向け。**公開鍵 + OAEP 暗号化のみ** (秘密鍵演算なし) |
| `scripts/` | WSL 用のテスト・相互運用スクリプト |

互換層は crate 名がどちらも `rsa` なのでワークスペースに入れず、個別にビルドします。

## 使い方 (各リポジトリの `Cargo.toml`)

```toml
[patch.crates-io]
rsa = { path = "../rsa-rs/compat-0.10" }                                   # rsa 0.10.0-rc.18 を置き換え
rsa-090 = { package = "rsa", path = "../rsa-rs/compat-0.9" }               # rsa 0.9.10 を置き換え (必要なら)
```

* `crypto-bigint` は **0.7.10 以上**が必須 (`cargo update -p crypto-bigint --precise 0.7.10`)。
  互換層は `>=0.7.10` を要求するので、古いロックのままだと解決に失敗します (意図した動作)。
* 片方しか使わないリポジトリは、使う方の行だけ書けば足ります。

## 実装した範囲 (それ以外は **コンパイルエラー**になる)

実装は「依存元が実際に呼ぶ API」に限定しています (全 API の複製はしません)。

**0.10 互換 (`compat-0.10`)**: `RsaPrivateKey` (`new`/`from_components`/`to_public_key`/`crt_coefficient`/`sign`/`decrypt`)、
`RsaPublicKey` (`new`/`encrypt`/`verify`)、`PublicKeyParts`/`PrivateKeyParts`、`pkcs1v15::{SigningKey, VerifyingKey, Signature}`、
`Pkcs1v15Sign`、`Oaep`、`BoxedUint`、`errors::Error`、`pkcs1`/`pkcs8` の Decode/Encode。

**0.9 互換 (`compat-0.9`)**: `RsaPublicKey` (`DecodePublicKey` 経由の PEM/DER 読込、`encrypt`)、`Oaep::new::<D>()` 等、`BigUint`。

**未実装**: PSS、PKCS#1 v1.5 *暗号化* (Bleichenbacher/Marvin の温床なので意図的に実装しない)、multi-prime 鍵、serde、`hazmat`。
0.9 互換では秘密鍵・署名も未実装。

## 設計 (防御)

* 秘密鍵演算 (RSADP): **ブラインディング** (毎回新しい r) + **CRT (Garner)** + **結果検証** (ブラインド後の値 m' に対し m'^e ≡ c' を確認、
  不一致なら値を返さない=フォールト攻撃対策)。べき乗・剰余・逆元は `crypto-bigint` 0.7.10+ の定数時間演算。
* 署名の検証は RFC 8017 §8.2.2 の注記どおり、期待される EM を再構成してバイト列比較 (EM を構文解析しない)。
* OAEP 復号は全ての失敗を 1 種類のエラーにまとめ、EM の検査 (Y・lHash・PS/0x01 探索) を分岐なしのマスク演算で行う (Manger 攻撃対策)。
* PKCS#1 v1.5 暗号化を持たないので、Bleichenbacher 型の復号オラクルは構造上存在しない。
* 署名/復号で乱数源が渡されない API (`Signer::try_sign` など) でも、OS 乱数でブラインディングする (上流は無効のまま)。
* 秘密値は `Drop` で zeroize。

## 検証

`wsl -d Ubuntu` で実行 (`CARGO_TARGET_DIR` は WSL ホーム。`scripts/build.sh` 参照)。

| 内容 | 結果 |
|---|---|
| `core`: OpenSSL 生成の既知回答 (PKCS#1 v1.5 署名は決定的なので **バイト一致**、OAEP は OpenSSL 暗号文を復号)、改ざん・長さ違い・ラベル違い・n 以上の入力の拒否、鍵検証、鍵生成、フォールト注入 | 全て pass (`cargo test`) |
| `compat-0.10`: `SigningKey<D>` の署名が OpenSSL とバイト一致 (SHA-1/256/384/512 × 1024/2048)、OAEP、PKCS#8/PKCS#1/SPKI 往復 | 全て pass |
| `compat-0.9`: sqlx-mysql と同じ使い方 (PEM→`Oaep::new::<Sha1>()`→`encrypt`) | pass。**`openssl pkeyutl -decrypt` で復号できる** (`scripts/interop-oaep.sh`) |
| `ssh-key 0.7.0-rc.11` の **自身のテストスイート** (rsa feature) を `rsa` 差し替えで実行 | 全 pass (`scripts/sshkey-test.sh`) |
| SSH 署名 ⇔ `ssh-keygen -Y verify` / `-Y sign` (rsa-sha2-256・512、生成鍵、改ざん検知) | 双方向 OK (`scripts/interop.sh`) |
| `sqlx-mysql 0.8.6` を `compat-0.9` でビルド | OK (`scripts/sqlxmysql-check.sh`) |
| `open-web-server` の別 clone で `sftp` (russh 0.63) 付きゲートウェイをビルド | OK (`scripts/owsrv-check.sh`) |
| dudect 風の簡易タイミング計測 (OAEP 復号の正常/異常、RSADP の固定/ランダム入力) | \|t\| < 1 (n=1500/600)。下記の限界を参照 |

## 限界 (正直に)

* **第三者監査なし。** 暗号の落とし穴を意識して RFC 8017 を根拠に書いたが、監査・形式検証はしていない。
* **定数時間性は実測で一部しか見ていない。** 上の簡易 t 検定は WSL2 上・数千サンプルで有意差が出なかった、というだけで、
  定数時間性の証明ではない。**命令列の確認 (逆アセンブルで秘密依存分岐・可変時間命令がないか) は未実施。** 数値演算の定数時間性は
  `crypto-bigint` 0.7.10+ に依存しており、ここでは検証していない。`ct.rs` のバイト列ヘルパは `black_box` で最適化を牽制しているが、
  コンパイラが分岐化しないことの保証はない。
* Wycheproof のテストベクタは **未使用** (ネットワーク取得をしていないため)。既知回答は OpenSSL 3.5.5 の出力と RFC 8017 §9.2 の DigestInfo 接頭辞。
  `scripts/gen-fixtures.sh` で再生成できる。
* `core/tests/fixtures/` の `*.pem` は **使い捨てのテスト鍵**であり秘密ではない (シークレットスキャナに検出されうる)。
* 返す OAEP 平文の長さは API 上、呼び出し側から見える。
* Windows ネイティブでは未ビルド (WSL Ubuntu のみ)。`getrandom` 経由の OS 乱数に依存するので `no_std`/WASM 向けではない。
* russh 自身のテストは dev-dependency (ratatui 等) がオフラインに無く未実行。ssh-key のテストと SSH 相互運用で代替している。
* 鍵生成の `d` は `e⁻¹ mod φ(n)` (λ(n) ではない)。機能的には等価で OpenSSH/OpenSSL と相互運用できるが、OpenSSL の現行出力とは値が異なる。

## ライセンス / English

MIT OR Apache-2.0。下は英語版の要約です。

---

## English

A **drop-in replacement for the part of the `rsa` crate** that aon-co-jp projects reach through their dependencies,
written from RFC 8017 to avoid RUSTSEC-2023-0071 (Marvin Attack; no fixed `rsa` release exists). Private repository; not published.

> ⚠️ **Not audited by any third party.** This is home-grown cryptography. Read "Limitations" before relying on it.

* `core/` — hash/RNG-agnostic core: keys, RSADP (CRT + blinding + post-check), PKCS#1 v1.5 signatures, OAEP, key generation.
* `compat-0.10/` — crate named `rsa` 0.10.0-rc.18, for `ssh-key 0.7.0-rc.11` / `russh`: signing, OAEP, PKCS#1/#8/SPKI.
* `compat-0.9/` — crate named `rsa` 0.9.10, for `sqlx-mysql 0.8.x`: **public key + OAEP encryption only**.

Use via `[patch.crates-io]` (see the Japanese section for the exact lines). `crypto-bigint >= 0.7.10` is required.

Not implemented (compile error if used): PSS, PKCS#1 v1.5 *encryption* (deliberately omitted), multi-prime keys, serde, `hazmat`.

Defences: blinding on every private-key operation (OS RNG even when the caller passes none), CRT with a post-computation
check `m'^e ≡ c'` (no result is released on mismatch), verification by re-encoding EM and comparing (no EM parsing),
OAEP decoding with branch-free masks and a single error kind, zeroization on drop.

Verified: byte-identical PKCS#1 v1.5 signatures vs OpenSSL, decryption of OpenSSL OAEP ciphertexts and vice-versa,
`ssh-key`'s own test-suite against the replacement, `ssh-keygen -Y sign/verify` both ways, `sqlx-mysql 0.8.6` and an
`open-web-server` clone (russh 0.63, `sftp`) build against the patch.

Limitations: no audit; constant-time behaviour only sampled with a crude t-test (|t| < 1) — **no instruction-level review was done**
and the bignum arithmetic's constant-time property is delegated to `crypto-bigint` 0.7.10+; no Wycheproof vectors (not fetched);
fixtures contain throw-away test keys; Linux/WSL only.
