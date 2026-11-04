# PORTING.md — 依存元への導入 / Adopting rsa-rs in a repository

## 日本語

### 1. 何が `rsa` を引いているか確認
```bash
cargo tree -i rsa            # 通常ビルド。空なら Cargo.lock にだけ載っている (ビルドされない)
cargo tree -i rsa -e all --target all
```
* `sqlx-mysql 0.8.x` → `rsa 0.9.x` (OAEP 暗号化のみ) → **`compat-0.9`**
* `russh 0.62/0.63`, `ssh-key 0.7.0-rc.x` → `rsa 0.10.0-rc.x` (署名/検証) → **`compat-0.10`**

### 2. `Cargo.toml` に追加 (小さな別コミットで)
```toml
[patch.crates-io]
rsa = { path = "../rsa-rs/compat-0.10" }
rsa-090 = { package = "rsa", path = "../rsa-rs/compat-0.9" }   # 0.9.x を引く場合のみ
```
CI では `rsa-rs` を兄弟ディレクトリに checkout する (open-web-server の `open-cpu` と同じ方式)。
`git = ` 指定にする場合は非公開リポジトリの認証が必要。

### 3. ロックの更新
```bash
cargo update -p crypto-bigint --precise 0.7.10   # 互換層の要求。ctutils も追従して上がる
cargo build && cargo test
```
`failed to select a version for crypto-bigint` が出たら、上の update を先に行う。

### 4. 受け入れ確認
* 通常ビルドに `rsa` が出る場合: `cargo tree -i rsa` が `(…/rsa-rs/compat-…)` を指すこと。
* 署名を使う場合: `ssh-keygen -Y verify` で相互運用を確認 (`scripts/interop.sh` 参照)。
* `cargo audit` で RUSTSEC-2023-0071 が消えること (patch 後は `rsa` が registry 由来ではなくなる)。
  ※ audit が path 依存を無視するだけで、安全性を意味しない。README の限界を理解した上で運用する。

### 5. 互換の差 (上流との違い)
* PSS、PKCS#1 v1.5 暗号化、multi-prime、serde、`hazmat` は無い。呼ぶとコンパイルエラー。
* 署名/復号は常にブラインディングする (rng を渡さない API でも OS 乱数を使う)。
* 3 素数以上の秘密鍵は `from_components` が `Error::InvalidPrime` を返す。
* `RsaPrivateKey::validate()` は構築時に検査済みのため常に `Ok`。
* `compat-0.9` は公開鍵と OAEP 暗号化のみ。

### 6. 新しい API が必要になったら
依存元のソースで実際の呼び出しを確認 → RFC 8017 の該当節を根拠に `core/` へ → 既知回答テスト → 互換層の薄いラッパ。

## English

1. Find who pulls `rsa`: `cargo tree -i rsa` (empty ⇒ lockfile-only). `sqlx-mysql` → `compat-0.9`; `russh`/`ssh-key` → `compat-0.10`.
2. Add `[patch.crates-io]` entries (see above) in a small separate commit; check out `rsa-rs` as a sibling directory in CI.
3. `cargo update -p crypto-bigint --precise 0.7.10`, then build and test.
4. Acceptance: `cargo tree -i rsa` points at the compat path; verify signatures with `ssh-keygen -Y verify`.
   Note that `cargo audit` silencing RUSTSEC-2023-0071 only means the registry crate is gone — read the README limitations.
5. Differences from upstream: no PSS / PKCS#1 v1.5 encryption / multi-prime / serde / hazmat; blinding is always on.
6. For new API: confirm the real call in the dependent's source → implement in `core/` from RFC 8017 → known-answer test → thin wrapper.
