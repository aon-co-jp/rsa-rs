# CLAUDE.md — rsa-rs

`rsa` クレート (RUSTSEC-2023-0071) の互換置き換え。README.md が一次資料。ここは作業者向けの注意だけ。
This is a private home-grown replacement for part of the `rsa` crate. See README.md; below are working rules.

## 原則
* **根拠は RFC 8017 と既知回答テスト。** 推測で埋めない。分からない挙動は上流のドキュメント/テスト/ソースで確認する。
* 実装範囲は「依存元が実際に呼ぶ API」だけ。足すときは依存元ソース (`~/.cargo/registry/src/*/`) で呼び出しを確認してから。
* 暗号の変更には必ず既知回答 (OpenSSL 生成) か相互運用 (`ssh-keygen`/`openssl`) のテストを付ける。
* 秘密値 (鍵・トークン) をログ・コミットに出さない。`core/tests/fixtures/*.pem` は使い捨てテスト鍵のみ。
* 公開 (public 化・crates.io 公開) はユーザー判断。勝手にしない。
* 「定数時間」「安全」と書くのは実測/確認できた範囲だけ。できていないことは「未検証」と書く (README の限界を更新する)。

## ビルド/テスト (WSL Ubuntu)
`cargo` は Windows 側 PATH に無い。`scripts/*.sh` を WSL で実行する (`CARGO_TARGET_DIR` は WSL ホーム):

```bash
MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash /mnt/f/rsa-rs/scripts/build.sh core test --offline
MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash /mnt/f/rsa-rs/scripts/build.sh compat-0.10 test --offline
MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash /mnt/f/rsa-rs/scripts/build.sh compat-0.9 test --offline
```

互換確認 (作業コピーで実施。依存元リポジトリの作業ツリーは触らない): `sshkey-test.sh`、`sqlxmysql-check.sh`、
`owsrv-check.sh`、`interop.sh` (ssh-keygen)、`interop-oaep.sh` (openssl)。フィクスチャ再生成は `gen-fixtures.sh`。

## 構造の注意
* 互換層 2 つは crate 名が `rsa` で衝突するため、ワークスペースに入れない (`exclude`)。それぞれ `[workspace]` を持つ。
* `rsa-rs-core` は `digest`/`rand_core` の版に依存しない (`HashFn`/`FillBytes` トレイト)。版差は互換層で吸収する。
* `crypto-bigint` は `>=0.7.10`。下げない。
* dependents 側の `[patch]` 追加は別の小さなコミットで。`cargo fmt --all` は禁止 (`cargo fmt -p` を使う)。
