#!/bin/bash
# registry の sqlx-mysql 0.8.6 を作業コピーに展開し、rsa を compat-0.9 に差し替えてビルド・テストする。
# 通常の依存グラフに sqlx-mysql が載らないリポジトリが多いため、単体で確認する。
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR="$HOME/rsa-rs-target-sqlx"
W=$HOME/work-sqlx-mysql
rm -rf "$W"; mkdir -p "$W"
R=$(ls -d ~/.cargo/registry/src/*/ | head -1)
cp -r "$R/sqlx-mysql-0.8.6/." "$W/"
cd "$W"
rm -f Cargo.toml.orig Cargo.lock
printf '\n[workspace]\n\n[patch.crates-io]\nrsa = { path = "/mnt/f/rsa-rs/compat-0.9" }\n' >> Cargo.toml
cargo tree --offline -i rsa 2>&1 | head -5
cargo build --offline --color never 2>&1 | grep -E "^(error|warning: unused)|Finished|could not|no matching|failed" | head -20
