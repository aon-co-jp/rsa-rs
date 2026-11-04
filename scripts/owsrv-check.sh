#!/bin/bash
# open-web-server を別 clone (作業ツリーには触れない) して rsa を差し替え、sftp(russh) 付きでビルド確認する。
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR="$HOME/rsa-rs-target-ows"
W=$HOME/work/open-web-server
mkdir -p $HOME/work
[ -d "$W" ] || git clone -q /mnt/f/open-web-server "$W"
for s in RS-SmartTCP open-raid-z open-cpu; do [ -d $HOME/work/$s ] || git clone -q /mnt/f/$s $HOME/work/$s; done
cd "$W"
git checkout -q -- Cargo.toml Cargo.lock
git log --oneline | head -1
# 1) パッチ無しで crypto-bigint を 0.7.10 へ (rsa の定数時間性修正の前提)
cargo update -p crypto-bigint --precise 0.7.10 2>&1 | tail -4
# 2) パッチ追加
printf '\n[patch.crates-io]\nrsa = { path = "/mnt/f/rsa-rs/compat-0.10" }\nrsa-090 = { package = "rsa", path = "/mnt/f/rsa-rs/compat-0.9" }\n' >> Cargo.toml
cargo tree --offline -p open-web-server-gateway --features sftp -i rsa 2>&1 | head -12
timeout 100 cargo check --offline -p open-web-server-gateway --features sftp --color never 2>&1 | grep -v "^\s*Compiling\|Checking" | tail -25
