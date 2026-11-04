#!/bin/bash
# 使い方: adopt.sh <repo>  — GitHub main を ~/adopt に新規 clone し、rsa-rs の [patch] を入れ、ロックを更新する。
# (~/ac は他リポジトリへの symlink 群なので使わない。)
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
R=$1
export CARGO_TARGET_DIR="$HOME/ac-target/$R"
mkdir -p ~/adopt && cd ~/adopt
[ -d $R ] || git clone -q https://github.com/aon-co-jp/$R.git
cd $R && git checkout -q -- . && git log --oneline | head -1
git config user.name "$(git -C /mnt/f/rsa-rs config user.name)"; git config user.email "$(git -C /mnt/f/rsa-rs config user.email)"
V10=$(grep -c 'version = "0.10.0-rc' <(grep -A1 '^name = "rsa"$' Cargo.lock) )
V09=$(grep -c 'version = "0.9' <(grep -A1 '^name = "rsa"$' Cargo.lock) )
[ -n "$FORCE10" ] && V10=1
echo "lock: rsa0.10=$V10 rsa0.9=$V09"
{
  printf '\n# RUSTSEC-2023-0071 (rsa Marvin Attack, 修正版なし) 回避: aon-co-jp/rsa-rs の互換実装へ差し替え。\n[patch.crates-io]\n'
  [ "$V10" != 0 ] && echo 'rsa = { git = "https://github.com/aon-co-jp/rsa-rs", tag = "v0.1.0", version = "=0.10.0-rc.18" }'
  [ "$V09" != 0 ] && echo 'rsa-090 = { package = "rsa", git = "https://github.com/aon-co-jp/rsa-rs", tag = "v0.1.0", version = "=0.9.10" }'
} >> Cargo.toml
cargo update -p crypto-bigint --precise 0.7.10 2>&1 | grep -E "Updating|error" | head
echo "--- after:"; cargo tree -i rsa --target all -e all 2>&1 | grep -E "^rsa |error" | head
