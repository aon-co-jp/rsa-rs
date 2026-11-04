#!/bin/bash
# 固定(deps.lock)を最新に更新し、ビルド確認して deps.lock(+Cargo.lock)だけコミットする。
# 使い方: pin-update.sh <repo> <clone元(URLか/mnt/...)> <名前...>
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
. /mnt/f/rsa-rs/scripts/git-id.sh
R=$1; SRC=$2; shift 2
export CARGO_TARGET_DIR="$HOME/ac-target/$R"
mkdir -p ~/pin && cd ~/pin && rm -rf $R
GIT_TERMINAL_PROMPT=0 git clone -q "$SRC" $R || exit 2
cd $R
bash scripts/update-deps.sh "$@" 2>&1 | tail -5
git diff --stat | tail -3
cargo check --color never 2>&1 | grep -E "^error|Finished" | head -5
git status --short | head
