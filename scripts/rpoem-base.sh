#!/bin/bash
# RPoem: パッチを一時的に外して (git stash) 失敗テストが同じか確認する。
export PATH="$HOME/.cargo/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR="$HOME/ac-target/RPoem-base"
. /mnt/f/rsa-rs/scripts/git-id.sh
cd ~/adopt/RPoem && git stash -q && echo stashed
cargo test --no-fail-fast --color never -p open-runo-appserver -p open-runo-gateway --lib > /tmp/base-RPoem.log 2>&1
awk '/^test result:/ {p+=$4; f+=$6} END {print "baseline passed="p" failed="f}' /tmp/base-RPoem.log
grep -E "^test .*FAILED" /tmp/base-RPoem.log | wc -l
git stash pop -q && git status --short
