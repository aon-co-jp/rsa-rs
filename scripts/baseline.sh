#!/bin/bash
# パッチ前 (GitHub main そのまま) の別クローンで cargo test を走らせ、比較用に集計する。
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
R=$1; shift
export CARGO_TARGET_DIR="$HOME/ac-target/$R-base"
mkdir -p ~/adopt-base && cd ~/adopt-base
[ -d $R ] || git clone -q https://github.com/aon-co-jp/$R.git
cd $R && git checkout -q -- .
cargo test --no-fail-fast --color never "$@" > /tmp/base-$R.log 2>&1
awk '/^test result:/ {p+=$4; f+=$6} END {print "baseline passed="p" failed="f}' /tmp/base-$R.log
grep -E "^test .* FAILED" /tmp/base-$R.log | head
