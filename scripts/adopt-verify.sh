#!/bin/bash
# adopt.sh 済みのクローンで build+test を実行し、passed/failed を集計する。
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
R=$1; shift
export CARGO_TARGET_DIR="$HOME/ac-target/$R"
cd ~/adopt/$R || exit 1
cargo test --no-fail-fast --color never "$@" > /tmp/verify-$R.log 2>&1
echo "exit=$?" >> /tmp/verify-$R.log
awk '/^test result:/ {p+=$4; f+=$6} END {print "passed="p" failed="f}' /tmp/verify-$R.log
grep -E "^error" /tmp/verify-$R.log | head -5
tail -1 /tmp/verify-$R.log
cargo tree -i rsa --target all -e all 2>&1 | grep -E "^rsa " | head -3
grep -A2 '^name = "rsa"' Cargo.lock | head -6
