#!/bin/bash
# RPoem: パッチ前の Cargo.toml/lock (HEAD~1) に一時的に戻して、同じ2パッケージのテスト結果を比較する。
export PATH="$HOME/.cargo/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR="$HOME/ac-target/RPoem-base"
cd ~/adopt/RPoem && git checkout -q HEAD~1 -- Cargo.toml Cargo.lock
cargo test --no-fail-fast --color never -p open-runo-appserver -p open-runo-gateway --lib > /tmp/base-RPoem.log 2>&1
awk '/^test result:/ {p+=$4; f+=$6} END {print "baseline passed="p" failed="f}' /tmp/base-RPoem.log
grep -E "^test .*FAILED" /tmp/base-RPoem.log | sort > /tmp/base-RPoem.fail
git checkout -q HEAD -- Cargo.toml Cargo.lock
cargo test --no-fail-fast --color never -p open-runo-appserver -p open-runo-gateway --lib > /tmp/patched-RPoem.log 2>&1
awk '/^test result:/ {p+=$4; f+=$6} END {print "patched  passed="p" failed="f}' /tmp/patched-RPoem.log
grep -E "^test .*FAILED" /tmp/patched-RPoem.log | sort > /tmp/patched-RPoem.fail
diff /tmp/base-RPoem.fail /tmp/patched-RPoem.fail && echo "failed sets identical"
