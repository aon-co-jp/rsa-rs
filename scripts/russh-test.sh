#!/bin/bash
# registry の russh を作業コピーに展開し、rsa を compat-0.10 に差し替えて自身のテストを走らせる。
# (criterion は offline に無く bench 専用なので、依存ブロックと _bench feature を外す。)
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR="$HOME/rsa-rs-target-russh"
V=${1:-0.63.3}
W=$HOME/work-russh
rm -rf "$W"; mkdir -p "$W"
R=$(ls -d ~/.cargo/registry/src/*/ | head -1)
cp -r "$R/russh-$V/." "$W/"
cd "$W"
rm -f Cargo.toml.orig Cargo.lock
awk '
  /^\[\[bench\]\]/ { skip=1; next }
  /^\[dependencies\.criterion\]/ { skip=1; next }
  /^\[dev-dependencies\.criterion\]/ { skip=1; next }
  skip && /^\[/ { skip=0 }
  skip { next }
  /^_bench = / { next }
  { print }' Cargo.toml > Cargo.toml.new && mv Cargo.toml.new Cargo.toml
printf '\n[patch.crates-io]\nrsa = { path = "/mnt/f/rsa-rs/compat-0.10" }\n' >> Cargo.toml
cargo test --offline --features rsa --lib --color never 2>&1 | grep -E "^(test result|error)|FAILED|failed|panicked|could not|no matching" | head -40
