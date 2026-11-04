#!/bin/bash
# registry の ssh-key 0.7.0-rc.11 を作業コピーに展開し、rsa を compat-0.10 に差し替えてテストする。
# (dsa は registry に無いため feature ごと外す。)
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR="$HOME/rsa-rs-target-ssh"
W=$HOME/work-ssh-key
rm -rf "$W"; mkdir -p "$W"
R=$(ls -d ~/.cargo/registry/src/*/ | head -1)
cp -r "$R/ssh-key-0.7.0-rc.11/." "$W/"
cd "$W"
rm -f Cargo.toml.orig Cargo.lock
# [dependencies.dsa] ブロックと dsa feature を削除
awk '
  /^\[dependencies\.dsa\]/ {skip=1; next}
  skip && /^\[/ {skip=0}
  skip {next}
  /^dsa = \[/ {skipf=1; next}
  skipf && /^\]/ {skipf=0; next}
  skipf {next}
  {print}' Cargo.toml > Cargo.toml.new && mv Cargo.toml.new Cargo.toml
sed -i '/^    "dsa",$/d' Cargo.toml
printf '\n[patch.crates-io]\nrsa = { path = "/mnt/f/rsa-rs/compat-0.10" }\n' >> Cargo.toml
FEATS="${FEATS:-rsa,sha1,ed25519,p256,rand_core,std,getrandom,crypto}"
cargo tree -i rsa --offline --features "$FEATS" 2>&1 | head -8
cargo test --offline --features "$FEATS" 2>&1 | grep -E "^(test result|error)|FAILED|failed|panicked|could not|^warning: unused" | head -60
