#!/bin/bash
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR="$HOME/rsa-rs-target"
cargo --version; rustc --version; openssl version; ssh-keygen -V 2>&1 | head -1
ls ~/.cargo/registry/src/*/ | grep -E "^(rsa|crypto-bigint|sha2|rand_core|subtle|num-bigint)"
