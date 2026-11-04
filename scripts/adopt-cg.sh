#!/bin/bash
export PATH="$HOME/.cargo/bin:/usr/bin:/bin"
bash /mnt/f/rsa-rs/scripts/adopt.sh open-cg-cad 2>&1 | tail -8
export CARGO_TARGET_DIR=$HOME/ac-target/open-cg-cad
cd ~/adopt/open-cg-cad && cargo check --workspace --color never 2>&1 | grep -E "^error|Finished" | head -8
cargo tree -i rsa --target all -e all 2>&1 | grep -E "^rsa |error"
echo CGDONE
