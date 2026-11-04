#!/bin/bash
export PATH="$HOME/.cargo/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR=$HOME/vc-target
cd /mnt/f/version-control && cargo test --color never 2>&1 | grep -E "^test |test result|error|warning: unused" | head -30
