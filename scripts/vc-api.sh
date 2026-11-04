#!/bin/bash
export PATH="$HOME/.cargo/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR=$HOME/vc-target
cd /mnt/f/version-control && timeout 110 cargo run -q --color never -- --dry-run --api-only 2>&1 | grep -E "timing|exceptions:"
