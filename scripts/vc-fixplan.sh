#!/bin/bash
export PATH="$HOME/.cargo/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR=$HOME/vc-target
cd /mnt/f/version-control && cp -n config.toml /tmp/vc-config.bak 2>/dev/null; timeout 100 cargo run -q --color never -- --dry-run --no-fetch --fix 2>&1 | sed -n "/--- fix plan/,\$p" | head -40
