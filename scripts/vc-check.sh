#!/bin/bash
export PATH="$HOME/.cargo/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR=$HOME/vc-target
cd /mnt/f/version-control && cargo check --color never 2>&1 | grep -v "^\s*\(Compiling\|Checking\|Downloaded\|Downloading\)" | head -40
