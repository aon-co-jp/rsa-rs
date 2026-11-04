#!/bin/bash
# 使い方: build.sh <相対ディレクトリ> <cargo引数...>   例: build.sh core test
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR="$HOME/rsa-rs-target"
cd /mnt/f/rsa-rs/"$1" || exit 1
shift
exec cargo "$@"
