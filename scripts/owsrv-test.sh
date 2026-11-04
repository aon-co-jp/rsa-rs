#!/bin/bash
# owsrv-check.sh 済みの別 clone で、sftp(russh) 付きゲートウェイの lib テストを走らせる。
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR="$HOME/rsa-rs-target-ows"
cd $HOME/work/open-web-server
cargo test --offline -p open-web-server-gateway --features sftp --lib --color never 2>&1 | grep -E "^(test result|error)|FAILED|panicked|sftp" | head -30
