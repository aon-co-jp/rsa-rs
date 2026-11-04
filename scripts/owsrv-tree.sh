#!/bin/bash
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR="$HOME/rsa-rs-target-ows"
cd $HOME/work/open-web-server
cargo tree --offline -p open-web-server-gateway --features sftp -i rsa@0.10.0-rc.18 2>&1 | head -12
grep -c "sftp\|russh" crates/open-web-server-gateway/src/*.rs | grep -v ":0" | head
timeout 100 cargo test --offline -p open-web-server-gateway --features sftp --lib --color never 2>&1 | grep -E "^(test result|error)|FAILED|panicked" | head
