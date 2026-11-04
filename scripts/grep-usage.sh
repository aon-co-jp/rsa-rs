#!/bin/bash
R=$(ls -d ~/.cargo/registry/src/*/ | head -1)
cd $R
echo "== sqlx-mysql 0.8.6"; grep -rn "rsa" sqlx-mysql-0.8.6/src sqlx-mysql-0.8.6/Cargo.toml | grep -v "^.*://"
for d in ssh-key-0.7.0-rc.11 russh-0.62.4 russh-0.63.3; do echo "== $d"; grep -rnE "rsa\b|Rsa|Pkcs1v15|Pss|Oaep" $d/src $d/Cargo.toml | grep -v "^\S*:\s*//" ; done
