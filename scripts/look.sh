#!/bin/bash
R=$(ls -d ~/.cargo/registry/src/*/ | head -1); cd $R
echo "### ssh private/rsa.rs"; sed -n 1,20p ssh-key-0.7.0-rc.11/src/private/rsa.rs; sed -n 245,340p ssh-key-0.7.0-rc.11/src/private/rsa.rs
echo "### ssh public/rsa.rs"; sed -n 1,30p ssh-key-0.7.0-rc.11/src/public/rsa.rs; sed -n 100,170p ssh-key-0.7.0-rc.11/src/public/rsa.rs
echo "### ssh-key Cargo rsa dep"; grep -n -A8 "dependencies.rsa\]" ssh-key-0.7.0-rc.11/Cargo.toml; grep -n -B2 -A12 '^rsa = \[' ssh-key-0.7.0-rc.11/Cargo.toml
echo "### rsa rc18 tree"; find rsa-0.10.0-rc.18 -name "*.rs" -path "*src*" | xargs wc -l; sed -n 1,200p rsa-0.10.0-rc.18/Cargo.toml | grep -vE "^#"
echo "### ssh rsa signature use"; sed -n 700,765p ssh-key-0.7.0-rc.11/src/signature.rs
echo "### russh uses"; grep -rn -B1 -A6 "rsa::\|use rsa" russh-0.63.3/src/helpers.rs russh-0.63.3/src/keys/format/pkcs8.rs | head -80
