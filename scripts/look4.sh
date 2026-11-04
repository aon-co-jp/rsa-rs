#!/bin/bash
R=$(ls -d ~/.cargo/registry/src/*/ | head -1); cd $R
echo "### rsa rc18 rsa.rs (algorithms)"; sed -n 1,140p rsa-0.10.0-rc.18/src/algorithms/rsa.rs
echo "### crypto-primes pub"; grep -n "pub fn\|pub trait" crypto-primes-0.7.2/src/lib.rs crypto-primes-0.7.2/src/hazmat.rs crypto-primes-0.7.2/src/generator.rs 2>/dev/null | head -30; ls crypto-primes-0.7.2/src
echo "### generate.rs"; sed -n 1,120p rsa-0.10.0-rc.18/src/algorithms/generate.rs
