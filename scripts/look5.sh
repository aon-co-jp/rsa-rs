#!/bin/bash
R=$(ls -d ~/.cargo/registry/src/*/ | head -1); cd $R
grep -n "pub fn\|pub use" crypto-primes-0.7.2/src/lib.rs crypto-primes-0.7.2/src/presets.rs | head -30
grep -n -A25 "fn generate_prime_with_rng" rsa-0.10.0-rc.18/src/algorithms/generate.rs | head -50
grep -n "^crypto-bigint\|^\[dependencies" -A6 crypto-primes-0.7.2/Cargo.toml | grep -A6 "crypto-bigint\|rand_core"| head -30
ls crypto-bigint-0.7.10/src/uint/boxed; grep -n "pub fn \(inv_mod\|gcd\|random\|from_be_slice\|to_be_bytes\|bits\|shl\|shr\|resize\|rem\|widen\|bit\)" -r crypto-bigint-0.7.10/src/uint/boxed/*.rs | head -50
