#!/bin/bash
R=$(ls -d ~/.cargo/registry/src/*/ | head -1); cd $R
ls | grep -E "^(getrandom|sha2|sha1|hex|const-oid|subtle|signature|zeroize|base64|rand_chacha|hmac)-" 
grep -n "pub use\|pub mod" crypto-bigint-0.7.10/src/lib.rs | head -40
grep -n "pub fn\|pub const fn" crypto-bigint-0.7.10/src/modular/boxed_monty_form.rs | head -30
