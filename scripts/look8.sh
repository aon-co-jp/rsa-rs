#!/bin/bash
R=$(ls -d ~/.cargo/registry/src/*/ | head -1); cd $R/crypto-bigint-0.7.10/src
sed -n 25,50p modular/boxed_monty_form.rs
ls modular modular/boxed_monty_form; grep -n "pub fn" modular/boxed_monty_form/pow.rs modular/boxed_monty_form/inv.rs modular/boxed_monty_form/mul.rs | head; grep -n "pub fn new" -B3 -A12 modular/boxed_monty_form.rs | sed -n 1,5p
grep -rn "pub fn random\|fn random_bits\|trait RandomBits\|trait RandomMod" . | head
