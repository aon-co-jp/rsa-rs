#!/bin/bash
R=$(ls -d ~/.cargo/registry/src/*/ | head -1); cd $R/rand_core-0.10.1/src
grep -n "pub trait\|fn \|impl<" lib.rs | head -50
