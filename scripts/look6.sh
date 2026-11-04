#!/bin/bash
R=$(ls -d ~/.cargo/registry/src/*/ | head -1); cd $R/rsa-0.10.0-rc.18/src
sed -n 214,260p key.rs; sed -n 700,800p key.rs
sed -n 60,75p key.rs; sed -n 460,490p key.rs
