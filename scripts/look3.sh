#!/bin/bash
R=$(ls -d ~/.cargo/registry/src/*/ | head -1); cd $R/rsa-0.10.0-rc.18/src
echo "### encoding.rs"; grep -vE "^\s*///" encoding.rs | sed -n 1,240p
echo "### pkcs1v15.rs head"; grep -vE "^\s*///" pkcs1v15.rs | sed -n 1,140p
echo "### signing_key"; grep -vE "^\s*///" pkcs1v15/signing_key.rs | sed -n 1,200p
echo "### verifying_key"; grep -vE "^\s*///" pkcs1v15/verifying_key.rs | sed -n 1,130p
echo "### signature"; grep -vE "^\s*///" pkcs1v15/signature.rs | sed -n 1,100p
