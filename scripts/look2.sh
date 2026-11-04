#!/bin/bash
R=$(ls -d ~/.cargo/registry/src/*/ | head -1); cd $R/rsa-0.10.0-rc.18/src
echo "### lib.rs"; grep -vE "^\s*//[/!]" lib.rs | sed -n 1,200p
echo "### traits"; cat traits.rs traits/keys.rs | grep -vE "^\s*///"
echo "### errors"; grep -vE "^\s*///" errors.rs | head -90
echo "### key.rs pub"; grep -nE "^\s*(pub |impl|#\[cfg)" key.rs | head -150
