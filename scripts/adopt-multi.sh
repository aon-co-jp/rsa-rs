#!/bin/bash
# 引数: repo[:subdir] ... 
S=/mnt/f/rsa-rs/scripts
for spec in "$@"; do
  r=${spec%%:*}; sub=""; [[ "$spec" == *:* ]] && sub=${spec#*:}
  export SUB=${sub:-.}
  echo "######## $spec"
  bash $S/adopt.sh $r 2>&1 | tail -6
  bash $S/adopt-siblings.sh $r 2>&1 | tail -3
  bash $S/adopt-verify.sh $r 2>&1 | tail -10
done
echo "######## MULTI DONE"
