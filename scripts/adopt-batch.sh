#!/bin/bash
# 全対象を順に adopt → siblings → verify。結果は /tmp/batch.out に集約。
S=/mnt/f/rsa-rs/scripts
for r in "$@"; do
  echo "######## $r"
  [ -d ~/adopt/$r ] || true
  bash $S/adopt.sh $r 2>&1 | tail -6
  bash $S/adopt-siblings.sh $r 2>&1 | tail -3
  bash $S/adopt-verify.sh $r 2>&1 | tail -12
done
echo "######## BATCH DONE"
