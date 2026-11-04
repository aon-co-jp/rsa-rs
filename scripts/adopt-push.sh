#!/bin/bash
# 検証済みクローンの [patch] 変更だけを小さな別コミットにし、format-patch で書き出す (push は Windows 側で行う)。
. /mnt/f/rsa-rs/scripts/git-id.sh
OUT=/mnt/f/rsa-rs/.adopt-patches; mkdir -p $OUT
for r in "$@"; do
  cd ~/adopt/$r || continue; ROOT=$PWD; cd ${SUB:-.} || continue
  git add Cargo.toml; git ls-files --error-unmatch Cargo.lock >/dev/null 2>&1 && git add Cargo.lock
  git diff --cached --quiet && { echo "$r: no changes"; continue; }
  cd $ROOT
  git commit -q -m "deps: rsa を rsa-rs に置き換え(RUSTSEC-2023-0071)" -m "rsa クレートの Marvin Attack (修正版なし) を避けるため、[patch.crates-io] で aon-co-jp/rsa-rs v0.1.0 の互換実装に差し替える。crypto-bigint は 0.7.10 以上。" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
  rm -f $OUT/$r.patch; git format-patch -1 --stdout > $OUT/$r.patch
  echo "$r: $(git diff --stat HEAD~1 | tail -1)"
done
