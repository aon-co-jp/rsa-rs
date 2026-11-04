#!/bin/bash
# 手元 (WSL) 用の毎晩/毎朝ジョブ: 全試験 → 結果記録 → 状況ファイル再生成 → 変化があれば commit/push。
# 重いビルド/試験を含むので VPS では走らせない (VPS は deploy/ の軽量 timer で update-status.sh のみ)。
# 使い方: bash scripts/nightly.sh [--no-push]
set -u
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/rsa-rs-target}"
cd "$(dirname "$0")/.."
ROOT=$PWD
RES=PASS
for d in core compat-0.10 compat-0.9; do
  (cd "$ROOT/$d" && cargo test --offline --color never >"/tmp/rsa-rs-$d.log" 2>&1) || { RES="FAIL($d)"; }
done
# 相互運用 (ssh-keygen / openssl)
bash scripts/sshkey-test.sh >/tmp/rsa-rs-sshkey.log 2>&1 && bash scripts/interop.sh >/tmp/rsa-rs-interop.log 2>&1 || RES="FAIL(interop-ssh)"
bash scripts/interop-oaep.sh >/tmp/rsa-rs-oaep.log 2>&1 || RES="FAIL(interop-oaep)"
bash scripts/sqlxmysql-check.sh >/tmp/rsa-rs-sqlx.log 2>&1 && grep -q Finished /tmp/rsa-rs-sqlx.log || RES="FAIL(sqlx-mysql)"
printf '%s\n%s\n' "$RES" "$(date -u +%Y-%m-%dT%H:%MZ)" > tests-result.txt
bash scripts/update-status.sh; rc=$?
if [ "$rc" = 10 ] || ! git diff --quiet -- STATUS.md status.json tests-result.txt 2>/dev/null; then
  git add STATUS.md status.json tests-result.txt
  git commit -q -m "chore(status): nightly status update ($RES)" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>" || true
  [ "${1:-}" = "--no-push" ] || git push origin main
fi
echo "nightly: $RES"
[ "$RES" = PASS ]
