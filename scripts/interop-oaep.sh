#!/bin/bash
# 相互運用: compat-0.9 (sqlx-mysql と同じ使い方) が作った OAEP 暗号文を openssl で復号する。
set -euo pipefail
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR="$HOME/rsa-rs-target"
D=$HOME/interop-oaep; rm -rf "$D"; mkdir -p "$D"
FX=/mnt/f/rsa-rs/core/tests/fixtures
(cd /mnt/f/rsa-rs/compat-0.9 && RSA_RS_OUT=$D cargo test --offline --test mysql_oaep --color never 2>&1 | grep -E "^test |test result")
cd "$D"
for spec in "sha1 mysql_oaep_sha1" "sha256 mysql_oaep_sha256"; do
  set -- $spec
  openssl pkeyutl -decrypt -inkey $FX/key2048.pem -in $2.bin -out $2.dec \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:$1 -pkeyopt rsa_mgf1_md:$1
done
cmp mysql_oaep_sha1.dec mysql_oaep_sha1.pt && echo "openssl decrypted compat-0.9 OAEP(SHA-1)  == plaintext  OK"
printf 'correct horse\0' | od -An -c | head -1 >/dev/null
openssl pkeyutl -decrypt -inkey $FX/key2048.pem -in mysql_oaep_sha256_lbl.bin -out lbl.dec \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 \
  -pkeyopt rsa_oaep_label:$(printf 'lbl' | od -An -tx1 | tr -d ' \n') && cmp lbl.dec mysql_oaep_sha1.pt && echo "openssl decrypted OAEP(SHA-256, label) OK"
# ラベル違いでは openssl 側も失敗するはず
if openssl pkeyutl -decrypt -inkey $FX/key2048.pem -in mysql_oaep_sha256_lbl.bin -out /dev/null \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 2>/dev/null; then echo "BUG"; exit 1; else echo "wrong label rejected by openssl OK"; fi
echo "=== OAEP interop OK ==="
