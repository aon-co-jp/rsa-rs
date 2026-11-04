#!/bin/bash
# テスト用の既知回答 (KAT) を OpenSSL で作る。鍵は使い捨てのテスト鍵 (秘密ではない)。
# 再生成: MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash /mnt/f/rsa-rs/scripts/gen-fixtures.sh
set -euo pipefail
out=/mnt/f/rsa-rs/core/tests/fixtures
mkdir -p "$out"
cd "$out"
openssl version > openssl-version.txt

for bits in 1024 2048; do
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$bits -out key$bits.pem 2>/dev/null
  openssl pkey -in key$bits.pem -pubout -out pub$bits.pem
  # 構成要素を 16 進で取り出す (modulus/privateExponent/prime1/prime2/publicExponent)
  openssl rsa -in key$bits.pem -noout -text 2>/dev/null | awk '
    /^modulus:/ {k="n"; next}
    /^publicExponent:/ {split($0,a," "); printf "e=%x\n", a[2]; k=""; next}
    /^privateExponent:/ {k="d"; next}
    /^prime1:/ {k="p"; next}
    /^prime2:/ {k="q"; next}
    /^exponent1:/ {k=""}
    /^[ \t]+[0-9a-f:]+$/ { if (k!="") { gsub(/[ \t:]/,""); h[k]=h[k] $0 } }
    END { for (x in h) printf "%s=%s\n", x, h[x] }' | sort > key$bits.txt
done

printf 'rsa-rs known-answer test message \xe3\x83\x86\xe3\x82\xb9\xe3\x83\x88' > msg.bin
for bits in 1024 2048; do
  for h in sha1 sha256 sha384 sha512; do
    openssl dgst -$h -sign key$bits.pem -out sig${bits}_$h.bin msg.bin
  done
done

printf 'hunter2-style test secret' > oaep_pt.bin
for h in sha1 sha256; do
  openssl pkeyutl -encrypt -pubin -inkey pub2048.pem -in oaep_pt.bin -out oaep2048_$h.bin \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:$h -pkeyopt rsa_mgf1_md:$h
done
ls -la
