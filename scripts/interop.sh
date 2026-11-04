#!/bin/bash
# 相互運用試験 (WSL): ssh-key(compat-0.10) 署名 ⇔ ssh-keygen、OAEP(compat-0.9) 暗号文 ⇔ openssl。
set -euo pipefail
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR="$HOME/rsa-rs-target-ssh"
D=$HOME/interop-work; rm -rf "$D"; mkdir -p "$D"; cd "$D"
ssh-keygen -q -t rsa -b 3072 -N '' -f id_rsa -C interop
printf 'interop message \xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\n' > msg.txt
# ssh-keygen 側の署名 (rsa-sha2-256 / rsa-sha2-512)
for h in sha256 sha512; do
  ssh-keygen -Y sign -f id_rsa -n rsa-rs-interop -O hashalg=$h msg.txt >/dev/null 2>&1
  mv msg.txt.sig ossh.$h.sig
done
# ssh-key テストの実行 (work-ssh-key は sshkey-test.sh が作成済み)
cp /mnt/f/rsa-rs/interop/ssh_sign.rs $HOME/work-ssh-key/tests/interop_sign.rs
grep -q interop_sign $HOME/work-ssh-key/Cargo.toml || printf "
[[test]]
name = \"interop_sign\"
path = \"tests/interop_sign.rs\"
" >> $HOME/work-ssh-key/Cargo.toml
(cd $HOME/work-ssh-key && INTEROP_DIR=$D cargo test --offline --features "rsa,sha1,ed25519,p256,rand_core,std,getrandom,crypto" --test interop_sign --color never 2>&1 | grep -E "^test |test result|error|panicked")
# ssh-keygen で検証: 我々の署名 (id_rsa 鍵 sha256/sha512, 生成鍵 sha512)
echo "interop $(cat id_rsa.pub)" > allowed
for h in sha256 sha512; do
  ssh-keygen -Y verify -f allowed -I interop -n rsa-rs-interop -s msg.$h.sig < msg.txt
done
echo "interop $(cat gen_rsa.pub)" > allowed_gen
ssh-keygen -Y verify -f allowed_gen -I interop -n rsa-rs-interop -s msg.gen.sig < msg.txt
# 生成鍵 (OpenSSH 形式) を ssh-keygen が読める / 公開鍵が一致する
chmod 600 gen_rsa
test "$(ssh-keygen -y -f gen_rsa)" = "$(cut -d" " -f1,2 gen_rsa.pub)" && echo "gen_rsa: ssh-keygen -y matches public key"
# 改ざん検知
if printf 'tampered' | ssh-keygen -Y verify -f allowed -I interop -n rsa-rs-interop -s msg.sha256.sig >/dev/null 2>&1; then echo "BUG: tampered accepted"; exit 1; else echo "tampered rejected OK"; fi
echo "=== SSH interop OK ==="
