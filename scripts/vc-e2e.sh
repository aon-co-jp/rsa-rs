export PATH="$HOME/.cargo/bin:/usr/bin:/bin"
export CARGO_TARGET_DIR=$HOME/vc-target
R=$HOME/vc-e2e; rm -rf $R; mkdir -p $R/root/broken $R/root/okrepo $R/site
echo "gitdir: /nonexistent/.git/worktrees/x" > $R/root/broken/.git
printf '[package]\nname="b"\nversion="0.1.0"\nedition="2021"\n' > $R/root/broken/Cargo.toml
cd $R/root/okrepo && git init -q && printf '[package]\nname="o"\nversion="0.1.0"\nedition="2021"\n' > Cargo.toml && git add . && git -c user.email=a@b -c user.name=t commit -qm i
cat > $R/config.toml <<C
root = "$R/root"
site_dir = "$R/site"
[advisory]
enabled = false
[apiex]
enabled = false
C
cd /mnt/f/version-control && cargo run -q --color never -- --config $R/config.toml --dry-run --no-fetch --no-api 2>&1 | tail -15
grep -o 'broken-git[^}]*' $R/site/status.json | head -2
