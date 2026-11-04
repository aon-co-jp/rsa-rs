#!/bin/bash
# パス依存の兄弟リポジトリを GitHub から ~/adopt に clone する (metadata が通るまで繰り返す)。
export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
cd ~/adopt/"$1"/${SUB:-.} || exit 1
for i in 1 2 3 4 5 6 7 8 9 10; do
  out=$(cargo metadata --format-version 1 --no-deps 2>&1 >/dev/null)
  # "failed to read `/home/.../adopt/NAME/Cargo.toml`" の NAME
  miss=$(printf '%s\n' "$out" | sed -n 's#.*failed to read `[^`]*/adopt/\([^/]*\)/[^`]*Cargo.toml`.*#\1#p' | head -1)
  if [ -z "$miss" ]; then printf '%s\n' "$out" | tail -3; echo "siblings done (iter $i)"; break; fi
  echo "clone sibling $miss"
  GIT_TERMINAL_PROMPT=0 timeout 60 git clone -q "https://github.com/aon-co-jp/$miss.git" "$HOME/adopt/$miss" || { rm -rf "$HOME/adopt/$miss"; echo "(GitHub 不可 → ローカルの /mnt/f/$miss から clone)"; git clone -q "/mnt/f/$miss" "$HOME/adopt/$miss" || break; }
done
