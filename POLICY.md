# POLICY.md — rsa-rs の方針 / Policy

[日本語](#日本語) | [English](#english)

---

## 日本語

このファイルは `rsa-rs` の**約束事**です。作りかた・使いかたは [README.md](README.md)、導入手順は [PORTING.md](PORTING.md)、作業者向けの注意は [CLAUDE.md](CLAUDE.md) にあります。

### 1. 目的と範囲
* `rsa` クレートの RUSTSEC-2023-0071(Marvin Attack)を避けるため、**依存元が実際に呼ぶ範囲だけ**を RFC 8017 に基づいて自前で実装する。
* 範囲外の API は**あえてコンパイルエラー**にする(黙って別の挙動になるより安全)。範囲を広げるときは、依存元のソースで呼び出しを確認してから。
* PKCS#1 v1.5 の**暗号化・復号**は実装しない(Bleichenbacher / Marvin の入口になるため)。

### 2. 保証しないこと(正直に)
* **第三者の暗号監査は受けていません。** 実験的です。
* 「定数時間」「Marvin に脆弱でない」とは**言いません**。簡易な時間計測で差が見えなかっただけで、命令列の確認は未実施です。
* 数値演算の定数時間性は `crypto-bigint`(0.7.10 以上)に任せており、ここでは検証していません。
* 「安全」と書くのは、実測や既知回答テストで**確認できた範囲だけ**。それ以外は「未検証」と書き、README の「限界」を更新する。
* 本番の重要な秘密に使う前に、独立した専門家のレビューを受けることを勧めます。

### 3. 変更のルール
* 暗号に関する変更には、必ず**既知回答(OpenSSL 生成)**か**相互運用**(`ssh-keygen` / `openssl`)のテストを付ける。
* 根拠は RFC 8017 と既知回答。推測で埋めない。
* `crypto-bigint` は `>=0.7.10` から下げない。
* 互換層 2 つは crate 名が `rsa` で衝突するため、ワークスペースに入れない。
* 依存元への `[patch]` 追加は、**別の小さなコミット**にする。`cargo fmt --all` は使わない(`cargo fmt -p` を使う)。
* ビルドとテストは WSL の手元で行う。**小さな VPS ではビルドしない**。VPS への配置やタイマーの有効化は、持ち主の確認を取ってから。

### 4. 秘密の扱い
* 鍵・トークン・パスワードを、ログ・コミット・チャット・報告に出さない。
* `core/tests/fixtures/*.pem` は**使い捨てのテスト鍵**のみ。本物の鍵を置かない。
* 通知用のトークンなどは、設定ファイルにファイルパスか環境変数で**参照だけ**する。

### 5. 公開と配布
* GitHub では公開しているが、**crates.io には公開しない**。
* 公開範囲を変えること、crates.io へ出すこと、リリースを切ることは**持ち主の判断**。勝手にしない。
* 依存元にはタグ(`v0.1.0` など)を指定して導入する。`[patch]` の書き方は PORTING.md を参照。

### 6. 脆弱性・不具合の報告
* 鍵や攻撃の詳細を含む内容は、公開の Issue に**書かないでください**。
* まず、持ち主(aon-co-jp)に非公開で連絡してください。公開の Issue には「報告したいことがある」とだけ書けば足ります。
* 修正の時期は約束できません。確認できた不具合は、README の「限界」と STATUS.md に正直に記録します。

### 7. 上流との関係
* 上流の `rsa` に修正版が出たら、そちらへ戻すことを検討する。戻すまでの**つなぎ**である。
* 上流には 0.10.0 正式版がある(2026-11-19 時点)。互換層は `0.10.0-rc.18` を名乗り、正式版との互換は**未検証**。依存元が新しい版を要求したら、版を上げて再検証する。

### 8. API の方針(このリポジトリの外の決まり)
* 新しい API は REST で作らない。ブラウザや `curl` からは **Connect**、サービス間は **gRPC**。JSON は RS-JSON に統一。
* 例外は、相手の規格が形を決めるもの(ACME、OAuth のコールバック、第三者の Webhook、ヘルスチェック、静的ファイル、OTLP)。
* 詳細は [CLAUDE.md](CLAUDE.md) と [PORTING.md](PORTING.md) の「API 方針」の節を参照。迷ったら Connect。

---

## English

This file lists the **promises and rules** for `rsa-rs`. How it works and how to use it is in [README.md](README.md). How to add it to a project is in [PORTING.md](PORTING.md). Notes for the people (and AI helpers) who work here are in [CLAUDE.md](CLAUDE.md).

### 1. Goal and scope
* We want to avoid RUSTSEC-2023-0071 (the Marvin Attack) in the `rsa` crate. So we write **only the parts our projects really call**, following RFC 8017.
* Anything outside that scope **fails to compile on purpose**. A compile error is safer than a quiet change in behavior. Before we widen the scope, we check the real call in the other project's source.
* We do **not** build PKCS#1 v1.5 *encryption or decryption*. It is the door that the Bleichenbacher and Marvin attacks use.

### 2. What we do NOT promise
* **No outside expert has audited this code.** It is experimental.
* We do **not** say it is "constant-time" or "safe from Marvin". A simple timing test showed no difference, but we have not read the machine code.
* The constant-time quality of the big-number math is trusted to `crypto-bigint` (0.7.10 or newer). We have not checked it here.
* We write "safe" only for what we **measured or tested**. For everything else we write "unverified", and we keep the README limits up to date.
* Before you protect something important with it, please get an independent expert review.

### 3. Rules for changes
* Every crypto change needs a **known-answer test** (made with OpenSSL) or an **interop test** (`ssh-keygen` or `openssl`).
* Use RFC 8017 and known answers as proof. Do not guess.
* Never lower `crypto-bigint` below `>=0.7.10`.
* The two compat crates are both named `rsa`, so they stay out of the workspace.
* In a dependent project, add the `[patch]` in its **own small commit**. Do not run `cargo fmt --all`; use `cargo fmt -p`.
* Build and test on the WSL machine. **Do not build on the small VPS.** Ask the owner before copying files to the VPS or turning on a timer.

### 4. Handling secrets
* Never put keys, tokens or passwords in logs, commits, chats or reports.
* The `.pem` files in `core/tests/fixtures/` are **throw-away test keys** only. Never put a real key there.
* Tokens for notifications are only **referenced** from the config file, by file path or environment variable.

### 5. Publishing and releases
* The code is public on GitHub, but we do **not** publish it on crates.io.
* Changing who can see the repo, publishing to crates.io, or making a release is **the owner's decision**. Never do it on your own.
* Dependent projects use a tag (like `v0.1.0`). See PORTING.md for the exact `[patch]` lines.

### 6. Reporting a vulnerability or bug
* Please do **not** put key material or attack details in a public issue.
* First, contact the owner (aon-co-jp) privately. In a public issue, just say you have something to report.
* We cannot promise a fix date. Confirmed problems are written honestly in the README limits and in STATUS.md.

### 7. Relationship with upstream
* If a fixed `rsa` is released upstream, we will think about going back to it. This repo is a **bridge**, not a goal.
* Upstream has `rsa` 0.10.0 final (as of 2026-11-19). Our compat layer says `0.10.0-rc.18`, and compatibility with the final release is **unverified**. If a dependent project asks for a newer version, we bump it and test again.

### 8. API policy (rules that reach beyond this repo)
* New APIs are not built as REST. Use **Connect** from browsers and `curl`, and **gRPC** between services. JSON is unified on RS-JSON.
* Exceptions are things where someone else's standard sets the shape (ACME, OAuth callbacks, third-party webhooks, health checks, static files, OTLP).
* See the "API 方針" sections in [CLAUDE.md](CLAUDE.md) and [PORTING.md](PORTING.md) for details. When in doubt, use Connect.
