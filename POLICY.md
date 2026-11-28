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

## 状況 / Status (2026-11-24)

**日本語.**
* v0.1.0 タグ + GitHub Release 済み。依存元 9 リポジトリが `[patch]` で採用(README の採用表)。VPS の `version-control` 巡回では RUSTSEC-2023-0071 は「対策済み(差し替え)」として別枠に出る。
* **REST は持たない**: これはライブラリで HTTP サーバー/クライアントのコードは無い。API 方針(Connect / gRPC)は他リポジトリ向けの記録。
* 未了(正直に): 第三者監査なし / 命令列レベルの定数時間確認なし / MySQL 実サーバー試験なし / 上流 `rsa` 0.10.0 正式版との互換は未検証 / LINE 通知トークンは持ち主の設定待ち(version-control 側)。

**English.**
* Tagged v0.1.0 with a GitHub Release. Nine dependent repositories use it through `[patch]` (see the adoption table in the README). In the VPS `version-control` patrol, RUSTSEC-2023-0071 now shows as "mitigated (replaced)" in its own list.
* **No REST here**: this is a library with no HTTP server or client code. The Connect / gRPC policy is a record for other repositories.
* Not done (honestly): no third-party audit; no instruction-level constant-time review; no live MySQL server test; compatibility with upstream `rsa` 0.10.0 final is unverified; the LINE token is waiting for the owner (in `version-control`).


## Versionless API の方針 / Versionless API policy (2026-11-25)
**日本語**: このリポジトリのAPIは **Versionless**(URL・パッケージ名に `v1` 等を付けず、互換性を壊さず足すだけで進化させる)。欄は足すだけ・足す欄は省略可能・知らない欄は無視・名前変更は新名を足して旧を非推奨に(期限は既定で6か月以上、使用0を確認してから削除)・enumは未知の値を許容・安全上の緊急修正は例外。既存の `.v1` は呼び出し側を壊さないよう当面残し、版なしの別名を追加して段階的に畳む。詳細・出典は [`runo/API-POLICY.md`](https://github.com/aon-co-jp/runo/blob/main/API-POLICY.md) 末尾。適用はこれから順に行う。
**English**: This repository's APIs are **Versionless**: no `v1` in URLs or package names; evolve by adding only, without breaking compatibility. Only add fields, new fields are optional, ignore unknown fields, rename by adding the new name and deprecating the old (default deadline 6 months or more, remove only after confirming zero use), tolerate unknown enum values, emergency security fixes are the exception. Existing `.v1` names stay for now so callers do not break; a versionless alias is added and `.v1` is retired in stages. Details and sources: the end of [`runo/API-POLICY.md`](https://github.com/aon-co-jp/runo/blob/main/API-POLICY.md). Rollout is step by step.

## API 方針: REST 全廃・gRPC / Connect へ
**日本語**: このリポジトリでは **REST API を新規に作らない**。ブラウザ・`curl` から呼ぶ API は **Connect の単純呼び出し**(`POST /<パッケージ>.<Service>/<Method>`、`content-type: application/json`)、サービス間は **gRPC / gRPC-web**。GraphQL は読み取り専用。既存の REST は触るときに移し、移したら旧経路は消す。JSON は RS-JSON(`from_str_secure` / `parse_secure`)で読む。例外は相手の規格が形を決めるもの(ACME、OAuth/OIDC のコールバック、第三者の Webhook、ヘルスチェック、静的ファイル、OTLP)のみ。迷ったら Connect。正本は [`runo/API-POLICY.md`](https://github.com/aon-co-jp/runo/blob/main/API-POLICY.md)。
**English**: This repository **does not add new REST APIs**. APIs called from browsers or `curl` use **Connect unary calls** (`POST /<package>.<Service>/<Method>`, `content-type: application/json`); service-to-service calls use **gRPC / gRPC-web**. GraphQL is read-only. Existing REST is migrated when touched and the old route is removed. Read JSON with RS-JSON (`from_str_secure` / `parse_secure`). Exceptions are only shapes dictated by someone else's standard (ACME, OAuth/OIDC callbacks, third-party webhooks, health checks, static files, OTLP). When in doubt, use Connect. Source of truth: the link above.

## 完成まで作り切る方針 / Finish everything policy (2026-11-27)
**日本語**: 全リポジトリで、**未確認は自動で確認し、未実施は実施し、未了は完成させる**(確認を求めず進める)。使用頻度が低いと判断される機能や、**1から作り直す大規模開発になる内容でも、やめずに最後まで開発・TEST・DEBUGする**(別の方式で済ませない、後回しにしない)。進め方: 調査(英語・日本語の検索とGitHub) → 設計 → 実装 → 実機/実データで確認 → 失敗は原因を直して再試験 → README・CLAUDE・PORTING・POLICY を日英で更新 → push。「できた」と書くのは実測した範囲だけ、確認できなかった所は「未確認」と正直に書く。例外(確認を取る): 元に戻せない削除、秘密の公開、所有者の認証・決済・実機操作が要るもの、利用者のシステム設定の変更。
**English**: In every repository, **verify what is unverified, do what is not yet done, and finish what is unfinished** automatically, without asking. Even features that look rarely used, or work that means **a large rewrite from scratch, are developed, tested and debugged to the end** (no substituting another approach, no postponing). Method: research (English and Japanese search plus GitHub) -> design -> implement -> verify on real devices or data -> fix causes and retest on failure -> update README, CLAUDE, PORTING and POLICY in Japanese and English -> push. Write "done" only for what was measured, and say "unverified" honestly for the rest. Exceptions that still need confirmation: irreversible deletions, publishing secrets, anything needing the owner's authentication, payment or real-device actions, and changes to the user's system settings.
## なぜ作ったか / Why this exists (2026-11-28)

**日本語.**
- Rust の `rsa` クレートには、処理時間のわずかな差を測ると秘密鍵が漏れうる弱点 **RUSTSEC-2023-0071(Marvin Attack)** があり、上流に**修正版がない**。版を上げても直らない。
- aon-co-jp の多くのリポジトリは `rsa` を直接ではなく、依存の中で使っていた: `sqlx-mysql`(MySQL パスワードの OAEP 暗号化)と `ssh-key` / `russh`(SSH の RSA 署名・検証)。
- そこで、それらが**実際に呼ぶ部分だけ**を RFC 8017 に沿って自前で実装し、`[patch.crates-io]` で本物と差し替えた(`compat-0.9` / `compat-0.10`)。弱点の入口になる PKCS#1 v1.5 の暗号化・復号はわざと作らない。秘密鍵の計算は毎回ブラインディングし、結果も検算する。
- 正しさは OpenSSL の既知回答、`ssh-keygen` との相互運用、Wycheproof で確認した。
- 結果: 依存元 9 リポジトリが採用し、`version-control` の巡回では「対策済み(差し替え)」と表示される。
- ただし第三者監査なし・命令列レベルの定数時間確認なし。上流 `rsa` に修正版が出たらそちらへ戻す前提の**つなぎ**。

**English.**
- The Rust `rsa` crate has a weakness, **RUSTSEC-2023-0071 (the Marvin Attack)**: by measuring tiny timing differences, an attacker may learn a secret key. **There is no fixed version upstream**, so updating does not help.
- Many aon-co-jp projects did not use `rsa` directly. It came in through other libraries: `sqlx-mysql` (OAEP encryption of the MySQL password) and `ssh-key` / `russh` (RSA signing and checking for SSH).
- So we wrote **only the parts those libraries really call**, following RFC 8017, and swapped them in with `[patch.crates-io]` (`compat-0.9` / `compat-0.10`). We left out PKCS#1 v1.5 encryption and decryption on purpose, because that is the door the attack uses. Every private-key calculation is blinded with a fresh random number, and the result is double-checked.
- We checked it with OpenSSL known answers, `ssh-keygen` interop and Wycheproof test vectors.
- Result: nine dependent projects use it, and the `version-control` patrol shows the issue as "mitigated (replaced)".
- But no outside expert has audited it, and nobody has reviewed the machine code for constant time. It is a **bridge**: when upstream `rsa` ships a fix, we plan to go back to it.

