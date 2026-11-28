> Latest translations / 翻訳の最新版: [0-LATEST-TRANSLATIONS.md](0-LATEST-TRANSLATIONS.md)

# rsa-rs

**日本語** | [English](#english) | [Deutsch](docs/README.de.md) | [Русский](docs/README.ru.md)

> 状態表(最新の上流 rsa / RUSTSEC の状況・試験結果)は自動更新される [STATUS.md](STATUS.md) / [status.json](status.json) を参照。
> **実験的・第三者監査なし**(下の「限界」参照)。約束事・報告先は [POLICY.md](POLICY.md)(日本語 / English)。

`rsa` クレートの **互換置き換え** (RUSTSEC-2023-0071 / Marvin Attack 対策)。aon-co-jp 配下のリポジトリが
依存経由で使っている範囲だけを、RFC 8017 に基づき自前で実装したものです。GitHub で公開していますが、crates.io には公開しません。

> ⚠️ **第三者監査は受けていません。** 自前の暗号実装です。「定数時間性」「Marvin 非脆弱」を保証するものではありません。
> 下の「限界」を必ず読んでください。

## 構成

| ディレクトリ | 内容 |
|---|---|
| `core/` (`rsa-rs-core`) | ハッシュ・乱数の版に依存しない RSA コア。鍵、RSADP(CRT+ブラインディング+結果検証)、PKCS#1 v1.5 署名、OAEP、鍵生成 |
| `compat-0.10/` (crate 名 `rsa` 0.10.0-rc.18) | `ssh-key 0.7.0-rc.11` / `russh 0.62・0.63` 向け。署名(PKCS#1 v1.5)・OAEP・PKCS#1/#8/SPKI 入出力 |
| `compat-0.9/` (crate 名 `rsa` 0.9.10) | `sqlx-mysql 0.8.x` 向け。**公開鍵 + OAEP 暗号化のみ** (秘密鍵演算なし) |
| `scripts/` | WSL 用のテスト・相互運用スクリプト |

互換層は crate 名がどちらも `rsa` なのでワークスペースに入れず、個別にビルドします。

## 使い方 (各リポジトリの `Cargo.toml`)

```toml
[patch.crates-io]
rsa = { path = "../rsa-rs/compat-0.10" }                                   # rsa 0.10.0-rc.18 を置き換え
rsa-090 = { package = "rsa", path = "../rsa-rs/compat-0.9" }               # rsa 0.9.10 を置き換え (必要なら)
```

* `crypto-bigint` は **0.7.10 以上**が必須 (`cargo update -p crypto-bigint --precise 0.7.10`)。
  互換層は `>=0.7.10` を要求するので、古いロックのままだと解決に失敗します (意図した動作)。
* 片方しか使わないリポジトリは、使う方の行だけ書けば足ります。

## 実装した範囲 (それ以外は **コンパイルエラー**になる)

実装は「依存元が実際に呼ぶ API」に限定しています (全 API の複製はしません)。

**0.10 互換 (`compat-0.10`)**: `RsaPrivateKey` (`new`/`from_components`/`to_public_key`/`crt_coefficient`/`sign`/`decrypt`)、
`RsaPublicKey` (`new`/`encrypt`/`verify`)、`PublicKeyParts`/`PrivateKeyParts`、`pkcs1v15::{SigningKey, VerifyingKey, Signature}`、
`Pkcs1v15Sign`、`Oaep`、`BoxedUint`、`errors::Error`、`pkcs1`/`pkcs8` の Decode/Encode。

**0.9 互換 (`compat-0.9`)**: `RsaPublicKey` (`DecodePublicKey` 経由の PEM/DER 読込、`encrypt`)、`Oaep::new::<D>()` 等、`BigUint`。

**未実装**: PSS、PKCS#1 v1.5 *暗号化* (Bleichenbacher/Marvin の温床なので意図的に実装しない)、multi-prime 鍵、serde、`hazmat`。
0.9 互換では秘密鍵・署名も未実装。

## 設計 (防御)

* 秘密鍵演算 (RSADP): **ブラインディング** (毎回新しい r) + **CRT (Garner)** + **結果検証** (ブラインド後の値 m' に対し m'^e ≡ c' を確認、
  不一致なら値を返さない=フォールト攻撃対策)。べき乗・剰余・逆元は `crypto-bigint` 0.7.10+ の定数時間演算。
* 署名の検証は RFC 8017 §8.2.2 の注記どおり、期待される EM を再構成してバイト列比較 (EM を構文解析しない)。
* OAEP 復号は全ての失敗を 1 種類のエラーにまとめ、EM の検査 (Y・lHash・PS/0x01 探索) を分岐なしのマスク演算で行う (Manger 攻撃対策)。
* PKCS#1 v1.5 暗号化を持たないので、Bleichenbacher 型の復号オラクルは構造上存在しない。
* 署名/復号で乱数源が渡されない API (`Signer::try_sign` など) でも、OS 乱数でブラインディングする (上流は無効のまま)。
* 秘密値は `Drop` で zeroize。

## 検証

`wsl -d Ubuntu` で実行 (`CARGO_TARGET_DIR` は WSL ホーム。`scripts/build.sh` 参照)。

| 内容 | 結果 |
|---|---|
| `core`: OpenSSL 生成の既知回答 (PKCS#1 v1.5 署名は決定的なので **バイト一致**、OAEP は OpenSSL 暗号文を復号)、改ざん・長さ違い・ラベル違い・n 以上の入力の拒否、鍵検証、鍵生成、フォールト注入 | 全て pass (`cargo test`) |
| `compat-0.10`: `SigningKey<D>` の署名が OpenSSL とバイト一致 (SHA-1/256/384/512 × 1024/2048)、OAEP、PKCS#8/PKCS#1/SPKI 往復 | 全て pass |
| `compat-0.9`: sqlx-mysql と同じ使い方 (PEM→`Oaep::new::<Sha1>()`→`encrypt`) | pass。**`openssl pkeyutl -decrypt` で復号できる** (`scripts/interop-oaep.sh`) |
| `ssh-key 0.7.0-rc.11` の **自身のテストスイート** (rsa feature) を `rsa` 差し替えで実行 | 全 pass (`scripts/sshkey-test.sh`) |
| SSH 署名 ⇔ `ssh-keygen -Y verify` / `-Y sign` (rsa-sha2-256・512、生成鍵、改ざん検知) | 双方向 OK (`scripts/interop.sh`) |
| `sqlx-mysql 0.8.6` を `compat-0.9` でビルド | OK (`scripts/sqlxmysql-check.sh`) |
| `open-web-server` の別 clone で `sftp` (russh 0.63) 付きゲートウェイをビルド | OK (`scripts/owsrv-check.sh`) |
| Wycheproof: RSA 署名検証 7 ファイル (valid/invalid 全件判定一致)、OAEP 復号 5 ファイル (Manger 系の不正パディングも全て拒否) | 全て pass (`core/tests/wycheproof.rs`) |
| dudect 風の簡易タイミング計測 (OAEP 復号の正常/異常、RSADP の固定/ランダム入力) | \|t\| < 1 (n=1500/600)。下記の限界を参照 |

## 限界 (正直に)

* **第三者監査なし。** 暗号の落とし穴を意識して RFC 8017 を根拠に書いたが、監査・形式検証はしていない。
* **定数時間性は実測で一部しか見ていない。** 上の簡易 t 検定は WSL2 上・数千サンプルで有意差が出なかった、というだけで、
  定数時間性の証明ではない。**命令列の確認 (逆アセンブルで秘密依存分岐・可変時間命令がないか) は未実施。** 数値演算の定数時間性は
  `crypto-bigint` 0.7.10+ に依存しており、ここでは検証していない。`ct.rs` のバイト列ヘルパは `black_box` で最適化を牽制しているが、
  コンパイラが分岐化しないことの保証はない。
* Wycheproof (C2SP/wycheproof testvectors_v1) の RSA 署名検証 7 ファイル (2048/SHA-256・384・512、3072/SHA-256・512、4096/SHA-256・512) と OAEP 復号 5 ファイル (2048/3072/4096、MGF1 が SHA-1 の組を含む) を取り込み済み、全件通過。SHA-1 署名・PSS・他の鍵長は未取り込み。
  OpenSSL 3.5.5 の出力と RFC 8017 §9.2 の DigestInfo 接頭辞も既知回答として使う。`scripts/gen-fixtures.sh` で再生成できる。
* `core/tests/fixtures/` の `*.pem` は **使い捨てのテスト鍵**であり秘密ではない (シークレットスキャナに検出されうる)。
* 返す OAEP 平文の長さは API 上、呼び出し側から見える。
* Windows ネイティブでは未ビルド (WSL Ubuntu のみ)。`getrandom` 経由の OS 乱数に依存するので `no_std`/WASM 向けではない。
* russh 自身のテストは dev-dependency (ratatui 等) がオフラインに無く未実行。ssh-key のテストと SSH 相互運用で代替している。
* 鍵生成の `d` は `e⁻¹ mod φ(n)` (λ(n) ではない)。機能的には等価で OpenSSH/OpenSSL と相互運用できるが、OpenSSL の現行出力とは値が異なる。

## ライセンス / English

MIT OR Apache-2.0。下は英語版の要約です。

---

## English

### What is this?

`rsa-rs` is a small, home-made stand-in for part of the Rust `rsa` crate.

Why do we need it? The `rsa` crate has a known security bug called the **Marvin Attack** (RUSTSEC-2023-0071). An attacker who can measure tiny timing differences might learn a secret key. Nobody has released a fixed version of `rsa`. So we wrote the few pieces we really use, following the RFC 8017 standard, and we test them against OpenSSL and `ssh-keygen`.

> ⚠️ **Please read this first.** No outside expert has checked this code. It is home-made cryptography and it is **experimental**. We do **not** promise it is "constant-time" or "safe from Marvin". See "Limits" below.

The code is public on GitHub. We do **not** publish it on crates.io.

### What is inside?

| Folder | What it does |
|---|---|
| `core/` | The real RSA code. It does not care which version of the hash or random-number libraries you use. It has keys, signing, OAEP encryption and key generation. |
| `compat-0.10/` | Looks like `rsa` 0.10.0-rc.18, so `ssh-key` and `russh` can use it. Signing, OAEP, key files. |
| `compat-0.9/` | Looks like `rsa` 0.9.10, so `sqlx-mysql` can use it. **Only public keys and OAEP encryption.** No private-key work at all. |
| `scripts/` | Test and "does it work with OpenSSL?" scripts. They run in WSL Ubuntu. |

### How do I use it?

Add a `[patch.crates-io]` section to the `Cargo.toml` of the project that uses `rsa`. The exact lines are in the Japanese section above and in `PORTING.md`. You also need `crypto-bigint` version **0.7.10 or newer**.

### What is NOT included?

Only the functions that our projects really call are included. If your code calls something else, it will **not compile**. That is on purpose. A compile error is better than a hidden surprise.

Missing on purpose or for now: PSS signatures, PKCS#1 v1.5 *encryption* (this one is left out on purpose, because it is the door that the Bleichenbacher and Marvin attacks use), keys with more than two primes, serde, and `hazmat`.

### How does it protect secrets?

* **Blinding.** Before every private-key calculation, we mix in a fresh random number. This makes timing tricks much harder. We do it even when the caller gives us no random source.
* **CRT with a double check.** We use a faster math shortcut (CRT). Then we check the answer. If it is wrong, we give back nothing. This stops "fault attacks".
* **Safe signature checking.** To check a signature, we rebuild what it should look like and compare the bytes. We never try to read the signature's inside.
* **One error for OAEP.** When OAEP decryption fails, you always get the same single error. The checks use math masks instead of `if` branches.
* **No tidy-up later.** Secret values are wiped from memory when they are dropped.

### How did we test it?

* Our signatures are **byte-for-byte the same** as OpenSSL's.
* We can decrypt OpenSSL's OAEP messages, and OpenSSL can decrypt ours.
* `ssh-key`'s own test suite passes when it uses our code instead of `rsa`.
* `ssh-keygen -Y sign` and `-Y verify` work in both directions.
* `sqlx-mysql 0.8.6` and an `open-web-server` copy (with `russh 0.63` and `sftp`) build with our code.
* We ran the Wycheproof test vectors: 7 files for RSA signature checks and 5 files for OAEP. All pass.

### Limits (we are honest about these)

* **No outside check.** Nobody independent has reviewed this code.
* **Timing is only sampled.** We ran a simple statistics test (|t| < 1). That only means "we saw no difference", not "there is none". **We have not read the machine code** to look for secret-dependent branches. The big-number math is trusted to `crypto-bigint` 0.7.10 or newer, and we have not checked it ourselves.
* Wycheproof does not yet cover SHA-1 signatures, PSS, or other key sizes.
* The `*.pem` files in `core/tests/fixtures/` are throw-away test keys. They are not secrets.
* The length of a decrypted OAEP message can be seen by the caller. That is how the API works.
* We only build on Linux (WSL Ubuntu). It needs the operating system's random numbers, so it is not for `no_std` or WASM.
* The tests of `russh` itself were not run offline. We use the `ssh-key` tests and the `ssh-keygen` checks instead.
* The private exponent `d` is `e⁻¹ mod φ(n)`, not `λ(n)`. It works and is compatible with OpenSSH and OpenSSL, but the number differs from what OpenSSL prints today.

### 追記 / Note (2026-11-04)
* 上流 `rsa` には 0.10.0 正式版(2026-11-19 時点で crates.io 確認、rc.19〜rc.22 も公開済み)が既にある。互換層は `0.10.0-rc.18` を名乗り、正式版との互換は未検証。`russh`/`ssh-key` が rc.19 以降を要求するようになったら互換層の版を上げて再検証すること(`STATUS.md` で最新版を確認)。
  Upstream already has `rsa` 0.10.0 final (checked on crates.io 2026-11-19; rc.19–rc.22 also exist). The compat layer claims rc.18 and compatibility with the final release is unverified, so bump and re-verify when dependents move to a newer rc.
* 夜間/朝の自動更新: `scripts/nightly.sh`(手元 WSL・全試験)、`scripts/update-status.sh`(軽量・VPS 可)、VPS 用 timer 雛形は `deploy/`(未配置)。

## API 方針: REST 全廃・gRPC / Connect へ (2026-11-04)

### 日本語
- **REST は全廃する。新しい API は REST で作らない。** ブラウザや `curl` から呼ぶ API は **Connect の単純呼び出し**(`POST /<パッケージ>.<Service>/<Method>`、`content-type: application/json`、本文は JSON)、サービス間は **gRPC / gRPC-web**(RPoem の管理API `open_runo.admin.v1.Admin` と同じ流儀)。ストリーミングは、必要になってから。
- **既存の REST は、触るときに順に移す。** 移したら旧 REST の経路は消す。移行が終わるまで残るが、**新規には追加しない**。
- **JSON は RS-JSON に統一**する(読み込みは `from_str_secure` / `parse_secure` でサイズ・深さ・重複キーの上限つき、書き出しは `rust_json::fast`)。ブラウザの WASM に `prost` は入れない(サイズが増えるため)。
- **例外(自分たちの API ではなく、相手の規格が決めているもの)**: ACME、OAuth/OIDC のコールバック、第三者(GitHub など)からの Webhook、ヘルスチェック、静的ファイル配信、OTLP など。これらは規格どおりの HTTP を受ける。
- 参考実装: `RPoem`(`open_runo.admin.v1.Admin`)、`open-easy-web`(`server/src/connect.rs`、`proto/open_easy_web/admin/v1/admin.proto`)。
- ※ このリポジトリのコードが既に方針どおりかどうかは、各リポジトリの現状による。この節は方針の記録であり、コードの変更を意味しない。

### English
- **REST is being abolished. New APIs are not built as REST.** APIs called from browsers or `curl` use **Connect unary calls** (`POST /<package>.<Service>/<Method>`, `content-type: application/json`, JSON body); service-to-service calls use **gRPC / gRPC-web** (the same style as RPoem's admin API `open_runo.admin.v1.Admin`). Streaming only when it is actually needed.
- **Existing REST endpoints are migrated one by one, when they are touched.** The old REST route is removed once migrated. Until migration is finished they remain, but **no new ones are added**.
- **JSON is unified on RS-JSON**: reading with `from_str_secure` / `parse_secure` (size, depth and duplicate-key limits), writing with `rust_json::fast`. `prost` is not put into browser WASM (it would grow the binary).
- **Exceptions (shapes dictated by someone else's standard, not our own API)**: ACME, OAuth/OIDC callbacks, webhooks from third parties (e.g. GitHub), health checks, static file serving, OTLP, and so on. These accept plain HTTP as the standard requires.
- Reference implementations: `RPoem` (`open_runo.admin.v1.Admin`) and `open-easy-web` (`server/src/connect.rs`, `proto/open_easy_web/admin/v1/admin.proto`).
- Note: whether the code in a given repository already follows this policy depends on that repository. This section records the policy; it does not mean the code has been changed.

### Deutsch (KI-Übersetzung, redaktionell überarbeitet; noch nicht von Muttersprachlern geprüft)
- **REST wird vollständig abgeschafft; neue APIs entstehen nicht mehr als REST.** APIs, die aus dem Browser oder per `curl` aufgerufen werden, verwenden **unäre Connect-Aufrufe** (`POST /<Paket>.<Service>/<Methode>`, `content-type: application/json`, JSON-Body). Zwischen Diensten kommen **gRPC bzw. gRPC-web** zum Einsatz, im selben Stil wie die Admin-API von RPoem (`open_runo.admin.v1.Admin`). Streaming wird erst ergänzt, wenn es tatsächlich gebraucht wird.
- **Bestehende REST-Endpunkte werden schrittweise umgestellt, und zwar immer dann, wenn man ohnehin an ihnen arbeitet.** Sobald ein Endpunkt umgestellt ist, wird die alte REST-Route entfernt. Bis zum Abschluss der Migration bleiben die übrigen bestehen, es werden aber **keine neuen mehr hinzugefügt**.
- **JSON wird einheitlich über RS-JSON verarbeitet**: Gelesen wird mit `from_str_secure` bzw. `parse_secure` (mit Obergrenzen für Größe, Verschachtelungstiefe und doppelte Schlüssel), geschrieben mit `rust_json::fast`. `prost` wird nicht in das Browser-WASM aufgenommen, da es die Datei vergrößern würde.
- **Ausnahmen (Schnittstellen, deren Form ein fremder Standard vorgibt und die nicht zu unserer eigenen API gehören)**: ACME, OAuth/OIDC-Callbacks, Webhooks von Drittanbietern (z. B. GitHub), Health-Checks, die Auslieferung statischer Dateien, OTLP und Ähnliches. Diese nehmen, wie vom jeweiligen Standard verlangt, gewöhnliches HTTP entgegen.
- Referenzimplementierungen: `RPoem` (`open_runo.admin.v1.Admin`) und `open-easy-web` (`server/src/connect.rs`, `proto/open_easy_web/admin/v1/admin.proto`).
- Hinweis: Ob der Code eines einzelnen Repositorys diese Richtlinie bereits erfüllt, hängt vom jeweiligen Repository ab. Dieser Abschnitt dokumentiert lediglich die Richtlinie; er besagt nicht, dass der Code schon angepasst wurde.

### Русский (перевод выполнен с помощью ИИ и отредактирован; носителями языка пока не проверен)
- **От REST мы полностью отказываемся; новые API больше не создаются в стиле REST.** API, к которым обращаются из браузера или через `curl`, используют **унарные вызовы Connect** (`POST /<пакет>.<Service>/<Method>`, `content-type: application/json`, тело запроса — JSON). Для взаимодействия между сервисами применяются **gRPC и gRPC-web** — в том же стиле, что и административный API RPoem (`open_runo.admin.v1.Admin`). Потоковая передача данных добавляется лишь тогда, когда в ней действительно возникает необходимость.
- **Существующие REST-эндпоинты переводятся поэтапно — по мере того, как с ними приходится работать.** После перевода старый REST-маршрут удаляется. Пока миграция не завершена, оставшиеся эндпоинты сохраняются, но **новые не добавляются**.
- **Работа с JSON унифицирована на основе RS-JSON**: чтение — через `from_str_secure` или `parse_secure` (с ограничениями на размер, глубину вложенности и повторяющиеся ключи), запись — через `rust_json::fast`. `prost` в браузерный WASM не включается, поскольку это увеличило бы размер файла.
- **Исключения (интерфейсы, форму которых определяет чужой стандарт, а не наш собственный API)**: ACME, обратные вызовы OAuth/OIDC, вебхуки сторонних сервисов (например, GitHub), проверки работоспособности, раздача статических файлов, OTLP и тому подобное. Такие интерфейсы принимают обычный HTTP, как того требует соответствующий стандарт.
- Эталонные реализации: `RPoem` (`open_runo.admin.v1.Admin`) и `open-easy-web` (`server/src/connect.rs`, `proto/open_easy_web/admin/v1/admin.proto`).
- Примечание: соответствует ли код конкретного репозитория этой политике, зависит от самого репозитория. Данный раздел лишь фиксирует политику и не означает, что код уже изменён.

## API 方針の補足: 用語の整理と使い分け (2026-11-04)

### 日本語
**1つに統一するものではなく、別の層の話です。** 「REST の代わり」になるのは Connect・gRPC・GraphQL だけで、WASM は画面を作る技術です。

| 用語 | 何か | REST の代わりか |
|---|---|---|
| REST | URL と HTTP メソッドで操作を表す API の作り方 | 全廃する側 |
| **Connect** | `POST /サービス名/メソッド名` に JSON を送る形式。`curl` でもブラウザの `fetch` でも呼べる | はい(**採用**) |
| **gRPC** | 同じ「サービス/メソッド」の考え方を、バイナリ(protobuf)と HTTP/2 で行う形式。速く、ストリーミングも得意 | はい(**サービス同士に採用**) |
| gRPC-web | gRPC のブラウザ向けの変形版 | はい(必要なら) |
| GraphQL | 欲しい項目を問い合わせる形式 | 一部だけ(**問い合わせ(読み取り)専用**) |
| WASM | Rust をブラウザの中で動かす仕組み | いいえ(画面を作る技術) |

- **ブラウザの画面や `curl` から呼ぶ API は Connect**(POST、JSON を RS-JSON で読み書き)。ブラウザの WASM は素の gRPC を話せず、Connect なら `fetch` のままで、`prost` を足さずに済む(画面のサイズも増えない)。
- **サービス同士の通信(サーバー間、重い処理、ストリーミング)は gRPC。** 多くは Connect で足りるので、ストリーミングが必要になった所だけ gRPC に上げる。
- **GraphQL は、まとめて問い合わせたいときの読み取り専用。** 書き込み(操作)には使わない。
- **WASM は画面を作る技術として、そのまま使う。** 画面から呼ぶ API が Connect になっただけ。
- 外部の規格が形を決めるもの(ACME、OAuth のコールバック、第三者の Webhook、ヘルスチェック、静的ファイル、OTLP)は、規格どおりの HTTP のまま。
- **迷ったら Connect。**

### English
**These are not alternatives to unify; they sit at different layers.** Only Connect, gRPC and GraphQL can replace REST; WASM is a way to build the UI.

| Term | What it is | Replaces REST? |
|---|---|---|
| REST | API style that expresses operations through URLs and HTTP methods | The thing being abolished |
| **Connect** | `POST /Service/Method` with a JSON body; callable from `curl` and from a browser `fetch` | Yes (**adopted**) |
| **gRPC** | The same service/method idea over binary (protobuf) and HTTP/2; fast, good at streaming | Yes (**for service-to-service**) |
| gRPC-web | A browser-friendly variant of gRPC | Yes (if needed) |
| GraphQL | A query language: ask for exactly the fields you want | Partly (**read-only queries**) |
| WASM | Runs Rust inside the browser | No (a UI technology) |

- **APIs called from browser screens or `curl` use Connect** (POST, JSON read and written with RS-JSON). Browser WASM cannot speak plain gRPC; with Connect it stays a `fetch`, and `prost` is not needed (the binary does not grow).
- **Service-to-service calls (server to server, heavy work, streaming) use gRPC.** Connect is enough in most places; move a call to gRPC only where streaming is actually needed.
- **GraphQL is read-only**, for queries that gather several pieces of data. It is not used for writes (operations).
- **WASM stays as the way to build the UI.** The API it calls simply became Connect.
- Interfaces whose shape an outside standard dictates (ACME, OAuth callbacks, third-party webhooks, health checks, static files, OTLP) stay plain HTTP.
- **When in doubt, use Connect.**

### Deutsch (KI-Übersetzung, sprachlich überarbeitet; noch nicht von Muttersprachlern geprüft)
**Es geht nicht darum, eine einzige Technik auszuwählen – die Begriffe liegen auf unterschiedlichen Ebenen.** Als Ersatz für REST kommen nur Connect, gRPC und GraphQL in Frage; WASM dagegen ist eine Technik, mit der die Benutzeroberfläche gebaut wird.

| Begriff | Was ist das? | Ersatz für REST? |
|---|---|---|
| REST | Ein API-Stil, bei dem Operationen über URLs und HTTP-Methoden ausgedrückt werden | wird abgeschafft |
| **Connect** | `POST /Dienst/Methode` mit JSON im Body; aufrufbar mit `curl` ebenso wie mit `fetch` im Browser | ja (**gewählt**) |
| **gRPC** | Dasselbe Prinzip aus Dienst und Methode, aber über binäres protobuf und HTTP/2; schnell und gut für Streaming geeignet | ja (**zwischen Diensten**) |
| gRPC-web | Eine für den Browser angepasste Variante von gRPC | ja (bei Bedarf) |
| GraphQL | Abfragesprache, mit der man genau die benötigten Felder anfordert | teilweise (**nur für lesende Abfragen**) |
| WASM | Führt Rust-Code direkt im Browser aus | nein (Technik für die Oberfläche) |

- **APIs, die von Browseroberflächen oder per `curl` aufgerufen werden, verwenden Connect** (POST; JSON wird mit RS-JSON gelesen und geschrieben). WASM im Browser kann kein reines gRPC sprechen. Mit Connect bleibt es bei einem gewöhnlichen `fetch`, und `prost` ist nicht nötig – die WASM-Datei wird dadurch nicht größer.
- **Für die Kommunikation zwischen Diensten (Server zu Server, rechenintensive Aufgaben, Streaming) wird gRPC eingesetzt.** In den meisten Fällen reicht Connect aus; auf gRPC wird nur dort umgestellt, wo Streaming tatsächlich gebraucht wird.
- **GraphQL dient ausschließlich lesenden Abfragen**, wenn mehrere Informationen gebündelt abgefragt werden sollen. Für Schreibzugriffe (Operationen) wird es nicht verwendet.
- **WASM bleibt die Technik für die Oberfläche.** Geändert hat sich lediglich, dass die aufgerufene API nun auf Connect beruht.
- Schnittstellen, deren Form durch einen externen Standard festgelegt ist (ACME, OAuth-Callbacks, Webhooks von Drittanbietern, Health-Checks, statische Dateien, OTLP), bleiben gewöhnliches HTTP.
- **Im Zweifel: Connect.**

### Русский (перевод выполнен с помощью ИИ и литературно отредактирован; носителями языка пока не проверен)
**Это не варианты, из которых нужно выбрать один, а технологии разных уровней.** Заменить REST могут только Connect, gRPC и GraphQL; WASM же — это способ создания пользовательского интерфейса.

| Термин | Что это | Заменяет REST? |
|---|---|---|
| REST | Стиль построения API, при котором операции выражаются через URL и HTTP-методы | отменяется |
| **Connect** | `POST /Сервис/Метод` с телом в формате JSON; вызывается как из `curl`, так и из браузерного `fetch` | да (**выбран**) |
| **gRPC** | Тот же принцип «сервис — метод», но поверх двоичного формата protobuf и HTTP/2; работает быстро и хорошо подходит для потоковой передачи | да (**для связи между сервисами**) |
| gRPC-web | Адаптированный для браузера вариант gRPC | да (при необходимости) |
| GraphQL | Язык запросов: клиент запрашивает ровно те поля, которые ему нужны | частично (**только запросы на чтение**) |
| WASM | Позволяет выполнять код на Rust прямо в браузере | нет (технология для интерфейса) |

- **API, которые вызываются из браузерных интерфейсов или через `curl`, строятся на Connect** (POST; JSON читается и записывается через RS-JSON). Браузерный WASM не умеет работать с «чистым» gRPC. С Connect достаточно обычного `fetch`, а `prost` не требуется — размер WASM-файла не увеличивается.
- **Для обмена между сервисами (сервер — сервер, ресурсоёмкие задачи, потоковая передача) применяется gRPC.** В большинстве случаев достаточно Connect; на gRPC переходят только там, где потоковая передача действительно необходима.
- **GraphQL используется только для чтения**, когда нужно получить сразу несколько связанных данных. Для записи (операций) он не применяется.
- **WASM по-прежнему остаётся технологией для интерфейса.** Изменилось лишь то, что вызываемый им API теперь построен на Connect.
- Интерфейсы, форма которых задана внешним стандартом (ACME, обратные вызовы OAuth, вебхуки сторонних сервисов, проверки работоспособности, статические файлы, OTLP), остаются обычным HTTP.
- **Если есть сомнения — выбирайте Connect.**

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

