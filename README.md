# rsa-rs

**日本語** | [English](#english) | [Deutsch](docs/README.de.md) | [Русский](docs/README.ru.md)

> 状態表(最新の上流 rsa / RUSTSEC の状況・試験結果)は自動更新される [STATUS.md](STATUS.md) / [status.json](status.json) を参照。
> **実験的・第三者監査なし**(下の「限界」参照)。

`rsa` クレートの **互換置き換え** (RUSTSEC-2023-0071 / Marvin Attack 対策)。aon-co-jp 配下のリポジトリが
依存経由で使っている範囲だけを、RFC 8017 に基づき自前で実装したものです。非公開リポジトリ。crates.io には公開しません。

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
| Wycheproof: RSA 署名検証 3 ファイル (valid/invalid 全件判定一致)、OAEP 復号 2 ファイル (Manger 系の不正パディングも全て拒否) | 全て pass (`core/tests/wycheproof.rs`) |
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

A **drop-in replacement for the part of the `rsa` crate** that aon-co-jp projects reach through their dependencies,
written from RFC 8017 to avoid RUSTSEC-2023-0071 (Marvin Attack; no fixed `rsa` release exists). Private repository; not published.

> ⚠️ **Not audited by any third party.** This is home-grown cryptography. Read "Limitations" before relying on it.

* `core/` — hash/RNG-agnostic core: keys, RSADP (CRT + blinding + post-check), PKCS#1 v1.5 signatures, OAEP, key generation.
* `compat-0.10/` — crate named `rsa` 0.10.0-rc.18, for `ssh-key 0.7.0-rc.11` / `russh`: signing, OAEP, PKCS#1/#8/SPKI.
* `compat-0.9/` — crate named `rsa` 0.9.10, for `sqlx-mysql 0.8.x`: **public key + OAEP encryption only**.

Use via `[patch.crates-io]` (see the Japanese section for the exact lines). `crypto-bigint >= 0.7.10` is required.

Not implemented (compile error if used): PSS, PKCS#1 v1.5 *encryption* (deliberately omitted), multi-prime keys, serde, `hazmat`.

Defences: blinding on every private-key operation (OS RNG even when the caller passes none), CRT with a post-computation
check `m'^e ≡ c'` (no result is released on mismatch), verification by re-encoding EM and comparing (no EM parsing),
OAEP decoding with branch-free masks and a single error kind, zeroization on drop.

Verified: byte-identical PKCS#1 v1.5 signatures vs OpenSSL, decryption of OpenSSL OAEP ciphertexts and vice-versa,
`ssh-key`'s own test-suite against the replacement, `ssh-keygen -Y sign/verify` both ways, `sqlx-mysql 0.8.6` and an
`open-web-server` clone (russh 0.63, `sftp`) build against the patch.

Limitations: no audit; constant-time behaviour only sampled with a crude t-test (|t| < 1) — **no instruction-level review was done**
and the bignum arithmetic's constant-time property is delegated to `crypto-bigint` 0.7.10+; Wycheproof only for RSA-2048/3072 PKCS#1 v1.5 verify and OAEP-2048 decrypt;
fixtures contain throw-away test keys; Linux/WSL only.

### 追記 / Note (2026-11-04)
* 上流 `rsa` には 0.10.0-rc.20 が既にある。互換層は `0.10.0-rc.18` を名乗るため、`russh`/`ssh-key` が rc.19 以降を要求するようになったら互換層の版を上げて再検証すること(`STATUS.md` で最新版を確認)。
  Upstream already has `rsa` 0.10.0-rc.20; the compat layer claims rc.18, so bump and re-verify when dependents move to a newer rc.
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
