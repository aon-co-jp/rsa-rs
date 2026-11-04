# PORTING.md — 依存元への導入 / Adopting rsa-rs in a repository

## 日本語

### 1. 何が `rsa` を引いているか確認
```bash
cargo tree -i rsa            # 通常ビルド。空なら Cargo.lock にだけ載っている (ビルドされない)
cargo tree -i rsa -e all --target all
```
* `sqlx-mysql 0.8.x` → `rsa 0.9.x` (OAEP 暗号化のみ) → **`compat-0.9`**
* `russh 0.62/0.63`, `ssh-key 0.7.0-rc.x` → `rsa 0.10.0-rc.x` (署名/検証) → **`compat-0.10`**

### 2. `Cargo.toml` に追加 (小さな別コミットで)
```toml
[patch.crates-io]
rsa = { path = "../rsa-rs/compat-0.10" }
rsa-090 = { package = "rsa", path = "../rsa-rs/compat-0.9" }   # 0.9.x を引く場合のみ
```
CI では `rsa-rs` を兄弟ディレクトリに checkout する (open-web-server の `open-cpu` と同じ方式)。
`git = ` 指定にする場合は非公開リポジトリの認証が必要。

### 3. ロックの更新
```bash
cargo update -p crypto-bigint --precise 0.7.10   # 互換層の要求。ctutils も追従して上がる
cargo build && cargo test
```
`failed to select a version for crypto-bigint` が出たら、上の update を先に行う。

### 4. 受け入れ確認
* 通常ビルドに `rsa` が出る場合: `cargo tree -i rsa` が `(…/rsa-rs/compat-…)` を指すこと。
* 署名を使う場合: `ssh-keygen -Y verify` で相互運用を確認 (`scripts/interop.sh` 参照)。
* `cargo audit` で RUSTSEC-2023-0071 が消えること (patch 後は `rsa` が registry 由来ではなくなる)。
  ※ audit が path 依存を無視するだけで、安全性を意味しない。README の限界を理解した上で運用する。

### 5. 互換の差 (上流との違い)
* PSS、PKCS#1 v1.5 暗号化、multi-prime、serde、`hazmat` は無い。呼ぶとコンパイルエラー。
* 署名/復号は常にブラインディングする (rng を渡さない API でも OS 乱数を使う)。
* 3 素数以上の秘密鍵は `from_components` が `Error::InvalidPrime` を返す。
* `RsaPrivateKey::validate()` は構築時に検査済みのため常に `Ok`。
* `compat-0.9` は公開鍵と OAEP 暗号化のみ。

### 6. 新しい API が必要になったら
依存元のソースで実際の呼び出しを確認 → RFC 8017 の該当節を根拠に `core/` へ → 既知回答テスト → 互換層の薄いラッパ。

## English

1. Find who pulls `rsa`: `cargo tree -i rsa` (empty ⇒ lockfile-only). `sqlx-mysql` → `compat-0.9`; `russh`/`ssh-key` → `compat-0.10`.
2. Add `[patch.crates-io]` entries (see above) in a small separate commit; check out `rsa-rs` as a sibling directory in CI.
3. `cargo update -p crypto-bigint --precise 0.7.10`, then build and test.
4. Acceptance: `cargo tree -i rsa` points at the compat path; verify signatures with `ssh-keygen -Y verify`.
   Note that `cargo audit` silencing RUSTSEC-2023-0071 only means the registry crate is gone — read the README limitations.
5. Differences from upstream: no PSS / PKCS#1 v1.5 encryption / multi-prime / serde / hazmat; blinding is always on.
6. For new API: confirm the real call in the dependent's source → implement in `core/` from RFC 8017 → known-answer test → thin wrapper.

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

### Deutsch (KI-Übersetzung, noch nicht von Muttersprachlern geprüft)
- **REST wird abgeschafft. Neue APIs werden nicht als REST gebaut.** APIs, die aus dem Browser oder mit `curl` aufgerufen werden, nutzen **Connect-Unary-Aufrufe** (`POST /<Paket>.<Service>/<Methode>`, `content-type: application/json`, JSON-Body); zwischen Diensten gilt **gRPC / gRPC-web** (wie bei der Admin-API von RPoem, `open_runo.admin.v1.Admin`). Streaming erst, wenn es wirklich nötig ist.
- **Bestehende REST-Endpunkte werden einzeln migriert, sobald man sie anfasst.** Nach der Migration wird die alte REST-Route entfernt. Bis dahin bleiben sie bestehen, es werden aber **keine neuen hinzugefügt**.
- **JSON wird auf RS-JSON vereinheitlicht**: Lesen mit `from_str_secure` / `parse_secure` (Grenzen für Größe, Tiefe und doppelte Schlüssel), Schreiben mit `rust_json::fast`. `prost` kommt nicht in Browser-WASM (die Datei würde größer).
- **Ausnahmen (Formate, die ein fremder Standard vorgibt, nicht unsere eigene API)**: ACME, OAuth/OIDC-Callbacks, Webhooks von Dritten (z. B. GitHub), Health-Checks, statische Dateien, OTLP usw. Diese nehmen schlichtes HTTP entgegen, wie es der Standard verlangt.
- Referenzimplementierungen: `RPoem` (`open_runo.admin.v1.Admin`) und `open-easy-web` (`server/src/connect.rs`, `proto/open_easy_web/admin/v1/admin.proto`).
- Hinweis: Ob der Code eines Repositorys diese Richtlinie schon befolgt, hängt vom jeweiligen Repository ab. Dieser Abschnitt hält die Richtlinie fest; er bedeutet nicht, dass der Code bereits geändert wurde.

### Русский (машинный перевод, носителями языка ещё не проверен)
- **REST полностью отменяется. Новые API не создаются как REST.** API, вызываемые из браузера или через `curl`, используют **унарные вызовы Connect** (`POST /<пакет>.<Service>/<Method>`, `content-type: application/json`, тело — JSON); между сервисами — **gRPC / gRPC-web** (так же, как административный API RPoem, `open_runo.admin.v1.Admin`). Потоковая передача — только когда она действительно нужна.
- **Существующие REST-эндпоинты переносятся по одному, когда до них доходят руки.** После переноса старый REST-маршрут удаляется. До завершения переноса они остаются, но **новые не добавляются**.
- **JSON унифицируется на RS-JSON**: чтение через `from_str_secure` / `parse_secure` (ограничения на размер, глубину и повторяющиеся ключи), запись через `rust_json::fast`. `prost` не добавляется в браузерный WASM (размер вырос бы).
- **Исключения (форматы, заданные чужим стандартом, а не наш собственный API)**: ACME, обратные вызовы OAuth/OIDC, вебхуки сторонних сервисов (например, GitHub), проверки работоспособности, раздача статических файлов, OTLP и т. п. Они принимают обычный HTTP, как требует стандарт.
- Эталонные реализации: `RPoem` (`open_runo.admin.v1.Admin`) и `open-easy-web` (`server/src/connect.rs`, `proto/open_easy_web/admin/v1/admin.proto`).
- Примечание: соответствует ли код конкретного репозитория этой политике, зависит от самого репозитория. Этот раздел фиксирует политику и не означает, что код уже изменён.
