# RESEARCH — RSA 最新動向の調査と採用判断 / Research log and design decisions

調査日 / Researched: 2026-11-04。出典の文章は転載せず要約。未確認の点は「未確認」と明記。
Sources are summarised, not quoted. Anything not confirmed is marked as such.

---

## 日本語

### 1. RUSTSEC-2023-0071(Marvin Attack)の経緯
* 2023-11 に報告・公開。`rsa` クレートの実装が定数時間でなく、ネットワークから観測できる時間差で秘密鍵が漏れうる(CVE-2023-49092、CVSS 5.9、攻撃難度は高)。
  確認時点(2026-09)で影響は 0.9.10(最新安定)と 0.10.0-rc.18、**修正版なし**。
* 助言の回避策は「攻撃者が時間を観測できる用途(ネットワーク越し)で使わない」。進行中の作業として、暗黙の拒否(PR #680)とデフォルト経路のブラインディング(PR #702)、
  PKCS#1 v1.5 パディングが定数時間でない問題(issue #626)が挙がっている。`crypto-bigint` への移行(PR #394)だけでは解決しなかった。
* 出典: <https://rustsec.org/advisories/RUSTSEC-2023-0071.html> 、Marvin 本家 <https://people.redhat.com/~hkario/marvin/> 、Red Hat 解説 <https://www.redhat.com/en/blog/marvin-attack>
* **採用**: 本リポジトリは (a) 秘密鍵演算に常時ブラインディング、(b) PKCS#1 v1.5 *復号を実装しない*(Marvin/Bleichenbacher の主戦場を持たない)、(c) OAEP 復号は単一エラー+マスク演算、とした。
  PR #680/#702 の中身は本調査では未確認(要約のみ参照)。

### 2. 他実装の対策(確認できた範囲)
* Marvin の調査では OpenSSL・NSS・Linux カーネル・libgcrypt・Java・Go など多くが何らかの時間漏れを持っていた(Red Hat の記事)。推奨は OAEP への移行と PKCS#1 v1.5 暗号化の無効化。
* **暗黙の拒否(implicit rejection)**: 不正パディングでエラーを返さず、秘密指数と暗号文から導いた疑似乱数の平文を返して成否を区別させない方式。OpenSSL は 3.2 系以降で有効という報告があり、
  CVE-2025-0306 関連のパッチで PKCS#1 v1.5 復号に導入・無効化オプションが付いた(Yocto の patchwork 経由の二次情報)。出典: <https://patchwork.yoctoproject.org/comment/29665>
* Go: 標準ライブラリの定数時間多倍長演算 `bigmod`(現在は `crypto/internal/fips140/bigmod`、別モジュール `filippo.io/bigmod` は API 不安定)。
  出典: <https://pkg.go.dev/filippo.io/bigmod> 。Go 1.20 での `math/big` からの置換の経緯は今回の検索では**未確認**。
* BoringSSL・Botan の個別の最新手法は今回の検索では**未確認**(次回調査項目)。
* **採用**: 暗黙の拒否は *PKCS#1 v1.5 復号を持たないため不要*(実装しないことで回避)。採用しなかった理由: 依存元(ssh-key/russh/sqlx-mysql)がその API を呼ばず、
  攻撃面を増やすだけだから。必要になったら RFC 8017 + 上記の考え方で追加し、既知回答テストを付ける。

### 3. `crypto-bigint` 0.7 系の注意点
* **RUSTSEC-2026-0387**(2026-10 公開): 定数時間のはずの演算(減算・ゼロ数え・除算・モンゴメリ乗算、`UintRef` の等値比較、`BoxedMontyForm::invert` の存在判定)が、
  コンパイラ/CPU によって秘密依存の分岐になりうる。**0.7.6 で修正**。出典: <https://osv.dev/vulnerability/RUSTSEC-2026-0387>
* **採用**: 本リポジトリは `crypto-bigint >= 0.7.10` を要求(0.7.10 は registry 上の最新確認版)。ロックが 0.7.5 以前だと解決に失敗する=意図した動作。
  ただし 0.7.6 以降でも命令列レベルの確認は本リポジトリでは**未実施**。

### 4. Wycheproof
* 現行のテストベクタは `C2SP/wycheproof` の `testvectors_v1/` に統合されている。`rsa_signature_2048_sha256_test.json` の存在は BoringSSL のミラーで確認。
  OAEP のファイル名は今回**未確認**。出典: <https://github.com/C2SP/wycheproof>
* **現状 (更新)**: RSA 署名検証 7 ファイルと OAEP 復号 5 ファイルを `core/tests/wycheproof/` に取り込み、全件通過 (2026-11-04)。SHA-1 署名・PSS・他の鍵長は今後。
  `core/tests/` に回帰テストとして追加する(未完了項目)。

### 5. 採用した対策 / 採用しなかった対策
| 項目 | 判断 | 理由 |
|---|---|---|
| 常時ブラインディング | 採用 | 上流の弱点(rng 無しでは無効)を避ける |
| CRT 後の再検証 | 採用 | フォールト攻撃(Bellcore)対策 |
| OAEP 単一エラー+マスク | 採用 | Manger 型オラクル対策 |
| 検証は EM 再構成して比較 | 採用 | RFC 8017 §8.2.2、解析バグ(Bleichenbacher 署名偽造)を避ける |
| PKCS#1 v1.5 復号 | 不採用 | 呼び出しが無い。暗黙の拒否の実装・検証コストと攻撃面を避ける |
| PSS | 不採用(未実装) | 依存元が呼ばない |
| multi-prime | 不採用 | ssh-key が非対応 |
| crypto-bigint の置き換え | 不採用 | 自前の多倍長は更にリスクが高い |

---

## English

### 1. RUSTSEC-2023-0071 (Marvin Attack)
* Reported 2023-11. The `rsa` crate is not constant time; network-observable timing can leak the private key (CVE-2023-49092, CVSS 5.9, high complexity).
  As of the check (2026-09) 0.9.10 and 0.10.0-rc.18 are affected and **no fixed release exists**.
* The advisory's workaround is not to use the crate where timing is observable. Listed work in progress: implicit rejection (PR #680), blinding on the default path (PR #702),
  non-constant-time PKCS#1 v1.5 padding (issue #626). Moving to `crypto-bigint` (PR #394) alone did not fix it.
* Sources: the RustSec page above; the Marvin page; Red Hat's write-up.
* **Adopted**: always-on blinding; *no PKCS#1 v1.5 decryption at all*; OAEP decoding with one error kind and mask arithmetic. The contents of PRs #680/#702 were *not* reviewed here.

### 2. Other implementations (what could be confirmed)
* Red Hat's survey found timing leaks in OpenSSL, NSS, the Linux kernel, libgcrypt, Java and Go; advice: prefer OAEP, disable PKCS#1 v1.5 encryption.
* **Implicit rejection** returns a pseudo-random plaintext derived from the private exponent and ciphertext instead of an error. OpenSSL is reported to enable it from 3.2.x
  (secondary source via Yocto patchwork). Go's constant-time `bigmod` is documented at pkg.go.dev; the Go 1.20 migration history, BoringSSL and Botan specifics were **not confirmed** in this pass.
* **Decision**: implicit rejection is unnecessary because there is no PKCS#1 v1.5 decryption; add it (RFC 8017 + known-answer tests) only if a dependent ever needs it.

### 3. `crypto-bigint` 0.7 caveats
* **RUSTSEC-2026-0387** (published 2026-10): operations meant to be constant time (subtraction, zero counting, division, Montgomery multiplication, `UintRef` equality,
  `BoxedMontyForm::invert` existence check) could branch on secrets depending on compiler/CPU. **Fixed in 0.7.6**.
* **Decision**: require `crypto-bigint >= 0.7.10`. Instruction-level review of the generated code is **not done** here.

### 4. Wycheproof
* Current vectors live in `testvectors_v1/` of `C2SP/wycheproof`; the RSA signature file name was confirmed via a BoringSSL mirror, the OAEP file name was not.
* **Status (updated)**: 3 RSA signature files and 2 OAEP files are imported under `core/tests/wycheproof/` and all pass (2026-11-04); other sizes/hashes remain.

### 5. Adopted vs not adopted
See the table above (Japanese section): blinding, post-CRT check, single-error OAEP, verify-by-re-encoding adopted;
PKCS#1 v1.5 decryption, PSS, multi-prime, own bignum rejected (no callers / more risk).
