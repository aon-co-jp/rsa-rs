# rsa-rs (Deutsch)

> ⚠️ **KI-Übersetzung – noch nicht von Muttersprachlern geprüft.** Maßgeblich sind die japanische/englische [README](../README.md).
> ⚠️ **Experimentell. Von keiner dritten Partei kryptografisch auditiert.** Konstante Laufzeit wurde nur stichprobenartig gemessen, nicht bewiesen.

**Kurz:** `rsa-rs` ist ein kompatibler Ersatz für den Teil der Rust-Crate `rsa`, den `ssh-key`/`russh` (Signaturen, PKCS#1 v1.5) und `sqlx-mysql`
(nur OAEP-Verschlüsselung mit öffentlichem Schlüssel) nutzen. Ziel: RUSTSEC-2023-0071 (Marvin-Angriff) umgehen, für den es keine korrigierte `rsa`-Version gibt.
Geschrieben nach RFC 8017; nicht veröffentlicht auf crates.io.

## Inhalt
1. [Aufbau](#aufbau) 2. [Verwendung](#verwendung) 3. [Schutzmaßnahmen](#schutzmaßnahmen) 4. [Prüfungen](#prüfungen) 5. [Grenzen](#grenzen) 6. [Aktueller Stand](#aktueller-stand)

## Aufbau
* `core/` – Kern (RSADP mit Blinding + CRT + Ergebnisprüfung, PKCS#1-v1.5-Signatur, OAEP, Schlüsselerzeugung).
* `compat-0.10/` – Crate `rsa` 0.10.0-rc.18 (für `ssh-key`, `russh`). `compat-0.9/` – Crate `rsa` 0.9.10 (nur öffentlicher Schlüssel + OAEP, für `sqlx-mysql`).

## Verwendung
```toml
[patch.crates-io]
rsa = { path = "../rsa-rs/compat-0.10" }
rsa-090 = { package = "rsa", path = "../rsa-rs/compat-0.9" }
```
`crypto-bigint >= 0.7.10` ist Pflicht (`cargo update -p crypto-bigint --precise 0.7.10`). Siehe [PORTING.md](../PORTING.md).

## Schutzmaßnahmen
Immer aktives Blinding; Prüfung des CRT-Ergebnisses (kein Ergebnis bei Fehler); Signaturprüfung durch erneute Kodierung und Vergleich;
OAEP-Dekodierung ohne Verzweigungen und mit nur einem Fehlertyp; **keine** PKCS#1-v1.5-Entschlüsselung (Bleichenbacher/Marvin-Angriffsfläche entfällt); Zeroize.

## Prüfungen
Bekannte-Antwort-Tests (OpenSSL, byte-identische Signaturen; RFC 8017 §9.2), **Wycheproof** (RSA-Signaturprüfung und OAEP), `ssh-key`-eigene Tests,
`ssh-keygen -Y sign/verify` in beide Richtungen, `openssl`-Entschlüsselung unserer OAEP-Chiffretexte, Build von `sqlx-mysql` 0.8.6 und `russh` 0.63 (open-web-server).

## Grenzen
Kein externes Audit; keine Prüfung auf Befehlsebene (Disassembly); Zeitmessung nur mit einfachem t-Test; PSS, PKCS#1-v1.5-Verschlüsselung, Multi-Prime, serde nicht implementiert; nur Linux/WSL getestet.

## Aktueller Stand
Wird automatisch erzeugt: [STATUS.md](../STATUS.md) / [status.json](../status.json) (aktualisiert durch `scripts/update-status.sh` bzw. `scripts/nightly.sh`).
