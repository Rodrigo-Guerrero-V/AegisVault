# Changelog

All notable changes to AegisVault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-11-11

### Security
- Added Content Security Policy for WebView2.
- Authenticated vault_config (prefs_nonce/prefs_ciphertext, vk_keycheck, hello_mac).
- Added CI and Release workflows with build provenance and SHA256SUMS; releases are built by CI.
- Added KDF limits on vault load, bounded backup reads, and Rust file dialogs for exports.
- DACL now uses the explicit TokenUser SID (no OWNER RIGHTS).
- ProtectedKey is page-locked and caches are zeroized.
- Corrupt AEAD rows are surfaced on export instead of silently skipped.
- Master and backup passwords now require zxcvbn >= 3; added KDF concurrency limit and unlock backoff.
- TOTP now supports SHA256/SHA512, with percent-decoding and validation.
- WDA_EXCLUDEFROMCAPTURE is on by default, with a Settings toggle; secret inputs are masked.
- PIN/card notes are visible, deletes require confirmation, and imports deduplicate.
- Test suite grown to 20 tests.

### Fixed
- Fixed a potential TOTP panic on multibyte input at a byte boundary.
- Made the ACL test robust on GitHub runners (SDDL abbreviates the admin SID as LA).

## [0.1.0] - 2026-11-11

### Added
- Initial public release: local-first, zero-knowledge password manager (Tauri v2, Windows).
- AES-256-GCM vault with Argon2id, TOTP, Windows Hello, backup/restore (.aegisvault), dark/light themes.
