# Changelog

All notable changes to **gbf-core** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] / v0.2.0

### Security
- Hardened cryptographic key handling in the `simple/` engine.
- Removed plaintext keyfile path leakage from error messages and manifests.
- Enforced `0600` file permissions on key files and blob writes on Unix.
- Randomized the CDC polynomial seed per repository to prevent
  cross-repo chunk correlation.
- Tightened nonce reuse checks in the AES-256-GCM encryptor.

### Added
- Open-source governance files: `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `NOTICE`, `CHANGELOG.md`.
- GitHub issue templates (bug report, feature request) and issue chooser.
- Pull request template.
- GitHub Actions CI workflow (`lint`, `test`, `vet`, `build`).

### Changed
- Updated contribution and security reporting expectations in `README.md`.

## [v0.1.0] - 2026-05-11

### Added
- Initial open-source release of gbf-core, the encryption and
  content-addressed storage engine for Ginkgo Backup.
- `crypto/` — AES-256-GCM encryption with HKDF key derivation.
- `simple/keys.go` — Argon2id key derivation for password-based keys.
- `simple/chunk_cdc.go` — content-defined chunking (CDC) for deduplication.
- `simple/` — GBF format: blob store, manifest, snapshot pipeline,
  restore pipeline, local storage engine.
- `compress/` — zstd, deflate, s2, none compression backends.
- `ratelimit/` — token bucket rate limiter.
- `fsutil/` — atomic writes and ignore patterns.
- `vault/` — minimal encryptor interface.
- `cmd/demo/` — end-to-end backup + restore demo.
- Apache-2.0 license and `README.md`.

[Unreleased]: https://github.com/ginkgobackup/gbf-core/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/ginkgobackup/gbf-core/releases/tag/v0.1.0
