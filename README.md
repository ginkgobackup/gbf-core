# gbf-core

The core encryption and content-addressed storage engine powering [Ginkgo Backup](https://ginkgobackup.com).

## Status

Released under Apache 2.0. The code in this repository is extracted from the main Ginkgo Backup codebase and is independently buildable and testable. The API is pre-1.0 and may change between minor versions until v1.0.

## Quickstart

Verify the engine actually runs a backup, end to end:

```bash
git clone https://github.com/ginkgobackup/gbf-core
cd gbf-core
go run ./cmd/demo/
```

The demo initializes an encrypted repo (GEK1 format), backs up three test files, runs an incremental pass (dedup), restores them, and verifies content integrity.

## What's included

- **AES-256-GCM encryption** with HKDF key derivation (`crypto/`)
- **Argon2id key derivation** for password-based keys (`simple/keys.go`)
- **Content-addressed chunking** (CDC) for binary deduplication (`simple/chunk_cdc.go`)
- **GBF format** — blob store, manifest, snapshot pipeline (`simple/`)
- **Local storage engine** — blob read/write with atomic commits (`simple/local_store.go`)
- **Restore pipeline** — snapshot → file reconstruction (`simple/restore.go`)
- **Compression** — zstd, deflate, s2, none (`compress/`)
- **Rate limiting** — token bucket writer (`ratelimit/`)
- **Filesystem utilities** — atomic writes, ignore patterns (`fsutil/`)

## Repository structure

```
gbf-core/
├── cmd/demo/      End-to-end backup + restore demo
├── vault/         Encryptor interface (3 methods, zero dependencies)
├── crypto/        AES-256-GCM + HKDF implementation
├── simple/        GBF storage engine (15 source + 7 test files)
├── compress/      Compression backends (zstd, deflate, s2, none)
├── fsutil/        Filesystem helpers (atomic write, ignore patterns)
├── ratelimit/     Token bucket rate limiter
├── go.mod         module github.com/ginkgobackup/gbf-core
└── LICENSE        Apache-2.0
```

## On-disk format

Four magic byte prefixes identify the four blob kinds produced by this engine. They are not version-compatible with each other and a given file always carries exactly one:

| Magic    | Kind                 | Source                       | Layout                                                                                                |
|----------|----------------------|------------------------------|-------------------------------------------------------------------------------------------------------|
| `GB1\0`  | Small blob           | `simple.Encryptor.Encrypt`   | `magic` ‖ `nonce` ‖ `ciphertext` ‖ `tag` (single AEAD block)                                         |
| `GB2\0`  | Large multi-chunk blob | `simple.Encryptor.Encrypt`  | `magic` ‖ `chunkCount` ‖ for each chunk: `nonce` ‖ `ciphertext` ‖ `tag` (chunked AEAD with IV per chunk) |
| `GKM1`   | Encrypted manifest   | `simple.EncryptManifest`     | `magic` ‖ `nonce` ‖ `ciphertext` ‖ `tag` (manifest key derived via HKDF from the master key)         |
| `GEK1`   | Encrypted keyfile     | `simple/keys.go`             | `magic` ‖ `salt` ‖ `nonce` ‖ `ciphertext` ‖ `tag` (master key wrapped by Argon2id-derived key; Argon2id parameters are compile-time constants, see `simple/keys.go`) |

`GB1\0` and `GB2\0` are produced by the same encryptor and selected automatically based on plaintext size relative to the configured chunk size. The decryptor inspects the magic byte and handles either form transparently.

## Content-Defined Chunking (CDC)

CDC is **enabled by default** for files larger than the chunk size. It uses a Galois-field polynomial persisted per-repo in `config.json` (`cdcPolynomial`) so chunk boundaries are stable for a given repository but not shared across all installations. This means two installations backing up the same file produce different chunk boundaries, which is the intended property — it prevents cross-repo deduplication attacks while preserving intra-repo dedup.

To opt out (e.g. for already-chunked inputs where stable boundaries matter more than dedup), set `disable_cdc: true` in `config.json` before running a backup. Legacy repositories without a persisted polynomial fall back to deriving one on first run and persisting it.

## Metadata scope

A backup manifest records, per file:

- Relative path (relative to the source root)
- Size
- Modification time (RFC3339, with sub-microsecond precision where available)
- Permission mode bits (POSIX-style `uint32`, no ACL or extended attributes)
- Content hash (SHA-256 of plaintext, or per-chunk hashes when CDC is active)
- Per-chunk references (hash + size) when CDC is active

The manifest itself is stored compressed (zstd) and, when the repo is encrypted, additionally wrapped with `GKM1`. File contents are stored as `GB1`/`GB2` blobs in the blob store, encrypted with the master key. No plaintext file content is ever written to disk by the pipeline; the only plaintext that touches disk is the user's source files themselves.

The manifest does **not** collect: hostname, OS, username, environment variables, mount points, or any system fingerprint beyond the per-repo `deviceId` chosen at `InitRepo`.

## `vault` vs `simple` encryptors

Two encryptor interfaces exist and are intentionally distinct:

- **`vault.Encryptor`** — stateless, single-block AEAD. Takes the key per call, returns a bare `nonce‖ciphertext` with no framing. Used by `crypto.AESEncryptor` for HKDF-derived subkeys (e.g. manifest keys). Zero dependencies outside the standard library.
- **`simple.Encryptor`** — stateful, bound to a fixed master key and chunk size. Emits the `GB1`/`GB2` on-disk format with magic bytes, chunk counts, and per-chunk IVs. Lives in `simple/crypto.go`.

They do not share an interface because the contracts differ: one is a primitive AEAD wrapper, the other is a format-bound streaming encryptor. Forcing them under a common interface would imply interchangeability that does not exist. See `vault/encryptor.go` and `simple/doc.go` for the rationale.

## What stays proprietary

- Cloud replication (S3, SFTP, WebDAV, Dropbox, Google Drive, OneDrive)
- License management and activation
- Desktop UI, tray, system integration
- Obsidian plugin runtime

The open source component covers everything needed to audit the zero-knowledge encryption claims and the on-disk backup format. Cloud replication and productization remain commercial.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Why open source the core?

For a zero-knowledge backup tool, trust must be verifiable. Opening the encryption and storage engine means anyone can audit:

- That encryption happens locally before any data leaves the machine
- That the AES-256-GCM + HKDF construction is correctly implemented
- That the content-addressed storage format matches the documented spec
- That no plaintext metadata leaks through the blob store

The commercial product layers convenience and cloud replication on top. The trust foundation is open.

## Security reports

Email security@ginkgobackup.com. Do not open public issues for security vulnerabilities.
