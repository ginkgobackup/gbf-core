# gbf-core

The core encryption and content-addressed storage engine powering [Ginkgo Backup](https://ginkgobackup.com).

## Status

Released under Apache 2.0. The code in this repository is extracted from the main Ginkgo Backup codebase and is independently buildable and testable.

## What's included

- **AES-256-GCM encryption** with HKDF key derivation (`crypto/`)
- **Argon2id key derivation** for password-based keys (`simple/keys.go`)
- **Content-addressed chunking** (CDC) for binary deduplication (`simple/chunk_cdc.go`)
- **GBF format** — blob store, manifest, snapshot pipeline (`simple/`)
- **Local storage engine** — blob read/write/verify (`simple/local_store.go`)
- **Restore pipeline** — snapshot → file reconstruction (`simple/restore.go`)
- **Compression** — zstd, deflate, s2, none (`compress/`)
- **Rate limiting** — token bucket writer (`ratelimit/`)
- **Filesystem utilities** — atomic writes, ignore patterns (`fsutil/`)

## Repository structure

```
gbf-core/
├── vault/         Encryptor interface (3 methods, zero dependencies)
├── crypto/        AES-256-GCM + HKDF implementation
├── simple/        GBF storage engine (15 source + 7 test files)
├── compress/      Compression backends (zstd, deflate, s2, none)
├── fsutil/        Filesystem helpers (atomic write, ignore patterns)
├── ratelimit/     Token bucket rate limiter
├── go.mod         module github.com/ginkgobackup/gbf-core
└── LICENSE        Apache-2.0
```

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
