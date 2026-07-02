# gbf-core

The core encryption and content-addressed storage engine powering [Ginkgo Backup](https://ginkgobackup.com).

## Status

This repository is being prepared for public release. The code is currently being extracted from the main Ginkgo Backup codebase and will be published here under Apache 2.0.

## What will be open sourced

- **AES-256-GCM encryption** with HKDF key derivation
- **Content-addressed chunking** (CDC) for binary deduplication
- **GBF format** — blob store, manifest, snapshot pipeline
- **Local storage engine** — blob read/write/verify
- **Restore pipeline** — snapshot → file reconstruction

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
