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
- Reject encrypted blobs (GB1/GB2) that carry trailing data after the
  final chunk, preventing silent truncation/corruption ambiguity.

### Fixed
- `PipelineConfig.CloudID` is now honored: an explicit CloudID takes
  precedence over the derived `device_src` key for manifest storage and
  incremental baselining.
- A scan that hits unreadable paths fails the run by default instead of
  committing a manifest that misreports the missing files as deleted.
  Opt in with `PipelineConfig.AllowScanErrors`; such incomplete snapshots
  record `Stats.ScanErrors` and are skipped as incremental baselines.
- Restore now validates every path component and refuses to traverse
  pre-existing symlinks/junctions inside the target directory, closing a
  directory-traversal escape on restore. On POSIX this is kernel-level
  PREVENTION: all restore writes go through openat(O_NOFOLLOW)/mkdirat/
  renameat/utimensat chains relative to directory fds, so a component
  swapped for a symlink fails the syscall itself — there is no
  check-then-write window. On Windows the defense remains detection-based
  (pre-write verification + post-write re-check of every file AND of the
  empty-directory skeleton), documented as a platform gap in SECURITY.md.
- The token-bucket rate limiter accumulates fractional tokens, so rates
  of 1-9 bytes/s no longer stall; `SetRate` can also enable limiting on
  a limiter initialized with rate zero.
- Manifest commits are now CROSS-PROCESS no-replace: the staged manifest
  is committed via an atomic link(2) (POSIX) or MoveFileEx without
  REPLACE_EXISTING (Windows), so two processes saving the same
  cloudID/second can never silently overwrite each other — the loser
  retries under a random same-second suffix. Within one process the saves
  are additionally serialized by a mutex. `LoadLatestManifest` falls back
  to the newest intact manifest when the latest one is corrupted; a crash
  between the manifest commit and its checksum sidecar leaves a
  sidecar-less manifest that loaders reject and skip, effectively rolling
  back the interrupted save without ever damaging another save's files.
- Small-file restore writes go through `fsutil.WriteFileAtomic` instead
  of ad-hoc `.tmp` files, unifying durability guarantees.
- The ignore size filter rejects bounds above `math.MaxInt64` instead of
  overflowing.
- The AES-GCM instance cache is bounded by a STRICT cap
  (`maxGCMCacheEntries`): insertions are size-checked under a mutex, so
  the cache never exceeds the cap even transiently under concurrency,
  ending unbounded memory growth under many distinct keys.

### Added
- Open-source governance files: `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `NOTICE`, `CHANGELOG.md`.
- GitHub issue templates (bug report, feature request) and issue chooser.
- Pull request template.
- GitHub Actions CI workflow: `lint` (golangci-lint), `fmt` (gofmt gate),
  `vet`, and `build`/`test` (with race detector and coverage) on Linux,
  Windows, and macOS.
- Weekly `govulncheck` vulnerability scanning workflow and Dependabot
  dependency updates.
- Tag-driven release workflow with cross-platform demo binaries attached
  to GitHub Releases.
- `compress.NewCompressorStrict` for strict compressor-type validation.
- On-disk format fixture test (`simple/testdata`) pinning the manifest
  and blob formats against accidental drift.
- Regression tests for CloudID precedence, scan-error semantics, symlink
  defense (including a real Windows junction), post-write link re-check,
  low-rate limiting, manifest fallback, concurrent same-second manifest
  saves, Unix permission-denied scans, strict AES cache cap under
  concurrency, size-filter overflow, and GB1/GB2 trailing-data rejection.

### Changed
- Updated contribution and security reporting expectations in `README.md`.

### Compatibility
- The exported `simple.ManifestDecryptHook` variable is retained: direct
  assignment (the pre-0.2 registration style) keeps working, and it shares
  storage with `SetManifestDecryptHook`/`GetManifestDecryptHook`. Direct
  assignment remains safe for startup-time registration, before any
  manifest-loading goroutine starts.

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
