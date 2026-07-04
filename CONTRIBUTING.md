# Contributing to gbf-core

First off, thank you for taking the time to contribute. gbf-core is the open
cryptographic and storage core of a zero-knowledge backup tool, so every
contribution is reviewed with care.

This document covers the expectations for contributing to the
`github.com/ginkgobackup/gbf-core` repository.

## Development Environment

- **Go 1.25 or newer** (the module is tracked at `go 1.25.5`).
- Git, with a GitHub account able to open pull requests.
- A POSIX-like shell or PowerShell; the test suite must pass on both Linux
  and Windows because the codebase has platform-specific filesystem helpers
  under `fsutil/`.

Clone and verify it builds:

```bash
git clone https://github.com/ginkgobackup/gbf-core
cd gbf-core
go build ./...
go test ./...
```

## Project Layout

| Path | Purpose |
| --- | --- |
| `crypto/` | AES-256-GCM + HKDF primitives |
| `simple/` | GBF storage engine: blob store, manifest, pipeline, restore |
| `compress/` | Compression backends (zstd, deflate, s2, none) |
| `fsutil/` | Atomic writes, ignore patterns, platform helpers |
| `ratelimit/` | Token bucket rate limiter |
| `vault/` | Encryptor interface |
| `cmd/demo/` | End-to-end backup + restore demo |

## Build and Test

```bash
# Build everything
go build ./...

# Run the full test suite
go test ./...

# Race detector (recommended before sending a PR)
go test -race ./...

# Vet
go vet ./...

# Format
gofmt -s -w .
```

## Code Style

- **SPDX license header is mandatory** in every `.go` source file added or
  modified. Use the existing files as a template. The header line is:

  ```go
  // SPDX-License-Identifier: Apache-2.0
  ```

  Place it above the package clause, followed by the copyright line if
  appropriate.

- Run `gofmt -s -w .` before committing. CI enforces formatting.
- Run `go vet ./...` before committing. CI enforces vet.
- Prefer table-driven tests; follow the style already used in
  `crypto/aes_test.go` and `simple/keys_test.go`.
- Do not introduce new dependencies without justification. Any new dependency
  must be added to `go.mod`, listed in `NOTICE` with its license, and
  compatible with Apache-2.0.

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

<optional body explaining why, not what>

<optional footer: BREAKING CHANGE:, Fixes #..., etc.>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`,
`build`, `ci`. Scope is optional and usually a package name (`crypto`,
`simple`, `compress`, ...).

Keep the summary line under 72 characters. Use the imperative mood
("add", "fix", "remove"), not the past tense.

## Pull Request Flow

1. **Fork** the repository and clone your fork.
2. **Create a branch** off `master`:

   ```bash
   git checkout -b feat/my-change master
   ```

3. **Commit** your changes, one logical change per commit, using conventional
   commit messages.
4. **Rebase** on `master` if it has moved forward. Keep history clean.
5. **Push** to your fork.
6. **Open a Pull Request** against `gbf-core/master`. Fill in the PR template.
7. Respond to review feedback. New commits are fine; do not force-push during
   review unless asked.

### Signing

All commits merged to `master` must be **cryptographically signed** (GPG or
SSH signing, configured per the GitHub docs). Enable
`Always sign commits` in your git config or use `git commit -S`.
Unverified commits will not be merged.

## Licensing

gbf-core is licensed under the Apache License, Version 2.0. Contributions are
accepted under the same license on an **inbound = outbound** basis; no
Contributor License Agreement (CLA) is required.

By submitting a pull request, you confirm that:

- You own the contribution or have the right to submit it under Apache-2.0.
- The contribution is your original work or properly attributed.
- You add the SPDX header (`SPDX-License-Identifier: Apache-2.0`) to any new
  `.go` file you introduce.

If your contribution includes third-party code under a different license,
disclose it explicitly in the PR description so it can be added to `NOTICE`.

## Issue and Discussion Etiquette

- Bug reports go through the issue template.
- Feature requests go through the issue template.
- General questions and ideas go to GitHub Discussions.
- Security vulnerabilities go to `security@ginkgobackup.com`; do **not**
  open a public issue. See [SECURITY.md](SECURITY.md).

## Code of Conduct

Participation in this project is governed by the
[Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating
you are expected to uphold this code. Report unacceptable behavior to
`conduct@ginkgobackup.com`.
