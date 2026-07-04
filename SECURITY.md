# Security Policy

This document describes how to report security vulnerabilities for the
**gbf-core** repository and what response you can expect from the maintainers.

## Reporting a Vulnerability

The ginkgobackup.com team takes security reports seriously. gbf-core is the
cryptographic and storage engine of a zero-knowledge backup product, so any
weakness in key derivation, encryption, chunking, or on-disk format handling
is treated as a critical issue.

- **Do NOT open a public GitHub issue** to report a security vulnerability.
  Public issues, pull requests, discussions, and social media posts about
  active vulnerabilities are not a supported reporting channel and may delay
  remediation.
- **Email** your report to **security@ginkgobackup.com**.
- Where possible, include:
  - A description of the issue and its security impact
  - The exact version or commit hash affected
  - The platform and Go toolchain version used to reproduce
  - A minimal reproduction (code, input file, or step list)
  - Suggested mitigation or fix, if any
- **PGP encryption is strongly recommended.** Encrypt the report to the
  published ginkgobackup.com security key. Sending the encrypted report first
  and then the key fingerprint over a separate channel is acceptable if you
  cannot obtain the key from a trusted source.

Please give us **at least 90 days** before publicly disclosing any report, to
allow time for a fix and a coordinated release.

## Response Timelines

| Stage | Target |
| --- | --- |
| Acknowledgement of receipt | Within **48 hours** |
| Initial assessment and triage | Within **7 days** |
| Fix or mitigation released | Within **90 days** of confirmation |

We will keep you informed of progress at each stage and will credit you in the
release notes unless you request otherwise. If a reported issue is declined as
out of scope or not a vulnerability, we will explain why.

## Supported Versions

Only the latest minor release line receives security fixes. When a new minor
version is released, the previous line receives fixes for **30 days** before
end-of-life.

| Version | Supported | Notes |
| --- | --- | --- |
| 0.2.x | :white_check_mark: | Active development |
| 0.1.x | :white_check_mark: | Security fixes only (30-day overlap after 0.2.0) |
| < 0.1 | :x: | Not supported |

## Scope

This policy applies **only** to the `github.com/ginkgobackup/gbf-core`
repository, including its packages `crypto/`, `simple/`, `compress/`,
`fsutil/`, `ratelimit/`, `vault/`, and `cmd/`.

The following are **out of scope** for this repository and have their own
security channels, if any:

- The Ginkgo Backup cloud replication service (S3, SFTP, WebDAV, Dropbox,
  Google Drive, OneDrive)
- The commercial license management and activation server
- The Ginkgo Backup desktop application, tray, and OS integrations
- The Obsidian plugin runtime and its distribution channel

Vulnerabilities in third-party dependencies should be reported to the
upstream maintainer directly. We will track and update affected dependencies
as fixes become available.

## What You Should Not Report

- General support questions (use GitHub Discussions)
- Feature requests
- Vulnerabilities in dependencies that have no public fix available and that
  we do not use in a vulnerable configuration
- Issues that require physical access to the user's machine or a
  fully-compromised host
