<!-- Thanks for contributing to gbf-core! Please fill in the sections below. -->

## Summary

<!-- One or two sentences describing what this PR does and why. -->

## Motivation

<!-- Why is this change needed? Link any issues this closes (e.g. "Closes #123").
If this is a security-sensitive change, do NOT put details here — coordinate
with security@ginkgobackup.com first. -->

## Changes

<!-- Bullet list of the key changes. Mention any public API, file format,
or behaviour change. Call out breaking changes explicitly. -->

-

## Checklist

Please confirm each item before requesting review. CI enforces formatting,
vet, and tests; the rest are reviewed manually.

- [ ] `go test -race ./...` passes locally
- [ ] Tests added or updated for the change (regression coverage where relevant)
- [ ] Docs updated (`README.md`, `CHANGELOG.md`, `NOTICE`) where applicable
- [ ] **SPDX header** (`// SPDX-License-Identifier: Apache-2.0`) on every
      new or modified `.go` file
- [ ] `gofmt -s -w .` produces no diff
- [ ] `go vet ./...` is clean
- [ ] No new third-party dependency added, OR new dependency is justified and
      listed in `NOTICE` with its license
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] All commits are **cryptographically signed** (`git commit -S`)
- [ ] No secrets, credentials, or customer data in the diff
