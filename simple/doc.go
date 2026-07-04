// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

// Package simple implements the GBF backup format pipeline, blob storage,
// manifest management, and encryption.
//
// # Stability: pre-1.0
//
// This package is under active development. The exported API may change
// between minor versions while the project is below v1.0. Consumers should
// pin to a specific tag and re-run tests after upgrading. Once the API
// stabilizes at v1.0, a formal compatibility policy will be documented here.
//
// # Main entry points
//
//   - NewSimplePipeline — backup pipeline entry point
//   - SaveManifest / LoadManifest — manifest persistence
//   - NewLocalBlobStore — local blob storage
//   - NewEncryptor / NewDecryptor — AES-256-GCM encrypt/decrypt
//   - InitRepoWithPassword / UnlockRepoWithPassword — GEK1 keyfile workflow
//   - NewSimpleRestore — restore pipeline
//
// # Error values
//
//   - ErrManifestNotFound
package simple
