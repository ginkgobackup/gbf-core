// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

// Package simple implements the GBF backup format pipeline, blob storage,
// manifest management, and encryption.
//
// # Stability: FROZEN (v1)
//
// The exported API surface listed below is frozen. No breaking changes
// (removals, signature changes, semantic behavior changes) will be made
// without a major version bump. Internal refactoring and additive changes
// (new methods, new fields with zero-value compatibility) are permitted.
//
// ## Frozen Types
//
//   - SimpleBlobStore (interface) — blob read/write/delete contract
//   - BlobInfo — blob metadata
//   - SimplePipeline — backup pipeline entry point
//   - PipelineConfig — pipeline configuration
//   - PipelineResult — pipeline output
//   - Manifest — snapshot manifest
//   - FileEntry — file record in manifest
//   - Dir — directory record in manifest (files + subdirs)
//   - ManifestStats — manifest statistics
//   - LocalBlobStore — local blob storage (implements SimpleBlobStore)
//   - Encryptor / Decryptor — AES-256-GCM encrypt/decrypt
//   - HashResult — file hash result
//   - ProgressTracker — backup progress tracking
//
// ## Frozen Functions
//
//   - NewSimplePipeline(cfg PipelineConfig, store SimpleBlobStore) *SimplePipeline
//   - (*SimplePipeline).Run(ctx, sourcePath, prevManifest) (*PipelineResult, error)
//   - NewManifest(sourceID, cloudID, sourceName, sourcePath, deviceID) *Manifest
//   - SaveManifest / SaveManifestWithKey / LoadManifest / LoadManifestFromData
//   - LoadLatestManifest / LoadManifestByTimestamp / ManifestExistsByTimestamp
//   - ListManifests / DeleteManifest / TrashManifest / CleanTrashManifests
//   - CollectAliveHashes / ManifestDir / ManifestFilePath
//   - NewLocalBlobStore
//   - NewEncryptor / NewDecryptor
//   - SHA256File / SHA256Bytes
//   - NewProgressTracker
//   - MetaDir
//   - SetManifestDecryptHook
//   - SaveSourceRegistry / LoadSourceRegistry / ListSourceRegistries
//
// ## Frozen Error Values
//
//   - ErrManifestNotFound
//
// ## Internal (unfrozen) — do not depend on these from outside this package
//
//   - processFile, processFileStreaming (pipeline internals)
//   - hashAndEncryptFile, hashAndEncryptToTempFile, hashOnlyFile (hash internals)
//   - uploadBlob, downloadBlob (blob transfer internals)
//   - All unexported functions and types
//
// ## Additive-only change policy
//
// New exported functions and types may be added. New struct fields must
// have zero-value semantics that are backward-compatible. Existing function
// signatures must not change.
package simple
