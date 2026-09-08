// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDownloadBlobToFile_HashMismatch verifies that the streaming restore
// path fails when the blob's decrypted plaintext does not match the
// content-addressed hash (e.g. a blob stored under the wrong key by an
// upstream bug, or a hash-keyed store returning the wrong object).
// AEAD success alone must not be treated as proof of content identity.
func TestDownloadBlobToFile_HashMismatch(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	ctx := context.Background()

	// A valid large blob's ciphertext, deliberately stored under the hash
	// of DIFFERENT content.
	plaintext := make([]byte, DefaultChunkSize+100)
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	wrongHash := SHA256Bytes([]byte("different content"))
	if err := store.Put(ctx, wrongHash, ciphertext); err != nil {
		t.Fatalf("put: %v", err)
	}

	target := filepath.Join(t.TempDir(), "restored.bin")
	if err := DownloadBlobToFile(ctx, store, dec, wrongHash, target, 0644); err == nil {
		t.Fatal("expected hash mismatch error from streaming path")
	} else if !strings.Contains(err.Error(), "hash mismatch") && !strings.Contains(err.Error(), "content hash mismatch") {
		t.Fatalf("expected hash mismatch error, got: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("target file must not exist after failed verification")
	}
}

// TestDownloadBlobToFile_CompressedSmallBlob verifies that a compressed
// GB1 small blob — the format hashAndEncryptFile and UploadBlobFromPath
// write for compressible files below the chunk size — restores correctly
// through the streaming path. The blob is keyed by the hash of the RAW
// content while the stored plaintext is the zstd frame, so the streaming
// small-blob branch must decompress before writing and before the hash
// verification.
func TestDownloadBlobToFile_CompressedSmallBlob(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	ctx := context.Background()

	// Compressible content well below the chunk size but above the 64 KiB
	// compression threshold used by both small-blob upload paths.
	var sb strings.Builder
	line := "compressed small blob roundtrip line\n"
	for sb.Len() < 128*1024 {
		sb.WriteString(line)
	}
	plaintext := []byte(sb.String())

	compressed, err := defaultStreamCompressor.Compress(plaintext)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	if len(compressed) >= len(plaintext) {
		t.Fatal("test content is not compressible; test setup broken")
	}

	contentHash := SHA256Bytes(plaintext)
	ciphertext, err := enc.Encrypt(compressed) // < chunkSize => GB1 small blob
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := store.Put(ctx, contentHash, ciphertext); err != nil {
		t.Fatalf("put: %v", err)
	}

	target := filepath.Join(t.TempDir(), "restored.txt")
	if err := DownloadBlobToFile(ctx, store, dec, contentHash, target, 0644); err != nil {
		t.Fatalf("DownloadBlobToFile: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("restored content mismatch: got %d bytes, want %d", len(got), len(plaintext))
	}
}

// TestRestoreRejectsTamperedLargeBlob corrupts a large single-blob file's
// blob AFTER a successful backup so that the ciphertext decrypts under the
// right key but no longer matches the manifest's content hash/size —
// simulating silent store-side corruption or a wrong-object return. The
// restore must fail loudly instead of committing unverified content.
func TestRestoreRejectsTamperedLargeBlob(t *testing.T) {
	repoDir := t.TempDir()
	sourceDir := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatalf("mkdir source: %v", err)
	}

	// A file above the chunk size so restore takes the
	// downloadBlobToSecureDir streaming path.
	content := make([]byte, DefaultChunkSize+4096)
	for i := range content {
		content[i] = byte(i % 253)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "large.bin"), content, 0644); err != nil {
		t.Fatalf("write large.bin: %v", err)
	}

	if err := InitRepo(InitParams{RepoRoot: repoDir, DeviceID: "test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	key, _ := GenerateRandomKey()
	SetManifestDecryptHook(func(encrypted []byte) ([]byte, error) {
		return DecryptManifest(encrypted, key)
	})
	store := NewLocalBlobStore(repoDir)
	ctx := context.Background()

	cfg := PipelineConfig{
		RepoRoot:   repoDir,
		SourceID:   1,
		SourceName: "test",
		SourcePath: sourceDir,
		DeviceID:   "test",
		Key:        key,
	}
	if _, err := NewSimplePipeline(cfg, store).Run(ctx); err != nil {
		t.Fatalf("pipeline run: %v", err)
	}

	// Tamper: replace the blob with a validly encrypted DIFFERENT large
	// file under the original content hash. AEAD opens fine; only the
	// plaintext hash/size verification can catch it.
	other := make([]byte, DefaultChunkSize+2048)
	for i := range other {
		other[i] = byte((i * 7) % 251)
	}
	tampered, err := NewEncryptor(key, DefaultChunkSize).Encrypt(other)
	if err != nil {
		t.Fatalf("encrypt tampered: %v", err)
	}
	blobPath := store.BlobPath(SHA256Bytes(content))
	if err := os.WriteFile(blobPath, tampered, 0644); err != nil {
		t.Fatalf("overwrite blob: %v", err)
	}

	restoreDir := filepath.Join(t.TempDir(), "restore")
	restore := NewSimpleRestore(RestoreConfig{
		RepoRoot:  repoDir,
		TargetDir: restoreDir,
		SourceID:  1,
		DeviceID:  "test",
		Key:       key,
	}, store)
	if _, err := restore.Run(ctx); err == nil {
		t.Fatal("expected restore to fail on tampered blob")
	} else if !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected hash/size mismatch error, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(restoreDir, "large.bin")); !os.IsNotExist(err) {
		t.Error("tampered file must not be committed to the restore target")
	}
}
