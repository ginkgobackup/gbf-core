// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// TestRestoreZstdFrameContent is the regression test for .zst restore
// corruption: a file whose own bytes are a valid zstd frame is stored
// verbatim (compression is skipped for already-compressed extensions), but
// the restore path used to see the zstd magic and decompress the user's
// file a second time. The small-blob (DownloadBlob) and chunked
// (restoreChunkedFile) paths must both return the exact original bytes.
func TestRestoreZstdFrameContent(t *testing.T) {
	repoDir := t.TempDir()
	sourceDir := t.TempDir()
	if err := InitRepo(InitParams{RepoRoot: repoDir, DeviceID: "test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	key, err := GenerateRandomKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	SetManifestDecryptHook(func(encrypted []byte) ([]byte, error) {
		return DecryptManifest(encrypted, key)
	})
	store := NewLocalBlobStore(repoDir)
	ctx := context.Background()

	// Small frame: well below chunkSize, so it takes the single-blob path.
	var smallRaw bytes.Buffer
	for smallRaw.Len() < 128*1024 {
		smallRaw.WriteString("ginkgo zstd frame content line\n")
	}
	smallFrame, err := defaultStreamCompressor.Compress(smallRaw.Bytes())
	if err != nil {
		t.Fatalf("compress small frame: %v", err)
	}
	if int64(len(smallFrame)) >= int64(DefaultChunkSize) {
		t.Fatalf("test setup: small frame is %d bytes, want < chunk size %d", len(smallFrame), DefaultChunkSize)
	}

	// Large frame: random payload does not compress, so the frame is larger
	// than chunkSize and the pipeline records per-chunk refs. Its first
	// chunk is a valid zstd frame prefix (and a later chunk may not start
	// with the magic at all), exercising both branches of the fix.
	largeRaw := make([]byte, DefaultChunkSize+1024*1024)
	if _, err := rand.Read(largeRaw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	largeFrame, err := defaultStreamCompressor.Compress(largeRaw)
	if err != nil {
		t.Fatalf("compress large frame: %v", err)
	}
	if int64(len(largeFrame)) < int64(DefaultChunkSize) {
		t.Fatalf("test setup: large frame is %d bytes, want >= chunk size %d", len(largeFrame), DefaultChunkSize)
	}

	files := map[string][]byte{
		"small.zst": smallFrame,
		"large.zst": largeFrame,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(sourceDir, name), data, 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	if _, err := NewSimplePipeline(PipelineConfig{
		RepoRoot:   repoDir,
		SourceID:   1,
		SourceName: "test",
		SourcePath: sourceDir,
		DeviceID:   "test",
		Key:        key,
		DisableCDC: true,
	}, store).Run(ctx); err != nil {
		t.Fatalf("pipeline run: %v", err)
	}

	restoreDir := filepath.Join(t.TempDir(), "restore")
	result, err := NewSimpleRestore(RestoreConfig{
		RepoRoot:  repoDir,
		TargetDir: restoreDir,
		SourceID:  1,
		DeviceID:  "test",
		Key:       key,
	}, store).Run(ctx)
	if err != nil {
		t.Fatalf("restore run: %v", err)
	}
	if result.RestoredFiles != len(files) {
		t.Fatalf("restored files: got %d, want %d", result.RestoredFiles, len(files))
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(restoreDir, name))
		if err != nil {
			t.Fatalf("read restored %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s corrupted on restore: got %d bytes, want %d", name, len(got), len(want))
		}
	}
}

// TestDownloadPreservesRawZstdFrame covers the download helpers directly:
// DownloadBlob (buffered) and DownloadBlobToFile (streaming small-blob
// branch) must both return the stored zstd frame unchanged.
func TestDownloadPreservesRawZstdFrame(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	ctx := context.Background()

	raw := bytes.Repeat([]byte("zstd frame payload\n"), 4096)
	frame, err := defaultStreamCompressor.Compress(raw)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	if int64(len(frame)) >= int64(DefaultChunkSize) {
		t.Fatalf("test setup: frame is %d bytes, want < chunk size %d", len(frame), DefaultChunkSize)
	}

	src := filepath.Join(dir, "archive.zst")
	if err := os.WriteFile(src, frame, 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	hash, err := UploadBlobFromPath(ctx, store, enc, src, "")
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if want := SHA256Bytes(frame); hash != want {
		t.Fatalf("hash = %s, want %s", hash, want)
	}

	got, err := DownloadBlob(ctx, store, dec, hash)
	if err != nil {
		t.Fatalf("DownloadBlob: %v", err)
	}
	if !bytes.Equal(got, frame) {
		t.Fatalf("DownloadBlob corrupted zstd frame: got %d bytes, want %d", len(got), len(frame))
	}

	target := filepath.Join(dir, "restored.zst")
	if err := DownloadBlobToFile(ctx, store, dec, hash, target, 0644); err != nil {
		t.Fatalf("DownloadBlobToFile: %v", err)
	}
	got, err = os.ReadFile(target)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(got, frame) {
		t.Fatalf("DownloadBlobToFile corrupted zstd frame: got %d bytes, want %d", len(got), len(frame))
	}
}
