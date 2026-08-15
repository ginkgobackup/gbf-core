// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEncryptDecryptSmall(t *testing.T) {
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	plaintext := []byte("Hello, GBF! This is a test of small file encryption.")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(ciphertext[:4]) != MagicGB1 {
		t.Fatalf("magic mismatch: got %q, want %q", ciphertext[:4], MagicGB1)
	}
	decrypted, err := dec.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptLarge(t *testing.T) {
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	plaintext := make([]byte, DefaultChunkSize*2+1234)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(ciphertext[:4]) != MagicGB1 {
		t.Fatalf("magic mismatch: got %q", ciphertext[:4])
	}
	decrypted, err := dec.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch: length got %d, want %d", len(decrypted), len(plaintext))
	}
}

func TestSHA256Bytes(t *testing.T) {
	data := []byte("test")
	hash := SHA256Bytes(data)
	if len(hash) != 64 {
		t.Fatalf("hash length: got %d, want 64", len(hash))
	}
}

func TestLocalBlobStorePutGet(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	ctx := context.Background()
	hash := SHA256Bytes([]byte("test data"))
	data := []byte("encrypted test data")
	if err := store.Put(ctx, hash, data); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := store.Get(ctx, hash)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("data mismatch: got %q, want %q", got, data)
	}
}

func TestLocalBlobStoreExists(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	ctx := context.Background()
	hash := SHA256Bytes([]byte("test"))
	exists, err := store.Exists(ctx, hash)
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if exists {
		t.Fatal("should not exist")
	}
	if err := store.Put(ctx, hash, []byte("data")); err != nil {
		t.Fatalf("put: %v", err)
	}
	exists, err = store.Exists(ctx, hash)
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if !exists {
		t.Fatal("should exist")
	}
}

func TestLocalBlobStoreList(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	ctx := context.Background()
	hash1 := SHA256Bytes([]byte("data1"))
	hash2 := SHA256Bytes([]byte("data2"))
	if err := store.Put(ctx, hash1, []byte("encrypted1")); err != nil {
		t.Fatalf("put hash1: %v", err)
	}
	if err := store.Put(ctx, hash2, []byte("encrypted2")); err != nil {
		t.Fatalf("put hash2: %v", err)
	}
	list, err := store.List(ctx, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("list length: got %d, want 2", len(list))
	}
}

func TestLocalBlobStoreDelete(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	ctx := context.Background()
	hash := SHA256Bytes([]byte("test"))
	if err := store.Put(ctx, hash, []byte("data")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := store.Delete(ctx, hash); err != nil {
		t.Fatalf("delete: %v", err)
	}
	exists, _ := store.Exists(ctx, hash)
	if exists {
		t.Fatal("should not exist after delete")
	}
}

func TestConfigSaveLoad(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig("test-device")
	if err := SaveConfig(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Format != FormatGBF {
		t.Fatalf("format: got %q, want %q", loaded.Format, FormatGBF)
	}
	if loaded.DeviceID != "test-device" {
		t.Fatalf("deviceId: got %q, want %q", loaded.DeviceID, "test-device")
	}
}

func TestManifestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	m := NewManifest(1, "", "TestSource", "/test/path", "device-1")
	m.AddFile(FileEntry{
		Name:        "test/file.txt",
		ContentHash: SHA256Bytes([]byte("file content")),
		Size:        12,
		Mtime:       "2026-05-14T10:00:00Z",
		Mode:        0644,
	})
	if _, err := SaveManifest(dir, m); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := LoadLatestManifest(dir, ManifestPathKey("device-1", "1"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected manifest, got nil")
	}
	if loaded.SourceID != 1 {
		t.Fatalf("sourceId: got %d, want 1", loaded.SourceID)
	}
	if loaded.Stats.FileCount != 1 {
		t.Fatalf("files: got %d, want 1", loaded.Stats.FileCount)
	}
	allFiles := loaded.AllFiles()
	if allFiles[0].Name != "test/file.txt" {
		t.Fatalf("path: got %q", allFiles[0].Name)
	}
}

func TestInitRepo(t *testing.T) {
	dir := t.TempDir()
	if err := InitRepo(InitParams{RepoRoot: dir, DeviceID: "test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if !IsGBRepo(dir) {
		t.Fatal("should be GB repo")
	}
	configPath := filepath.Join(dir, MetaDirName, "config.json")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatal("config.json should exist")
	}
	gbDir := filepath.Join(dir, "gb")
	if _, err := os.Stat(gbDir); os.IsNotExist(err) {
		t.Fatal("gb/ should exist")
	}
}

func TestUploadDownloadBlob(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	ctx := context.Background()
	plaintext := []byte("This is a test file for upload and download.")
	hash, err := UploadBlob(ctx, store, enc, plaintext)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if len(hash) != 64 {
		t.Fatalf("hash length: got %d, want 64", len(hash))
	}
	got, err := DownloadBlob(ctx, store, dec, hash)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("data mismatch: got %q, want %q", got, plaintext)
	}
	hash2, err := UploadBlob(ctx, store, enc, plaintext)
	if err != nil {
		t.Fatalf("upload dedup: %v", err)
	}
	if hash2 != hash {
		t.Fatalf("dedup hash mismatch: got %q, want %q", hash2, hash)
	}
}

func TestUploadBlobFromPath(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	ctx := context.Background()

	smallFile := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(smallFile, []byte("small file content"), 0644); err != nil {
		t.Fatalf("write small: %v", err)
	}
	hash, err := UploadBlobFromPath(ctx, store, enc, smallFile, "")
	if err != nil {
		t.Fatalf("upload small from path: %v", err)
	}
	got, err := DownloadBlob(ctx, store, dec, hash)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if string(got) != "small file content" {
		t.Fatalf("small file mismatch: got %q", string(got))
	}

	largeData := make([]byte, DefaultChunkSize+100)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	largeFile := filepath.Join(dir, "large.bin")
	if err := os.WriteFile(largeFile, largeData, 0644); err != nil {
		t.Fatalf("write large: %v", err)
	}
	hash2, err := UploadBlobFromPath(ctx, store, enc, largeFile, "")
	if err != nil {
		t.Fatalf("upload large from path: %v", err)
	}
	got2, err := DownloadBlob(ctx, store, dec, hash2)
	if err != nil {
		t.Fatalf("download large: %v", err)
	}
	if !bytes.Equal(got2, largeData) {
		t.Fatalf("large file mismatch: length got %d, want %d", len(got2), len(largeData))
	}
}

func TestUploadBlobFromPath_CompressesLargeFile(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	ctx := context.Background()

	largeData := make([]byte, DefaultChunkSize+100)
	for i := range largeData {
		largeData[i] = byte(i % 2)
	}
	largeFile := filepath.Join(dir, "large.txt")
	if err := os.WriteFile(largeFile, largeData, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	hash, err := UploadBlobFromPath(ctx, store, enc, largeFile, "")
	if err != nil {
		t.Fatalf("upload: %v", err)
	}

	blobPath := filepath.Join(dir, "gb", hash[:2], hash+".gb")
	stat, err := os.Stat(blobPath)
	if err != nil {
		t.Fatalf("stat blob: %v", err)
	}
	if stat.Size() >= int64(len(largeData)) {
		t.Fatalf("expected compressed blob to be smaller than original %d, got %d", len(largeData), stat.Size())
	}

	got, err := DownloadBlob(ctx, store, dec, hash)
	if err != nil {
		t.Fatalf("download in-memory: %v", err)
	}
	if !bytes.Equal(got, largeData) {
		t.Fatalf("in-memory data mismatch: length got %d, want %d", len(got), len(largeData))
	}

	streamTarget := filepath.Join(dir, "restore-large.bin")
	if err := DownloadBlobToFile(ctx, store, dec, hash, streamTarget, 0644); err != nil {
		t.Fatalf("download stream: %v", err)
	}
	streamGot, err := os.ReadFile(streamTarget)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(streamGot, largeData) {
		t.Fatalf("stream data mismatch: length got %d, want %d", len(streamGot), len(largeData))
	}
}

func TestUploadBlobFromPath_SkipsCompressionForIncompressible(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	ctx := context.Background()

	largeData := make([]byte, DefaultChunkSize+100)
	for i := range largeData {
		largeData[i] = byte(i % 2)
	}
	largeFile := filepath.Join(dir, "large.zip")
	if err := os.WriteFile(largeFile, largeData, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	hash, err := UploadBlobFromPath(ctx, store, enc, largeFile, "")
	if err != nil {
		t.Fatalf("upload: %v", err)
	}

	blobPath := filepath.Join(dir, "gb", hash[:2], hash+".gb")
	stat, err := os.Stat(blobPath)
	if err != nil {
		t.Fatalf("stat blob: %v", err)
	}
	// MagicGB1 large file: original + chunkCount*(IV+Tag) + Magic + count header.
	minExpected := int64(len(largeData) + ((len(largeData)+DefaultChunkSize-1)/DefaultChunkSize)*(IVSize+TagSize) + MagicSize + ChunkCountSize)
	if stat.Size() < minExpected {
		t.Fatalf("expected uncompressed blob at least %d, got %d", minExpected, stat.Size())
	}

	got, err := DownloadBlob(ctx, store, dec, hash)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !bytes.Equal(got, largeData) {
		t.Fatalf("data mismatch: length got %d, want %d", len(got), len(largeData))
	}
}

// TestUploadBlobFromPath_HashMatchesStoredContent is the regression test for
// the single-pass rework of UploadBlobFromPath: the returned hash must be
// computed over exactly the bytes that were encrypted and stored. This is
// verified by downloading the blob back and re-hashing the decrypted
// content. Previously the hash came from a first read of the file and the
// ciphertext from a second one, so a file modified in between produced a
// "successful" upload whose blob could never be restored under that key.
func TestUploadBlobFromPath_HashMatchesStoredContent(t *testing.T) {
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	ctx := context.Background()

	cases := []struct {
		name string
		data []byte
		ext  string
	}{
		// ~120 KiB: exercises the in-memory (small) path, including the
		// >= 64 KiB compression branch.
		{"small", bytes.Repeat([]byte("small hash/content invariant "), 4096), ".txt"},
		// ~8 MiB: exercises the streaming (>= chunkSize) path.
		{"large_stream", bytes.Repeat([]byte("large hash/content invariant "), 300*1024), ".txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := NewLocalBlobStore(t.TempDir())
			src := filepath.Join(t.TempDir(), "src"+tc.ext)
			if err := os.WriteFile(src, tc.data, 0644); err != nil {
				t.Fatalf("write src: %v", err)
			}
			hash, err := UploadBlobFromPath(ctx, store, enc, src, "")
			if err != nil {
				t.Fatalf("upload: %v", err)
			}
			if want := SHA256Bytes(tc.data); hash != want {
				t.Fatalf("returned hash = %q, want hash of source content %q", hash, want)
			}
			got, err := DownloadBlob(ctx, store, dec, hash)
			if err != nil {
				t.Fatalf("download (DownloadBlob verifies stored content against key): %v", err)
			}
			if !bytes.Equal(got, tc.data) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(tc.data))
			}
			if SHA256Bytes(got) != hash {
				t.Fatalf("hash of downloaded content %q != returned hash %q", SHA256Bytes(got), hash)
			}
		})
	}
}

// TestUploadBlobFromPath_StaleKnownHashRejected covers the knownHash guard:
// when the caller-supplied hash no longer matches the file's actual content
// (the file changed between the caller's hash pass and this upload), the
// upload must fail instead of storing the new content under the stale key.
func TestUploadBlobFromPath_StaleKnownHashRejected(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	ctx := context.Background()

	small := bytes.Repeat([]byte("v1 content "), 100)
	src := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(src, small, 0644); err != nil {
		t.Fatalf("write small: %v", err)
	}

	staleHash := SHA256Bytes([]byte("completely different content"))
	if _, err := UploadBlobFromPath(ctx, store, enc, src, staleHash); err == nil {
		t.Fatal("expected error for stale knownHash on small path")
	}

	// A correct knownHash must still upload successfully.
	freshStore := NewLocalBlobStore(t.TempDir())
	if _, err := UploadBlobFromPath(ctx, freshStore, enc, src, SHA256Bytes(small)); err != nil {
		t.Fatalf("upload with correct knownHash: %v", err)
	}

	// Same guard on the streaming (>= chunkSize) path.
	large := bytes.Repeat([]byte("v1 large content "), 300*1024)
	largeSrc := filepath.Join(dir, "large.txt")
	if err := os.WriteFile(largeSrc, large, 0644); err != nil {
		t.Fatalf("write large: %v", err)
	}
	if _, err := UploadBlobFromPath(ctx, freshStore, enc, largeSrc, staleHash); err == nil {
		t.Fatal("expected error for stale knownHash on large path")
	}
}

func TestPipelineBackupRestore(t *testing.T) {
	repoDir := t.TempDir()
	sourceDir := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(filepath.Join(sourceDir, "subdir"), 0755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("hello world"), 0644); err != nil {
		t.Fatalf("write file1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "subdir", "file2.txt"), []byte("nested file"), 0644); err != nil {
		t.Fatalf("write file2: %v", err)
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
	pipeline := NewSimplePipeline(cfg, store)
	result, err := pipeline.Run(ctx)
	if err != nil {
		t.Fatalf("pipeline run: %v", err)
	}
	if result.NewFiles != 2 {
		t.Fatalf("new files: got %d, want 2", result.NewFiles)
	}

	restoreDir := filepath.Join(t.TempDir(), "restore")
	restoreCfg := RestoreConfig{
		RepoRoot:  repoDir,
		TargetDir: restoreDir,
		SourceID:  1,
		DeviceID:  "test",
		Key:       key,
	}
	restore := NewSimpleRestore(restoreCfg, store)
	rResult, err := restore.Run(ctx)
	if err != nil {
		t.Fatalf("restore run: %v", err)
	}
	if rResult.RestoredFiles != 2 {
		t.Fatalf("restored files: got %d, want 2", rResult.RestoredFiles)
	}
	data, _ := os.ReadFile(filepath.Join(restoreDir, "file1.txt"))
	if string(data) != "hello world" {
		t.Fatalf("restored content mismatch: got %q", string(data))
	}
}

func TestPipelineIncremental(t *testing.T) {
	repoDir := t.TempDir()
	sourceDir := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(sourceDir, 0755); err != nil {
		t.Fatalf("mkdir source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "file.txt"), []byte("original"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
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

	pipeline := NewSimplePipeline(cfg, store)
	result1, err := pipeline.Run(ctx)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if result1.NewFiles != 1 {
		t.Fatalf("first run new files: got %d, want 1", result1.NewFiles)
	}

	pipeline2 := NewSimplePipeline(cfg, store)
	result2, err := pipeline2.Run(ctx)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if result2.UnchangedFiles != 1 {
		t.Fatalf("incremental unchanged: got %d, want 1", result2.UnchangedFiles)
	}
	if result2.NewFiles != 0 {
		t.Fatalf("incremental new: got %d, want 0", result2.NewFiles)
	}
}

func TestFormatDetection(t *testing.T) {
	dir := t.TempDir()
	format := DetectRepoFormat(dir)
	if format != RepoFormatUnknown {
		t.Fatalf("unknown repo: got %v", format)
	}
	if err := InitRepo(InitParams{RepoRoot: dir, DeviceID: "test"}); err != nil {
		t.Fatalf("init repo: %v", err)
	}
	format = DetectRepoFormat(dir)
	if format != RepoFormatGBF {
		t.Fatalf("gb repo: got %v", format)
	}
}

func TestMatchExclude(t *testing.T) {
	tests := []struct {
		path     string
		patterns []string
		want     bool
	}{
		{"node_modules/pkg/index.js", []string{"node_modules"}, true},
		{"src/index.js", []string{"node_modules"}, false},
		{"logs/app.log", []string{"logs/**"}, true},
		{"src/cache/data.json", []string{"**/cache"}, true},
		{"test.go", []string{"*.go"}, true},
		{"src/test.go", []string{"*.go"}, true},
	}
	for _, tt := range tests {
		got := MatchExclude(tt.path, tt.patterns)
		if got != tt.want {
			t.Errorf("MatchExclude(%q, %v) = %v, want %v", tt.path, tt.patterns, got, tt.want)
		}
	}
}

// TestSafeRestorePath_RejectsTraversal verifies that the restore path
// sanitizer refuses manifest entries that would escape TargetDir. This is
// the regression test for the path-traversal vulnerability fixed in
// restore.go: safeRestorePath must reject "..", absolute paths, and
// any combination that resolves outside the target.
func TestSafeRestorePath_RejectsTraversal(t *testing.T) {
	target := t.TempDir()
	cases := []struct {
		name    string
		relPath string
		wantErr bool
	}{
		{"parent", "../../etc/passwd", true},
		{"parent_single", "..", true},
		{"parent_nested", "subdir/../../../etc/passwd", true},
		{"absolute_unix", "/etc/passwd", true},
		{"absolute_windows", `C:\Windows\System32`, true},
		{"dotdot_only", "../", true},
		{"valid_simple", "file.txt", false},
		{"valid_nested", "subdir/file.txt", false},
		{"valid_deep", "a/b/c/file.txt", false},
		{"valid_dot", ".", false},
		{"valid_inner_dotdot", "a/../b/file.txt", false}, // resolves to b/file.txt
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := safeRestorePath(target, tc.relPath)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("safeRestorePath(%q) = %q; want error", tc.relPath, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("safeRestorePath(%q) returned error: %v", tc.relPath, err)
			}
			// The resolved path must live inside target.
			absTarget, _ := filepath.Abs(target)
			if !strings.HasPrefix(got, absTarget+string(os.PathSeparator)) && got != absTarget {
				t.Fatalf("safeRestorePath(%q) = %q; want inside %s", tc.relPath, got, absTarget)
			}
		})
	}
}

// TestLocalBlobStore_RejectsInvalidHash verifies that all blob operations
// refuse hashes that are not 64-character hex SHA-256. This is the regression
// test for the blob path-traversal vulnerability (B4): crafted hash values
// like "../../etc/passwd" must not be joined into the storage path.
func TestLocalBlobStore_RejectsInvalidHash(t *testing.T) {
	store := NewLocalBlobStore(t.TempDir())
	ctx := context.Background()

	badHashes := []string{
		"",
		"abc",
		"../../etc/passwd",
		strings.Repeat("x", 64), // wrong charset
		strings.Repeat("A", 64), // uppercase rejected
		strings.Repeat("0", 63), // too short
		strings.Repeat("0", 65), // too long
	}
	for _, h := range badHashes {
		t.Run("Put_"+h, func(t *testing.T) {
			if err := store.Put(ctx, h, []byte("data")); err != ErrInvalidHash {
				t.Errorf("Put(%q) err = %v; want ErrInvalidHash", h, err)
			}
		})
		t.Run("Get_"+h, func(t *testing.T) {
			if _, err := store.Get(ctx, h); err != ErrInvalidHash {
				t.Errorf("Get(%q) err = %v; want ErrInvalidHash", h, err)
			}
		})
		t.Run("Exists_"+h, func(t *testing.T) {
			// Exists must reject malformed hashes like every other blob
			// operation: reporting (false, nil) would invite callers to
			// misread "invalid hash" as "blob missing" and retry the
			// upload, which Put would then reject anyway.
			exists, err := store.Exists(ctx, h)
			if err != ErrInvalidHash || exists {
				t.Errorf("Exists(%q) = (%v, %v); want (false, ErrInvalidHash)", h, exists, err)
			}
		})
		t.Run("Delete_"+h, func(t *testing.T) {
			if err := store.Delete(ctx, h); err != ErrInvalidHash {
				t.Errorf("Delete(%q) err = %v; want ErrInvalidHash", h, err)
			}
		})
		t.Run("BlobPath_"+h, func(t *testing.T) {
			if got := store.BlobPath(h); got != "" {
				t.Errorf("BlobPath(%q) = %q; want empty", h, got)
			}
		})
	}
}

// TestLocalBlobStore_WarmExistsCache_ConcurrentSafety runs WarmExistsCache
// concurrently with Exists calls to verify the lock fix (B5). Before the fix,
// this would intermittently panic with "concurrent map writes".
func TestLocalBlobStore_WarmExistsCache_ConcurrentSafety(t *testing.T) {
	store := NewLocalBlobStore(t.TempDir())
	ctx := context.Background()

	// Pre-populate a few blobs so WarmExistsCache has work to do.
	for i := 0; i < 5; i++ {
		hash := fmt.Sprintf("%064x", i)
		if err := store.Put(ctx, hash, []byte{byte(i)}); err != nil {
			t.Fatalf("put: %v", err)
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_, _ = store.Exists(ctx, fmt.Sprintf("%064x", i%10))
		}
	}()

	for i := 0; i < 10; i++ {
		if err := store.WarmExistsCache(ctx); err != nil {
			t.Fatalf("warm: %v", err)
		}
	}
	<-done
}

// TestUploadBlobFromPath_CompressibleSmallRoundtrip covers the 64KB..chunkSize
// interval that was previously broken: UploadBlobFromPath compressed these
// files and then stored the blob under the hash of the *compressed* bytes,
// so DownloadBlob (which verifies the hash of the *original* content after
// decompress) always failed with a hash mismatch. The blob name must be the
// hash of the raw content; compression is a storage-layer detail only.
func TestUploadBlobFromPath_CompressibleSmallRoundtrip(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	ctx := context.Background()

	// ~100KB of highly compressible content — above the 64KB compression
	// threshold but below chunkSize, i.e. the small-file path in
	// UploadBlobFromPath. .txt is not on the incompressible list.
	data := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog. ", 2280))
	if len(data) < 65536 || len(data) >= DefaultChunkSize {
		t.Fatalf("test data size %d outside target interval", len(data))
	}
	midFile := filepath.Join(dir, "mid.txt")
	if err := os.WriteFile(midFile, data, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	hash, err := UploadBlobFromPath(ctx, store, enc, midFile, "")
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	// Content addressing: the returned blob name must be the SHA-256 of the
	// original (uncompressed) content — matching what the pipeline path
	// produces for the same file.
	if want := SHA256Bytes(data); hash != want {
		t.Fatalf("hash mismatch: got %s, want original-content hash %s", hash, want)
	}

	// The blob must actually be stored compressed (regression interval:
	// compression engaged but addressing stayed on raw content).
	blobPath := filepath.Join(dir, "gb", hash[:2], hash+".gb")
	stat, err := os.Stat(blobPath)
	if err != nil {
		t.Fatalf("stat blob: %v", err)
	}
	if stat.Size() >= int64(len(data)) {
		t.Fatalf("expected compressed blob smaller than original %d, got %d", len(data), stat.Size())
	}

	got, err := DownloadBlob(ctx, store, dec, hash)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("data mismatch: length got %d, want %d", len(got), len(data))
	}

	// Re-uploading the same file must dedup to the same blob name.
	hash2, err := UploadBlobFromPath(ctx, store, enc, midFile, "")
	if err != nil {
		t.Fatalf("re-upload: %v", err)
	}
	if hash2 != hash {
		t.Fatalf("dedup hash mismatch: got %q, want %q", hash2, hash)
	}
}

// TestRestoreSkipsLockedAndFailedEntries is the regression test for restore
// aborting on manifest entries written for files that were locked or failed
// during backup (Status "locked"/"error", empty ContentHash). Restore must
// skip those entries and still restore the healthy ones.
func TestRestoreSkipsLockedAndFailedEntries(t *testing.T) {
	repoDir := t.TempDir()
	if err := InitRepo(InitParams{RepoRoot: repoDir, DeviceID: "test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	key, _ := GenerateRandomKey()
	SetManifestDecryptHook(func(encrypted []byte) ([]byte, error) {
		return DecryptManifest(encrypted, key)
	})
	store := NewLocalBlobStore(repoDir)
	ctx := context.Background()
	enc := NewEncryptor(key, DefaultChunkSize)

	goodData := []byte("healthy file content")
	goodHash, err := UploadBlob(ctx, store, enc, goodData)
	if err != nil {
		t.Fatalf("upload good blob: %v", err)
	}

	m := NewManifest(1, "", "test", "/src", "test")
	m.AddFile(FileEntry{
		Name:        "good.txt",
		ContentHash: goodHash,
		Size:        int64(len(goodData)),
		Mtime:       "2026-05-14T10:00:00Z",
		Mode:        0644,
		Status:      "new",
	})
	// Locked small file: no blob uploaded, empty ContentHash.
	m.AddFile(FileEntry{
		Name:   "locked.txt",
		Size:   128,
		Mtime:  "2026-05-14T10:00:00Z",
		Mode:   0644,
		Status: "locked",
	})
	// Failed small file.
	m.AddFile(FileEntry{
		Name:   "failed.txt",
		Size:   256,
		Mtime:  "2026-05-14T10:00:00Z",
		Mode:   0644,
		Status: "error",
	})
	// Locked large file (>= chunkSize, no Chunks, empty hash): previously
	// aborted the restore via the DownloadBlobToFile branch.
	m.AddFile(FileEntry{
		Name:   "big-locked.bin",
		Size:   int64(DefaultChunkSize) + 10,
		Mtime:  "2026-05-14T10:00:00Z",
		Mode:   0644,
		Status: "locked",
	})
	if _, err := SaveManifestWithKey(MetaDir(repoDir), m, key); err != nil {
		t.Fatalf("save manifest: %v", err)
	}

	restoreDir := filepath.Join(t.TempDir(), "restore")
	restore := NewSimpleRestore(RestoreConfig{
		RepoRoot:  repoDir,
		TargetDir: restoreDir,
		SourceID:  1,
		DeviceID:  "test",
		Key:       key,
	}, store)
	result, err := restore.Run(ctx)
	if err != nil {
		t.Fatalf("restore run: %v", err)
	}
	if result.RestoredFiles != 1 {
		t.Fatalf("restored files: got %d, want 1", result.RestoredFiles)
	}
	if result.SkippedFiles != 3 {
		t.Fatalf("skipped files: got %d, want 3", result.SkippedFiles)
	}
	got, err := os.ReadFile(filepath.Join(restoreDir, "good.txt"))
	if err != nil {
		t.Fatalf("read restored good.txt: %v", err)
	}
	if !bytes.Equal(got, goodData) {
		t.Fatalf("good.txt mismatch: got %q, want %q", got, goodData)
	}
	for _, name := range []string{"locked.txt", "failed.txt", "big-locked.bin"} {
		if _, err := os.Stat(filepath.Join(restoreDir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s should not have been restored", name)
		}
	}
}

func TestRestoreCreatesEmptyDirectories(t *testing.T) {
	repoDir := t.TempDir()
	sourceDir := filepath.Join(t.TempDir(), "source")
	// One real file plus a nested chain of empty directories.
	if err := os.MkdirAll(filepath.Join(sourceDir, "empty", "nested"), 0755); err != nil {
		t.Fatalf("mkdir empty: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "file.txt"), []byte("data"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
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

	pipeline := NewSimplePipeline(PipelineConfig{
		RepoRoot:   repoDir,
		SourceID:   1,
		SourceName: "test",
		SourcePath: sourceDir,
		DeviceID:   "test",
		Key:        key,
	}, store)
	if _, err := pipeline.Run(ctx); err != nil {
		t.Fatalf("pipeline run: %v", err)
	}

	restoreDir := filepath.Join(t.TempDir(), "restore")
	restore := NewSimpleRestore(RestoreConfig{
		RepoRoot:  repoDir,
		TargetDir: restoreDir,
		SourceID:  1,
		DeviceID:  "test",
		Key:       key,
	}, store)
	if _, err := restore.Run(ctx); err != nil {
		t.Fatalf("restore run: %v", err)
	}

	// The empty directory chain must exist in the restore — previously only
	// directories containing files were recreated, so empty dirs were lost.
	info, err := os.Stat(filepath.Join(restoreDir, "empty", "nested"))
	if err != nil {
		t.Fatalf("empty/nested not restored: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("empty/nested should be a directory")
	}
	if _, err := os.Stat(filepath.Join(restoreDir, "file.txt")); err != nil {
		t.Fatalf("file.txt not restored: %v", err)
	}
}

// TestInMemoryChunkBackup_ModifyDedupAndRestore guards optimization 1a
// (chunk plaintext retained in memory for files <= 32 MiB): a multi-chunk
// file must round-trip through backup, zero-upload re-run, tail
// modification (only the touched chunk re-uploaded), and streaming
// restore. Fixed chunking keeps the chunk layout deterministic.
func TestInMemoryChunkBackup_ModifyDedupAndRestore(t *testing.T) {
	repoDir := t.TempDir()
	sourceDir := t.TempDir()
	if err := InitRepo(InitParams{RepoRoot: repoDir, DeviceID: "test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	key, _ := GenerateRandomKey()
	SetManifestDecryptHook(func(encrypted []byte) ([]byte, error) {
		return DecryptManifest(encrypted, key)
	})
	store := NewLocalBlobStore(repoDir)
	ctx := context.Background()

	// 10 MiB = fixed chunks of 4+4+2 MiB, below inMemoryChunkThreshold.
	content := make([]byte, 10*1024*1024)
	rand.New(rand.NewSource(11)).Read(content)
	fp := filepath.Join(sourceDir, "mem.bin")
	if err := os.WriteFile(fp, content, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := PipelineConfig{
		RepoRoot:   repoDir,
		SourceID:   1,
		SourceName: "test",
		SourcePath: sourceDir,
		DeviceID:   "test",
		Key:        key,
		DisableCDC: true,
	}

	result1, err := NewSimplePipeline(cfg, store).Run(ctx)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if result1.NewFiles != 1 || result1.FailedFiles != 0 {
		t.Fatalf("first run: new=%d failed=%d, want 1/0", result1.NewFiles, result1.FailedFiles)
	}

	// Second run with no changes: the mtime fast path plus batch existence
	// check must report the file unchanged with zero uploaded bytes.
	result2, err := NewSimplePipeline(cfg, store).Run(ctx)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if result2.UnchangedFiles != 1 || result2.UploadedBytes != 0 {
		t.Fatalf("second run: unchanged=%d uploaded=%d, want 1/0", result2.UnchangedFiles, result2.UploadedBytes)
	}

	// Rewrite only the final 1 MiB (inside the last 2 MiB chunk) and bump
	// mtime explicitly so the same-second RFC3339 window cannot hide it.
	updated := append([]byte(nil), content...)
	tail := make([]byte, 1024*1024)
	rand.New(rand.NewSource(12)).Read(tail)
	copy(updated[len(updated)-len(tail):], tail)
	if err := os.WriteFile(fp, updated, 0644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	future := time.Now().Add(3 * time.Second)
	if err := os.Chtimes(fp, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Third run: content hash changes, but only the modified last chunk
	// (2 MiB plaintext) is re-uploaded — the in-memory pass uploads the
	// exact hashed bytes, and prefix chunks dedup against the store.
	result3, err := NewSimplePipeline(cfg, store).Run(ctx)
	if err != nil {
		t.Fatalf("third run: %v", err)
	}
	if result3.ChangedFiles != 1 {
		t.Fatalf("third run: changed=%d, want 1", result3.ChangedFiles)
	}
	if result3.UploadedBytes != int64(2*1024*1024) {
		t.Fatalf("third run: uploaded=%d, want %d (only the modified chunk)", result3.UploadedBytes, 2*1024*1024)
	}

	// Restore from the latest manifest and verify byte-exact content —
	// proves the blobs uploaded from the in-memory pass decrypt back to
	// exactly what was hashed, and exercises the streaming chunked restore.
	restoreDir := filepath.Join(t.TempDir(), "restore")
	restore := NewSimpleRestore(RestoreConfig{
		RepoRoot:  repoDir,
		TargetDir: restoreDir,
		SourceID:  1,
		DeviceID:  "test",
		Key:       key,
		Overwrite: true,
	}, store)
	rResult, err := restore.Run(ctx)
	if err != nil {
		t.Fatalf("restore run: %v", err)
	}
	if rResult.RestoredFiles != 1 {
		t.Fatalf("restored files: got %d, want 1", rResult.RestoredFiles)
	}
	got, err := os.ReadFile(filepath.Join(restoreDir, "mem.bin"))
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if !bytes.Equal(got, updated) {
		t.Fatalf("restored content mismatch: got %d bytes, want %d", len(got), len(updated))
	}
}

// TestUploadChangedChunks_ReReadPath_RestoreRoundtrip exercises the
// two-pass upload path (re-read + per-chunk hash verification, used for
// files above the in-memory threshold) together with the streaming chunked
// restore: blobs produced by re-reading the file must restore to the exact
// original content, chunk by chunk.
func TestUploadChangedChunks_ReReadPath_RestoreRoundtrip(t *testing.T) {
	repoDir := t.TempDir()
	sourceDir := t.TempDir()
	key, _ := GenerateRandomKey()
	store := NewLocalBlobStore(repoDir)
	ctx := context.Background()

	content := make([]byte, 10*1024*1024)
	rand.New(rand.NewSource(7)).Read(content)
	fp := filepath.Join(sourceDir, "twopass.bin")
	if err := os.WriteFile(fp, content, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	p := NewSimplePipeline(PipelineConfig{
		SourceID:   1,
		SourceName: "test",
		SourcePath: sourceDir,
		DeviceID:   "test",
		Key:        key,
		DisableCDC: true,
	}, store)

	// Hash without retention and upload through the re-read path.
	contentHash, chunks, retained, err := p.hashFileWithChunks(ctx, fp, int64(len(content)), false)
	if err != nil {
		t.Fatalf("hashFileWithChunks: %v", err)
	}
	if len(retained) != 0 {
		t.Fatalf("retain=false returned %d chunk buffers, want 0", len(retained))
	}
	if len(chunks) != 3 {
		t.Fatalf("chunks = %d, want 3 (10 MiB in 4 MiB fixed chunks)", len(chunks))
	}
	uploaded, err := p.uploadChangedChunks(ctx, fp, int64(len(content)), chunks, nil, nil)
	if err != nil {
		t.Fatalf("uploadChangedChunks: %v", err)
	}
	if uploaded != int64(len(content)) {
		t.Fatalf("uploaded = %d, want %d", uploaded, len(content))
	}

	// Stream-restore the resulting chunk list and compare byte-exact.
	restoreDir := filepath.Join(t.TempDir(), "restore")
	r := NewSimpleRestore(RestoreConfig{
		RepoRoot:  repoDir,
		TargetDir: restoreDir,
		SourceID:  1,
		DeviceID:  "test",
		Key:       key,
	}, store)
	entry := FileEntry{
		Name:        "twopass.bin",
		ContentHash: contentHash,
		Size:        int64(len(content)),
		Mode:        0644,
		Chunks:      chunks,
	}
	target := filepath.Join(restoreDir, "twopass.bin")
	if err := r.restoreChunkedFile(ctx, entry, target); err != nil {
		t.Fatalf("restoreChunkedFile: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("restored content mismatch: got %d bytes, want %d", len(got), len(content))
	}
}
