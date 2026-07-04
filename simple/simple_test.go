// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
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
	store.Put(ctx, hash1, []byte("encrypted1"))
	store.Put(ctx, hash2, []byte("encrypted2"))
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
	store.Put(ctx, hash, []byte("data"))
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
	if err := SaveManifest(dir, m); err != nil {
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
	os.WriteFile(smallFile, []byte("small file content"), 0644)
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
	os.WriteFile(largeFile, largeData, 0644)
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

func TestPipelineBackupRestore(t *testing.T) {
	repoDir := t.TempDir()
	sourceDir := filepath.Join(t.TempDir(), "source")
	os.MkdirAll(filepath.Join(sourceDir, "subdir"), 0755)
	os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("hello world"), 0644)
	os.WriteFile(filepath.Join(sourceDir, "subdir", "file2.txt"), []byte("nested file"), 0644)

	if err := InitRepo(InitParams{RepoRoot: repoDir, DeviceID: "test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	key, _ := GenerateRandomKey()
	ManifestDecryptHook = func(encrypted []byte) ([]byte, error) {
		return DecryptManifest(encrypted, key)
	}
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
	os.MkdirAll(sourceDir, 0755)
	os.WriteFile(filepath.Join(sourceDir, "file.txt"), []byte("original"), 0644)

	if err := InitRepo(InitParams{RepoRoot: repoDir, DeviceID: "test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	key, _ := GenerateRandomKey()
	ManifestDecryptHook = func(encrypted []byte) ([]byte, error) {
		return DecryptManifest(encrypted, key)
	}
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
	InitRepo(InitParams{RepoRoot: dir, DeviceID: "test"})
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
