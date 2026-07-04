// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/restic/chunker"
)

func TestIsLikelyIncompressible_ImageExtensions(t *testing.T) {
	exts := []string{".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic"}
	for _, ext := range exts {
		if !isLikelyIncompressible("photo" + ext) {
			t.Errorf("isLikelyIncompressible(%q) = false, want true", "photo"+ext)
		}
	}
}

func TestIsLikelyIncompressible_VideoExtensions(t *testing.T) {
	exts := []string{".mp4", ".avi", ".mkv", ".mov"}
	for _, ext := range exts {
		if !isLikelyIncompressible("video" + ext) {
			t.Errorf("isLikelyIncompressible(%q) = false, want true", "video"+ext)
		}
	}
}

func TestIsLikelyIncompressible_AudioExtensions(t *testing.T) {
	exts := []string{".mp3", ".aac", ".flac", ".ogg"}
	for _, ext := range exts {
		if !isLikelyIncompressible("track" + ext) {
			t.Errorf("isLikelyIncompressible(%q) = false, want true", "track"+ext)
		}
	}
}

func TestIsLikelyIncompressible_ArchiveExtensions(t *testing.T) {
	exts := []string{".zip", ".rar", ".7z", ".gz", ".zst"}
	for _, ext := range exts {
		if !isLikelyIncompressible("archive" + ext) {
			t.Errorf("isLikelyIncompressible(%q) = false, want true", "archive"+ext)
		}
	}
}

func TestIsLikelyIncompressible_DiskImageExtensions(t *testing.T) {
	exts := []string{".iso", ".dmg", ".vmdk"}
	for _, ext := range exts {
		if !isLikelyIncompressible("image" + ext) {
			t.Errorf("isLikelyIncompressible(%q) = false, want true", "image"+ext)
		}
	}
}

func TestIsLikelyIncompressible_DocumentExtensions(t *testing.T) {
	exts := []string{".pdf", ".docx", ".xlsx", ".epub"}
	for _, ext := range exts {
		if !isLikelyIncompressible("doc" + ext) {
			t.Errorf("isLikelyIncompressible(%q) = false, want true", "doc"+ext)
		}
	}
}

func TestIsLikelyIncompressible_BinaryExtensions(t *testing.T) {
	exts := []string{".exe", ".dll", ".so", ".dylib"}
	for _, ext := range exts {
		if !isLikelyIncompressible("binary" + ext) {
			t.Errorf("isLikelyIncompressible(%q) = false, want true", "binary"+ext)
		}
	}
}

func TestIsLikelyIncompressible_CaseInsensitive(t *testing.T) {
	cases := []string{"photo.JPG", "video.Mp4", "music.PnG"}
	for _, c := range cases {
		if !isLikelyIncompressible(c) {
			t.Errorf("isLikelyIncompressible(%q) = false, want true", c)
		}
	}
}

func TestIsLikelyIncompressible_CompressibleExtensions(t *testing.T) {
	exts := []string{".txt", ".go", ".py", ".json", ".xml", ".csv", ".log", ".md"}
	for _, ext := range exts {
		if isLikelyIncompressible("file" + ext) {
			t.Errorf("isLikelyIncompressible(%q) = true, want false", "file"+ext)
		}
	}
}

func TestIsLikelyIncompressible_SpecialFilenames(t *testing.T) {
	names := []string{"pagefile.sys", "hiberfil.sys", "swapfile.sys"}
	for _, name := range names {
		if !isLikelyIncompressible(name) {
			t.Errorf("isLikelyIncompressible(%q) = false, want true", name)
		}
	}
}

func TestIsLikelyIncompressible_SpecialFilenamesCaseInsensitive(t *testing.T) {
	if !isLikelyIncompressible("PageFile.Sys") {
		t.Error("isLikelyIncompressible(\"PageFile.Sys\") = false, want true")
	}
}

func TestIsLikelyIncompressible_NoExtension(t *testing.T) {
	if isLikelyIncompressible("Makefile") {
		t.Error("isLikelyIncompressible(\"Makefile\") = true, want false")
	}
}

func TestIsLikelyIncompressible_EmptyString(t *testing.T) {
	if isLikelyIncompressible("") {
		t.Error("isLikelyIncompressible(\"\") = true, want false")
	}
}

func TestNewSimplePipeline_SetsFields(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	cfg := PipelineConfig{
		RepoRoot:    dir,
		SourceID:    42,
		SourceName:  "test-source",
		SourcePath:  "/data",
		DeviceID:    "dev-1",
		Key:         nil,
		Excludes:    []string{"*.tmp"},
		ForceFull:   false,
		WorkerCount: 4,
	}
	p := NewSimplePipeline(cfg, store)
	if p.cfg.SourceID != 42 {
		t.Errorf("SourceID = %d, want 42", p.cfg.SourceID)
	}
	if p.cfg.SourceName != "test-source" {
		t.Errorf("SourceName = %q, want %q", p.cfg.SourceName, "test-source")
	}
	if p.cfg.SourcePath != "/data" {
		t.Errorf("SourcePath = %q, want %q", p.cfg.SourcePath, "/data")
	}
	if p.cfg.DeviceID != "dev-1" {
		t.Errorf("DeviceID = %q, want %q", p.cfg.DeviceID, "dev-1")
	}
	if p.cfg.WorkerCount != 4 {
		t.Errorf("WorkerCount = %d, want 4", p.cfg.WorkerCount)
	}
	if p.store != store {
		t.Error("store not set correctly")
	}
	if p.compressor == nil {
		t.Error("compressor is nil")
	}
}

func TestPipelineConfig_DefaultValues(t *testing.T) {
	cfg := PipelineConfig{}
	if cfg.SourceID != 0 {
		t.Errorf("SourceID = %d, want 0", cfg.SourceID)
	}
	if cfg.ForceFull != false {
		t.Error("ForceFull = true, want false")
	}
	if cfg.Key != nil {
		t.Error("Key should be nil by default")
	}
	if cfg.Excludes != nil {
		t.Error("Excludes should be nil by default")
	}
}

func TestPipelineResult_ZeroValues(t *testing.T) {
	r := PipelineResult{}
	if r.NewFiles != 0 {
		t.Errorf("NewFiles = %d, want 0", r.NewFiles)
	}
	if r.ChangedFiles != 0 {
		t.Errorf("ChangedFiles = %d, want 0", r.ChangedFiles)
	}
	if r.UnchangedFiles != 0 {
		t.Errorf("UnchangedFiles = %d, want 0", r.UnchangedFiles)
	}
	if r.UploadedBytes != 0 {
		t.Errorf("UploadedBytes = %d, want 0", r.UploadedBytes)
	}
	if r.Duration != 0 {
		t.Errorf("Duration = %v, want 0", r.Duration)
	}
	if r.Manifest != nil {
		t.Error("Manifest should be nil")
	}
}

func TestMetaDir(t *testing.T) {
	result := MetaDir("/data/repo")
	expected := filepath.Join("/data/repo", ".ginkgo-backup")
	if result != expected {
		t.Errorf("MetaDir(%q) = %q, want %q", "/data/repo", result, expected)
	}
}

func TestMetaDir_EmptyString(t *testing.T) {
	result := MetaDir("")
	expected := filepath.Join("", ".ginkgo-backup")
	if result != expected {
		t.Errorf("MetaDir(\"\") = %q, want %q", result, expected)
	}
}

type mockBlobStore struct {
	blobs    map[string][]byte
	putCalls int
}

func newMockBlobStore() *mockBlobStore {
	return &mockBlobStore{blobs: make(map[string][]byte)}
}

func (m *mockBlobStore) Put(_ context.Context, hash string, data []byte) error {
	m.putCalls++
	m.blobs[hash] = data
	return nil
}

func (m *mockBlobStore) Get(_ context.Context, hash string) ([]byte, error) {
	data, ok := m.blobs[hash]
	if !ok {
		return nil, fmt.Errorf("blob %s not found", hash)
	}
	return data, nil
}

func (m *mockBlobStore) Exists(_ context.Context, hash string) (bool, error) {
	_, ok := m.blobs[hash]
	return ok, nil
}

func (m *mockBlobStore) PutStream(_ context.Context, hash string, r io.Reader, _ int64) error {
	m.putCalls++
	data, _ := io.ReadAll(r)
	m.blobs[hash] = data
	return nil
}

func (m *mockBlobStore) GetStream(_ context.Context, hash string) (io.ReadCloser, error) {
	data, ok := m.blobs[hash]
	if !ok {
		return nil, fmt.Errorf("blob %s not found", hash)
	}
	// Take the address so the pointer-receiver Read can advance the slice.
	r := bytesReader(data)
	return io.NopCloser(&r), nil
}

func (m *mockBlobStore) List(_ context.Context, _ string) ([]string, error) {
	var result []string
	for k := range m.blobs {
		result = append(result, k)
	}
	return result, nil
}

func (m *mockBlobStore) ListWithModTime(_ context.Context, _ string) ([]BlobInfo, error) {
	var result []BlobInfo
	for k := range m.blobs {
		result = append(result, BlobInfo{Hash: k})
	}
	return result, nil
}

func (m *mockBlobStore) Delete(_ context.Context, hash string) error {
	delete(m.blobs, hash)
	return nil
}

func (m *mockBlobStore) Close() error { return nil }

func (m *mockBlobStore) BlobPath(hash string) string {
	return filepath.Join("mock", "gb", hash[:2], hash+".gb")
}

type bytesReader []byte

// Pointer receiver so the b = b[n:] slice advance persists across Read
// calls. With a value receiver the slice header is copied on every call,
// the advance is lost, and the reader loops forever returning the same
// prefix — staticcheck flags the assignment as unused (SA4006).
func (b *bytesReader) Read(p []byte) (int, error) {
	if len(*b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, *b)
	*b = (*b)[n:]
	return n, nil
}

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func fileMtime(p string) string {
	fi, err := os.Stat(p)
	if err != nil {
		return ""
	}
	return fi.ModTime().UTC().Format(time.RFC3339)
}

func fileSize(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func TestProcessFile_NewFile(t *testing.T) {
	dir := t.TempDir()
	store := newMockBlobStore()
	cfg := PipelineConfig{
		SourceID:   1,
		SourceName: "test",
		SourcePath: dir,
		DeviceID:   "dev",
		Key:        nil,
	}
	p := NewSimplePipeline(cfg, store)

	fp := writeTestFile(t, dir, "new.txt", "hello world")
	fe := scanEntry{
		relPath: "new.txt",
		absPath: fp,
		size:    fileSize(fp),
		mtime:   fileMtime(fp),
		mode:    0644,
	}

	entry, uploaded, isChanged, isNew, _ := p.processFile(context.Background(), fe, nil)
	if entry == nil {
		t.Fatal("entry is nil")
	}
	if !isNew {
		t.Error("isNew = false, want true for new file")
	}
	if isChanged {
		t.Error("isChanged = true, want false for new file")
	}
	if uploaded == 0 {
		t.Error("uploaded = 0, want > 0 for new file")
	}
	if entry.ContentHash == "" {
		t.Error("ContentHash is empty")
	}
	if entry.Name != "new.txt" {
		t.Errorf("Name = %q, want %q", entry.Name, "new.txt")
	}
}

func TestProcessFile_UnchangedFile(t *testing.T) {
	dir := t.TempDir()
	store := newMockBlobStore()
	cfg := PipelineConfig{
		SourceID:   1,
		SourceName: "test",
		SourcePath: dir,
		DeviceID:   "dev",
		Key:        nil,
	}
	p := NewSimplePipeline(cfg, store)

	fp := writeTestFile(t, dir, "unchanged.txt", "same content")
	mtime := fileMtime(fp)
	size := fileSize(fp)

	content := []byte("same content")
	h := sha256.Sum256(content)
	hash := hex.EncodeToString(h[:])
	store.blobs[hash] = content

	prevFiles := map[string]FileEntry{
		"unchanged.txt": {
			Name:        "unchanged.txt",
			ContentHash: hash,
			Size:        size,
			Mtime:       FlexTime(mtime),
			Mode:        0644,
		},
	}

	fe := scanEntry{
		relPath: "unchanged.txt",
		absPath: fp,
		size:    size,
		mtime:   mtime,
		mode:    0644,
	}

	entry, uploaded, isChanged, isNew, _ := p.processFile(context.Background(), fe, prevFiles)
	if entry == nil {
		t.Fatal("entry is nil")
	}
	if isNew {
		t.Error("isNew = true, want false for unchanged file")
	}
	if isChanged {
		t.Error("isChanged = true, want false for unchanged file")
	}
	if uploaded != 0 {
		t.Errorf("uploaded = %d, want 0 for unchanged file", uploaded)
	}
	if store.putCalls != 0 {
		t.Errorf("putCalls = %d, want 0 for unchanged file", store.putCalls)
	}
}

func TestProcessFile_ChangedFile(t *testing.T) {
	dir := t.TempDir()
	store := newMockBlobStore()
	cfg := PipelineConfig{
		SourceID:   1,
		SourceName: "test",
		SourcePath: dir,
		DeviceID:   "dev",
		Key:        nil,
	}
	p := NewSimplePipeline(cfg, store)

	fp := writeTestFile(t, dir, "changed.txt", "new content")

	oldHash := SHA256Bytes([]byte("old content"))
	store.blobs[oldHash] = []byte("old content")

	prevFiles := map[string]FileEntry{
		"changed.txt": {
			Name:        "changed.txt",
			ContentHash: oldHash,
			Size:        11,
			Mtime:       "2020-01-01T00:00:00Z",
			Mode:        0644,
		},
	}

	fe := scanEntry{
		relPath: "changed.txt",
		absPath: fp,
		size:    fileSize(fp),
		mtime:   fileMtime(fp),
		mode:    0644,
	}

	entry, uploaded, isChanged, isNew, _ := p.processFile(context.Background(), fe, prevFiles)
	if entry == nil {
		t.Fatal("entry is nil")
	}
	if isNew {
		t.Error("isNew = true, want false for changed file")
	}
	if !isChanged {
		t.Error("isChanged = false, want true for changed file")
	}
	if uploaded == 0 {
		t.Error("uploaded = 0, want > 0 for changed file")
	}
}

func TestProcessFile_MissingBlobMtimeMatch(t *testing.T) {
	dir := t.TempDir()
	store := newMockBlobStore()
	cfg := PipelineConfig{
		SourceID:   1,
		SourceName: "test",
		SourcePath: dir,
		DeviceID:   "dev",
		Key:        nil,
	}
	p := NewSimplePipeline(cfg, store)

	fp := writeTestFile(t, dir, "missing.txt", "content")
	mtime := fileMtime(fp)
	size := fileSize(fp)

	oldHash := SHA256Bytes([]byte("content"))

	prevFiles := map[string]FileEntry{
		"missing.txt": {
			Name:        "missing.txt",
			ContentHash: oldHash,
			Size:        size,
			Mtime:       FlexTime(mtime),
			Mode:        0644,
		},
	}

	fe := scanEntry{
		relPath: "missing.txt",
		absPath: fp,
		size:    size,
		mtime:   mtime,
		mode:    0644,
	}

	entry, uploaded, _, _, _ := p.processFile(context.Background(), fe, prevFiles)
	if entry == nil {
		t.Fatal("entry is nil for missing blob case")
	}
	if uploaded == 0 {
		t.Error("uploaded = 0, want > 0 when blob is missing despite mtime+size match")
	}
	if store.putCalls == 0 {
		t.Error("putCalls = 0, want > 0; missing blob should trigger re-upload")
	}
}

func TestProcessFile_MissingBlobContentHashMatch(t *testing.T) {
	dir := t.TempDir()
	store := newMockBlobStore()
	cfg := PipelineConfig{
		SourceID:   1,
		SourceName: "test",
		SourcePath: dir,
		DeviceID:   "dev",
		Key:        nil,
	}
	p := NewSimplePipeline(cfg, store)

	fp := writeTestFile(t, dir, "gone.txt", "data")

	contentHash := SHA256Bytes([]byte("data"))

	prevFiles := map[string]FileEntry{
		"gone.txt": {
			Name:        "gone.txt",
			ContentHash: contentHash,
			Size:        4,
			Mtime:       "2020-01-01T00:00:00Z",
			Mode:        0644,
		},
	}

	fe := scanEntry{
		relPath: "gone.txt",
		absPath: fp,
		size:    fileSize(fp),
		mtime:   fileMtime(fp),
		mode:    0644,
	}

	entry, uploaded, _, _, _ := p.processFile(context.Background(), fe, prevFiles)
	if entry == nil {
		t.Fatal("entry is nil for missing blob with content hash match")
	}
	if uploaded == 0 {
		t.Error("uploaded = 0, want > 0 when blob missing despite content hash match")
	}
	if store.putCalls == 0 {
		t.Error("putCalls = 0, want > 0; missing blob should trigger re-upload even with hash match")
	}
}

func TestHashOnlyFile(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "test.txt")
	content := []byte("hash only test")
	if err := os.WriteFile(fp, content, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := PipelineConfig{
		SourceID:   1,
		SourceName: "test",
		SourcePath: dir,
		DeviceID:   "dev",
		Key:        nil,
	}
	store := newMockBlobStore()
	p := NewSimplePipeline(cfg, store)

	hash, data, err := p.hashOnlyFile(context.Background(), fp, int64(len(content)))
	if err != nil {
		t.Fatalf("hashOnlyFile: %v", err)
	}

	expectedHash := SHA256Bytes(content)
	if hash != expectedHash {
		t.Errorf("hash = %q, want %q", hash, expectedHash)
	}
	if !bytesEqual(data, content) {
		t.Errorf("data mismatch: got %q, want %q", string(data), string(content))
	}
}

func TestHashOnlyFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(fp, []byte{}, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := PipelineConfig{
		SourceID:   1,
		SourceName: "test",
		SourcePath: dir,
		DeviceID:   "dev",
		Key:        nil,
	}
	store := newMockBlobStore()
	p := NewSimplePipeline(cfg, store)

	hash, data, err := p.hashOnlyFile(context.Background(), fp, 0)
	if err != nil {
		t.Fatalf("hashOnlyFile: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("data length = %d, want 0", len(data))
	}
	expectedHash := SHA256Bytes([]byte{})
	if hash != expectedHash {
		t.Errorf("hash = %q, want %q", hash, expectedHash)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPipelineEmptyDirDetection(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "empty"), 0755); err != nil {
		t.Fatalf("mkdir empty: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "parent", "child_empty"), 0755); err != nil {
		t.Fatalf("mkdir child_empty: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "has_files"), 0755); err != nil {
		t.Fatalf("mkdir has_files: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "has_files", "file.txt"), []byte("data"), 0644); err != nil {
		t.Fatalf("write file.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root.txt"), []byte("root"), 0644); err != nil {
		t.Fatalf("write root.txt: %v", err)
	}

	repoDir := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := InitRepoWithPassword(repoDir, "test", "demo-password"); err != nil {
		t.Fatalf("init repo: %v", err)
	}

	store := NewLocalBlobStore(repoDir)
	cfg := PipelineConfig{
		RepoRoot:   repoDir,
		SourceID:   1,
		SourceName: "test",
		SourcePath: dir,
		DeviceID:   "test",
	}
	sp := NewSimplePipeline(cfg, store)
	result, err := sp.Run(context.Background())
	if err != nil {
		t.Fatalf("pipeline run: %v", err)
	}

	emptyDirMap := make(map[string]bool)
	for dirPath, d := range result.Manifest.Dirs {
		if len(d.Files) == 0 && len(d.SubDirs) == 0 && dirPath != "" {
			emptyDirMap[dirPath] = true
		}
	}

	if !emptyDirMap["empty"] {
		t.Error("expected 'empty' to be detected as empty dir")
	}
	if !emptyDirMap["parent/child_empty"] {
		t.Error("expected 'parent/child_empty' to be detected as empty dir")
	}
	if emptyDirMap["has_files"] {
		t.Error("'has_files' should NOT be detected as empty dir (contains file.txt)")
	}
	if emptyDirMap["parent"] {
		t.Error("'parent' should NOT be detected as empty dir (contains child_empty)")
	}
}

func TestProcessFileStreaming_CompressesLargeChunks(t *testing.T) {
	dir := t.TempDir()
	store := newMockBlobStore()
	key := make([]byte, 32)
	cfg := PipelineConfig{
		SourceID:   1,
		SourceName: "test",
		SourcePath: dir,
		DeviceID:   "dev",
		Key:        key,
		DisableCDC: true,
	}
	p := NewSimplePipeline(cfg, store)

	size := int64(DefaultChunkSize + 100)
	content := bytes.Repeat([]byte("a"), int(size))
	fp := filepath.Join(dir, "big.txt")
	if err := os.WriteFile(fp, content, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	fe := scanEntry{
		relPath: "big.txt",
		absPath: fp,
		size:    size,
		mtime:   fileMtime(fp),
		mode:    0644,
	}

	entry, uploaded, _, _, err := p.processFileStreaming(context.Background(), fe, nil)
	if err != nil {
		t.Fatalf("processFileStreaming: %v", err)
	}
	if entry == nil {
		t.Fatal("entry is nil")
	}
	if len(entry.Chunks) != 2 {
		t.Fatalf("chunks = %d, want 2", len(entry.Chunks))
	}
	if uploaded != size {
		t.Errorf("uploaded = %d, want %d", uploaded, size)
	}

	dec := NewDecryptor(key, DefaultChunkSize)
	for i, c := range entry.Chunks {
		got, err := DownloadBlob(context.Background(), store, dec, c.Hash)
		if err != nil {
			t.Fatalf("download chunk %d: %v", i, err)
		}
		start := int64(i) * int64(DefaultChunkSize)
		end := start + int64(DefaultChunkSize)
		if end > size {
			end = size
		}
		if !bytes.Equal(got, content[start:end]) {
			t.Errorf("chunk %d data mismatch (got len=%d, want len=%d)", i, len(got), end-start)
		}
	}

	firstStored := store.blobs[entry.Chunks[0].Hash]
	if len(firstStored) >= DefaultChunkSize {
		t.Errorf("first chunk stored size %d >= %d, compression not applied", len(firstStored), DefaultChunkSize)
	}
}

func TestProcessFileStreaming_SkipsCompressionForIncompressible(t *testing.T) {
	dir := t.TempDir()
	store := newMockBlobStore()
	key := make([]byte, 32)
	cfg := PipelineConfig{
		SourceID:   1,
		SourceName: "test",
		SourcePath: dir,
		DeviceID:   "dev",
		Key:        key,
		DisableCDC: true,
	}
	p := NewSimplePipeline(cfg, store)

	size := int64(DefaultChunkSize + 100)
	content := bytes.Repeat([]byte("a"), int(size))
	fp := filepath.Join(dir, "big.zip")
	if err := os.WriteFile(fp, content, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	fe := scanEntry{
		relPath: "big.zip",
		absPath: fp,
		size:    size,
		mtime:   fileMtime(fp),
		mode:    0644,
	}

	entry, uploaded, _, _, err := p.processFileStreaming(context.Background(), fe, nil)
	if err != nil {
		t.Fatalf("processFileStreaming: %v", err)
	}
	if entry == nil {
		t.Fatal("entry is nil")
	}
	if len(entry.Chunks) != 2 {
		t.Fatalf("chunks = %d, want 2", len(entry.Chunks))
	}
	if uploaded != size {
		t.Errorf("uploaded = %d, want %d", uploaded, size)
	}

	dec := NewDecryptor(key, DefaultChunkSize)
	for i, c := range entry.Chunks {
		got, err := DownloadBlob(context.Background(), store, dec, c.Hash)
		if err != nil {
			t.Fatalf("download chunk %d: %v", i, err)
		}
		start := int64(i) * int64(DefaultChunkSize)
		end := start + int64(DefaultChunkSize)
		if end > size {
			end = size
		}
		if !bytes.Equal(got, content[start:end]) {
			t.Errorf("chunk %d data mismatch (got len=%d, want len=%d)", i, len(got), end-start)
		}
	}

	firstStored := store.blobs[entry.Chunks[0].Hash]
	if len(firstStored) <= DefaultChunkSize {
		t.Errorf("first chunk stored size %d <= %d, expected raw chunk with encryption overhead", len(firstStored), DefaultChunkSize)
	}
}

func TestHashFileWithCDC_Basic(t *testing.T) {
	t.Setenv("GINKGO_CDC", "1")
	// Derive a valid irreducible polynomial since this test bypasses Run()
	// and therefore never loads the per-repo polynomial from config.
	pol, err := GenerateCDCPolynomial()
	if err != nil {
		t.Fatalf("derive polynomial: %v", err)
	}
	SetCDCPolynomial(pol)
	dir := t.TempDir()
	size := int64(8 * 1024 * 1024)
	data := make([]byte, size)
	rand.New(rand.NewSource(42)).Read(data)
	fp := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(fp, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := PipelineConfig{SourceID: 1, SourceName: "test", SourcePath: dir, DeviceID: "dev", Key: make([]byte, 32)}
	p := NewSimplePipeline(cfg, newMockBlobStore())
	contentHash, chunks, err := p.hashFileWithCDC(context.Background(), fp, size)
	if err != nil {
		t.Fatalf("hashFileWithCDC: %v", err)
	}

	var sum int64
	for _, c := range chunks {
		sum += c.Size
	}
	if sum != size {
		t.Errorf("chunk sizes sum = %d, want %d", sum, size)
	}

	expectedHash := SHA256Bytes(data)
	if contentHash != expectedHash {
		t.Errorf("contentHash = %q, want %q", contentHash, expectedHash)
	}
}

func TestProcessFileStreaming_CDC_DedupsShiftedData(t *testing.T) {
	t.Setenv("GINKGO_CDC", "1")
	// Derive a deterministic irreducible polynomial so the test is
	// reproducible. Using crypto/rand per run makes the dedup ratio
	// non-deterministic and the test flaky. The seed below yields a
	// polynomial that produces stable chunk boundaries for shifted data.
	pol, err := chunker.DerivePolynomial(rand.New(rand.NewSource(42)))
	if err != nil {
		t.Fatalf("derive deterministic polynomial: %v", err)
	}
	SetCDCPolynomial(uint64(pol))
	dir := t.TempDir()
	store := newMockBlobStore()
	key := make([]byte, 32)
	cfg := PipelineConfig{SourceID: 1, SourceName: "test", SourcePath: dir, DeviceID: "dev", Key: key}
	p := NewSimplePipeline(cfg, store)

	size := int64(16 * 1024 * 1024)
	base := make([]byte, size)
	rand.New(rand.NewSource(7)).Read(base)

	basePath := filepath.Join(dir, "base.bin")
	if err := os.WriteFile(basePath, base, 0644); err != nil {
		t.Fatalf("write base: %v", err)
	}
	fe := scanEntry{
		relPath: "file.bin",
		absPath: basePath,
		size:    size,
		mtime:   fileMtime(basePath),
		mode:    0644,
	}

	entry1, _, _, _, err := p.processFileStreaming(context.Background(), fe, nil)
	if err != nil {
		t.Fatalf("first processFileStreaming: %v", err)
	}
	if len(entry1.Chunks) < 2 {
		t.Fatalf("expected multiple cdc chunks, got %d", len(entry1.Chunks))
	}

	shifted := append([]byte{0xAB}, base...)
	shiftedPath := filepath.Join(dir, "shifted.bin")
	if err := os.WriteFile(shiftedPath, shifted, 0644); err != nil {
		t.Fatalf("write shifted: %v", err)
	}
	fe2 := scanEntry{
		relPath: "file.bin",
		absPath: shiftedPath,
		size:    int64(len(shifted)),
		mtime:   fileMtime(shiftedPath),
		mode:    0644,
	}
	prevFiles := map[string]FileEntry{
		"file.bin": *entry1,
	}

	_, uploaded2, _, _, err := p.processFileStreaming(context.Background(), fe2, prevFiles)
	if err != nil {
		t.Fatalf("second processFileStreaming: %v", err)
	}

	if uploaded2 >= size/2 {
		t.Errorf("uploaded after shift = %d, expected << %d", uploaded2, size/2)
	}
}

func TestCDCEnabled_DefaultOn(t *testing.T) {
	p := NewSimplePipeline(PipelineConfig{}, nil)
	if !p.cdcEnabled() {
		t.Error("expected CDC enabled by default")
	}
}

func TestCDCEnabled_ConfigDisable(t *testing.T) {
	p := NewSimplePipeline(PipelineConfig{DisableCDC: true}, nil)
	if p.cdcEnabled() {
		t.Error("expected CDC disabled when PipelineConfig.DisableCDC=true")
	}
}

func TestCDCEnabled_EnvOverrideDisable(t *testing.T) {
	t.Setenv("GINKGO_CDC", "0")
	p := NewSimplePipeline(PipelineConfig{}, nil)
	if p.cdcEnabled() {
		t.Error("expected GINKGO_CDC=0 to disable CDC")
	}
}

func TestCDCEnabled_EnvOverrideEnable(t *testing.T) {
	t.Setenv("GINKGO_CDC", "1")
	p := NewSimplePipeline(PipelineConfig{DisableCDC: true}, nil)
	if !p.cdcEnabled() {
		t.Error("expected GINKGO_CDC=1 to enable CDC even when config disables")
	}
}
