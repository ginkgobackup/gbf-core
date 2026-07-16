// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileEntryMtimeMicro(t *testing.T) {
	t.Run("valid_rfc3339", func(t *testing.T) {
		f := FileEntry{Mtime: "2026-05-19T10:30:00Z"}
		got := f.MtimeMicro()
		expected := time.Date(2026, 5, 19, 10, 30, 0, 0, time.UTC).UnixMicro()
		if got != expected {
			t.Fatalf("got %d, want %d", got, expected)
		}
	})

	t.Run("valid_rfc3339_with_nanos", func(t *testing.T) {
		f := FileEntry{Mtime: "2026-05-19T10:30:00.123456Z"}
		got := f.MtimeMicro()
		expected := time.Date(2026, 5, 19, 10, 30, 0, 123456000, time.UTC).UnixMicro()
		if got != expected {
			t.Fatalf("got %d, want %d", got, expected)
		}
	})

	t.Run("empty_string", func(t *testing.T) {
		f := FileEntry{Mtime: ""}
		if got := f.MtimeMicro(); got != 0 {
			t.Fatalf("got %d, want 0", got)
		}
	})

	t.Run("invalid_format", func(t *testing.T) {
		f := FileEntry{Mtime: "not-a-date"}
		if got := f.MtimeMicro(); got != 0 {
			t.Fatalf("got %d, want 0", got)
		}
	})
}

func TestFileEntryMtimeTime(t *testing.T) {
	t.Run("valid_rfc3339", func(t *testing.T) {
		f := FileEntry{Mtime: "2026-05-19T10:30:00Z"}
		got := f.MtimeTime()
		expected := time.Date(2026, 5, 19, 10, 30, 0, 0, time.UTC)
		if !got.Equal(expected) {
			t.Fatalf("got %v, want %v", got, expected)
		}
	})

	t.Run("empty_string", func(t *testing.T) {
		f := FileEntry{Mtime: ""}
		got := f.MtimeTime()
		if !got.IsZero() {
			t.Fatalf("got %v, want zero time", got)
		}
	})

	t.Run("invalid_format", func(t *testing.T) {
		f := FileEntry{Mtime: "garbage"}
		got := f.MtimeTime()
		if !got.IsZero() {
			t.Fatalf("got %v, want zero time", got)
		}
	})
}

func TestManifestChecksumSidecar(t *testing.T) {
	dir := t.TempDir()

	m := NewManifest(1, "", "src", "/data", "dev1")
	m.Timestamp = "2026-05-19T10:00:00Z"
	m.AddFile(FileEntry{Name: "a.txt", Size: 10})
	if _, err := SaveManifest(dir, m); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := LoadLatestManifest(dir, ManifestPathKey("dev1", "1"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.SourceID != 1 {
		t.Fatalf("SourceID: got %d, want 1", loaded.SourceID)
	}

	manifestDir := ManifestDir(dir, ManifestPathKey("dev1", "1"))
	entries, err := os.ReadDir(manifestDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var manifestPath string
	for _, e := range entries {
		if isManifestFile(e.Name()) {
			manifestPath = filepath.Join(manifestDir, e.Name())
			break
		}
	}
	if manifestPath == "" {
		t.Fatal("no manifest file found")
	}

	// Tamper with the manifest file; the next load should fail checksum verification.
	if err := os.WriteFile(manifestPath, []byte("tampered"), 0644); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := LoadManifest(manifestPath); err == nil {
		t.Fatal("expected checksum mismatch error after tampering")
	}
}

func TestManifestChecksumSidecarMissingIsRejected(t *testing.T) {
	dir := t.TempDir()

	m := NewManifest(1, "", "src", "/data", "dev1")
	m.Timestamp = "2026-05-19T10:00:00Z"
	m.AddFile(FileEntry{Name: "a.txt", Size: 10})
	if _, err := SaveManifest(dir, m); err != nil {
		t.Fatalf("save: %v", err)
	}

	manifestDir := ManifestDir(dir, ManifestPathKey("dev1", "1"))
	entries, err := os.ReadDir(manifestDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var manifestPath string
	for _, e := range entries {
		if isManifestFile(e.Name()) {
			manifestPath = filepath.Join(manifestDir, e.Name())
			break
		}
	}
	if manifestPath == "" {
		t.Fatal("no manifest file found")
	}

	if err := os.Remove(manifestChecksumPath(manifestPath)); err != nil {
		t.Fatalf("remove checksum: %v", err)
	}

	// A manifest without a sidecar checksum is not trustworthy: an attacker
	// (or partial sync) could tamper with the body without detection. Load
	// must refuse rather than silently accept.
	if _, err := LoadManifest(manifestPath); err == nil {
		t.Fatal("expected error when checksum sidecar is missing")
	}
}

func TestExtractHashesFromJSON_InvalidJSONReturnsError(t *testing.T) {
	_, err := extractHashesFromJSON([]byte("not valid json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestExtractHashesFromJSON_ValidManifest(t *testing.T) {
	m := NewManifest(1, "", "src", "/data", "dev1")
	m.AddFile(FileEntry{Name: "a.txt", ContentHash: "hash_a", Size: 10})
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	hashes, err := extractHashesFromJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hashes) != 1 || hashes[0] != "hash_a" {
		t.Fatalf("expected [hash_a], got %v", hashes)
	}
}

func TestManifestBuildFileMap(t *testing.T) {
	t.Run("multiple_files", func(t *testing.T) {
		m := NewManifest(1, "", "src", "/data", "dev1")
		m.AddFile(FileEntry{Name: "a.txt", ContentHash: "hash_a", Size: 10})
		m.AddFile(FileEntry{Name: "b.txt", ContentHash: "hash_b", Size: 20})
		m.AddFile(FileEntry{Name: "c.txt", ContentHash: "hash_c", Size: 30})
		fm := m.BuildFileMap()
		if len(fm) != 3 {
			t.Fatalf("got %d entries, want 3", len(fm))
		}
		if fm["a.txt"].ContentHash != "hash_a" {
			t.Fatalf("a.txt hash: got %q", fm["a.txt"].ContentHash)
		}
		if fm["b.txt"].ContentHash != "hash_b" {
			t.Fatalf("b.txt hash: got %q", fm["b.txt"].ContentHash)
		}
		if fm["c.txt"].ContentHash != "hash_c" {
			t.Fatalf("c.txt hash: got %q", fm["c.txt"].ContentHash)
		}
	})

	t.Run("duplicate_paths_last_wins", func(t *testing.T) {
		m := NewManifest(1, "", "src", "/data", "dev1")
		m.AddFile(FileEntry{Name: "a.txt", ContentHash: "hash_old", Size: 10})
		m.AddFile(FileEntry{Name: "a.txt", ContentHash: "hash_new", Size: 20})
		fm := m.BuildFileMap()
		if len(fm) != 1 {
			t.Fatalf("got %d entries, want 1", len(fm))
		}
		if fm["a.txt"].ContentHash != "hash_new" {
			t.Fatalf("got %q, want hash_new", fm["a.txt"].ContentHash)
		}
		if fm["a.txt"].Size != 20 {
			t.Fatalf("got size %d, want 20", fm["a.txt"].Size)
		}
	})

	t.Run("empty_manifest", func(t *testing.T) {
		m := NewManifest(1, "", "src", "/data", "dev1")
		fm := m.BuildFileMap()
		if len(fm) != 0 {
			t.Fatalf("got %d entries, want 0", len(fm))
		}
	})
}

func TestManifestAddFile(t *testing.T) {
	m := NewManifest(1, "", "src", "/data", "dev1")
	if m.Stats.FileCount != 0 || m.Stats.TotalSize != 0 {
		t.Fatalf("initial stats: FileCount=%d TotalSize=%d", m.Stats.FileCount, m.Stats.TotalSize)
	}

	m.AddFile(FileEntry{Name: "a.txt", Size: 100})
	if m.Stats.FileCount != 1 {
		t.Fatalf("FileCount: got %d, want 1", m.Stats.FileCount)
	}
	if m.Stats.TotalSize != 100 {
		t.Fatalf("TotalSize: got %d, want 100", m.Stats.TotalSize)
	}

	m.AddFile(FileEntry{Name: "b.txt", Size: 250})
	if m.Stats.FileCount != 2 {
		t.Fatalf("FileCount: got %d, want 2", m.Stats.FileCount)
	}
	if m.Stats.TotalSize != 350 {
		t.Fatalf("TotalSize: got %d, want 350", m.Stats.TotalSize)
	}

	m.AddFile(FileEntry{Name: "c.txt", Size: 0})
	if m.Stats.FileCount != 3 {
		t.Fatalf("FileCount: got %d, want 3", m.Stats.FileCount)
	}
	if m.Stats.TotalSize != 350 {
		t.Fatalf("TotalSize: got %d, want 350", m.Stats.TotalSize)
	}

	if m.Stats.FileCount != 3 {
		t.Fatalf("Files length: got %d, want 3", m.Stats.FileCount)
	}
}

func TestManifestFilePath(t *testing.T) {
	ts := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	got := ManifestFilePath("/repo/.ginkgo-backup", "cloud42", ts, "dev1")
	expected := filepath.Join("/repo/.ginkgo-backup", "manifests", "cloud42", fmt.Sprintf("%d_dev1.json.zst", ts.Unix()))
	if got != expected {
		t.Fatalf("got %q, want %q", got, expected)
	}
}

func TestSaveManifestWithKey(t *testing.T) {
	dir := t.TempDir()
	key, err := GenerateRandomKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	m := NewManifest(1, "", "src", "/data", "dev1")
	m.AddFile(FileEntry{Name: "secret.txt", ContentHash: "abc123", Size: 42, Mtime: "2026-05-19T10:00:00Z", Mode: 0644})

	if _, err := SaveManifestWithKey(dir, m, key); err != nil {
		t.Fatalf("save with key: %v", err)
	}

	origHook := ManifestDecryptHook
	ManifestDecryptHook = func(encrypted []byte) ([]byte, error) {
		return DecryptManifest(encrypted, key)
	}
	defer func() { ManifestDecryptHook = origHook }()

	loaded, err := LoadLatestManifest(dir, ManifestPathKey("dev1", "1"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.SourceID != 1 {
		t.Fatalf("SourceID: got %d, want 1", loaded.SourceID)
	}
	allFiles := loaded.AllFiles()
	if len(allFiles) != 1 {
		t.Fatalf("Files: got %d, want 1", len(allFiles))
	}
	if allFiles[0].Name != "secret.txt" {
		t.Fatalf("Name: got %q", allFiles[0].Name)
	}
	if allFiles[0].ContentHash != "abc123" {
		t.Fatalf("ContentHash: got %q", allFiles[0].ContentHash)
	}
	if allFiles[0].Size != 42 {
		t.Fatalf("Size: got %d, want 42", allFiles[0].Size)
	}
}

func TestLoadManifestFromData(t *testing.T) {
	t.Run("plain_json", func(t *testing.T) {
		m := NewManifest(1, "", "src", "/data", "dev1")
		m.AddFile(FileEntry{Name: "a.txt", Size: 10})
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		loaded, err := LoadManifestFromData(data)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if loaded.SourceID != 1 {
			t.Fatalf("SourceID: got %d, want 1", loaded.SourceID)
		}
	})

	t.Run("compressed", func(t *testing.T) {
		m := NewManifest(2, "2", "src", "/data", "dev1")
		m.AddFile(FileEntry{Name: "b.txt", Size: 20})
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		compressed, err := localManifestCompressor.Compress(data)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		loaded, err := LoadManifestFromData(compressed)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if loaded.SourceID != 2 {
			t.Fatalf("SourceID: got %d, want 2", loaded.SourceID)
		}
		if loaded.AllFiles()[0].Name != "b.txt" {
			t.Fatalf("Name: got %q", loaded.AllFiles()[0].Name)
		}
	})

	t.Run("gkm1_encrypted_with_hook", func(t *testing.T) {
		key, err := GenerateRandomKey()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		m := NewManifest(3, "3", "src", "/data", "dev1")
		m.AddFile(FileEntry{Name: "c.txt", Size: 30})
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		compressed, err := localManifestCompressor.Compress(data)
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		encrypted, err := EncryptManifest(compressed, key)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if string(encrypted[:4]) != GKM1Magic {
			t.Fatalf("magic: got %q, want %q", encrypted[:4], GKM1Magic)
		}

		origHook := ManifestDecryptHook
		ManifestDecryptHook = func(enc []byte) ([]byte, error) {
			return DecryptManifest(enc, key)
		}
		defer func() { ManifestDecryptHook = origHook }()

		loaded, err := LoadManifestFromData(encrypted)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if loaded.SourceID != 3 {
			t.Fatalf("SourceID: got %d, want 3", loaded.SourceID)
		}
	})

	t.Run("gkm1_encrypted_no_hook", func(t *testing.T) {
		key, err := GenerateRandomKey()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		plaintext := []byte(`{"version":1}`)
		compressed, _ := localManifestCompressor.Compress(plaintext)
		encrypted, _ := EncryptManifest(compressed, key)

		origHook := ManifestDecryptHook
		ManifestDecryptHook = nil
		defer func() { ManifestDecryptHook = origHook }()

		_, err = LoadManifestFromData(encrypted)
		if err == nil {
			t.Fatal("expected error for encrypted manifest without hook")
		}
	})

	t.Run("invalid_data", func(t *testing.T) {
		_, err := LoadManifestFromData([]byte("not json at all"))
		if err == nil {
			t.Fatal("expected error for invalid data")
		}
	})

	t.Run("short_data", func(t *testing.T) {
		_, err := LoadManifestFromData([]byte("{}"))
		if err != nil {
			t.Fatalf("empty json object should parse: %v", err)
		}
	})

	t.Run("v1_migration", func(t *testing.T) {
		v1JSON := `{
			"version": 1,
			"sourceId": 42,
			"sourceName": "legacy",
			"sourcePath": "/old",
			"timestamp": "2026-01-01T00:00:00Z",
			"deviceId": "dev1",
			"files": [
				{"path": "root.txt", "contentHash": "h1", "size": 10},
				{"path": "sub/nested.txt", "contentHash": "h2", "size": 20},
				{"path": "a/b/deep.txt", "contentHash": "h3", "size": 30}
			],
			"emptyDirs": [
				{"relPath": "empty_dir", "name": "empty_dir"},
				{"relPath": "a/b/empty_nested", "name": "empty_nested"}
			],
			"stats": {"fileCount": 3, "totalSize": 60}
		}`
		m, err := LoadManifestFromData([]byte(v1JSON))
		if err != nil {
			t.Fatalf("load v1: %v", err)
		}
		if m.Version != 2 {
			t.Fatalf("version: got %d, want 2", m.Version)
		}
		if m.Stats.FileCount != 3 {
			t.Fatalf("fileCount: got %d, want 3", m.Stats.FileCount)
		}
		allFiles := m.AllFiles()
		if len(allFiles) != 3 {
			t.Fatalf("allFiles: got %d, want 3", len(allFiles))
		}
		fm := m.BuildFileMap()
		if fm["root.txt"].ContentHash != "h1" {
			t.Fatalf("root.txt hash: got %q", fm["root.txt"].ContentHash)
		}
		if fm["sub/nested.txt"].ContentHash != "h2" {
			t.Fatalf("sub/nested.txt hash: got %q", fm["sub/nested.txt"].ContentHash)
		}
		if fm["a/b/deep.txt"].ContentHash != "h3" {
			t.Fatalf("a/b/deep.txt hash: got %q", fm["a/b/deep.txt"].ContentHash)
		}
		if d, ok := m.Dirs["sub"]; !ok || len(d.Files) != 1 || d.Files[0].Name != "nested.txt" {
			t.Fatalf("sub dir: got %v", m.Dirs["sub"])
		}
		if d, ok := m.Dirs["empty_dir"]; !ok || len(d.Files) != 0 {
			t.Fatalf("empty_dir: got %v", m.Dirs["empty_dir"])
		}
		if d, ok := m.Dirs["a/b/empty_nested"]; !ok || len(d.Files) != 0 {
			t.Fatalf("empty_nested: got %v", m.Dirs["a/b/empty_nested"])
		}
	})
}

func TestLoadLatestManifest(t *testing.T) {
	t.Run("multiple_manifests_returns_latest", func(t *testing.T) {
		dir := t.TempDir()

		m1 := NewManifest(1, "", "src", "/data", "dev1")
		m1.Timestamp = "2026-05-19T10:00:00Z"
		m1.AddFile(FileEntry{Name: "old.txt", Size: 10})
		if _, err := SaveManifest(dir, m1); err != nil {
			t.Fatalf("save m1: %v", err)
		}

		m2 := NewManifest(1, "", "src", "/data", "dev1")
		m2.Timestamp = "2026-05-19T12:00:00Z"
		m2.AddFile(FileEntry{Name: "new.txt", Size: 20})
		if _, err := SaveManifest(dir, m2); err != nil {
			t.Fatalf("save m2: %v", err)
		}

		m3 := NewManifest(1, "", "src", "/data", "dev1")
		m3.Timestamp = "2026-05-19T11:00:00Z"
		m3.AddFile(FileEntry{Name: "mid.txt", Size: 15})
		if _, err := SaveManifest(dir, m3); err != nil {
			t.Fatalf("save m3: %v", err)
		}

		loaded, err := LoadLatestManifest(dir, ManifestPathKey("dev1", "1"))
		if err != nil {
			t.Fatalf("load latest: %v", err)
		}
		if loaded.AllFiles()[0].Name != "new.txt" {
			t.Fatalf("got %q, want new.txt (latest manifest)", loaded.AllFiles()[0].Name)
		}
	})

	t.Run("empty_dir", func(t *testing.T) {
		dir := t.TempDir()
		_, err := LoadLatestManifest(dir, ManifestPathKey("dev1", "1"))
		if err != ErrManifestNotFound {
			t.Fatalf("got err=%v, want ErrManifestNotFound", err)
		}
	})

	t.Run("nonexistent_cloud_dir", func(t *testing.T) {
		dir := t.TempDir()
		_, err := LoadLatestManifest(dir, "nonexistent")
		if err != ErrManifestNotFound {
			t.Fatalf("got err=%v, want ErrManifestNotFound", err)
		}
	})
}

func TestListManifests(t *testing.T) {
	t.Run("multiple_manifests", func(t *testing.T) {
		dir := t.TempDir()

		m1 := NewManifest(1, "", "src", "/data", "dev1")
		m1.Timestamp = "2026-05-19T10:00:00Z"
		if _, err := SaveManifest(dir, m1); err != nil {
			t.Fatalf("save m1: %v", err)
		}

		m2 := NewManifest(1, "", "src", "/data", "dev1")
		m2.Timestamp = "2026-05-19T12:00:00Z"
		if _, err := SaveManifest(dir, m2); err != nil {
			t.Fatalf("save m2: %v", err)
		}

		manifests, loadErrors, err := ListManifests(dir, ManifestPathKey("dev1", "1"))
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(loadErrors) != 0 {
			t.Fatalf("load errors: %v", loadErrors)
		}
		if len(manifests) != 2 {
			t.Fatalf("got %d manifests, want 2", len(manifests))
		}
		if manifests[0].Timestamp < manifests[1].Timestamp {
			t.Fatal("manifests not sorted descending by timestamp")
		}
	})

	t.Run("empty_dir", func(t *testing.T) {
		dir := t.TempDir()
		manifests, loadErrors, err := ListManifests(dir, ManifestPathKey("dev1", "1"))
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(manifests) != 0 {
			t.Fatalf("got %d manifests, want 0", len(manifests))
		}
		if len(loadErrors) != 0 {
			t.Fatalf("got load errors: %v", loadErrors)
		}
	})

	t.Run("corrupted_file", func(t *testing.T) {
		dir := t.TempDir()
		manifestDir := ManifestDir(dir, ManifestPathKey("dev1", "1"))
		if err := os.MkdirAll(manifestDir, 0755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}

		m := NewManifest(1, "", "src", "/data", "dev1")
		m.Timestamp = "2026-05-19T10:00:00Z"
		if _, err := SaveManifest(dir, m); err != nil {
			t.Fatalf("save: %v", err)
		}

		corruptPath := filepath.Join(manifestDir, "9999999999_dev1.json.zst")
		if err := os.WriteFile(corruptPath, []byte("corrupted data"), 0644); err != nil {
			t.Fatalf("write corrupt: %v", err)
		}

		manifests, loadErrors, err := ListManifests(dir, ManifestPathKey("dev1", "1"))
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(manifests) != 1 {
			t.Fatalf("got %d manifests, want 1", len(manifests))
		}
		if len(loadErrors) != 1 {
			t.Fatalf("got %d load errors, want 1", len(loadErrors))
		}
	})
}

func TestDeleteManifest(t *testing.T) {
	t.Run("successful_delete", func(t *testing.T) {
		dir := t.TempDir()

		m := NewManifest(1, "", "src", "/data", "dev1")
		m.Timestamp = "2026-05-19T10:00:00Z"
		if _, err := SaveManifest(dir, m); err != nil {
			t.Fatalf("save: %v", err)
		}

		if err := DeleteManifest(dir, ManifestPathKey("dev1", "1"), "2026-05-19T10:00:00Z", "dev1"); err != nil {
			t.Fatalf("delete: %v", err)
		}

		_, err := LoadLatestManifest(dir, ManifestPathKey("dev1", "1"))
		if err != ErrManifestNotFound {
			t.Fatalf("got err=%v, want ErrManifestNotFound", err)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		dir := t.TempDir()
		err := DeleteManifest(dir, ManifestPathKey("dev1", "1"), "2026-05-19T10:00:00Z", "dev1")
		if err == nil {
			t.Fatal("expected error for missing manifest")
		}
	})
}

func TestTrashManifest(t *testing.T) {
	dir := t.TempDir()

	m := NewManifest(1, "", "src", "/data", "dev1")
	m.Timestamp = "2026-05-19T10:00:00Z"
	m.AddFile(FileEntry{Name: "a.txt", Size: 10})
	if _, err := SaveManifest(dir, m); err != nil {
		t.Fatalf("save: %v", err)
	}

	if err := TrashManifest(dir, ManifestPathKey("dev1", "1"), "2026-05-19T10:00:00Z", "dev1"); err != nil {
		t.Fatalf("trash: %v", err)
	}

	_, err := LoadLatestManifest(dir, ManifestPathKey("dev1", "1"))
	if err != ErrManifestNotFound {
		t.Fatalf("manifest should be gone from main dir: %v", err)
	}

	trashDir := ManifestTrashDir(dir, ManifestPathKey("dev1", "1"))
	entries, err := os.ReadDir(trashDir)
	if err != nil {
		t.Fatalf("read trash dir: %v", err)
	}
	var trashedPath string
	for _, e := range entries {
		if isManifestFile(e.Name()) {
			trashedPath = filepath.Join(trashDir, e.Name())
			break
		}
	}
	if trashedPath == "" {
		t.Fatal("no trashed manifest found")
	}

	loaded, err := LoadManifest(trashedPath)
	if err != nil {
		t.Fatalf("load trashed manifest: %v", err)
	}
	if loaded.SourceID != 1 {
		t.Fatalf("trashed SourceID: got %d, want 1", loaded.SourceID)
	}
}

func TestCleanTrashManifests(t *testing.T) {
	dir := t.TempDir()

	m := NewManifest(1, "", "src", "/data", "dev1")
	m.Timestamp = "2026-05-19T10:00:00Z"
	if _, err := SaveManifest(dir, m); err != nil {
		t.Fatalf("save: %v", err)
	}

	if err := TrashManifest(dir, ManifestPathKey("dev1", "1"), "2026-05-19T10:00:00Z", "dev1"); err != nil {
		t.Fatalf("trash: %v", err)
	}

	trashDir := ManifestTrashDir(dir, ManifestPathKey("dev1", "1"))
	entries, _ := os.ReadDir(trashDir)
	for _, e := range entries {
		oldPath := filepath.Join(trashDir, e.Name())
		newTime := time.Now().Add(-2 * time.Hour)
		if err := os.Chtimes(oldPath, newTime, newTime); err != nil {
			t.Fatalf("chtimes %s: %v", oldPath, err)
		}
	}

	cleaned, err := CleanTrashManifests(dir, time.Hour)
	if err != nil {
		t.Fatalf("clean: %v", err)
	}
	if cleaned != 2 {
		t.Fatalf("cleaned: got %d, want 2 (manifest + checksum)", cleaned)
	}

	remaining, _ := os.ReadDir(trashDir)
	if len(remaining) != 0 {
		t.Fatalf("trash should be empty, got %d entries", len(remaining))
	}
}

func TestCleanTrashManifestsRecentFilesKept(t *testing.T) {
	dir := t.TempDir()

	m := NewManifest(1, "", "src", "/data", "dev1")
	m.Timestamp = "2026-05-19T10:00:00Z"
	if _, err := SaveManifest(dir, m); err != nil {
		t.Fatalf("save: %v", err)
	}

	if err := TrashManifest(dir, ManifestPathKey("dev1", "1"), "2026-05-19T10:00:00Z", "dev1"); err != nil {
		t.Fatalf("trash: %v", err)
	}

	cleaned, err := CleanTrashManifests(dir, 24*time.Hour)
	if err != nil {
		t.Fatalf("clean: %v", err)
	}
	if cleaned != 0 {
		t.Fatalf("cleaned: got %d, want 0 (recent file)", cleaned)
	}

	trashDir := ManifestTrashDir(dir, ManifestPathKey("dev1", "1"))
	remaining, _ := os.ReadDir(trashDir)
	if len(remaining) != 2 {
		t.Fatalf("trash should still have 2 entries, got %d", len(remaining))
	}
}

func TestCleanTrashManifestsNoTrashDir(t *testing.T) {
	dir := t.TempDir()
	cleaned, err := CleanTrashManifests(dir, time.Hour)
	if err != nil {
		t.Fatalf("clean: %v", err)
	}
	if cleaned != 0 {
		t.Fatalf("cleaned: got %d, want 0", cleaned)
	}
}

func TestManifestExistsByTimestamp(t *testing.T) {
	dir := t.TempDir()

	m := NewManifest(1, "", "src", "/data", "dev1")
	ts := "2026-05-19T10:00:00Z"
	m.Timestamp = ts
	if _, err := SaveManifest(dir, m); err != nil {
		t.Fatalf("save: %v", err)
	}

	parsed, _ := time.Parse(time.RFC3339, ts)

	if !ManifestExistsByTimestamp(dir, ManifestPathKey("dev1", "1"), parsed.Unix()) {
		t.Fatal("should exist")
	}

	if ManifestExistsByTimestamp(dir, ManifestPathKey("dev1", "1"), 0) {
		t.Fatal("should not exist for timestamp 0")
	}

	if ManifestExistsByTimestamp(dir, "nonexistent", parsed.Unix()) {
		t.Fatal("should not exist for unknown cloudID")
	}
}

func TestLoadManifestByTimestamp(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		dir := t.TempDir()

		m := NewManifest(1, "", "src", "/data", "dev1")
		m.Timestamp = "2026-05-19T10:00:00Z"
		m.AddFile(FileEntry{Name: "found.txt", Size: 10})
		if _, err := SaveManifest(dir, m); err != nil {
			t.Fatalf("save: %v", err)
		}

		loaded, err := LoadManifestByTimestamp(dir, ManifestPathKey("dev1", "1"), "2026-05-19T10:00:00Z")
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if loaded.AllFiles()[0].Name != "found.txt" {
			t.Fatalf("got %q", loaded.AllFiles()[0].Name)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		dir := t.TempDir()
		_, err := LoadManifestByTimestamp(dir, ManifestPathKey("dev1", "1"), "2026-05-19T10:00:00Z")
		if err != ErrManifestNotFound {
			t.Fatalf("got err=%v, want ErrManifestNotFound", err)
		}
	})

	t.Run("invalid_timestamp", func(t *testing.T) {
		dir := t.TempDir()
		_, err := LoadManifestByTimestamp(dir, ManifestPathKey("dev1", "1"), "not-a-timestamp")
		if err == nil {
			t.Fatal("expected error for invalid timestamp")
		}
	})
}

func TestSourceRegistryRoundtrip(t *testing.T) {
	dir := t.TempDir()

	reg := &SourceRegistry{
		CloudID:       "42",
		Name:          "MySource",
		Path:          "/data/important",
		DeviceID:      "dev1",
		LastSnapshot:  "2026-05-19T10:00:00Z",
		SnapshotCount: 7,
		CreatedAt:     "2026-01-01T00:00:00Z",
	}

	if err := SaveSourceRegistry(dir, reg); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := LoadSourceRegistry(dir, "42")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.CloudID != "42" {
		t.Fatalf("CloudID: got %q, want 42", loaded.CloudID)
	}
	if loaded.Name != "MySource" {
		t.Fatalf("Name: got %q", loaded.Name)
	}
	if loaded.Path != "/data/important" {
		t.Fatalf("Path: got %q", loaded.Path)
	}
	if loaded.DeviceID != "dev1" {
		t.Fatalf("DeviceID: got %q", loaded.DeviceID)
	}
	if loaded.SnapshotCount != 7 {
		t.Fatalf("SnapshotCount: got %d, want 7", loaded.SnapshotCount)
	}

	list, err := ListSourceRegistries(dir)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("got %d registries, want 1", len(list))
	}
	if list[0].CloudID != "42" {
		t.Fatalf("listed CloudID: got %q", list[0].CloudID)
	}
}

func TestSourceRegistryMultiple(t *testing.T) {
	dir := t.TempDir()

	reg1 := &SourceRegistry{CloudID: "1", Name: "Source1", Path: "/a"}
	reg2 := &SourceRegistry{CloudID: "2", Name: "Source2", Path: "/b"}

	if err := SaveSourceRegistry(dir, reg1); err != nil {
		t.Fatalf("save reg1: %v", err)
	}
	if err := SaveSourceRegistry(dir, reg2); err != nil {
		t.Fatalf("save reg2: %v", err)
	}

	list, err := ListSourceRegistries(dir)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d, want 2", len(list))
	}

	names := map[string]bool{}
	for _, r := range list {
		names[r.Name] = true
	}
	if !names["Source1"] || !names["Source2"] {
		t.Fatalf("expected Source1 and Source2, got %v", list)
	}
}

func TestLoadSourceRegistryNotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadSourceRegistry(dir, "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing registry")
	}
}

func TestListSourceRegistriesEmpty(t *testing.T) {
	dir := t.TempDir()
	list, err := ListSourceRegistries(dir)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("got %d, want 0", len(list))
	}
}

func TestNewManifest(t *testing.T) {
	m := NewManifest(5, "c5", "myname", "/my/path", "device-x")
	if m.Version != 2 {
		t.Fatalf("Version: got %d, want 2", m.Version)
	}
	if m.SourceID != 5 {
		t.Fatalf("SourceID: got %d, want 5", m.SourceID)
	}
	if m.CloudID != "c5" {
		t.Fatalf("CloudID: got %q, want c5", m.CloudID)
	}
	if m.SourceName != "myname" {
		t.Fatalf("SourceName: got %q", m.SourceName)
	}
	if m.SourcePath != "/my/path" {
		t.Fatalf("SourcePath: got %q", m.SourcePath)
	}
	if m.DeviceID != "device-x" {
		t.Fatalf("DeviceID: got %q", m.DeviceID)
	}
	if m.Stats.FileCount != 0 {
		t.Fatalf("Files: got %d, want 0", m.Stats.FileCount)
	}
	if m.Timestamp == "" {
		t.Fatal("Timestamp should be set")
	}
}

func TestManifestDir(t *testing.T) {
	got := ManifestDir("/repo/.ginkgo-backup", "cloud7")
	expected := filepath.Join("/repo/.ginkgo-backup", "manifests", "cloud7")
	if got != expected {
		t.Fatalf("got %q, want %q", got, expected)
	}
}

func TestSaveManifestWithKeyFallsBackToDevicePathKey(t *testing.T) {
	dir := t.TempDir()
	key, _ := GenerateRandomKey()

	// CloudID is empty: SaveManifestWithKey must fall back to the device
	// fingerprint + sourceID path key, not the bare sourceID. Codifies
	// the H3 fix — a stale earlier version wrote to "42/" instead of
	// "dev1/42/".
	m := NewManifest(42, "", "src", "/data", "dev1")
	m.Timestamp = "2026-05-19T10:00:00Z"
	if _, err := SaveManifestWithKey(dir, m, key); err != nil {
		t.Fatalf("save: %v", err)
	}

	expectedDir := ManifestDir(dir, ManifestPathKey("dev1", "42"))
	entries, err := os.ReadDir(expectedDir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no manifests saved in device-fingerprint path key dir")
	}

	// And the legacy bare-sourceID dir must NOT exist.
	legacyDir := ManifestDir(dir, "42")
	if _, err := os.Stat(legacyDir); err == nil {
		t.Fatalf("legacy bare-sourceID cloudID dir should not exist, but does: %s", legacyDir)
	}
}

func TestSaveManifestInvalidTimestamp(t *testing.T) {
	dir := t.TempDir()

	m := NewManifest(1, "", "src", "/data", "dev1")
	m.Timestamp = "invalid-timestamp"
	m.AddFile(FileEntry{Name: "a.txt", Size: 10})

	if _, err := SaveManifest(dir, m); err != nil {
		t.Fatalf("save with invalid timestamp should use time.Now fallback: %v", err)
	}

	loaded, err := LoadLatestManifest(dir, ManifestPathKey("dev1", "1"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.SourceID != 1 {
		t.Fatalf("SourceID: got %d, want 1", loaded.SourceID)
	}
}

func TestDeleteManifestPreservesOtherManifests(t *testing.T) {
	dir := t.TempDir()

	m1 := NewManifest(1, "", "src", "/data", "dev1")
	m1.Timestamp = "2026-05-19T10:00:00Z"
	if _, err := SaveManifest(dir, m1); err != nil {
		t.Fatalf("save m1: %v", err)
	}

	m2 := NewManifest(1, "", "src", "/data", "dev1")
	m2.Timestamp = "2026-05-19T12:00:00Z"
	if _, err := SaveManifest(dir, m2); err != nil {
		t.Fatalf("save m2: %v", err)
	}

	if err := DeleteManifest(dir, ManifestPathKey("dev1", "1"), "2026-05-19T10:00:00Z", "dev1"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	manifests, _, err := ListManifests(dir, ManifestPathKey("dev1", "1"))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("got %d manifests, want 1", len(manifests))
	}
	if manifests[0].Timestamp != "2026-05-19T12:00:00Z" {
		t.Fatalf("remaining timestamp: got %q", manifests[0].Timestamp)
	}
}

func TestTrashManifestNotFound(t *testing.T) {
	dir := t.TempDir()
	err := TrashManifest(dir, ManifestPathKey("dev1", "1"), "2026-05-19T10:00:00Z", "dev1")
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}
}

func TestManifestExistsByTimestampNoDir(t *testing.T) {
	dir := t.TempDir()
	if ManifestExistsByTimestamp(dir, "nonexistent", 12345) {
		t.Fatal("should return false for nonexistent dir")
	}
}

func TestValidateCloudID(t *testing.T) {
	valid := []string{
		"dev1/42",
		"42",
		"device-fingerprint/123",
		"a/b/c",
	}
	for _, id := range valid {
		if err := validateCloudID(id); err != nil {
			t.Errorf("validateCloudID(%q) should pass, got %v", id, err)
		}
	}

	invalid := []string{
		"",                       // empty
		"/etc/passwd",            // Unix absolute
		`\windows\system32`,      // Windows absolute (UNC-style prefix)
		`C:\evil`,                // Windows drive
		"C:/evil",                // Windows drive with slash
		"../../evil",             // Unix-style escape
		`..\..\evil`,             // Windows-style escape (backslash separators)
		`dev1\..\..\evil`,        // mixed separators
		"..",                     // bare parent
		"a/../../../b",           // embedded escape
		`a\..\b`,                 // backslash-separated parent segment
	}
	for _, id := range invalid {
		if err := validateCloudID(id); err == nil {
			t.Errorf("validateCloudID(%q) should fail", id)
		} else if !errors.Is(err, ErrInvalidCloudID) {
			t.Errorf("validateCloudID(%q) error should wrap ErrInvalidCloudID, got %v", id, err)
		}
	}
}

func TestSaveManifestSameSecondConflict(t *testing.T) {
	dir := t.TempDir()
	cloudID := ManifestPathKey("dev1", "1")

	m1 := NewManifest(1, "", "first", "/data", "dev1")
	m1.Timestamp = "2026-05-19T10:00:00Z"
	m1.AddFile(FileEntry{Name: "a.txt", Size: 10})
	path1, err := SaveManifest(dir, m1)
	if err != nil {
		t.Fatalf("save m1: %v", err)
	}
	if m1.FilePath != path1 {
		t.Fatalf("m1.FilePath = %q, want %q", m1.FilePath, path1)
	}

	// Same source, same second, same device: the deterministic filename
	// collides and the second save must NOT overwrite the first — it
	// writes a suffixed name instead.
	m2 := NewManifest(1, "", "second", "/data", "dev1")
	m2.Timestamp = "2026-05-19T10:00:00Z"
	m2.AddFile(FileEntry{Name: "b.txt", Size: 20})
	path2, err := SaveManifest(dir, m2)
	if err != nil {
		t.Fatalf("save m2: %v", err)
	}
	if path2 == path1 {
		t.Fatal("same-second save overwrote the first manifest")
	}
	if m2.FilePath != path2 {
		t.Fatalf("m2.FilePath = %q, want %q", m2.FilePath, path2)
	}
	base1, base2 := filepath.Base(path1), filepath.Base(path2)
	if !strings.HasPrefix(base2, strings.TrimSuffix(base1, ".json.zst")+"_") {
		t.Fatalf("suffixed name %q should extend %q", base2, base1)
	}

	// Both manifests survive on disk and round-trip (checksum sidecar
	// included), with FilePath recording where each was loaded from.
	loaded1, err := LoadManifest(path1)
	if err != nil {
		t.Fatalf("load m1: %v", err)
	}
	if loaded1.SourceName != "first" || loaded1.FilePath != path1 {
		t.Fatalf("loaded1 = %q @ %q, want first @ %q", loaded1.SourceName, loaded1.FilePath, path1)
	}
	loaded2, err := LoadManifest(path2)
	if err != nil {
		t.Fatalf("load m2: %v", err)
	}
	if loaded2.SourceName != "second" || loaded2.FilePath != path2 {
		t.Fatalf("loaded2 = %q @ %q, want second @ %q", loaded2.SourceName, loaded2.FilePath, path2)
	}

	// The suffixed name sorts after the deterministic one, so the latest
	// manifest is the second save.
	latest, err := LoadLatestManifest(dir, cloudID)
	if err != nil {
		t.Fatalf("load latest: %v", err)
	}
	if latest.SourceName != "second" {
		t.Fatalf("latest = %q, want %q", latest.SourceName, "second")
	}

	// Timestamp-based readers still find a manifest for that second.
	unixSec := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC).Unix()
	if !ManifestExistsByTimestamp(dir, cloudID, unixSec) {
		t.Fatal("ManifestExistsByTimestamp should see the conflicted second")
	}
	if _, err := LoadManifestByTimestamp(dir, cloudID, "2026-05-19T10:00:00Z"); err != nil {
		t.Fatalf("LoadManifestByTimestamp: %v", err)
	}
}
