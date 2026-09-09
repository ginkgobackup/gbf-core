// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustMarshalManifestJSON(t *testing.T, m *Manifest) []byte {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

func validTestManifest() *Manifest {
	m := NewManifest(1, "device1-source1", "src", "C:/data", "device1")
	m.AddFile(FileEntry{
		Name:        "a.txt",
		ContentHash: strings.Repeat("a", 64),
		Size:        10,
		Status:      FileStatusNew,
	})
	m.AddFile(FileEntry{
		Name:        "sub/b.txt",
		ContentHash: strings.Repeat("b", 64),
		Size:        20,
		Status:      FileStatusUnchanged,
		Chunks: []ChunkRef{
			{Hash: strings.Repeat("c", 64), Size: 8},
			{Hash: strings.Repeat("d", 64), Size: 12},
		},
	})
	m.AddEmptyDir("empty")
	return m
}

func TestManifestValidateAcceptsValidManifest(t *testing.T) {
	m := validTestManifest()
	if err := m.Validate(); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
}

func TestManifestValidateRoundTripThroughData(t *testing.T) {
	m := validTestManifest()
	data := mustMarshalManifestJSON(t, m)
	loaded, err := LoadManifestFromData(data)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !loaded.IsComplete() {
		t.Fatal("loaded manifest should be complete")
	}
}

func TestManifestValidateRejectsBadVersion(t *testing.T) {
	m := validTestManifest()
	m.Version = 1
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("want version error, got %v", err)
	}
}

func TestManifestValidateRejectsBadSourceID(t *testing.T) {
	m := validTestManifest()
	m.SourceID = 0
	if err := m.Validate(); err == nil {
		t.Fatal("want sourceId error")
	}
}

func TestManifestValidateRejectsPathEscapeDirKey(t *testing.T) {
	for _, bad := range []string{"..", "a/../b", "/abs", "C:/data", "a\\\\b", "a//b"} {
		m := validTestManifest()
		m.Dirs[bad] = &Dir{}
		if err := m.Validate(); err == nil {
			t.Fatalf("dir key %q should be rejected", bad)
		}
	}
}

func TestManifestValidateRejectsDotDotFileName(t *testing.T) {
	m := validTestManifest()
	m.AddFile(FileEntry{Name: "../escape.txt", ContentHash: strings.Repeat("e", 64), Size: 1, Status: FileStatusNew})
	// AddFile normalizes into a parent dir ".." whose key is invalid.
	if err := m.Validate(); err == nil {
		t.Fatal("dot-dot path should be rejected")
	}
}

func TestManifestValidateRejectsDuplicateFileName(t *testing.T) {
	m := validTestManifest()
	d := m.Dirs[""]
	d.Files = append(d.Files, FileEntry{
		Name:        "a.txt",
		ContentHash: strings.Repeat("f", 64),
		Size:        10,
		Status:      FileStatusNew,
	})
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("want duplicate error, got %v", err)
	}
}

func TestManifestValidateRejectsBadHashFormat(t *testing.T) {
	m := validTestManifest()
	m.Dirs[""].Files[0].ContentHash = "not-a-hash"
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "sha-256") {
		t.Fatalf("want hash format error, got %v", err)
	}
}

func TestManifestValidateRejectsChunkSizeMismatch(t *testing.T) {
	m := validTestManifest()
	m.Dirs["sub"].Files[0].Chunks[1].Size = 999
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "chunk sizes") {
		t.Fatalf("want chunk size error, got %v", err)
	}
}

func TestManifestValidateRejectsStatsDrift(t *testing.T) {
	m := validTestManifest()
	m.Stats.TotalSize += 1
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "totalSize") {
		t.Fatalf("want totalSize error, got %v", err)
	}
	m2 := validTestManifest()
	m2.Stats.FileCount += 1
	if err := m2.Validate(); err == nil || !strings.Contains(err.Error(), "fileCount") {
		t.Fatalf("want fileCount error, got %v", err)
	}
}

func TestManifestValidateRejectsDanglingSubdir(t *testing.T) {
	m := validTestManifest()
	m.Dirs[""].SubDirs = append(m.Dirs[""].SubDirs, "ghost")
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "subdir") {
		t.Fatalf("want subdir error, got %v", err)
	}
}

func TestManifestValidateAllowsIncompleteFiles(t *testing.T) {
	m := validTestManifest()
	// A locked file has no hash and no chunks; must stay valid.
	m.AddFile(FileEntry{Name: "locked.txt", Size: 5, Status: FileStatusLocked})
	if err := m.Validate(); err != nil {
		t.Fatalf("locked file should not fail validation: %v", err)
	}
	if m.IsComplete() {
		t.Fatal("snapshot with locked file must be incomplete")
	}
	if f, ok := m.FindFile("locked.txt"); !ok || f.IsRestorable() {
		t.Fatal("locked file must not be restorable")
	}
}

func TestManifestCompletenessDerivedForLegacyManifest(t *testing.T) {
	// Legacy manifest JSON without the completeness field.
	raw := `{"version":2,"sourceId":1,"sourceName":"s","sourcePath":"/d","deviceId":"dev","timestamp":"2026-01-01T00:00:00Z","dirs":{"":{"files":[{"name":"a.txt","contentHash":"` + strings.Repeat("a", 64) + `","size":1,"mtime":"2026-01-01T00:00:00Z","status":"new"}]}},"stats":{"fileCount":1,"totalSize":1}}`
	m, err := LoadManifestFromData([]byte(raw))
	if err != nil {
		t.Fatalf("legacy manifest should load: %v", err)
	}
	if !m.IsComplete() {
		t.Fatal("legacy manifest without bad files should derive complete")
	}

	rawIncomplete := `{"version":2,"sourceId":1,"sourceName":"s","sourcePath":"/d","deviceId":"dev","timestamp":"2026-01-01T00:00:00Z","dirs":{"":{"files":[{"name":"a.txt","size":1,"mtime":"2026-01-01T00:00:00Z","status":"locked"}]}},"stats":{"fileCount":1,"totalSize":1}}`
	m2, err := LoadManifestFromData([]byte(rawIncomplete))
	if err != nil {
		t.Fatalf("legacy incomplete manifest should load: %v", err)
	}
	if m2.IsComplete() {
		t.Fatal("legacy manifest with locked file should derive incomplete")
	}
}

func TestManifestValidateRejectsLoadTimeCorruption(t *testing.T) {
	// Corrupt the stats of a serialized manifest; LoadManifestFromData
	// must reject it instead of surfacing the damage at restore time.
	m := validTestManifest()
	m.Stats.FileCount = 99
	data := mustMarshalManifestJSON(t, m)
	if _, err := LoadManifestFromData(data); err == nil || !strings.Contains(err.Error(), "validation") {
		t.Fatalf("want load-time validation error, got %v", err)
	}
}
