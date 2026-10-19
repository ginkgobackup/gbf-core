// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chunkedRestoreFixture backs up a deterministic multi-chunk file and
// returns everything a restore test needs: the chunk list, the file-level
// content hash, the repo/store, and the key.
func chunkedRestoreFixture(t *testing.T) (repoDir string, store *LocalBlobStore, key []byte, content []byte, contentHash string, chunks []ChunkRef) {
	t.Helper()

	repoDir = t.TempDir()
	sourceDir := t.TempDir()
	if err := InitRepo(InitParams{RepoRoot: repoDir, DeviceID: "test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	var err error
	key, err = GenerateRandomKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	store = NewLocalBlobStore(repoDir)
	ctx := context.Background()

	content = make([]byte, 3*DefaultChunkSize+123)
	if _, err := rand.Read(content); err != nil {
		t.Fatalf("rand: %v", err)
	}
	fp := filepath.Join(sourceDir, "chunked.dat")
	if err := os.WriteFile(fp, content, 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	p := NewSimplePipeline(PipelineConfig{
		SourceID:   1,
		SourceName: "test",
		SourcePath: sourceDir,
		DeviceID:   "test",
		Key:        key,
		DisableCDC: true,
	}, store)
	contentHash, chunks, retained, err := p.hashFileWithChunks(ctx, fp, int64(len(content)), false)
	if err != nil {
		t.Fatalf("hashFileWithChunks: %v", err)
	}
	if len(retained) != 0 {
		t.Fatalf("retain=false returned %d buffers", len(retained))
	}
	if len(chunks) != 4 {
		t.Fatalf("chunks = %d, want 4", len(chunks))
	}
	if _, err := p.uploadChangedChunks(ctx, fp, int64(len(content)), chunks, nil, nil); err != nil {
		t.Fatalf("uploadChangedChunks: %v", err)
	}
	return repoDir, store, key, content, contentHash, chunks
}

func newChunkedRestore(t *testing.T, repoDir string, store SimpleBlobStore, key []byte, targetDir string) (*SimpleRestore, secureDir) {
	t.Helper()
	r := NewSimpleRestore(RestoreConfig{
		RepoRoot:  repoDir,
		TargetDir: targetDir,
		SourceID:  1,
		DeviceID:  "test",
		Key:       key,
	}, store)
	root, err := openSecureDir(targetDir)
	if err != nil {
		t.Fatalf("openSecureDir: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return r, root
}

// TestRestoreChunkedFileRejectsReorderedChunks is the regression test for
// the file-level hash gap: every chunk hash can be valid while the chunk
// list as a whole describes different content (reordered, duplicated, or
// missing chunks). The assembled file must be verified against
// ContentHash before it is committed.
func TestRestoreChunkedFileRejectsReorderedChunks(t *testing.T) {
	repoDir, store, key, _, contentHash, chunks := chunkedRestoreFixture(t)
	ctx := context.Background()

	restoreDir := t.TempDir()
	r, root := newChunkedRestore(t, repoDir, store, key, restoreDir)

	reordered := []ChunkRef{chunks[1], chunks[0], chunks[2], chunks[3]}
	var total int64
	for _, c := range reordered {
		total += c.Size
	}
	entry := FileEntry{
		Name:        "reordered.dat",
		ContentHash: contentHash,
		Size:        total,
		Mode:        0644,
		Chunks:      reordered,
	}

	err := r.restoreChunkedFile(ctx, entry, root, entry.Name)
	if err == nil {
		t.Fatal("expected file-level hash mismatch for reordered chunks")
	}
	if !strings.Contains(err.Error(), "content hash mismatch") {
		t.Fatalf("error = %q, want content hash mismatch", err)
	}
	if _, statErr := os.Stat(filepath.Join(restoreDir, entry.Name)); !os.IsNotExist(statErr) {
		t.Fatal("tampered file must not be committed")
	}
}

// TestRestoreChunkedFileRejectsSizeMismatch verifies the assembled size is
// checked too: a manifest can carry a correct ContentHash but a wrong Size
// (or a chunk list whose sum was tampered with independently).
func TestRestoreChunkedFileRejectsSizeMismatch(t *testing.T) {
	repoDir, store, key, content, contentHash, chunks := chunkedRestoreFixture(t)
	ctx := context.Background()

	restoreDir := t.TempDir()
	r, root := newChunkedRestore(t, repoDir, store, key, restoreDir)

	entry := FileEntry{
		Name:        "wrong-size.dat",
		ContentHash: contentHash,
		Size:        int64(len(content)) + 1,
		Mode:        0644,
		Chunks:      chunks,
	}
	err := r.restoreChunkedFile(ctx, entry, root, entry.Name)
	if err == nil {
		t.Fatal("expected file-level size mismatch")
	}
	if !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("error = %q, want size mismatch", err)
	}
	if _, statErr := os.Stat(filepath.Join(restoreDir, entry.Name)); !os.IsNotExist(statErr) {
		t.Fatal("mismatched file must not be committed")
	}
}
