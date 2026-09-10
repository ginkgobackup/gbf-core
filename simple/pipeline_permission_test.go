// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// sha256HexOf computes the plaintext hash the pipeline caller normally
// passes into checkAndUploadBlob.
func sha256HexOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// permissionDeniedStore overrides Exists to simulate an auth/permission
// outage on the blob store (e.g. expired cloud credentials).
type permissionDeniedStore struct {
	*mockBlobStore
	existsErr error
}

func (m *permissionDeniedStore) Exists(_ context.Context, _ string) (bool, error) {
	return false, m.existsErr
}

// TestCheckAndUploadBlobAbortsOnPermissionDenied pins the fail-fast
// contract: when the exists check reports ErrPermissionDenied, the
// backup aborts instead of degrading into a full redundant re-upload.
func TestCheckAndUploadBlobAbortsOnPermissionDenied(t *testing.T) {
	dir := t.TempDir()
	content := []byte("permission denied abort test payload")
	fp := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(fp, content, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	store := &permissionDeniedStore{
		mockBlobStore: newMockBlobStore(),
		existsErr:     ErrPermissionDenied,
	}
	p := NewSimplePipeline(PipelineConfig{DisableCDC: true}, store)
	fe := scanEntry{relPath: "a.txt", absPath: fp, size: int64(len(content))}
	contentHash := sha256HexOf(content)

	_, _, _, _, err := p.checkAndUploadBlob(context.Background(), fe, false, "", contentHash, nil, nil)
	if err == nil {
		t.Fatal("expected abort error on permission-denied exists check")
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("want ErrPermissionDenied in chain, got: %v", err)
	}
	if store.putCalls != 0 {
		t.Fatalf("Put called %d time(s) during permission outage, want 0 (no redundant re-upload)", store.putCalls)
	}
}

// TestCheckAndUploadBlobReuploadsOnTransientExistsError pins the other
// side of the contract: transient/unclassified exists errors keep the
// old warn-and-reupload behavior (the upload may well succeed).
func TestCheckAndUploadBlobReuploadsOnTransientExistsError(t *testing.T) {
	dir := t.TempDir()
	content := []byte("transient exists failure payload")
	fp := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(fp, content, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	store := &permissionDeniedStore{
		mockBlobStore: newMockBlobStore(),
		existsErr:     ErrTransientFailure,
	}
	p := NewSimplePipeline(PipelineConfig{DisableCDC: true}, store)
	fe := scanEntry{relPath: "a.txt", absPath: fp, size: int64(len(content))}
	contentHash := sha256HexOf(content)

	entry, _, _, _, err := p.checkAndUploadBlob(context.Background(), fe, false, "", contentHash, []byte("ciphertext"), nil)
	if err != nil {
		t.Fatalf("transient exists error must not abort: %v", err)
	}
	if entry == nil {
		t.Fatal("expected a file entry after re-upload")
	}
	if store.putCalls == 0 {
		t.Fatal("expected the blob to be (re-)uploaded after transient exists failure")
	}
}

// TestBlobsExistPropagatesPermissionDenied pins the fail-fast contract on
// the dedup probe path: an auth/permission outage must surface as an
// error, NOT be silently read as "blob missing" — otherwise every chunk
// and every unchanged file would be re-uploaded during the outage.
func TestBlobsExistPropagatesPermissionDenied(t *testing.T) {
	store := &permissionDeniedStore{
		mockBlobStore: newMockBlobStore(),
		existsErr:     ErrPermissionDenied,
	}
	p := NewSimplePipeline(PipelineConfig{DisableCDC: true}, store)

	_, err := p.blobsExist(context.Background(), []string{sha256HexOf([]byte("x"))})
	if err == nil {
		t.Fatal("blobsExist must propagate ErrPermissionDenied, got nil")
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("want ErrPermissionDenied in chain, got: %v", err)
	}
}

// TestBlobsExistTreatsTransientAsMissing pins the other side: a transient
// failure stays non-fatal (treated as "missing") so a flaky store does not
// abort the whole backup.
func TestBlobsExistTreatsTransientAsMissing(t *testing.T) {
	store := &permissionDeniedStore{
		mockBlobStore: newMockBlobStore(),
		existsErr:     ErrTransientFailure,
	}
	p := NewSimplePipeline(PipelineConfig{DisableCDC: true}, store)

	presence, err := p.blobsExist(context.Background(), []string{sha256HexOf([]byte("y"))})
	if err != nil {
		t.Fatalf("transient error must not fail blobsExist: %v", err)
	}
	for h, present := range presence {
		if present {
			t.Fatalf("hash %s reported present after a transient failure", h)
		}
	}
}

// TestUploadChangedChunksAbortsOnPermissionDenied pins the wiring: the
// chunk-upload path must abort (not re-upload) when the dedup probe hits
// an auth/permission outage.
func TestUploadChangedChunksAbortsOnPermissionDenied(t *testing.T) {
	dir := t.TempDir()
	content := []byte("chunk permission abort payload")
	fp := filepath.Join(dir, "c.bin")
	if err := os.WriteFile(fp, content, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	store := &permissionDeniedStore{
		mockBlobStore: newMockBlobStore(),
		existsErr:     ErrPermissionDenied,
	}
	p := NewSimplePipeline(PipelineConfig{DisableCDC: true}, store)

	prevChunks := []ChunkRef{{Hash: sha256HexOf([]byte("prev")), Size: 4}}
	chunks := []ChunkRef{{Hash: sha256HexOf(content), Size: int64(len(content))}}

	_, err := p.uploadChangedChunks(context.Background(), fp, int64(len(content)), chunks, [][]byte{content}, prevChunks)
	if err == nil {
		t.Fatal("uploadChangedChunks must abort on permission-denied dedup probe")
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("want ErrPermissionDenied in chain, got: %v", err)
	}
}
