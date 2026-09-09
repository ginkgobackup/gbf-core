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
