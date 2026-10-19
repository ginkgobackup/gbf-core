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

// TestPutStreamEnforcesDeclaredSize verifies PutStream compares the bytes
// actually read against the caller-declared size. Storing short input would
// truncate the blob (its name already hashes the full content), and storing
// long input would do the same in the other direction. Both must fail and
// leave no temp file behind; only an exact-size stream is committed.
func TestPutStreamEnforcesDeclaredSize(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	ctx := context.Background()
	data := []byte("exactly this many bytes")
	hash := SHA256Bytes(data)

	blobDir := filepath.Join(dir, "gb", hash[:2])
	assertNoBlobOrTemp := func(t *testing.T) {
		t.Helper()
		if _, err := os.Stat(store.BlobPath(hash)); !os.IsNotExist(err) {
			t.Fatalf("blob must not be committed: stat err = %v", err)
		}
		entries, err := os.ReadDir(blobDir)
		if err != nil {
			if os.IsNotExist(err) {
				return
			}
			t.Fatalf("read blob dir: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("temp file left behind after failed PutStream: %v", entries)
		}
	}

	if err := store.PutStream(ctx, hash, bytes.NewReader(data), int64(len(data)-1)); err == nil {
		t.Fatal("expected error when reader is longer than declared size")
	}
	assertNoBlobOrTemp(t)

	if err := store.PutStream(ctx, hash, bytes.NewReader(data), int64(len(data)+5)); err == nil {
		t.Fatal("expected error when reader is shorter than declared size")
	}
	assertNoBlobOrTemp(t)

	if err := store.PutStream(ctx, hash, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("exact-size PutStream failed: %v", err)
	}
	got, err := store.Get(ctx, hash)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("blob mismatch: got %q, want %q", got, data)
	}
}

// TestPutStreamEmptyBlob pins the zero-size boundary: an empty reader with
// size 0 succeeds, and a non-empty reader with size 0 is rejected.
func TestPutStreamEmptyBlob(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	ctx := context.Background()

	emptyHash := SHA256Bytes(nil)
	if err := store.PutStream(ctx, emptyHash, bytes.NewReader(nil), 0); err != nil {
		t.Fatalf("empty PutStream failed: %v", err)
	}
	if exists, err := store.Exists(ctx, emptyHash); err != nil || !exists {
		t.Fatalf("empty blob should exist: exists=%v err=%v", exists, err)
	}

	otherHash := SHA256Bytes([]byte("x"))
	if err := store.PutStream(ctx, otherHash, bytes.NewReader([]byte("x")), 0); err == nil {
		t.Fatal("expected error for non-empty reader with size 0")
	}
	if exists, err := store.Exists(ctx, otherHash); err != nil || exists {
		t.Fatalf("size-0 mismatch must not store a blob: exists=%v err=%v", exists, err)
	}
}
