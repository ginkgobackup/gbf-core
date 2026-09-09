// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// BlobStoreConformance is the conformance suite every SimpleBlobStore
// implementation must pass. Run it from any package:
//
//	simple.BlobStoreConformance(t, func(t *testing.T) simple.SimpleBlobStore {
//	    return newStoreUnderTest()
//	})
//
// It pins the semantic contract that the pipeline, restore, and GC paths
// rely on: missing-blob errors must classify as ErrBlobNotFound, Delete
// is idempotent, Put overwrites atomically, and prefix listing is
// consistent with what was written.
func BlobStoreConformance(t *testing.T, newStore func(t *testing.T) SimpleBlobStore) {
	t.Helper()
	ctx := context.Background()

	newHash := func(seed string) string {
		// 64 hex chars: a valid sha-256-shaped key built from a 2-char
		// hex seed repeated 32 times.
		return strings.Repeat(seed, 32)
	}

	t.Run("PutGetRoundTrip", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		h := newHash("a1")
		data := []byte("conformance round trip payload")
		if err := s.Put(ctx, h, data); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := s.Get(ctx, h)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("Get returned different bytes than Put wrote")
		}
	})

	t.Run("PutEmptyBlob", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		h := newHash("b2")
		if err := s.Put(ctx, h, nil); err != nil {
			t.Fatalf("Put empty: %v", err)
		}
		got, err := s.Get(ctx, h)
		if err != nil {
			t.Fatalf("Get empty: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("empty blob came back with %d bytes", len(got))
		}
	})

	t.Run("PutExistingIdempotent", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		h := newHash("c3")
		// Content addressing: the hash determines the content. Re-Putting
		// the same blob is a no-op success (the first commit wins).
		if err := s.Put(ctx, h, []byte("same")); err != nil {
			t.Fatalf("Put first: %v", err)
		}
		if err := s.Put(ctx, h, []byte("same")); err != nil {
			t.Fatalf("Put existing: %v", err)
		}
		got, err := s.Get(ctx, h)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if string(got) != "same" {
			t.Fatalf("existing blob content changed to %q", got)
		}
	})

	t.Run("GetMissingClassifiesNotFound", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		_, err := s.Get(ctx, newHash("d4"))
		if err == nil {
			t.Fatal("Get of missing blob must fail")
		}
		if !errors.Is(err, ErrBlobNotFound) {
			t.Fatalf("missing blob error must wrap ErrBlobNotFound, got: %v", err)
		}
	})

	t.Run("GetStreamMissingClassifiesNotFound", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		_, err := s.GetStream(ctx, newHash("e5"))
		if err == nil {
			t.Fatal("GetStream of missing blob must fail")
		}
		if !errors.Is(err, ErrBlobNotFound) {
			t.Fatalf("missing blob error must wrap ErrBlobNotFound, got: %v", err)
		}
	})

	t.Run("PutStreamGetStreamRoundTrip", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		h := newHash("f6")
		data := []byte("streamed conformance payload")
		if err := s.PutStream(ctx, h, bytes.NewReader(data), int64(len(data))); err != nil {
			t.Fatalf("PutStream: %v", err)
		}
		rc, err := s.GetStream(ctx, h)
		if err != nil {
			t.Fatalf("GetStream: %v", err)
		}
		defer rc.Close()
		var got bytes.Buffer
		if _, err := got.ReadFrom(rc); err != nil {
			t.Fatalf("read stream: %v", err)
		}
		if !bytes.Equal(got.Bytes(), data) {
			t.Fatal("stream round trip mismatch")
		}
	})

	t.Run("Exists", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		h := newHash("07")
		exists, err := s.Exists(ctx, h)
		if err != nil || exists {
			t.Fatalf("Exists before Put: (%v, %v)", exists, err)
		}
		if err := s.Put(ctx, h, []byte("x")); err != nil {
			t.Fatalf("Put: %v", err)
		}
		exists, err = s.Exists(ctx, h)
		if err != nil || !exists {
			t.Fatalf("Exists after Put: (%v, %v)", exists, err)
		}
	})

	t.Run("DeleteIdempotent", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		h := newHash("18")
		// Deleting a missing blob is a no-op, not an error.
		if err := s.Delete(ctx, h); err != nil {
			t.Fatalf("Delete missing must be idempotent, got: %v", err)
		}
		if err := s.Put(ctx, h, []byte("x")); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := s.Delete(ctx, h); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := s.Get(ctx, h); !errors.Is(err, ErrBlobNotFound) {
			t.Fatalf("Get after Delete must be ErrBlobNotFound, got: %v", err)
		}
	})

	t.Run("ListPrefix", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		// The shard-level prefix contract: a prefix of up to 2 chars
		// (the shard width of the local store) must return every stored
		// key starting with that prefix, and only such keys. Both local
		// and cloud stores satisfy this; longer prefixes are NOT part
		// of the contract (the local store matches at shard granularity
		// and may over-return).
		prefix := newHash("29")[:2]
		var want []string
		for i := 0; i < 3; i++ {
			h := fmt.Sprintf("%s%02d%s", prefix, i, strings.Repeat("9", 60))
			if err := s.Put(ctx, h, []byte("x")); err != nil {
				t.Fatalf("Put %s: %v", h, err)
			}
			want = append(want, h)
		}
		// An unrelated blob (different shard) must not appear.
		if err := s.Put(ctx, newHash("aa"), []byte("y")); err != nil {
			t.Fatalf("Put unrelated: %v", err)
		}
		keys, err := s.List(ctx, prefix)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		gotSet := make(map[string]bool)
		for _, k := range keys {
			if !strings.HasPrefix(k, prefix) {
				t.Fatalf("List returned key %s outside prefix %s", k, prefix)
			}
			gotSet[k] = true
		}
		for _, w := range want {
			if !gotSet[w] {
				t.Fatalf("List missing %s (got %d keys)", w, len(keys))
			}
		}
	})

	t.Run("ListWithModTime", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		h := newHash("3a")
		if err := s.Put(ctx, h, []byte("info")); err != nil {
			t.Fatalf("Put: %v", err)
		}
		infos, err := s.ListWithModTime(ctx, h[:2])
		if err != nil {
			t.Fatalf("ListWithModTime: %v", err)
		}
		var found *BlobInfo
		for i := range infos {
			if infos[i].Hash == h {
				found = &infos[i]
			}
		}
		if found == nil {
			t.Fatal("ListWithModTime missing the stored blob")
		}
		if found.Size != 4 {
			t.Fatalf("info size = %d, want 4", found.Size)
		}
		if found.ModTime <= 0 {
			t.Fatalf("info modtime = %d, want positive", found.ModTime)
		}
	})

	t.Run("InvalidHash", func(t *testing.T) {
		s := newStore(t)
		defer s.Close()
		if _, err := s.Get(ctx, "not-a-hash"); !errors.Is(err, ErrInvalidHash) {
			t.Fatalf("Get with invalid hash must wrap ErrInvalidHash, got: %v", err)
		}
		if err := s.Put(ctx, "not-a-hash", []byte("x")); !errors.Is(err, ErrInvalidHash) {
			t.Fatalf("Put with invalid hash must wrap ErrInvalidHash, got: %v", err)
		}
	})
}
