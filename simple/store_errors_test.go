// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestLocalBlobStoreConformance pins the SimpleBlobStore contract for the
// local disk implementation.
func TestLocalBlobStoreConformance(t *testing.T) {
	BlobStoreConformance(t, func(t *testing.T) SimpleBlobStore {
		t.Helper()
		return NewLocalBlobStore(t.TempDir())
	})
}

// TestClassifyPathErrorWrapsBothSentinelAndOriginal pins the dual-wrap
// contract: legacy errors.Is(err, fs.ErrNotExist) checks and new
// errors.Is(err, ErrBlobNotFound) checks must both succeed.
func TestClassifyPathErrorWrapsBothSentinelAndOriginal(t *testing.T) {
	_, err := os.Open(filepath.Join(t.TempDir(), "missing-blob"))
	if err == nil {
		t.Fatal("expected open error")
	}
	classified := ClassifyPathError("get", "abc", err)
	if !errors.Is(classified, ErrBlobNotFound) {
		t.Fatalf("want ErrBlobNotFound in chain, got: %v", classified)
	}
	if !errors.Is(classified, fs.ErrNotExist) {
		t.Fatalf("want original fs.ErrNotExist in chain, got: %v", classified)
	}
}
