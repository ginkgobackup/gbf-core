// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestCommitFileNoReplace pins the no-replace commit semantics: a fresh
// commit succeeds and consumes the staging file, a second commit onto the
// SAME final name fails with os.ErrExist and leaves both files untouched,
// and the surviving final name holds the FIRST writer's content.
func TestCommitFileNoReplace(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "target.bin")

	if err := WriteStagingFile(final+".staging1", []byte("first"), 0600); err != nil {
		t.Fatalf("staging1: %v", err)
	}
	if err := CommitFileNoReplace(final+".staging1", final); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if _, err := os.Stat(final + ".staging1"); !os.IsNotExist(err) {
		t.Fatalf("staging1 still exists after commit: %v", err)
	}

	if err := WriteStagingFile(final+".staging2", []byte("second"), 0600); err != nil {
		t.Fatalf("staging2: %v", err)
	}
	err := CommitFileNoReplace(final+".staging2", final)
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("second commit error = %v, want os.ErrExist", err)
	}

	// The loser's staging file must still exist (untouched), and the final
	// name must still hold the first writer's content.
	if _, err := os.Stat(final + ".staging2"); err != nil {
		t.Fatalf("loser staging file removed on conflict: %v", err)
	}
	data, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if string(data) != "first" {
		t.Fatalf("final content = %q, want %q (no-replace was violated)", data, "first")
	}
}

// TestCommitFileNoReplaceConcurrent races N concurrent commits onto one
// final name: exactly one must win, the rest must get os.ErrExist, and the
// final content must equal the winner's payload.
func TestCommitFileNoReplaceConcurrent(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "target.bin")

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			staging := filepath.Join(dir, "staging-"+string(rune('a'+i)))
			if err := WriteStagingFile(staging, []byte{byte(i)}, 0600); err != nil {
				errs[i] = err
				return
			}
			errs[i] = CommitFileNoReplace(staging, final)
		}(i)
	}
	wg.Wait()

	wins := 0
	var winner byte
	for i, err := range errs {
		if err == nil {
			wins++
			winner = byte(i)
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatalf("commit %d: unexpected error %v", i, err)
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent commits: %d winners, want exactly 1", wins)
	}
	data, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if len(data) != 1 || data[0] != winner {
		t.Fatalf("final content = %v, want the single winner's payload [%d]", data, winner)
	}
}
