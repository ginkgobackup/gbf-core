//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSecureDirPosixRejectsSymlinkComponent pins the kernel-level no-follow
// guarantee: opening a symlinked child via Child() must fail (openat with
// O_NOFOLLOW yields ELOOP), and the symlink must never be traversed.
func TestSecureDirPosixRejectsSymlinkComponent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "escaped.txt"), []byte("outside"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "evil")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	d, err := openSecureDir(root)
	if err != nil {
		t.Fatalf("openSecureDir: %v", err)
	}
	defer d.Close()

	_, err = d.Child("evil")
	if err == nil {
		t.Fatal("Child() accepted a symlinked component")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("unexpected error: %v", err)
	}
	// The symlink itself must be untouched (still a link, not replaced by
	// a directory).
	fi, err := os.Lstat(filepath.Join(root, "evil"))
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the pre-existing symlink was replaced during the rejected Child()")
	}
}

// TestSecureDirPosixChildCreatesDirectories verifies Child() creates
// missing directories (mkdirat) and that deep chains work, including the
// empty-directory skeleton case (EnsureDir is a no-op after Child).
func TestSecureDirPosixChildCreatesDirectories(t *testing.T) {
	root := t.TempDir()
	d, err := openSecureDir(root)
	if err != nil {
		t.Fatalf("openSecureDir: %v", err)
	}
	defer d.Close()

	sub, err := d.Child("a")
	if err != nil {
		t.Fatalf("Child(a): %v", err)
	}
	subsub, err := sub.Child("b")
	if err != nil {
		t.Fatalf("Child(b): %v", err)
	}
	_ = sub.Close()
	if err := subsub.EnsureDir(); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(root, "a", "b")); err != nil || !fi.IsDir() {
		t.Fatalf("a/b was not created: %v", err)
	}
	_ = subsub.Close()
}

// TestSecureDirPosixWriteAtomicAndChtimes round-trips a file through the
// secure abstraction: staging created with O_EXCL relative to the dir fd,
// committed via renameat, mtime set via utimensat — all without a single
// path-based traversal that a swapped component could redirect.
func TestSecureDirPosixWriteAtomicAndChtimes(t *testing.T) {
	root := t.TempDir()
	d, err := openSecureDir(root)
	if err != nil {
		t.Fatalf("openSecureDir: %v", err)
	}
	defer d.Close()

	if err := d.WriteAtomic("file.txt", []byte("payload"), 0640); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "file.txt"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "payload" {
		t.Fatalf("content = %q", data)
	}
	if fi, err := os.Stat(filepath.Join(root, "file.txt")); err != nil || fi.Mode().Perm() != 0640 {
		t.Fatalf("mode not applied: %v %v", fi, err)
	}

	want := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	if err := d.Chtimes("file.txt", want); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	fi, err := os.Stat(filepath.Join(root, "file.txt"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !fi.ModTime().Equal(want) {
		t.Fatalf("mtime = %v, want %v", fi.ModTime(), want)
	}

	// No staging leftovers.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "file.txt" {
		t.Fatalf("dir entries after commit = %v, want only file.txt", entries)
	}
}

// TestSecureDirPosixExistsNoFollow: a dangling symlink final component must
// count as "exists" (lstat semantics) so non-overwrite restores skip it
// instead of renaming over it.
func TestSecureDirPosixExistsNoFollow(t *testing.T) {
	root := t.TempDir()
	d, err := openSecureDir(root)
	if err != nil {
		t.Fatalf("openSecureDir: %v", err)
	}
	defer d.Close()

	if err := os.Symlink("nowhere", filepath.Join(root, "dangling")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	exists, err := d.Exists("dangling")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("dangling symlink reported as non-existent (must use lstat semantics)")
	}
}
