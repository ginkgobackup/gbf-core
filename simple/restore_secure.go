// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"os"
	"time"
)

// secureDir is the platform-abstracted handle onto one directory of the
// restore target tree. All restore writes go through it so the write path
// cannot be redirected through a symlink/junction component:
//
//   - POSIX: the handle is an openat(2) directory fd. Child(), CreateStaging()
//     and Commit() resolve names RELATIVE TO THAT FD with O_NOFOLLOW, so a
//     component swapped for a symlink between (or even DURING) the check and
//     the write simply fails the syscall — the TOCTOU window is closed at
//     the kernel level, not merely detected afterwards.
//   - Windows: the handle is a path plus the existing linkChecker
//     (pre-write Lstat verification + post-write re-check). The Win32 API
//     Go exposes has no handle-relative directory opens (that requires
//     NtCreateFile with RootDirectory), so Windows keeps detection-based
//     defense; this gap is documented in SECURITY.md.
//
// All names passed to the methods are single path elements below the
// directory the handle refers to; multi-element names are a programming
// error.
type secureDir interface {
	// Child returns a handle to the (possibly not yet existing) child
	// directory name. On POSIX the directory is created if missing
	// (mkdirat) and the open uses O_NOFOLLOW, rejecting symlinked
	// components atomically. On Windows it only lexically verifies the
	// component; call EnsureDir to create it.
	Child(name string) (secureDir, error)

	// EnsureDir creates the directory this handle refers to if it does not
	// exist yet (empty-directory skeleton restore).
	EnsureDir() error

	// Exists reports whether name exists below this directory WITHOUT
	// following a final symlink (lstat semantics).
	Exists(name string) (bool, error)

	// WriteAtomic atomically writes data to name below this directory with
	// the durability semantics of fsutil.WriteFileAtomic.
	WriteAtomic(name string, data []byte, mode os.FileMode) error

	// CreateStaging opens a fresh staging file for name (the caller gets a
	// unique staging name) for streamed writes, committed later with
	// Commit.
	CreateStaging(name string) (secureStaging, error)

	// Chtimes sets the access and modification times of name below this
	// directory to t.
	Chtimes(name string, t time.Time) error

	// Close releases the handle. It is idempotent.
	Close() error
}

// secureStaging is a streamed-write staging file inside a secureDir,
// committed atomically to its final name via Commit.
type secureStaging interface {
	Write(p []byte) (int, error)
	Chmod(mode os.FileMode) error
	Sync() error
	Close() error
	// Commit atomically moves the staging file to finalName in the same
	// directory. After a successful Commit the staging file is gone;
	// Cleanup becomes a no-op.
	Commit(finalName string) error
	// Cleanup discards the staging file (close + unlink). No-op after a
	// successful Commit.
	Cleanup()
}

// openSecurePath walks comps from root and returns a handle to the final
// component. Intermediate handles are opened and closed along the way; the
// returned handle is owned by the caller (Close it), EXCEPT when comps is
// empty — then root itself is returned unowned (owned stays false).
func openSecurePath(root secureDir, comps []string) (dir secureDir, owned bool, err error) {
	dir = root
	for _, c := range comps {
		if c == "" || c == "." || c == ".." {
			return nil, false, &os.PathError{Op: "openSecurePath", Path: c, Err: os.ErrInvalid}
		}
		next, err := dir.Child(c)
		if dir != root {
			_ = dir.Close()
		}
		if err != nil {
			return nil, false, err
		}
		dir = next
		owned = true
	}
	return dir, owned, nil
}
