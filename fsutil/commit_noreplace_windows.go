//go:build windows

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package fsutil

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// CommitFileNoReplace atomically moves src to dst WITHOUT replacing an
// existing dst: if dst already exists the call fails with an error matching
// errors.Is(err, os.ErrExist), and both src and dst are left untouched.
// This is the no-replace counterpart of the rename in WriteFileAtomic and
// gives cross-PROCESS protection: two processes racing to commit the same
// final name cannot silently overwrite each other — exactly one wins and
// the loser gets a distinguishable already-exists error.
//
// Windows implementation: MoveFileEx WITHOUT the MOVEFILE_REPLACE_EXISTING
// flag fails with ERROR_ALREADY_EXISTS (mapped to os.ErrExist by
// syscall.Errno) when dst exists, and is otherwise an atomic same-volume
// move. MOVEFILE_WRITE_THROUGH flushes the rename to disk before returning.
// Unlike the POSIX link(2) implementation, src is consumed by the move.
func CommitFileNoReplace(src, dst string) error {
	srcPtr, err := windows.UTF16PtrFromString(filepath.Clean(src))
	if err != nil {
		return fmt.Errorf("commit %s: %w", dst, err)
	}
	dstPtr, err := windows.UTF16PtrFromString(filepath.Clean(dst))
	if err != nil {
		return fmt.Errorf("commit %s: %w", dst, err)
	}
	if err := windows.MoveFileEx(srcPtr, dstPtr, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		// ERROR_ALREADY_EXISTS / ERROR_FILE_EXISTS map to os.ErrExist
		// via syscall.Errno.Is.
		return fmt.Errorf("commit %s: %w", dst, err)
	}
	return syncParentDir(filepath.Dir(dst))
}
