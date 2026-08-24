//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// CommitFileNoReplace atomically moves src to dst WITHOUT replacing an
// existing dst: if dst already exists the call fails with an error matching
// errors.Is(err, os.ErrExist), and both src and dst are left untouched.
// This is the no-replace counterpart of the rename in WriteFileAtomic and
// gives cross-PROCESS protection: two processes racing to commit the same
// final name cannot silently overwrite each other — exactly one wins and
// the loser gets a distinguishable EEXIST error.
//
// POSIX implementation: link(2) + unlink(2). hard-linking the fsynced
// staging file onto the final name is atomic and fails with EEXIST when
// the target exists; unlinking the staging name afterwards leaves exactly
// one name for the data. src and dst must be on the same filesystem (the
// usual case: staging files live next to their final names).
func CommitFileNoReplace(src, dst string) error {
	if err := os.Link(src, dst); err != nil {
		// *LinkError wraps EEXIST — errors.Is(err, os.ErrExist) is true.
		return fmt.Errorf("commit %s: %w", dst, err)
	}
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("remove staging file %s: %w", src, err)
	}
	return syncParentDir(filepath.Dir(dst))
}
