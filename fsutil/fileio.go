// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

// Package fsutil provides cross-platform file IO helpers used by the backup
// pipeline: atomic writes, sequential scan reads, and parent-directory fsync.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

// writeFileAtomicCommon contains the platform-independent portion of
// WriteFileAtomic: MkdirAll, write to a per-call unique temp file, fsync,
// close, rename, then sync the parent directory (delegated to the
// platform-specific syncParentDir). Extracting it avoids duplicating ~40
// lines between fileio_other.go and fileio_windows.go.
func writeFileAtomicCommon(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Per-call unique temp name so concurrent WriteFileAtomic calls on the
	// same path do not clobber each other's staging file.
	tmp := path + "." + uuid.NewString() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("create tmp file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write tmp file: %w", err)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("sync tmp file: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close tmp file: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename tmp file: %w", err)
	}

	return syncParentDir(dir)
}

// SyncParent fsyncs the parent directory of path (or dir itself if path is a
// directory). After a file is renamed into place, the directory entry update
// is not guaranteed to be durable until the directory is fsynced. Call this
// after any rename that must survive a crash.
func SyncParent(dir string) error {
	return syncParentDir(dir)
}
