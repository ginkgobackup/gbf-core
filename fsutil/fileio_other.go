//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package fsutil

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

func OpenFileSequential(path string) (*os.File, error) {
	return os.Open(path)
}

func ReadFileSequential(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Use a per-call unique temp name so concurrent WriteFileAtomic calls
	// on the same path do not clobber each other's staging file.
	tmp := path + "." + uuid.NewString() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("create tmp file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write tmp file: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("sync tmp file: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close tmp file: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename tmp file: %w", err)
	}

	if err := syncParentDir(dir); err != nil {
		return fmt.Errorf("sync parent dir: %w", err)
	}

	return nil
}

func SyncParent(dir string) error {
	return syncParentDir(dir)
}

func syncParentDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open parent dir: %w", err)
	}
	defer d.Close()

	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync parent dir: %w", err)
	}
	return nil
}
