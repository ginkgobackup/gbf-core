//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package fsutil

import (
	"fmt"
	"os"
)

func OpenFileSequential(path string) (*os.File, error) {
	return os.Open(path)
}

func ReadFileSequential(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeFileAtomicCommon(path, data, perm)
}

func syncParentDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open parent dir: %w", err)
	}
	defer func() { _ = d.Close() }()

	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync parent dir: %w", err)
	}
	return nil
}
