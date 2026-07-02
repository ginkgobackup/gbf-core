//go:build windows

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package fsutil

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

const (
	_FlagSequentialScan  = 0x08000000
	_FileAttributeNormal = 0x00000080
)

func OpenFileSequential(path string) (*os.File, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("OpenFileSequential: %w", err)
	}

	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		_FlagSequentialScan|_FileAttributeNormal,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("OpenFileSequential CreateFile: %w", err)
	}

	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("OpenFileSequential: os.NewFile returned nil")
	}

	return f, nil
}

func ReadFileSequential(path string) ([]byte, error) {
	f, err := OpenFileSequential(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("ReadFileSequential Stat: %w", err)
	}

	size := stat.Size()
	if size < 0 {
		return nil, fmt.Errorf("ReadFileSequential: negative file size")
	}

	data := make([]byte, size)
	n, err := f.Read(data)
	if err != nil {
		return nil, fmt.Errorf("ReadFileSequential Read: %w", err)
	}

	return data[:n], nil
}

func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	tmp := path + ".tmp"
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

	return syncParentDir(dir)
}

func SyncParent(dir string) error {
	return syncParentDir(dir)
}

func syncParentDir(dir string) error {
	return nil
}
