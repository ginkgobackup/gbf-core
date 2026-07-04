//go:build windows

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package fsutil

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

const (
	_FlagSequentialScan  = 0x08000000
	_FileAttributeNormal = 0x00000080
	// FILE_FLAG_BACKUP_SEMANTICS is required to open a directory handle on
	// Windows; without it CreateFile fails with ERROR_ACCESS_DENIED.
	_FlagBackupSemantics = 0x02000000
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
	// io.ReadFull guarantees we read exactly `size` bytes. A bare f.Read can
	// return a short read, silently truncating the file content that gets
	// hashed and stored. If the file was truncated between Stat and Read,
	// io.ReadFull returns ErrUnexpectedEOF, which we surface as an error
	// rather than persisting a partial buffer under the original hash.
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, fmt.Errorf("ReadFileSequential Read: %w", err)
	}

	return data, nil
}

func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeFileAtomicCommon(path, data, perm)
}

// syncParentDir fsyncs a directory on Windows. Windows does not expose a
// direct fsync-on-directory syscall, but opening the directory with
// FILE_FLAG_BACKUP_SEMANTICS and calling FlushFileBuffers persists its
// metadata (including the entry update from a just-performed rename).
// Without this, a crash between rename and the OS flushing the directory
// can lose the rename. Previously this was a no-op, which silently broke
// the durability guarantee that callers (manifest, blob store, config)
// rely on.
func syncParentDir(dir string) error {
	pathPtr, err := windows.UTF16PtrFromString(filepath.Clean(dir))
	if err != nil {
		return fmt.Errorf("syncParentDir: %w", err)
	}
	// GENERIC_WRITE is required for FlushFileBuffers to succeed on the handle.
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		_FlagBackupSemantics|_FileAttributeNormal,
		0,
	)
	if err != nil {
		// If the directory does not exist there is nothing to sync; treat as
		// success so callers that race with rmdir don't fail spuriously.
		if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
			return nil
		}
		return fmt.Errorf("syncParentDir CreateFile: %w", err)
	}
	defer windows.CloseHandle(handle)

	if err := windows.FlushFileBuffers(handle); err != nil {
		return fmt.Errorf("syncParentDir FlushFileBuffers: %w", err)
	}
	return nil
}
