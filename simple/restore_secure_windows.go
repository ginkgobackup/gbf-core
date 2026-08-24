//go:build windows

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/ginkgobackup/gbf-core/fsutil"
)

// winDir is a secureDir backed by a path plus the linkChecker: pre-write
// Lstat verification of every component and a post-write re-check. The
// Win32 API surface Go exposes (CreateFile etc.) has no handle-relative
// directory opens — that would require ntdll's NtCreateFile with a
// RootDirectory — so on Windows the symlink defense is DETECTION-based
// while POSIX gets kernel-level prevention. See SECURITY.md.
type winDir struct {
	path string
	lc   *linkChecker
}

func openSecureDir(root string) (secureDir, error) {
	lc, err := newLinkChecker(root)
	if err != nil {
		return nil, err
	}
	return &winDir{path: lc.targetDir, lc: lc}, nil
}

func (d *winDir) Child(name string) (secureDir, error) {
	p := filepath.Join(d.path, name)
	if err := d.lc.ensureLinkFree(p); err != nil {
		return nil, err
	}
	return &winDir{path: p, lc: d.lc}, nil
}

// EnsureDir creates the directory (empty-dir skeleton) and re-verifies all
// components afterwards: MkdirAll follows pre-existing symlinks, so a
// component swapped in mid-restore is caught here.
func (d *winDir) EnsureDir() error {
	if err := os.MkdirAll(d.path, 0o755); err != nil {
		return err
	}
	return d.lc.recheckLinkFree(d.path)
}

func (d *winDir) Exists(name string) (bool, error) {
	_, err := os.Lstat(filepath.Join(d.path, name))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (d *winDir) WriteAtomic(name string, data []byte, mode os.FileMode) error {
	p := filepath.Join(d.path, name)
	if err := fsutil.WriteFileAtomic(p, data, mode); err != nil {
		return err
	}
	return d.lc.recheckLinkFree(p)
}

type winStaging struct {
	f    *os.File
	path string // staging file path
	dir  *winDir
	name string // final base name
	done bool
}

func (d *winDir) CreateStaging(name string) (secureStaging, error) {
	// The directory may not exist yet (first file restored into it); the
	// pre-secure code created it via MkdirAll in the callers. Verify it is
	// link-free, then create it.
	if err := d.lc.ensureLinkFree(d.path); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(d.path, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	p := filepath.Join(d.path, name+"."+uuid.NewString()+".tmp")
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create staging: %w", err)
	}
	return &winStaging{f: f, path: p, dir: d, name: name}, nil
}

func (s *winStaging) Write(p []byte) (int, error)  { return s.f.Write(p) }
func (s *winStaging) Chmod(mode os.FileMode) error { return s.f.Chmod(mode) }
func (s *winStaging) Sync() error                  { return s.f.Sync() }
func (s *winStaging) Close() error                 { return s.f.Close() }

func (s *winStaging) Commit(finalName string) error {
	p := filepath.Join(s.dir.path, finalName)
	if err := os.Rename(s.path, p); err != nil {
		return fmt.Errorf("rename staging to %s: %w", finalName, err)
	}
	s.done = true
	return s.dir.lc.recheckLinkFree(p)
}

func (s *winStaging) Cleanup() {
	if s.done {
		return
	}
	_ = s.f.Close()
	_ = os.Remove(s.path)
}

func (d *winDir) Chtimes(name string, t time.Time) error {
	return os.Chtimes(filepath.Join(d.path, name), t, t)
}

func (d *winDir) Close() error { return nil }
