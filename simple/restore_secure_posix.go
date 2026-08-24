//go:build !windows

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
	"golang.org/x/sys/unix"
)

// posixDir is a secureDir backed by an open directory file descriptor.
// Every operation resolves a name RELATIVE TO the fd with O_NOFOLLOW /
// AT_SYMLINK_NOFOLLOW, so symlinks in restored path components fail at the
// syscall itself — there is no check-then-write window to exploit.
type posixDir struct {
	fd   int
	path string // absolute path, for error messages only
}

// openSecureDir opens the restore target root. The root itself may be any
// path the user chose (including a symlink — the user picked it); the
// no-follow guarantee applies to everything BELOW the root.
func openSecureDir(root string) (secureDir, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve target dir: %w", err)
	}
	fd, err := unix.Open(abs, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if mkErr := os.MkdirAll(abs, 0o755); mkErr != nil {
				return nil, fmt.Errorf("mkdir target dir: %w", mkErr)
			}
			fd, err = unix.Open(abs, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		}
		if err != nil {
			return nil, fmt.Errorf("open target dir: %w", err)
		}
	}
	return &posixDir{fd: fd, path: abs}, nil
}

// Child opens (creating if needed) the child directory name via openat
// with O_NOFOLLOW: a child that is a symlink fails with ELOOP instead of
// being traversed.
func (d *posixDir) Child(name string) (secureDir, error) {
	const openFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Openat(d.fd, name, openFlags, 0)
	if err == nil {
		return &posixDir{fd: fd, path: filepath.Join(d.path, name)}, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		if mkErr := unix.Mkdirat(d.fd, name, 0o755); mkErr != nil && !errors.Is(mkErr, fs.ErrExist) {
			return nil, fmt.Errorf("mkdir %s: %w", name, mkErr)
		}
		// Retry the open: a concurrent creator may have made name a
		// symlink between Mkdirat's EEXIST and this open — O_NOFOLLOW
		// still rejects it.
		fd, err = unix.Openat(d.fd, name, openFlags, 0)
		if err == nil {
			return &posixDir{fd: fd, path: filepath.Join(d.path, name)}, nil
		}
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return nil, fmt.Errorf("restore path %s is or passes through a symlink; refusing to restore outside the target dir", filepath.Join(d.path, name))
	}
	return nil, fmt.Errorf("open %s: %w", filepath.Join(d.path, name), err)
}

// EnsureDir is a no-op: POSIX Child() already created the directory.
func (d *posixDir) EnsureDir() error { return nil }

func (d *posixDir) Exists(name string) (bool, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", name, err)
	}
	return true, nil
}

func (d *posixDir) WriteAtomic(name string, data []byte, mode os.FileMode) error {
	st, err := d.CreateStaging(name)
	if err != nil {
		return err
	}
	defer st.Cleanup()
	if _, err := st.Write(data); err != nil {
		return fmt.Errorf("write staging: %w", err)
	}
	if err := st.Chmod(mode); err != nil {
		return fmt.Errorf("chmod staging: %w", err)
	}
	if err := st.Sync(); err != nil {
		return fmt.Errorf("sync staging: %w", err)
	}
	if err := st.Close(); err != nil {
		return fmt.Errorf("close staging: %w", err)
	}
	return st.Commit(name)
}

type posixStaging struct {
	f    *os.File
	dir  *posixDir
	name string // staging file name within dir
	done bool
}

func (d *posixDir) CreateStaging(name string) (secureStaging, error) {
	stagingName := name + "." + uuid.NewString() + ".tmp"
	fd, err := unix.Openat(d.fd, stagingName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create staging %s: %w", stagingName, err)
	}
	return &posixStaging{
		f:    os.NewFile(uintptr(fd), filepath.Join(d.path, stagingName)),
		dir:  d,
		name: stagingName,
	}, nil
}

func (s *posixStaging) Write(p []byte) (int, error)  { return s.f.Write(p) }
func (s *posixStaging) Chmod(mode os.FileMode) error { return s.f.Chmod(mode) }
func (s *posixStaging) Sync() error                  { return s.f.Sync() }
func (s *posixStaging) Close() error                 { return s.f.Close() }

// Commit renames the staging file onto finalName within the same directory
// (renameat), then fsyncs the directory so the rename itself is durable —
// mirroring fsutil.WriteFileAtomic's durability contract.
func (s *posixStaging) Commit(finalName string) error {
	if err := unix.Renameat(s.dir.fd, s.name, s.dir.fd, finalName); err != nil {
		return fmt.Errorf("rename staging to %s: %w", finalName, err)
	}
	s.done = true
	if err := unix.Fsync(s.dir.fd); err != nil {
		// The rename already happened; a directory-sync failure leaves a
		// crash-durability gap, not a correctness one. Surface it.
		return fmt.Errorf("fsync dir after rename: %w", err)
	}
	return nil
}

func (s *posixStaging) Cleanup() {
	if s.done {
		return
	}
	_ = s.f.Close()
	_ = unix.Unlinkat(s.dir.fd, s.name, 0)
}

func (d *posixDir) Chtimes(name string, t time.Time) error {
	ts := []unix.Timespec{
		{Sec: t.Unix(), Nsec: int64(t.Nanosecond())},
		{Sec: t.Unix(), Nsec: int64(t.Nanosecond())},
	}
	return unix.UtimesNanoAt(d.fd, name, ts, 0)
}

func (d *posixDir) Close() error {
	if d.fd < 0 {
		return nil
	}
	err := unix.Close(d.fd)
	d.fd = -1
	return err
}
