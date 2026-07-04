// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ginkgobackup/gbf-core/fsutil"
	"github.com/ginkgobackup/gbf-core/ratelimit"
	"github.com/google/uuid"
)

type LocalBlobStore struct {
	baseDir      string
	dirCache     map[string]bool
	dirCacheMu   sync.Mutex
	existsSet    map[string]bool
	existsMu     sync.RWMutex
	putMu        sync.Map
	writeLimiter *ratelimit.Limiter
}

func NewLocalBlobStore(baseDir string) *LocalBlobStore {
	return &LocalBlobStore{
		baseDir:   baseDir,
		dirCache:  make(map[string]bool),
		existsSet: make(map[string]bool),
	}
}

func (s *LocalBlobStore) SetWriteLimiter(l *ratelimit.Limiter) {
	s.writeLimiter = l
}

// ErrInvalidHash is returned when a blob hash is not a valid 64-character
// lowercase hex SHA-256. Rejecting early prevents path-traversal via crafted
// hash values (e.g. "../../etc/passwd") that would otherwise be joined into
// the blob storage path.
var ErrInvalidHash = fmt.Errorf("invalid blob hash: expected 64-character hex SHA-256")

// validateHash returns true if hash is a 64-character lowercase hex string.
// We accept lowercase only to match hex.EncodeToString output; uppercase
// is rejected to avoid case-sensitive filesystem surprises on case-insensitive
// filesystems (NTFS, HFS+).
func validateHash(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	for i := 0; i < len(hash); i++ {
		c := hash[i]
		// Only accept 0-9 and a-f. Reject A-F (uppercase) explicitly.
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (s *LocalBlobStore) BlobPath(hash string) string {
	if !validateHash(hash) {
		return ""
	}
	return filepath.Join(s.baseDir, "gb", hash[:2], hash+".gb")
}

func (s *LocalBlobStore) blobPath(hash string) string {
	return s.BlobPath(hash)
}

func (s *LocalBlobStore) resolveBlobPath(hash string) string {
	return s.blobPath(hash)
}

func (s *LocalBlobStore) ensureDir(dir string) error {
	s.dirCacheMu.Lock()
	if s.dirCache[dir] {
		s.dirCacheMu.Unlock()
		return nil
	}
	s.dirCacheMu.Unlock()

	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	s.dirCacheMu.Lock()
	s.dirCache[dir] = true
	s.dirCacheMu.Unlock()
	return nil
}

func (s *LocalBlobStore) lockPut(hash string) func() {
	v, _ := s.putMu.LoadOrStore(hash, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// putBlob is the shared implementation of Put and PutStream. writeBlob is
// responsible for writing the blob content to f; on error it should return
// a wrapped error and leave f open (putBlob closes f and removes the temp
// file on cleanup). The rest of the atomic-rename + fsync + exists-cache
// dance lives here so the two public methods don't drift out of sync.
func (s *LocalBlobStore) putBlob(ctx context.Context, hash string, writeBlob func(f *os.File) error) error {
	if !validateHash(hash) {
		return ErrInvalidHash
	}
	unlock := s.lockPut(hash)
	defer unlock()

	s.existsMu.RLock()
	if s.existsSet[hash] {
		s.existsMu.RUnlock()
		return nil
	}
	s.existsMu.RUnlock()

	path := s.blobPath(hash)
	if _, err := os.Stat(path); err == nil {
		s.existsMu.Lock()
		s.existsSet[hash] = true
		s.existsMu.Unlock()
		return nil
	}

	dir := filepath.Dir(path)
	if err := s.ensureDir(dir); err != nil {
		return err
	}

	tmp := path + "." + uuid.New().String() + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create tmp blob: %w", err)
	}

	if err := writeBlob(f); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("sync tmp blob: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close tmp blob: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		// A concurrent put for the same hash may have completed first.
		// Treat "target already exists" as success rather than a race failure.
		if _, statErr := os.Stat(path); statErr == nil {
			s.existsMu.Lock()
			s.existsSet[hash] = true
			s.existsMu.Unlock()
			return nil
		}
		return fmt.Errorf("rename tmp blob: %w", err)
	}
	if err := fsutil.SyncParent(dir); err != nil {
		return fmt.Errorf("sync parent dir: %w", err)
	}
	s.existsMu.Lock()
	s.existsSet[hash] = true
	s.existsMu.Unlock()
	return nil
}

func (s *LocalBlobStore) Put(ctx context.Context, hash string, data []byte) error {
	return s.putBlob(ctx, hash, func(f *os.File) error {
		if s.writeLimiter != nil {
			w := ratelimit.NewWriter(f, s.writeLimiter)
			if _, err := w.WriteContext(ctx, data); err != nil {
				return fmt.Errorf("write tmp blob: %w", err)
			}
			return nil
		}
		if _, err := f.Write(data); err != nil {
			return fmt.Errorf("write tmp blob: %w", err)
		}
		return nil
	})
}

func (s *LocalBlobStore) Get(ctx context.Context, hash string) ([]byte, error) {
	if !validateHash(hash) {
		return nil, ErrInvalidHash
	}
	return os.ReadFile(s.resolveBlobPath(hash))
}

func (s *LocalBlobStore) PutStream(ctx context.Context, hash string, r io.Reader, size int64) error {
	return s.putBlob(ctx, hash, func(f *os.File) error {
		if s.writeLimiter != nil {
			w := ratelimit.NewWriter(f, s.writeLimiter)
			// Honor ctx cancellation during the copy: io.Copy would block on
			// WriteContext's WaitN with context.Background(), defeating ctx
			// propagation. A manual loop lets us pass ctx through WriteContext.
			buf := make([]byte, 32*1024)
			for {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				n, rerr := r.Read(buf)
				if n > 0 {
					if _, werr := w.WriteContext(ctx, buf[:n]); werr != nil {
						return fmt.Errorf("write tmp blob stream: %w", werr)
					}
				}
				if rerr == io.EOF {
					return nil
				}
				if rerr != nil {
					return fmt.Errorf("write tmp blob stream: %w", rerr)
				}
			}
		}
		if _, err := io.Copy(f, r); err != nil {
			return fmt.Errorf("write tmp blob stream: %w", err)
		}
		return nil
	})
}

func (s *LocalBlobStore) GetStream(ctx context.Context, hash string) (io.ReadCloser, error) {
	if !validateHash(hash) {
		return nil, ErrInvalidHash
	}
	return os.Open(s.resolveBlobPath(hash))
}

func (s *LocalBlobStore) Exists(ctx context.Context, hash string) (bool, error) {
	if !validateHash(hash) {
		return false, nil
	}
	s.existsMu.RLock()
	if s.existsSet[hash] {
		s.existsMu.RUnlock()
		return true, nil
	}
	s.existsMu.RUnlock()

	_, err := os.Stat(s.blobPath(hash))
	if err == nil {
		s.existsMu.Lock()
		s.existsSet[hash] = true
		s.existsMu.Unlock()
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (s *LocalBlobStore) WarmExistsCache(ctx context.Context) error {
	blobDir := filepath.Join(s.baseDir, "gb")
	entries, err := os.ReadDir(blobDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	// Build the new entries in a local map first, then merge under the lock.
	// Writing directly to existsSet without the lock would race with concurrent
	// Exists/Put/Get callers and trigger "concurrent map writes" panics.
	newEntries := make(map[string]bool, 256)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		subDir := filepath.Join(blobDir, e.Name())
		blobs, err := os.ReadDir(subDir)
		if err != nil {
			continue
		}
		for _, b := range blobs {
			if b.IsDir() || !strings.HasSuffix(b.Name(), ".gb") {
				continue
			}
			name := strings.TrimSuffix(b.Name(), ".gb")
			if validateHash(name) {
				newEntries[name] = true
			}
		}
	}
	s.existsMu.Lock()
	for k, v := range newEntries {
		s.existsSet[k] = v
	}
	s.existsMu.Unlock()
	return nil
}

func (s *LocalBlobStore) List(ctx context.Context, prefix string) ([]string, error) {
	var result []string

	blobDir := filepath.Join(s.baseDir, "gb")
	entries, err := os.ReadDir(blobDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if prefix != "" && !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		subDir := filepath.Join(blobDir, e.Name())
		blobs, err := os.ReadDir(subDir)
		if err != nil {
			continue
		}
		for _, b := range blobs {
			if b.IsDir() || !strings.HasSuffix(b.Name(), ".gb") {
				continue
			}
			name := strings.TrimSuffix(b.Name(), ".gb")
			if validateHash(name) {
				result = append(result, name)
			}
		}
	}
	return result, nil
}

func (s *LocalBlobStore) ListWithModTime(ctx context.Context, prefix string) ([]BlobInfo, error) {
	var result []BlobInfo

	blobDir := filepath.Join(s.baseDir, "gb")
	entries, err := os.ReadDir(blobDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if prefix != "" && !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		subDir := filepath.Join(blobDir, e.Name())
		blobs, err := os.ReadDir(subDir)
		if err != nil {
			continue
		}
		for _, b := range blobs {
			if b.IsDir() || !strings.HasSuffix(b.Name(), ".gb") {
				continue
			}
			name := strings.TrimSuffix(b.Name(), ".gb")
			if validateHash(name) {
				info, statErr := b.Info()
				modTime := int64(0)
				size := int64(0)
				if statErr == nil {
					modTime = info.ModTime().Unix()
					size = info.Size()
				}
				result = append(result, BlobInfo{Hash: name, ModTime: modTime, Size: size})
			}
		}
	}
	return result, nil
}

func (s *LocalBlobStore) Delete(ctx context.Context, hash string) error {
	if !validateHash(hash) {
		return ErrInvalidHash
	}
	p := s.blobPath(hash)
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	s.existsMu.Lock()
	delete(s.existsSet, hash)
	s.existsMu.Unlock()
	return nil
}

func (s *LocalBlobStore) Close() error {
	return nil
}
