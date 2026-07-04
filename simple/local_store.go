// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"context"
	"encoding/hex"
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

func (s *LocalBlobStore) BlobPath(hash string) string {
	if len(hash) < 2 {
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

func (s *LocalBlobStore) Put(ctx context.Context, hash string, data []byte) error {
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
	if s.writeLimiter != nil {
		f, err := os.Create(tmp)
		if err != nil {
			os.Remove(tmp)
			return fmt.Errorf("create tmp blob: %w", err)
		}
		w := ratelimit.NewWriter(f, s.writeLimiter)
		if _, err := w.Write(data); err != nil {
			f.Close()
			os.Remove(tmp)
			return fmt.Errorf("write tmp blob: %w", err)
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
	} else {
		if err := os.WriteFile(tmp, data, 0600); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("write tmp blob: %w", err)
		}
		f, err := os.OpenFile(tmp, os.O_WRONLY, 0600)
		if err != nil {
			os.Remove(tmp)
			return fmt.Errorf("open tmp blob for sync: %w", err)
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
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
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

func (s *LocalBlobStore) Get(ctx context.Context, hash string) ([]byte, error) {
	return os.ReadFile(s.resolveBlobPath(hash))
}

func (s *LocalBlobStore) PutStream(ctx context.Context, hash string, r io.Reader, size int64) error {
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
		return err
	}
	if s.writeLimiter != nil {
		w := ratelimit.NewWriter(f, s.writeLimiter)
		if _, err := io.Copy(w, r); err != nil {
			f.Close()
			os.Remove(tmp)
			return fmt.Errorf("write tmp blob stream: %w", err)
		}
	} else {
		if _, err := io.Copy(f, r); err != nil {
			f.Close()
			os.Remove(tmp)
			return fmt.Errorf("write tmp blob stream: %w", err)
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("sync tmp blob stream: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close tmp blob stream: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		if _, statErr := os.Stat(path); statErr == nil {
			s.existsMu.Lock()
			s.existsSet[hash] = true
			s.existsMu.Unlock()
			return nil
		}
		return fmt.Errorf("rename tmp blob stream: %w", err)
	}
	if err := fsutil.SyncParent(dir); err != nil {
		return fmt.Errorf("sync parent dir: %w", err)
	}
	s.existsMu.Lock()
	s.existsSet[hash] = true
	s.existsMu.Unlock()
	return nil
}

func (s *LocalBlobStore) GetStream(ctx context.Context, hash string) (io.ReadCloser, error) {
	return os.Open(s.resolveBlobPath(hash))
}

func (s *LocalBlobStore) Exists(ctx context.Context, hash string) (bool, error) {
	if len(hash) < 2 {
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
			if _, err := hex.DecodeString(name); err == nil {
				s.existsSet[name] = true
			}
		}
	}
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
			if _, err := hex.DecodeString(name); err == nil {
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
			if _, err := hex.DecodeString(name); err == nil {
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
