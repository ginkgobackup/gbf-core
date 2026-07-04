// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// safeRestorePath sanitizes a manifest-supplied relative path so it cannot
// escape TargetDir via ".." or absolute paths. Returns the cleaned absolute
// path, or an error if the path would escape TargetDir.
//
// This is a defense-in-depth boundary: manifests are normally written by this
// engine, but in a multi-device or cloud-sync scenario a malicious peer can
// push a crafted manifest entry whose Name is "../../etc/passwd". Without
// sanitization, filepath.Join would resolve the ".." segments and write
// outside TargetDir.
func safeRestorePath(targetDir, relPath string) (string, error) {
	// Reject empty paths outright.
	if relPath == "" {
		return "", fmt.Errorf("manifest path is empty")
	}
	// Reject Unix absolute paths. filepath.FromSlash + Clean would otherwise
	// turn "/etc/passwd" into "etc/passwd" (a relative path) on Windows, which
	// is a cross-platform bug we need to catch at the source.
	if strings.HasPrefix(relPath, "/") || strings.HasPrefix(relPath, "\\") {
		return "", fmt.Errorf("manifest path is absolute: %q", relPath)
	}
	// Reject Windows drive paths like "C:\..." or "C:/...".
	if len(relPath) >= 2 && relPath[1] == ':' && ((relPath[0] >= 'A' && relPath[0] <= 'Z') || (relPath[0] >= 'a' && relPath[0] <= 'z')) {
		return "", fmt.Errorf("manifest path is absolute: %q", relPath)
	}
	// Normalize separators and strip any residual leading "/" (we already
	// rejected absolute paths above, so this is belt-and-suspenders).
	clean := filepath.Clean(filepath.FromSlash(relPath))
	// Reject ".." at the start or any ".." that escapes after Clean.
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("manifest path escapes target dir: %q", relPath)
	}
	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return "", fmt.Errorf("resolve target dir: %w", err)
	}
	joined := filepath.Join(absTarget, clean)
	// Final check: the joined path must be inside absTarget.
	rel, err := filepath.Rel(absTarget, joined)
	if err != nil {
		return "", fmt.Errorf("manifest path escapes target dir: %q", relPath)
	}
	if rel != "." && strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("manifest path escapes target dir: %q", relPath)
	}
	return joined, nil
}

type RestoreConfig struct {
	RepoRoot  string
	TargetDir string
	SourceID  int64
	CloudID   string
	Timestamp string
	DeviceID  string
	Key       []byte
	Overwrite bool
}

type RestoreResult struct {
	RestoredFiles int
	RestoredBytes int64
	SkippedFiles  int
	Duration      time.Duration
}

type SimpleRestore struct {
	cfg      RestoreConfig
	store    SimpleBlobStore
	dec      *Decryptor
	progress *ProgressTracker
}

func NewSimpleRestore(cfg RestoreConfig, store SimpleBlobStore) *SimpleRestore {
	return &SimpleRestore{
		cfg:   cfg,
		store: store,
		dec:   NewDecryptor(cfg.Key, DefaultChunkSize),
	}
}

func (r *SimpleRestore) WithProgress(cb ProgressCallback) *SimpleRestore {
	r.progress = NewProgressTracker(r.cfg.SourceID, "", cb)
	return r
}

func (r *SimpleRestore) Run(ctx context.Context) (*RestoreResult, error) {
	start := time.Now()
	result := &RestoreResult{}
	metaDir := MetaDir(r.cfg.RepoRoot)

	if r.progress != nil {
		r.progress.SetPhase(PhaseScanning)
	}

	var m *Manifest
	var err error
	cloudID := r.cfg.CloudID
	if cloudID == "" {
		cloudID = ResolveCloudID(r.cfg.DeviceID, r.cfg.SourceID)
	}
	if r.cfg.Timestamp != "" {
		ts, _ := time.Parse(time.RFC3339, r.cfg.Timestamp)
		path := ManifestFilePath(metaDir, cloudID, ts, r.cfg.DeviceID)
		m, err = LoadManifest(path)
		if err != nil {
			return nil, fmt.Errorf("load manifest: %w", err)
		}
	} else {
		m, err = LoadLatestManifest(metaDir, cloudID)
		if err != nil {
			return nil, fmt.Errorf("load latest manifest: %w", err)
		}
	}

	if r.progress != nil {
		r.progress.SetPhase(PhaseUploading)
		r.progress.SetTotal(m.Stats.FileCount, m.Stats.TotalSize)
	}

	for _, file := range m.AllFiles() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		targetPath, err := safeRestorePath(r.cfg.TargetDir, file.Name)
		if err != nil {
			return nil, fmt.Errorf("restore %s: %w", file.Name, err)
		}
		if !r.cfg.Overwrite {
			if _, err := os.Stat(targetPath); err == nil {
				result.SkippedFiles++
				if r.progress != nil {
					r.progress.FileProcessed(file.Name, file.Size, false, false)
				}
				continue
			}
		}

		if len(file.Chunks) > 0 {
			if err := r.restoreChunkedFile(ctx, file, targetPath); err != nil {
				return nil, fmt.Errorf("download %s: %w", file.Name, err)
			}
		} else if file.Size >= int64(DefaultChunkSize) {
			if err := DownloadBlobToFile(ctx, r.store, r.dec, file.ContentHash, targetPath, file.Mode); err != nil {
				return nil, fmt.Errorf("download %s: %w", file.Name, err)
			}
		} else {
			plaintext, err := DownloadBlob(ctx, r.store, r.dec, file.ContentHash)
			if err != nil {
				return nil, fmt.Errorf("download %s: %w", file.Name, err)
			}
			dir := filepath.Dir(targetPath)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("mkdir %s: %w", dir, err)
			}
			tmp := targetPath + ".tmp"
			if err := os.WriteFile(tmp, plaintext, os.FileMode(file.Mode)); err != nil {
				return nil, fmt.Errorf("write %s: %w", file.Name, err)
			}
			if err := os.Rename(tmp, targetPath); err != nil {
				os.Remove(tmp)
				return nil, fmt.Errorf("rename %s: %w", file.Name, err)
			}
		}

		mtime := file.MtimeTime()
		if !mtime.IsZero() {
			os.Chtimes(targetPath, mtime, mtime)
		}
		result.RestoredFiles++
		result.RestoredBytes += file.Size
		if r.progress != nil {
			r.progress.FileProcessed(file.Name, file.Size, true, false)
		}
	}

	if r.progress != nil {
		r.progress.SetPhase(PhaseComplete)
	}

	result.Duration = time.Since(start)
	return result, nil
}

func (r *SimpleRestore) restoreChunkedFile(ctx context.Context, file FileEntry, targetPath string) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp := targetPath + "." + uuid.New().String() + ".tmp"
	tmpF, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	defer func() {
		tmpF.Close()
		os.Remove(tmp)
	}()

	for _, chunk := range file.Chunks {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		plaintext, err := DownloadBlob(ctx, r.store, r.dec, chunk.Hash)
		if err != nil {
			return fmt.Errorf("download chunk %s: %w", chunk.Hash[:12], err)
		}
		if _, err := tmpF.Write(plaintext); err != nil {
			return fmt.Errorf("write chunk: %w", err)
		}
	}

	if err := tmpF.Chmod(os.FileMode(file.Mode)); err != nil {
	}
	if err := tmpF.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	tmpF.Close()

	return os.Rename(tmp, targetPath)
}
