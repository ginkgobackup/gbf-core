// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ginkgobackup/gbf-core/compress"
	"github.com/ginkgobackup/gbf-core/fsutil"
	"github.com/google/uuid"
)

type PipelineConfig struct {
	RepoRoot   string
	SourceID   int64
	CloudID    string
	SourceName string
	SourcePath string
	ScanPath   string
	OverlayDir string
	DeviceID   string
	Key        []byte
	Excludes   []string
	DataDir    string
	ForceFull  bool
	DisableCDC bool
	SessionID  string
}

type PipelineResult struct {
	Manifest        *Manifest
	NewFiles        int
	ChangedFiles    int
	UnchangedFiles  int
	DeletedFiles    int
	UploadedBytes   int64
	TotalSourceSize int64
	Duration        time.Duration
	FailedFiles     int
	FailedPaths     []string
	FailedErrors    []string
	LockedFiles     int
	LockedPaths     []string
}

type SimplePipeline struct {
	cfg         PipelineConfig
	store       SimpleBlobStore
	enc         *Encryptor
	dec         *Decryptor
	progress    *ProgressTracker
	gcm         cipher.AEAD
	gcmOnce     sync.Once
	gcmErr      error
	compressor  *compress.ZstdCompressor
	posExcludes []string
	negExcludes []string
	sizeFilters []fsutil.SizeFilter
}

func NewSimplePipeline(cfg PipelineConfig, store SimpleBlobStore) *SimplePipeline {
	chunkSize := DefaultChunkSize
	return &SimplePipeline{
		cfg:        cfg,
		store:      store,
		enc:        NewEncryptor(cfg.Key, chunkSize),
		dec:        NewDecryptor(cfg.Key, chunkSize),
		compressor: compress.NewZstdCompressor(1),
	}
}

func (p *SimplePipeline) getGCM() (cipher.AEAD, error) {
	p.gcmOnce.Do(func() {
		if len(p.enc.key) == 0 {
			return
		}
		block, err := aes.NewCipher(p.enc.key)
		if err != nil {
			p.gcmErr = err
			return
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			p.gcmErr = err
			return
		}
		p.gcm = gcm
	})
	return p.gcm, p.gcmErr
}

func (p *SimplePipeline) WithProgress(cb ProgressCallback) *SimplePipeline {
	p.progress = NewProgressTracker(p.cfg.SourceID, p.cfg.SourceName, cb)
	return p
}

type scanEntry struct {
	relPath string
	absPath string
	size    int64
	mtime   string
	mode    uint32
}

func (p *SimplePipeline) Run(ctx context.Context) (*PipelineResult, error) {
	start := time.Now()
	result := &PipelineResult{}
	var metaDir string
	if strings.HasPrefix(p.cfg.RepoRoot, "cloud://") || strings.HasPrefix(p.cfg.RepoRoot, "s3://") ||
		strings.HasPrefix(p.cfg.RepoRoot, "webdav://") || strings.HasPrefix(p.cfg.RepoRoot, "sftp://") ||
		strings.HasPrefix(p.cfg.RepoRoot, "peer://") {
		cloudID := p.cfg.CloudID
		if cloudID == "" {
			cloudID = ResolveCloudID(p.cfg.DeviceID, p.cfg.SourceID)
		}
		metaDir = filepath.Join(p.cfg.DataDir, "cloud-manifests", cloudID)
	} else {
		metaDir = MetaDir(p.cfg.RepoRoot)
	}

	slog.Info("GBF pipeline starting", "source_id", p.cfg.SourceID, "source", p.cfg.SourceName, "repo", p.cfg.RepoRoot, "source_path", p.cfg.SourcePath, "scan_path", p.cfg.ScanPath, "session_id", p.cfg.SessionID)

	scanPath := p.cfg.SourcePath
	if p.cfg.ScanPath != "" {
		scanPath = p.cfg.ScanPath
	}
	ignorePatterns := fsutil.LoadIgnoreFile(scanPath)
	merged := fsutil.MergeExcludes(p.cfg.Excludes, ignorePatterns)
	p.posExcludes, p.negExcludes, p.sizeFilters = fsutil.SplitExcludePatterns(merged)

	if p.progress != nil {
		p.progress.SetPhase(PhaseScanning)
	}

	if lbs, ok := p.store.(*LocalBlobStore); ok {
		_ = lbs.WarmExistsCache(ctx)
	}

	var prevFiles map[string]FileEntry
	cloudID := p.cfg.CloudID
	if cloudID == "" {
		cloudID = ResolveCloudID(p.cfg.DeviceID, p.cfg.SourceID)
	}
	if !p.cfg.ForceFull {
		prevManifest, loadErr := LoadLatestManifest(metaDir, cloudID)
		if loadErr != nil && !errors.Is(loadErr, ErrManifestNotFound) {
			return nil, fmt.Errorf("load previous manifest: %w", loadErr)
		}
		if prevManifest != nil {
			prevFiles = prevManifest.BuildFileMap()
			slog.Info("GBF loaded previous manifest", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "prev_files", len(prevFiles), "session_id", p.cfg.SessionID)
		} else {
			slog.Info("GBF no previous manifest, full backup", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "session_id", p.cfg.SessionID)
		}
	} else {
		slog.Info("GBF force full backup, skipping previous manifest", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "session_id", p.cfg.SessionID)
	}

	newManifest := NewManifest(p.cfg.SourceID, cloudID, p.cfg.SourceName, p.cfg.SourcePath, p.cfg.DeviceID)

	if p.progress != nil {
		p.progress.SetPhase(PhaseUploading)
	}

	var files []scanEntry
	var dirEntries []scanEntry
	var walkErrors int
	var walkErrorPaths []string
	walkErr := filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			walkErrors++
			if walkErrors <= 10 {
				walkErrorPaths = append(walkErrorPaths, path)
			}
			if info != nil && info.IsDir() {
				slog.Warn("GBF scan: skipping directory due to error",
					"source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "path", path, "error", err, "session_id", p.cfg.SessionID)
				return filepath.SkipDir
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		relPath, err := filepath.Rel(scanPath, path)
		if err != nil {
			return nil
		}
		relPath = filepath.ToSlash(relPath)
		if relPath == "." {
			return nil
		}
		if info.IsDir() {
			if info.Name() == fsutil.IgnoreFileName {
				return filepath.SkipDir
			}
			if fsutil.ShouldSkipDir(relPath, p.posExcludes, p.negExcludes) {
				return filepath.SkipDir
			}
			dirEntries = append(dirEntries, scanEntry{
				relPath: relPath,
				absPath: path,
				mtime:   info.ModTime().UTC().Format(time.RFC3339),
				mode:    uint32(info.Mode().Perm()),
			})
			return nil
		}
		if fsutil.IsExcluded(relPath, p.posExcludes, p.negExcludes) {
			return nil
		}
		if len(p.sizeFilters) > 0 && fsutil.IsSizeExcluded(info.Size(), p.sizeFilters) {
			return nil
		}
		files = append(files, scanEntry{
			relPath: relPath,
			absPath: path,
			size:    info.Size(),
			mtime:   info.ModTime().UTC().Format(time.RFC3339),
			mode:    uint32(info.Mode().Perm()),
		})
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk: %w", walkErr)
	}
	if walkErrors > 0 {
		slog.Warn("GBF scan encountered errors",
			"source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot,
			"error_count", walkErrors,
			"sample_paths", walkErrorPaths, "session_id", p.cfg.SessionID)
	}

	slog.Info("GBF scan complete", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "files", len(files), "session_id", p.cfg.SessionID)

	if p.cfg.OverlayDir != "" {
		overlayFilesDir := filepath.Join(p.cfg.OverlayDir, "files")
		for i := range files {
			overlayPath := filepath.Join(overlayFilesDir, filepath.FromSlash(files[i].relPath))
			if info, err := os.Stat(overlayPath); err == nil && !info.IsDir() {
				files[i].absPath = overlayPath
				files[i].size = info.Size()
				files[i].mtime = info.ModTime().UTC().Format(time.RFC3339)
			}
		}
	}

	dirHasChildren := make(map[string]bool)
	for _, f := range files {
		parts := strings.Split(f.relPath, "/")
		for j := 1; j < len(parts); j++ {
			dirHasChildren[strings.Join(parts[:j], "/")] = true
		}
	}
	for _, d := range dirEntries {
		if idx := strings.LastIndex(d.relPath, "/"); idx >= 0 {
			dirHasChildren[d.relPath[:idx]] = true
		}
	}

	for _, d := range dirEntries {
		if dirHasChildren[d.relPath] {
			continue
		}
		parts := strings.Split(d.relPath, "/")
		dirName := parts[len(parts)-1]
		if dirName == "" {
			continue
		}
		newManifest.AddEmptyDir(d.relPath)
	}

	var totalSourceSize int64
	for _, fe := range files {
		totalSourceSize += fe.size
	}
	slog.Info("GBF source size", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "total_bytes", totalSourceSize, "session_id", p.cfg.SessionID)

	if p.progress != nil {
		p.progress.SetTotal(len(files), totalSourceSize)
	}

	manifestMu := sync.Mutex{}
	var uploadedBytes int64
	var newFiles, changedFiles, unchangedFiles, skippedFiles, failedFiles, lockedFiles int
	var failedPaths, lockedPaths []string
	var failedErrors []string

	workerCount := runtime.NumCPU()
	if workerCount < 2 {
		workerCount = 2
	}
	if workerCount > 8 {
		workerCount = 8
	}

	ch := make(chan scanEntry, workerCount*4)
	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fe := range ch {
				if ctx.Err() != nil {
					return
				}
				entry, uploaded, isChanged, isNew, fileErr := p.processFile(ctx, fe, prevFiles)
				if fileErr != nil {
					isLocked := isFileLockedError(fileErr)
					status := "error"
					if isLocked {
						status = "locked"
					}
					manifestMu.Lock()
					if isLocked {
						lockedFiles++
						lockedPaths = append(lockedPaths, fe.relPath)
					} else {
						failedFiles++
						failedPaths = append(failedPaths, fe.relPath)
						failedErrors = append(failedErrors, fmt.Sprintf("%s: %v", fe.relPath, fileErr))
					}
					newManifest.AddFile(FileEntry{
						Name:   fe.relPath,
						Size:   fe.size,
						Mtime:  FlexTime(fe.mtime),
						Mode:   fe.mode,
						Status: status,
					})
					manifestMu.Unlock()
					if isLocked {
						slog.Warn("GBF file locked by another process, skipped after retries",
							"source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "error", fileErr, "session_id", p.cfg.SessionID)
					} else {
						slog.Warn("GBF file processing failed", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "error", fileErr, "session_id", p.cfg.SessionID)
					}
				} else if entry != nil {
					manifestMu.Lock()
					newManifest.AddFile(*entry)
					if isNew {
						newFiles++
					} else if isChanged {
						changedFiles++
					} else {
						unchangedFiles++
					}
					uploadedBytes += uploaded
					manifestMu.Unlock()
				} else {
					skippedFiles++
				}
				if p.progress != nil {
					p.progress.FileProcessed(fe.relPath, fe.size, isNew || isChanged, isChanged)
				}
			}
		}()
	}

	for _, fe := range files {
		if ctx.Err() != nil {
			break
		}
		select {
		case ch <- fe:
		case <-ctx.Done():
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(ch)
	wg.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	result.NewFiles = newFiles
	result.ChangedFiles = changedFiles
	result.UnchangedFiles = unchangedFiles
	result.UploadedBytes = uploadedBytes

	if len(prevFiles) > 0 {
		curSet := make(map[string]struct{}, len(files))
		for _, f := range files {
			curSet[f.relPath] = struct{}{}
		}
		deleted := 0
		for path := range prevFiles {
			if _, ok := curSet[path]; !ok {
				deleted++
			}
		}
		result.DeletedFiles = deleted
	}

	newManifest.Stats.NewFiles = newFiles
	newManifest.Stats.ChangedFiles = changedFiles
	newManifest.Stats.UnchangedFiles = unchangedFiles
	newManifest.Stats.NewBytes = uploadedBytes

	if skippedFiles > 0 {
		slog.Warn("GBF skipped files during backup", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "skipped", skippedFiles, "total", len(files), "session_id", p.cfg.SessionID)
	}

	if lockedFiles > 0 {
		samplePaths := lockedPaths
		if len(samplePaths) > 10 {
			samplePaths = samplePaths[:10]
		}
		slog.Warn("GBF files locked by another process, skipped after retries",
			"source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot,
			"locked", lockedFiles, "sample_paths", samplePaths, "session_id", p.cfg.SessionID)
	}

	if err := SaveManifestWithKey(metaDir, newManifest, p.cfg.Key); err != nil {
		return nil, fmt.Errorf("save manifest: %w", err)
	}

	hostname, _ := os.Hostname()
	reg, regErr := LoadSourceRegistry(metaDir, cloudID)
	if regErr != nil {
		reg = &SourceRegistry{
			CloudID:   cloudID,
			Name:      newManifest.SourceName,
			Path:      newManifest.SourcePath,
			DeviceID:  newManifest.DeviceID,
			Hostname:  hostname,
			OS:        runtime.GOOS,
			CreatedAt: newManifest.Timestamp,
		}
	}
	reg.Name = newManifest.SourceName
	reg.Path = newManifest.SourcePath
	reg.DeviceID = newManifest.DeviceID
	reg.Hostname = hostname
	reg.OS = runtime.GOOS
	reg.LastSnapshot = newManifest.Timestamp
	reg.SnapshotCount++

	if saveErr := SaveSourceRegistry(metaDir, reg); saveErr != nil {
		slog.Warn("GBF source registry save failed", "cloud_id", cloudID, "error", saveErr)
	}

	if p.progress != nil {
		p.progress.SetPhase(PhaseComplete)
	}

	result.Manifest = newManifest
	result.Duration = time.Since(start)
	result.FailedFiles = failedFiles
	result.FailedPaths = failedPaths
	result.FailedErrors = failedErrors
	result.LockedFiles = lockedFiles
	result.LockedPaths = lockedPaths
	result.TotalSourceSize = totalSourceSize

	totalFiles := newFiles + changedFiles + unchangedFiles
	var dedupRatio float64
	if totalFiles > 0 {
		dedupRatio = float64(unchangedFiles) / float64(totalFiles)
	}
	var throughputMBps float64
	if result.Duration.Seconds() > 0 {
		throughputMBps = float64(uploadedBytes) / result.Duration.Seconds() / (1024 * 1024)
	}

	slog.Info("GBF pipeline complete",
		"source_id", p.cfg.SourceID,
		"repo", p.cfg.RepoRoot,
		"new", newFiles,
		"changed", changedFiles,
		"unchanged", unchangedFiles,
		"skipped", skippedFiles,
		"failed", failedFiles,
		"locked", lockedFiles,
		"uploaded_bytes", uploadedBytes,
		"total_source_bytes", totalSourceSize,
		"dedup_ratio", fmt.Sprintf("%.1f%%", dedupRatio*100),
		"throughput_mbps", fmt.Sprintf("%.1f", throughputMBps),
		"duration", result.Duration.Round(time.Millisecond),
		"session_id", p.cfg.SessionID,
	)

	return result, nil
}

func resolveFileStatus(hasPrev bool, contentHash, prevHash string) (status string, isNew, isChanged bool) {
	isNew = !hasPrev
	isChanged = hasPrev && contentHash != prevHash
	switch {
	case isChanged:
		status = "changed"
	case hasPrev && contentHash == prevHash:
		status = "unchanged"
	default:
		status = "new"
	}
	return
}

func makeFileEntry(fe scanEntry, contentHash, status string) *FileEntry {
	return &FileEntry{
		Name:        fe.relPath,
		ContentHash: contentHash,
		Size:        fe.size,
		Mtime:       FlexTime(fe.mtime),
		Mode:        fe.mode,
		Status:      status,
	}
}

// isFileLockedError reports whether err indicates the file is being used by
// another process (Windows sharing violation) or is otherwise temporarily
// unavailable (EBUSY/EACCES on Unix). These errors are transient and worth
// retrying after a short backoff.
func isFileLockedError(err error) bool {
	if err == nil {
		return false
	}
	// Walk the error chain via errors.As so that wrapping with
	// fmt.Errorf("...: %w", err) does not hide the underlying *os.PathError.
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		errno, ok := pathErr.Err.(syscall.Errno)
		if !ok {
			return false
		}
		switch errno {
		case 32, 33: // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION
			return true
		}
	}
	// Fallback: match by error message for cross-platform robustness.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "being used by another process") ||
		strings.Contains(msg, "sharing violation") ||
		strings.Contains(msg, "text file is busy") // Linux EBUSY
}

// openFileWithRetry attempts to open a file, retrying up to 3 times with
// exponential backoff (200ms, 500ms, 1s) when the file is locked by another
// process. Returns the opened file or the last error encountered.
func openFileWithRetry(ctx context.Context, path string) (*os.File, error) {
	backoffs := []time.Duration{200 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second}
	var lastErr error
	for attempt := 0; attempt <= len(backoffs); attempt++ {
		f, err := os.Open(path)
		if err == nil {
			return f, nil
		}
		lastErr = err
		if !isFileLockedError(err) {
			return nil, err
		}
		if attempt < len(backoffs) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoffs[attempt]):
			}
		}
	}
	return nil, lastErr
}

func (p *SimplePipeline) processFile(ctx context.Context, fe scanEntry, prevFiles map[string]FileEntry) (_ *FileEntry, _ int64, _ bool, _ bool, ferr error) {
	prevFile, hasPrev := prevFiles[fe.relPath]
	if hasPrev && string(prevFile.Mtime) == fe.mtime && prevFile.Size == fe.size && len(prevFile.ContentHash) >= 2 {
		allBlobsExist := true
		if len(prevFile.Chunks) > 0 {
			for _, c := range prevFile.Chunks {
				exists, eErr := p.store.Exists(ctx, c.Hash)
				if eErr != nil || !exists {
					allBlobsExist = false
					break
				}
			}
		} else {
			blobExists, blobErr := p.store.Exists(ctx, prevFile.ContentHash)
			if blobErr != nil || !blobExists {
				allBlobsExist = false
			}
		}
		if allBlobsExist {
			entry := makeFileEntry(fe, prevFile.ContentHash, "unchanged")
			if len(prevFile.Chunks) > 0 {
				entry.Chunks = prevFile.Chunks
			}
			return entry, 0, false, false, nil
		}
		hashLog := prevFile.ContentHash
		if len(hashLog) > 16 {
			hashLog = hashLog[:16]
		}
		slog.Warn("GBF blob missing in fast path, re-uploading",
			"source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "hash", hashLog, "session_id", p.cfg.SessionID)
	}

	useStream := fe.size >= int64(p.enc.chunkSize)

	if useStream {
		return p.processFileStreaming(ctx, fe, prevFiles)
	}

	contentHash, ciphertext, err := p.hashAndEncryptFile(ctx, fe.absPath, fe.size)
	if err != nil {
		slog.Warn("GBF hash+encrypt failed", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "error", err, "session_id", p.cfg.SessionID)
		return nil, 0, false, false, fmt.Errorf("hash+encrypt %s: %w", fe.relPath, err)
	}

	var prevChunks []ChunkRef
	if hasPrev {
		prevChunks = prevFile.Chunks
	}
	return p.checkAndUploadBlob(ctx, fe, hasPrev, prevFile.ContentHash, contentHash, ciphertext, nil, prevChunks)
}

func (p *SimplePipeline) processFileStreaming(ctx context.Context, fe scanEntry, prevFiles map[string]FileEntry) (_ *FileEntry, _ int64, _ bool, _ bool, ferr error) {
	prevFile, hasPrev := prevFiles[fe.relPath]

	var contentHash string
	var chunkRefs []ChunkRef
	var hashErr error
	if p.cdcEnabled() {
		contentHash, chunkRefs, hashErr = p.hashFileWithCDC(ctx, fe.absPath, fe.size)
	} else {
		contentHash, chunkRefs, hashErr = p.hashFileWithChunks(ctx, fe.absPath, fe.size)
	}
	if hashErr != nil {
		slog.Warn("GBF hash streaming failed", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "error", hashErr, "session_id", p.cfg.SessionID)
		return nil, 0, false, false, fmt.Errorf("hash streaming %s: %w", fe.relPath, hashErr)
	}

	if hasPrev && prevFile.ContentHash == contentHash {
		allExist := true
		if len(prevFile.Chunks) > 0 {
			for _, c := range prevFile.Chunks {
				exists, eErr := p.store.Exists(ctx, c.Hash)
				if eErr != nil || !exists {
					allExist = false
					break
				}
			}
		} else {
			exists, eErr := p.store.Exists(ctx, contentHash)
			if eErr != nil || !exists {
				allExist = false
			}
		}
		if allExist {
			entry := makeFileEntry(fe, contentHash, "unchanged")
			if len(prevFile.Chunks) > 0 {
				entry.Chunks = prevFile.Chunks
			}
			return entry, 0, false, false, nil
		}
	}

	status, isNew, isChanged := resolveFileStatus(hasPrev, contentHash, prevFile.ContentHash)

	var prevChunks []ChunkRef
	if hasPrev {
		prevChunks = prevFile.Chunks
	}

	uploaded, uploadErr := p.uploadChangedChunks(ctx, fe.absPath, fe.size, chunkRefs, prevChunks)
	if uploadErr != nil {
		slog.Warn("GBF chunk upload failed", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "error", uploadErr, "session_id", p.cfg.SessionID)
		return nil, 0, false, false, fmt.Errorf("chunk upload %s: %w", fe.relPath, uploadErr)
	}

	entry := makeFileEntry(fe, contentHash, status)
	entry.Chunks = chunkRefs
	return entry, uploaded, isChanged, isNew, nil
}

type streamUploadInfo struct {
	tmpPath string
	encSize int64
}

func (p *SimplePipeline) checkAndUploadBlob(ctx context.Context, fe scanEntry, hasPrev bool, prevHash string, contentHash string, ciphertext []byte, stream *streamUploadInfo, prevChunks []ChunkRef) (_ *FileEntry, _ int64, _ bool, _ bool, ferr error) {
	if hasPrev && prevHash == contentHash {
		blobExists, blobErr := p.store.Exists(ctx, contentHash)
		if blobErr == nil && blobExists {
			entry := makeFileEntry(fe, contentHash, "unchanged")
			if len(prevChunks) > 0 {
				entry.Chunks = prevChunks
			}
			return entry, 0, false, false, nil
		}
		if blobErr != nil {
			slog.Warn("GBF blob exists check failed for unchanged file, re-uploading",
				"source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "hash", contentHash[:16], "error", blobErr, "session_id", p.cfg.SessionID)
		} else {
			slog.Warn("GBF blob missing for unchanged file, re-uploading",
				"source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "hash", contentHash[:16], "session_id", p.cfg.SessionID)
		}
	}

	status, isNew, isChanged := resolveFileStatus(hasPrev, contentHash, prevHash)

	exists, err := p.store.Exists(ctx, contentHash)
	if err != nil {
		slog.Warn("GBF exists check failed, will upload", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "hash", contentHash[:16], "error", err, "session_id", p.cfg.SessionID)
	} else if exists {
		return makeFileEntry(fe, contentHash, status), 0, isChanged, isNew, nil
	}

	if stream != nil {
		tmpF, openErr := os.Open(stream.tmpPath)
		if openErr != nil {
			slog.Warn("GBF failed to open encrypted temp file", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "error", openErr, "session_id", p.cfg.SessionID)
			return nil, 0, false, false, fmt.Errorf("open temp %s: %w", fe.relPath, openErr)
		}
		defer tmpF.Close()

		if err := p.store.PutStream(ctx, contentHash, tmpF, stream.encSize); err != nil {
			slog.Warn("GBF store.PutStream failed", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "hash", contentHash[:16], "error", err, "session_id", p.cfg.SessionID)
			return nil, 0, false, false, fmt.Errorf("store.PutStream %s: %w", fe.relPath, err)
		}
	} else {
		if err := p.store.Put(ctx, contentHash, ciphertext); err != nil {
			slog.Warn("GBF store.Put failed", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "hash", contentHash[:16], "error", err, "session_id", p.cfg.SessionID)
			return nil, 0, false, false, fmt.Errorf("store.Put %s: %w", fe.relPath, err)
		}
	}

	return makeFileEntry(fe, contentHash, status), fe.size, isChanged, isNew, nil
}

func (p *SimplePipeline) hashAndEncryptFile(ctx context.Context, path string, size int64) (string, []byte, error) {
	if len(p.enc.key) == 0 {
		return p.hashOnlyFile(ctx, path, size)
	}

	f, err := openFileWithRetry(ctx, path)
	if err != nil {
		return "", nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	if size < int64(p.enc.chunkSize) {
		data, err := io.ReadAll(f)
		if err != nil {
			return "", nil, fmt.Errorf("read: %w", err)
		}
		h := sha256.Sum256(data)
		contentHash := hex.EncodeToString(h[:])

		encryptData := data
		if p.compressor != nil && len(data) >= 65536 && !isLikelyIncompressible(path) {
			if compressed, cerr := p.compressor.Compress(data); cerr == nil && len(compressed) < len(data) {
				encryptData = compressed
			}
		}

		gcm, err := p.getGCM()
		if err != nil {
			return "", nil, fmt.Errorf("gcm: %w", err)
		}
		iv := make([]byte, IVSize)
		if _, err := rand.Read(iv); err != nil {
			return "", nil, fmt.Errorf("iv: %w", err)
		}
		ciphertext := gcm.Seal(nil, iv, encryptData, nil)
		result := make([]byte, 0, MagicSize+IVSize+len(ciphertext))
		result = append(result, MagicGB1...)
		result = append(result, iv...)
		result = append(result, ciphertext...)
		return contentHash, result, nil
	}

	return "", nil, fmt.Errorf("large file (%d bytes) must use streaming path", size)
}

func (p *SimplePipeline) hashOnlyFile(ctx context.Context, path string, size int64) (string, []byte, error) {
	f, err := openFileWithRetry(ctx, path)
	if err != nil {
		return "", nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, p.enc.chunkSize)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", nil, fmt.Errorf("hash: %w", err)
	}
	contentHash := hex.EncodeToString(h.Sum(nil))
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", nil, fmt.Errorf("seek: %w", err)
	}
	if size < int64(p.enc.chunkSize) {
		data, err := io.ReadAll(f)
		if err != nil {
			return "", nil, fmt.Errorf("read: %w", err)
		}
		return contentHash, data, nil
	}
	return contentHash, nil, fmt.Errorf("large unencrypted file (%d bytes) must use streaming path", size)
}

func (p *SimplePipeline) hashAndEncryptToTempFile(ctx context.Context, filePath string, size int64) (string, string, int64, error) {
	f, err := openFileWithRetry(ctx, filePath)
	if err != nil {
		return "", "", 0, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", "", 0, fmt.Errorf("seek: %w", err)
	}

	h := sha256.New()
	buf := make([]byte, p.enc.chunkSize)

	gcm, gcmErr := p.getGCM()
	if gcmErr != nil {
		return "", "", 0, fmt.Errorf("gcm: %w", gcmErr)
	}

	tmpPath := filepath.Join(os.TempDir(), "gb-encrypt-"+uuid.New().String()+".tmp")
	tmpF, err := os.Create(tmpPath)
	if err != nil {
		return "", "", 0, fmt.Errorf("create tmp: %w", err)
	}

	if gcm == nil {
		for {
			if ctx.Err() != nil {
				tmpF.Close()
				os.Remove(tmpPath)
				return "", "", 0, ctx.Err()
			}
			n, readErr := io.ReadFull(f, buf)
			if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
				tmpF.Close()
				os.Remove(tmpPath)
				return "", "", 0, fmt.Errorf("read: %w", readErr)
			}
			if n == 0 {
				break
			}
			h.Write(buf[:n])
			if _, err := tmpF.Write(buf[:n]); err != nil {
				tmpF.Close()
				os.Remove(tmpPath)
				return "", "", 0, fmt.Errorf("write: %w", err)
			}
		}
	} else {
		if _, err := tmpF.Write([]byte(MagicGB1)); err != nil {
			tmpF.Close()
			os.Remove(tmpPath)
			return "", "", 0, fmt.Errorf("write magic: %w", err)
		}
		chunkCount := uint32((size + int64(p.enc.chunkSize) - 1) / int64(p.enc.chunkSize))
		countBuf := make([]byte, ChunkCountSize)
		binary.BigEndian.PutUint32(countBuf, chunkCount)
		if _, err := tmpF.Write(countBuf); err != nil {
			tmpF.Close()
			os.Remove(tmpPath)
			return "", "", 0, fmt.Errorf("write count: %w", err)
		}

		ivBuf := make([]byte, IVSize)
		for i := uint32(0); i < chunkCount; i++ {
			if ctx.Err() != nil {
				tmpF.Close()
				os.Remove(tmpPath)
				return "", "", 0, ctx.Err()
			}
			n, readErr := io.ReadFull(f, buf)
			if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
				tmpF.Close()
				os.Remove(tmpPath)
				return "", "", 0, fmt.Errorf("read chunk %d: %w", i, readErr)
			}
			if n == 0 {
				break
			}
			chunk := buf[:n]
			h.Write(chunk)

			if _, err := rand.Read(ivBuf); err != nil {
				tmpF.Close()
				os.Remove(tmpPath)
				return "", "", 0, fmt.Errorf("iv chunk %d: %w", i, err)
			}
			encrypted := gcm.Seal(nil, ivBuf, chunk, nil)
			if _, err := tmpF.Write(ivBuf); err != nil {
				tmpF.Close()
				os.Remove(tmpPath)
				return "", "", 0, fmt.Errorf("write iv %d: %w", i, err)
			}
			if _, err := tmpF.Write(encrypted); err != nil {
				tmpF.Close()
				os.Remove(tmpPath)
				return "", "", 0, fmt.Errorf("write chunk %d: %w", i, err)
			}
		}
	}

	if err := tmpF.Sync(); err != nil {
		tmpF.Close()
		os.Remove(tmpPath)
		return "", "", 0, fmt.Errorf("sync: %w", err)
	}

	fi, fiErr := tmpF.Stat()
	var encSize int64
	if fiErr == nil {
		encSize = fi.Size()
	}
	tmpF.Close()

	contentHash := hex.EncodeToString(h.Sum(nil))
	return contentHash, tmpPath, encSize, nil
}

func (p *SimplePipeline) isExcluded(relPath string) bool {
	return fsutil.IsExcluded(relPath, p.posExcludes, p.negExcludes)
}

var incompressibleExts = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
	".tiff": true, ".tif": true, ".webp": true, ".heic": true, ".heif": true,
	".avif": true, ".ico": true, ".raw": true, ".cr2": true, ".nef": true,
	".orf": true, ".arw": true, ".dng": true, ".rw2": true,
	".psd": true, ".psb": true,

	".mp4": true, ".avi": true, ".mkv": true, ".mov": true, ".wmv": true,
	".flv": true, ".webm": true, ".m4v": true, ".mpg": true, ".mpeg": true,
	".3gp": true, ".3g2": true, ".ts": true, ".mts": true, ".vob": true,
	".m2ts": true, ".rm": true, ".rmvb": true,

	".mp3": true, ".aac": true, ".flac": true, ".ogg": true, ".wma": true,
	".m4a": true, ".wav": true, ".opus": true, ".aiff": true, ".alac": true,
	".amr": true, ".ape": true, ".wv": true, ".tta": true,

	".zip": true, ".zipx": true, ".rar": true, ".rar5": true, ".7z": true,
	".gz": true, ".bz2": true, ".xz": true, ".zst": true, ".lz4": true,
	".tar": true, ".tgz": true, ".lz": true, ".lzma": true,
	".br": true, ".sz": true, ".cab": true, ".arj": true, ".ace": true,
	".lha": true, ".lzh": true, ".arc": true, ".uha": true, ".kgb": true,
	".z": true, ".zz": true, ".sit": true, ".sitx": true, ".brotli": true,

	".iso": true, ".dmg": true, ".img": true, ".bin": true, ".nrg": true,
	".mdf": true, ".mds": true, ".ccd": true, ".sub": true,
	".vmdk": true, ".vdi": true, ".vhd": true, ".vhdx": true,
	".qcow2": true, ".qcow": true, ".qed": true,
	".ova": true, ".ovf": true, ".xva": true,
	".wim": true, ".esd": true, ".squashfs": true, ".cramfs": true,
	".gho": true, ".tib": true, ".tibx": true, ".vbk": true, ".vib": true,
	".adi": true, ".fbk": true, ".sna": true,

	".pdf": true, ".docx": true, ".xlsx": true, ".pptx": true,
	".odt": true, ".ods": true, ".odp": true, ".doc": true, ".xls": true,
	".ppt": true, ".epub": true, ".mobi": true, ".azw3": true,
	".cbr": true, ".cbz": true,

	".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".jar": true, ".war": true, ".apk": true, ".ipa": true,
	".deb": true, ".rpm": true, ".pkg": true, ".msi": true,
	".app": true, ".appx": true, ".msix": true, ".nupkg": true,
}

var incompressibleNames = map[string]bool{
	"pagefile.sys": true,
	"hiberfil.sys": true,
	"swapfile.sys": true,
}

func isLikelyIncompressible(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if incompressibleExts[ext] {
		return true
	}
	name := strings.ToLower(filepath.Base(path))
	return incompressibleNames[name]
}

func (p *SimplePipeline) hashFileWithChunks(ctx context.Context, filePath string, size int64) (string, []ChunkRef, error) {
	f, err := openFileWithRetry(ctx, filePath)
	if err != nil {
		return "", nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	buf := make([]byte, p.enc.chunkSize)
	var chunks []ChunkRef
	remaining := size

	for remaining > 0 {
		if ctx.Err() != nil {
			return "", nil, ctx.Err()
		}
		readSize := int64(len(buf))
		if remaining < readSize {
			readSize = remaining
		}
		n, readErr := io.ReadFull(f, buf[:readSize])
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			return "", nil, fmt.Errorf("read: %w", readErr)
		}
		if n == 0 {
			break
		}
		chunkData := buf[:n]
		h.Write(chunkData)
		ch := sha256.Sum256(chunkData)
		chunks = append(chunks, ChunkRef{
			Hash: hex.EncodeToString(ch[:]),
			Size: int64(n),
		})
		remaining -= int64(n)
	}

	contentHash := hex.EncodeToString(h.Sum(nil))
	return contentHash, chunks, nil
}

func (p *SimplePipeline) uploadChangedChunks(ctx context.Context, filePath string, size int64, chunks []ChunkRef, prevChunks []ChunkRef) (int64, error) {
	prevChunkMap := make(map[string]bool, len(prevChunks))
	for _, c := range prevChunks {
		prevChunkMap[c.Hash] = true
	}

	for _, c := range prevChunks {
		exists, _ := p.store.Exists(ctx, c.Hash)
		if !exists {
			prevChunkMap[c.Hash] = false
		}
	}

	skipped := 0
	needRead := false
	for _, c := range chunks {
		if !prevChunkMap[c.Hash] {
			needRead = true
		}
	}
	if !needRead {
		return 0, nil
	}

	f, err := openFileWithRetry(ctx, filePath)
	if err != nil {
		return 0, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	gcm, gcmErr := p.getGCM()
	if gcmErr != nil {
		return 0, fmt.Errorf("gcm: %w", gcmErr)
	}

	bufSize := p.enc.chunkSize
	if p.cdcEnabled() && bufSize < cdcMaxSize {
		bufSize = cdcMaxSize
	}
	buf := make([]byte, bufSize)
	tryCompress := p.compressor != nil && !isLikelyIncompressible(filePath)
	var uploaded int64
	chunkIdx := 0

	for chunkIdx < len(chunks) {
		if ctx.Err() != nil {
			return uploaded, ctx.Err()
		}
		readSize := chunks[chunkIdx].Size
		if readSize > int64(len(buf)) {
			readSize = int64(len(buf))
		}
		n, readErr := io.ReadFull(f, buf[:readSize])
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			return uploaded, fmt.Errorf("read chunk %d: %w", chunkIdx, readErr)
		}
		if n == 0 {
			break
		}

		c := chunks[chunkIdx]
		if prevChunkMap[c.Hash] {
			skipped++
			chunkIdx++
			continue
		}

		chunkData := buf[:n]
		toStore := chunkData
		if tryCompress && len(chunkData) >= 65536 {
			if compressed, cerr := p.compressor.Compress(chunkData); cerr == nil && len(compressed) < len(chunkData) {
				toStore = compressed
			}
		}

		var blobData []byte
		if gcm == nil {
			blobData = toStore
		} else {
			iv := make([]byte, IVSize)
			if _, err := rand.Read(iv); err != nil {
				return uploaded, fmt.Errorf("iv chunk %d: %w", chunkIdx, err)
			}
			encrypted := gcm.Seal(nil, iv, toStore, nil)
			blobData = make([]byte, 0, MagicSize+IVSize+len(encrypted))
			blobData = append(blobData, MagicGB1...)
			blobData = append(blobData, iv...)
			blobData = append(blobData, encrypted...)
		}

		if err := p.store.Put(ctx, c.Hash, blobData); err != nil {
			return uploaded, fmt.Errorf("put chunk %d: %w", chunkIdx, err)
		}
		uploaded += int64(n)
		chunkIdx++
	}

	return uploaded, nil
}
