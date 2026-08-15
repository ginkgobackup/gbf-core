// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
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
	"github.com/restic/chunker"
)

// inMemoryChunkThreshold is the maximum file size for which the hash pass
// retains each chunk's plaintext in memory so the upload pass can encrypt
// and store the exact bytes that were hashed (no second read, no second
// hash). Larger files keep the two-pass streaming behavior. Memory upper
// bound: workerCount × threshold (default 8 workers × 32 MiB = 256 MiB
// worst case, and only when all workers simultaneously process large
// files); the retained slices are released as soon as the upload finishes.
const inMemoryChunkThreshold = 32 << 20

// Two size classes cover every buffer the streaming paths allocate:
// DefaultChunkSize (4 MiB fixed-chunk buffers) and cdcMaxSize (16 MiB CDC
// buffers). Buffers whose capacity matches neither class (custom chunk
// sizes) are dropped for GC instead of pooled. Pool entries are *[]byte so
// the slice header itself is not copied on Put/Get.
var (
	smallChunkBufPool = sync.Pool{New: func() any { b := make([]byte, DefaultChunkSize); return &b }}
	largeChunkBufPool = sync.Pool{New: func() any { b := make([]byte, cdcMaxSize); return &b }}
)

// getChunkBuf returns a buffer (as a pointer, len == 0) with capacity >=
// minCap. Callers slice it to the size they need and must not retain any
// slice of it past putChunkBuf.
func getChunkBuf(minCap int) *[]byte {
	switch {
	case minCap <= DefaultChunkSize:
		return smallChunkBufPool.Get().(*[]byte)
	case minCap <= cdcMaxSize:
		return largeChunkBufPool.Get().(*[]byte)
	default:
		b := make([]byte, minCap)
		return &b
	}
}

// putChunkBuf returns a buffer to its pool after truncating the slice so
// the pooled entry holds no logical data. Callers must have released every
// reference to the buffer's contents (compression/AEAD helpers all copy).
func putChunkBuf(b *[]byte) {
	if b == nil {
		return
	}
	switch cap(*b) {
	case DefaultChunkSize:
		*b = (*b)[:0]
		smallChunkBufPool.Put(b)
	case cdcMaxSize:
		*b = (*b)[:0]
		largeChunkBufPool.Put(b)
	}
}

type PipelineConfig struct {
	RepoRoot   string
	SourceID   int64
	CloudID    string
	SourceName string
	SourcePath string
	ScanPath   string
	DeviceID   string
	Key        []byte
	Excludes   []string
	ForceFull  bool
	DisableCDC bool
	SessionID  string
	// OverlayDir, when set, points to a directory whose contents are layered
	// on top of SourcePath during backup (e.g. for virtualized Notion mounts).
	OverlayDir string
	// DataDir is the application-wide data directory used for ancillary
	// caches (e.g. cloud-manifest cache).
	DataDir string
	// WorkerCount overrides the default worker pool size. Values <= 0 fall
	// back to a sensible default derived from runtime.NumCPU() (capped to
	// avoid thrashing on high-core machines).
	WorkerCount int
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
	// cdcPolynomial is the per-instance CDC polynomial, loaded from the repo
	// config in NewSimplePipeline (and re-loaded in Run if the constructor
	// could not read it). Storing it on the struct — returned directly by
	// LoadCDCPolynomial without a detour through the package-level global —
	// lets multiple pipelines targeting different repos coexist in the same
	// process without racing through the global's write/read window.
	cdcPolynomial chunker.Pol
}

func NewSimplePipeline(cfg PipelineConfig, store SimpleBlobStore) *SimplePipeline {
	chunkSize := DefaultChunkSize
	p := &SimplePipeline{
		cfg:        cfg,
		store:      store,
		enc:        NewEncryptor(cfg.Key, chunkSize),
		dec:        NewDecryptor(cfg.Key, chunkSize),
		compressor: compress.NewZstdCompressor(1),
	}
	// Bind the CDC polynomial to this pipeline instance. LoadCDCPolynomial
	// returns the repo's polynomial directly without touching the package
	// global, so concurrent pipelines with different repos never read each
	// other's polynomial. Repos without a readable config (e.g. unit tests
	// with an empty RepoRoot) leave cdcPolynomial zero; hashFileWithCDC
	// then falls back to the global for backward compatibility.
	if pol, err := LoadCDCPolynomial(cfg.RepoRoot); err == nil {
		p.cdcPolynomial = pol
	}
	return p
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
	metaDir := MetaDir(p.cfg.RepoRoot)

	if err := p.ensureCDCPolynomial(); err != nil {
		return nil, err
	}

	slog.Info("GBF pipeline starting", "source_id", p.cfg.SourceID, "source", p.cfg.SourceName, "repo", p.cfg.RepoRoot, "source_path", p.cfg.SourcePath, "scan_path", p.cfg.ScanPath, "session_id", p.cfg.SessionID)

	scanPath := p.cfg.SourcePath
	if p.cfg.ScanPath != "" {
		scanPath = p.cfg.ScanPath
	}
	p.loadExcludePatterns(scanPath)

	if p.progress != nil {
		p.progress.SetPhase(PhaseScanning)
	}
	p.warmStoreCache(ctx)

	cloudID := ResolveCloudID(p.cfg.DeviceID, p.cfg.SourceID)
	prevFiles, err := p.loadPreviousFiles(metaDir, cloudID)
	if err != nil {
		return nil, err
	}

	newManifest := NewManifest(p.cfg.SourceID, cloudID, p.cfg.SourceName, p.cfg.SourcePath, p.cfg.DeviceID)

	if p.progress != nil {
		p.progress.SetPhase(PhaseUploading)
	}

	files, dirEntries, err := p.scanSourceTree(ctx, scanPath)
	if err != nil {
		return nil, err
	}

	addEmptyDirs(newManifest, files, dirEntries)

	var totalSourceSize int64
	for _, fe := range files {
		totalSourceSize += fe.size
	}
	slog.Info("GBF source size", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "total_bytes", totalSourceSize, "session_id", p.cfg.SessionID)

	if p.progress != nil {
		p.progress.SetTotal(len(files), totalSourceSize)
	}

	stats := p.runUploadWorkers(ctx, files, prevFiles, newManifest)

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	result.NewFiles = stats.newFiles
	result.ChangedFiles = stats.changedFiles
	result.UnchangedFiles = stats.unchangedFiles
	result.UploadedBytes = stats.uploadedBytes
	result.DeletedFiles = countDeletedFiles(prevFiles, files)

	newManifest.Stats.NewFiles = stats.newFiles
	newManifest.Stats.ChangedFiles = stats.changedFiles
	newManifest.Stats.UnchangedFiles = stats.unchangedFiles
	newManifest.Stats.NewBytes = stats.uploadedBytes

	p.logUploadAnomalies(len(files), stats)

	// SaveManifestWithKey sets newManifest.FilePath to the actual path
	// written (same-second conflicts get a suffixed name), which downstream
	// consumers (snapshot target records, cloud upload) rely on.
	if _, err := SaveManifestWithKey(metaDir, newManifest, p.cfg.Key); err != nil {
		return nil, fmt.Errorf("save manifest: %w", err)
	}

	p.updateSourceRegistry(metaDir, cloudID, newManifest)

	if p.progress != nil {
		p.progress.SetPhase(PhaseComplete)
	}

	result.Manifest = newManifest
	result.Duration = time.Since(start)
	result.FailedFiles = stats.failedFiles
	result.FailedPaths = stats.failedPaths
	result.FailedErrors = stats.failedErrors
	result.LockedFiles = stats.lockedFiles
	result.LockedPaths = stats.lockedPaths
	result.TotalSourceSize = totalSourceSize

	p.logRunSummary(result, stats, totalSourceSize)

	return result, nil
}

// ensureCDCPolynomial loads the per-repo CDC polynomial so chunk boundaries
// match what was persisted at init time. Without this, incremental backups
// would compute different chunk hashes against a different polynomial and
// re-upload everything. The polynomial is bound to this pipeline instance
// (set before any worker goroutine starts) — never via the package global,
// which races when pipelines for different repos run concurrently.
func (p *SimplePipeline) ensureCDCPolynomial() error {
	pol, err := LoadCDCPolynomial(p.cfg.RepoRoot)
	if err != nil {
		return fmt.Errorf("load cdc polynomial: %w", err)
	}
	if p.cdcPolynomial == 0 {
		p.cdcPolynomial = pol
	}
	return nil
}

func (p *SimplePipeline) loadExcludePatterns(scanPath string) {
	ignorePatterns := fsutil.LoadIgnoreFile(scanPath)
	merged := fsutil.MergeExcludes(p.cfg.Excludes, ignorePatterns)
	p.posExcludes, p.negExcludes, p.sizeFilters = fsutil.SplitExcludePatterns(merged)
}

func (p *SimplePipeline) warmStoreCache(ctx context.Context) {
	if lbs, ok := p.store.(*LocalBlobStore); ok {
		_ = lbs.WarmExistsCache(ctx)
	}
}

// loadPreviousFiles returns the file map of the latest manifest for this
// source, or nil when a full backup is requested or no previous manifest
// exists.
func (p *SimplePipeline) loadPreviousFiles(metaDir, cloudID string) (map[string]FileEntry, error) {
	var prevFiles map[string]FileEntry
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
	return prevFiles, nil
}

// scanSourceTree walks scanPath and partitions the result into file and
// directory entries. Unreadable paths are counted and logged while the walk
// continues; only walk failures or a cancelled context abort the scan.
func (p *SimplePipeline) scanSourceTree(ctx context.Context, scanPath string) (files []scanEntry, dirEntries []scanEntry, err error) {
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
		return nil, nil, fmt.Errorf("walk: %w", walkErr)
	}
	if walkErrors > 0 {
		slog.Warn("GBF scan encountered errors",
			"source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot,
			"error_count", walkErrors,
			"sample_paths", walkErrorPaths, "session_id", p.cfg.SessionID)
	}

	slog.Info("GBF scan complete", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "files", len(files), "session_id", p.cfg.SessionID)

	return files, dirEntries, nil
}

// addEmptyDirs records directories that contain neither files nor other
// directories in the manifest so restores can recreate them.
func addEmptyDirs(m *Manifest, files, dirEntries []scanEntry) {
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
		m.AddEmptyDir(d.relPath)
	}
}

// uploadStats aggregates the per-file outcomes of the upload worker pool.
type uploadStats struct {
	uploadedBytes  int64
	newFiles       int
	changedFiles   int
	unchangedFiles int
	skippedFiles   int
	failedFiles    int
	lockedFiles    int
	failedPaths    []string
	lockedPaths    []string
	failedErrors   []string
}

// runUploadWorkers feeds the scanned files through a worker pool and returns
// the aggregated outcomes. The manifest mutex plus WaitGroup serialize the
// counter updates; the returned stats are read only after all workers exit.
func (p *SimplePipeline) runUploadWorkers(ctx context.Context, files []scanEntry, prevFiles map[string]FileEntry, newManifest *Manifest) uploadStats {
	manifestMu := sync.Mutex{}
	var uploadedBytes int64
	var newFiles, changedFiles, unchangedFiles, skippedFiles, failedFiles, lockedFiles int
	var failedPaths, lockedPaths []string
	var failedErrors []string

	workerCount := p.cfg.WorkerCount
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
		if workerCount < 2 {
			workerCount = 2
		}
		// Cap the auto-derived count to avoid overwhelming the blob store
		// with concurrent puts on high-core machines. Callers that genuinely
		// need more parallelism can set PipelineConfig.WorkerCount.
		const defaultWorkerCap = 8
		if workerCount > defaultWorkerCap {
			workerCount = defaultWorkerCap
		}
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
			// The select returned because ctx was cancelled; the
			// ctx.Err() check at the top of the next iteration (or the
			// one right after the select) terminates the loop. A bare
			// `break` here would only exit the select, not the for —
			// staticcheck flags it as ineffective, so we rely on the
			// explicit ctx.Err() check below instead.
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(ch)
	wg.Wait()

	return uploadStats{
		uploadedBytes:  uploadedBytes,
		newFiles:       newFiles,
		changedFiles:   changedFiles,
		unchangedFiles: unchangedFiles,
		skippedFiles:   skippedFiles,
		failedFiles:    failedFiles,
		lockedFiles:    lockedFiles,
		failedPaths:    failedPaths,
		lockedPaths:    lockedPaths,
		failedErrors:   failedErrors,
	}
}

// countDeletedFiles reports how many paths present in the previous manifest
// no longer exist in the current scan.
func countDeletedFiles(prevFiles map[string]FileEntry, files []scanEntry) int {
	if len(prevFiles) == 0 {
		return 0
	}
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
	return deleted
}

func (p *SimplePipeline) logUploadAnomalies(totalFiles int, stats uploadStats) {
	if stats.skippedFiles > 0 {
		slog.Warn("GBF skipped files during backup", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "skipped", stats.skippedFiles, "total", totalFiles, "session_id", p.cfg.SessionID)
	}

	if stats.lockedFiles > 0 {
		samplePaths := stats.lockedPaths
		if len(samplePaths) > 10 {
			samplePaths = samplePaths[:10]
		}
		slog.Warn("GBF files locked by another process, skipped after retries",
			"source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot,
			"locked", stats.lockedFiles, "sample_paths", samplePaths, "session_id", p.cfg.SessionID)
	}
}

// updateSourceRegistry refreshes the source registry after a successful
// manifest save. A failed registry save only warns: the backup itself is
// already durable at that point.
func (p *SimplePipeline) updateSourceRegistry(metaDir, cloudID string, m *Manifest) {
	reg, regErr := LoadSourceRegistry(metaDir, cloudID)
	if regErr != nil {
		reg = &SourceRegistry{
			CloudID:   cloudID,
			Name:      m.SourceName,
			Path:      m.SourcePath,
			DeviceID:  m.DeviceID,
			CreatedAt: m.Timestamp,
		}
	}
	reg.Name = m.SourceName
	reg.Path = m.SourcePath
	reg.DeviceID = m.DeviceID
	reg.LastSnapshot = m.Timestamp
	reg.SnapshotCount++

	if saveErr := SaveSourceRegistry(metaDir, reg); saveErr != nil {
		slog.Warn("GBF source registry save failed", "cloud_id", cloudID, "error", saveErr)
	}
}

func (p *SimplePipeline) logRunSummary(result *PipelineResult, stats uploadStats, totalSourceSize int64) {
	totalFiles := stats.newFiles + stats.changedFiles + stats.unchangedFiles
	var dedupRatio float64
	if totalFiles > 0 {
		dedupRatio = float64(stats.unchangedFiles) / float64(totalFiles)
	}
	var throughputMBps float64
	if result.Duration.Seconds() > 0 {
		throughputMBps = float64(stats.uploadedBytes) / result.Duration.Seconds() / (1024 * 1024)
	}

	slog.Info("GBF pipeline complete",
		"source_id", p.cfg.SourceID,
		"repo", p.cfg.RepoRoot,
		"new", stats.newFiles,
		"changed", stats.changedFiles,
		"unchanged", stats.unchangedFiles,
		"skipped", stats.skippedFiles,
		"failed", stats.failedFiles,
		"locked", stats.lockedFiles,
		"uploaded_bytes", stats.uploadedBytes,
		"total_source_bytes", totalSourceSize,
		"dedup_ratio", fmt.Sprintf("%.1f%%", dedupRatio*100),
		"throughput_mbps", fmt.Sprintf("%.1f", throughputMBps),
		"duration", result.Duration.Round(time.Millisecond),
		"session_id", p.cfg.SessionID,
	)
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

// blobsExist resolves the presence of the given (deduplicated) hashes in
// the store. Stores implementing BatchExistencer answer the whole batch
// with one call; otherwise — and whenever the batch call fails — the code
// falls back to per-hash Exists with the historical error semantics (an
// error counts as "missing" so the caller re-uploads instead of failing
// the backup).
func (p *SimplePipeline) blobsExist(ctx context.Context, hashes []string) map[string]bool {
	result := make(map[string]bool, len(hashes))
	if len(hashes) == 0 {
		return result
	}
	uniq := make([]string, 0, len(hashes))
	for _, h := range hashes {
		// Key-presence check, not value: absent hashes map to false, and a
		// value check would re-enqueue every duplicate of a missing hash.
		if _, ok := result[h]; ok {
			continue
		}
		result[h] = false
		uniq = append(uniq, h)
	}
	if be, ok := p.store.(BatchExistencer); ok {
		if batch, bErr := be.ExistsBatch(ctx, uniq); bErr == nil {
			for _, h := range uniq {
				result[h] = batch[h]
			}
			return result
		}
	}
	for _, h := range uniq {
		exists, eErr := p.store.Exists(ctx, h)
		if eErr == nil && exists {
			result[h] = true
		}
	}
	return result
}

// tryUnchangedEntry returns an "unchanged" FileEntry for fe if every blob
// referenced by prevFile is still present in the store. Any Exists() error
// is treated as "blob missing" so we fall back to re-uploading rather than
// failing the whole backup — the same defensive behavior the inline loops
// used before this helper extracted them.
//
// Shared by the mtime/size fast path in processFile and the content-hash
// fast path in processFileStreaming so the existence-check loop can't drift
// between the two callers.
func (p *SimplePipeline) tryUnchangedEntry(ctx context.Context, fe scanEntry, prevFile FileEntry, contentHash string) (*FileEntry, bool) {
	var hashes []string
	if len(prevFile.Chunks) > 0 {
		hashes = make([]string, 0, len(prevFile.Chunks))
		for _, c := range prevFile.Chunks {
			hashes = append(hashes, c.Hash)
		}
	} else {
		hashes = []string{contentHash}
	}
	presence := p.blobsExist(ctx, hashes)
	for _, h := range hashes {
		if !presence[h] {
			return nil, false
		}
	}
	entry := makeFileEntry(fe, contentHash, "unchanged")
	if len(prevFile.Chunks) > 0 {
		entry.Chunks = prevFile.Chunks
	}
	return entry, true
}

func (p *SimplePipeline) processFile(ctx context.Context, fe scanEntry, prevFiles map[string]FileEntry) (_ *FileEntry, _ int64, _ bool, _ bool, ferr error) {
	prevFile, hasPrev := prevFiles[fe.relPath]
	// fastPathBlobMissing records that the mtime/size fast path already ran
	// tryUnchangedEntry and confirmed a referenced blob is absent (the only
	// way that check can fail once mtime+size matched). The streaming path
	// then skips its own tryUnchangedEntry — it would probe the exact same
	// hash set and fail again — halving the existence checks for this file.
	fastPathBlobMissing := false
	if hasPrev && string(prevFile.Mtime) == fe.mtime && prevFile.Size == fe.size && len(prevFile.ContentHash) >= 2 {
		if entry, ok := p.tryUnchangedEntry(ctx, fe, prevFile, prevFile.ContentHash); ok {
			return entry, 0, false, false, nil
		}
		fastPathBlobMissing = true
		hashLog := prevFile.ContentHash
		if len(hashLog) > 16 {
			hashLog = hashLog[:16]
		}
		slog.Warn("GBF blob missing in fast path, re-uploading",
			"source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "hash", hashLog, "session_id", p.cfg.SessionID)
	}

	useStream := fe.size >= int64(p.enc.chunkSize)

	if useStream {
		return p.processFileStreaming(ctx, fe, prevFiles, fastPathBlobMissing)
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
	return p.checkAndUploadBlob(ctx, fe, hasPrev, prevFile.ContentHash, contentHash, ciphertext, prevChunks)
}

func (p *SimplePipeline) processFileStreaming(ctx context.Context, fe scanEntry, prevFiles map[string]FileEntry, skipUnchangedEntry bool) (_ *FileEntry, _ int64, _ bool, _ bool, ferr error) {
	prevFile, hasPrev := prevFiles[fe.relPath]

	// Small/medium files: retain each chunk's plaintext from the hash pass
	// so uploadChangedChunks encrypts exactly the bytes that were hashed
	// (single read, single hash). Larger files fall back to the two-pass
	// streaming behavior.
	retain := fe.size <= inMemoryChunkThreshold

	var contentHash string
	var chunkRefs []ChunkRef
	var chunkData [][]byte
	var hashErr error
	if p.cdcEnabled() {
		contentHash, chunkRefs, chunkData, hashErr = p.hashFileWithCDC(ctx, fe.absPath, fe.size, retain)
	} else {
		contentHash, chunkRefs, chunkData, hashErr = p.hashFileWithChunks(ctx, fe.absPath, fe.size, retain)
	}
	if hashErr != nil {
		slog.Warn("GBF hash streaming failed", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "error", hashErr, "session_id", p.cfg.SessionID)
		return nil, 0, false, false, fmt.Errorf("hash streaming %s: %w", fe.relPath, hashErr)
	}

	if hasPrev && prevFile.ContentHash == contentHash && !skipUnchangedEntry {
		if entry, ok := p.tryUnchangedEntry(ctx, fe, prevFile, contentHash); ok {
			return entry, 0, false, false, nil
		}
	}

	status, isNew, isChanged := resolveFileStatus(hasPrev, contentHash, prevFile.ContentHash)

	var prevChunks []ChunkRef
	if hasPrev {
		prevChunks = prevFile.Chunks
	}

	uploaded, uploadErr := p.uploadChangedChunks(ctx, fe.absPath, fe.size, chunkRefs, chunkData, prevChunks)
	chunkData = nil // release retained chunk bytes promptly after the upload
	if uploadErr != nil {
		slog.Warn("GBF chunk upload failed", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "error", uploadErr, "session_id", p.cfg.SessionID)
		return nil, 0, false, false, fmt.Errorf("chunk upload %s: %w", fe.relPath, uploadErr)
	}

	entry := makeFileEntry(fe, contentHash, status)
	entry.Chunks = chunkRefs
	return entry, uploaded, isChanged, isNew, nil
}

func (p *SimplePipeline) checkAndUploadBlob(ctx context.Context, fe scanEntry, hasPrev bool, prevHash string, contentHash string, ciphertext []byte, prevChunks []ChunkRef) (_ *FileEntry, _ int64, _ bool, _ bool, ferr error) {
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

	if err := p.store.Put(ctx, contentHash, ciphertext); err != nil {
		slog.Warn("GBF store.Put failed", "source_id", p.cfg.SourceID, "repo", p.cfg.RepoRoot, "file", fe.relPath, "hash", contentHash[:16], "error", err, "session_id", p.cfg.SessionID)
		return nil, 0, false, false, fmt.Errorf("store.Put %s: %w", fe.relPath, err)
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
	defer func() { _ = f.Close() }()

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
		iv, err := newSmallBlobIV()
		if err != nil {
			return "", nil, err
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
	defer func() { _ = f.Close() }()
	h := sha256.New()
	bp := getChunkBuf(p.enc.chunkSize)
	buf := (*bp)[:p.enc.chunkSize]
	defer putChunkBuf(bp)
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

// hashFileWithChunks hashes a file in fixed-size chunks. When retain is
// true (file at or below inMemoryChunkThreshold) the plaintext of every
// chunk is kept in memory and returned alongside the refs so the upload
// pass can store exactly the bytes that were hashed. With retain=false a
// pooled scratch buffer is used and no chunk data is returned.
func (p *SimplePipeline) hashFileWithChunks(ctx context.Context, filePath string, size int64, retain bool) (string, []ChunkRef, [][]byte, error) {
	f, err := openFileWithRetry(ctx, filePath)
	if err != nil {
		return "", nil, nil, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	var retained [][]byte
	var bp *[]byte
	var buf []byte
	if !retain {
		bp = getChunkBuf(p.enc.chunkSize)
		buf = (*bp)[:p.enc.chunkSize]
		defer putChunkBuf(bp)
	}
	var chunks []ChunkRef
	remaining := size

	for remaining > 0 {
		if ctx.Err() != nil {
			return "", nil, nil, ctx.Err()
		}
		readSize := remaining
		if retain {
			// Read straight into a per-chunk allocation: the bytes are
			// handed to the upload pass, so no shared buffer may be used.
			chunkBuf := make([]byte, min(readSize, int64(p.enc.chunkSize)))
			n, readErr := io.ReadFull(f, chunkBuf)
			if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
				return "", nil, nil, fmt.Errorf("read: %w", readErr)
			}
			if n == 0 {
				break
			}
			chunkData := chunkBuf[:n]
			h.Write(chunkData)
			ch := sha256.Sum256(chunkData)
			chunks = append(chunks, ChunkRef{
				Hash: hex.EncodeToString(ch[:]),
				Size: int64(n),
			})
			retained = append(retained, chunkData)
			remaining -= int64(n)
			continue
		}
		if readSize > int64(len(buf)) {
			readSize = int64(len(buf))
		}
		n, readErr := io.ReadFull(f, buf[:readSize])
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			return "", nil, nil, fmt.Errorf("read: %w", readErr)
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
	if !retain {
		return contentHash, chunks, nil, nil
	}
	return contentHash, chunks, retained, nil
}

// uploadChangedChunks stores every chunk of the freshly hashed file that is
// not already present. chunkData carries the plaintext retained by the hash
// pass (files at or below inMemoryChunkThreshold): those bytes are exactly
// what was hashed, so they are uploaded directly — no second file read and
// no re-hash. When chunkData is empty the file is re-read chunk by chunk and
// each chunk is re-verified against its hash (tamper detection between the
// two passes is preserved).
func (p *SimplePipeline) uploadChangedChunks(ctx context.Context, filePath string, size int64, chunks []ChunkRef, chunkData [][]byte, prevChunks []ChunkRef) (int64, error) {
	prevChunkMap := make(map[string]bool, len(prevChunks))
	if len(prevChunks) > 0 {
		prevHashes := make([]string, 0, len(prevChunks))
		for _, c := range prevChunks {
			prevChunkMap[c.Hash] = false
			prevHashes = append(prevHashes, c.Hash)
		}
		presence := p.blobsExist(ctx, prevHashes)
		for h := range prevChunkMap {
			prevChunkMap[h] = presence[h]
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

	// In-memory fast path: the hash pass handed us the exact plaintext of
	// every chunk, so the store receives the very bytes that were hashed.
	useMemChunks := len(chunks) > 0 && len(chunkData) == len(chunks)

	var f *os.File
	var bp *[]byte
	var buf []byte
	if !useMemChunks {
		var err error
		f, err = openFileWithRetry(ctx, filePath)
		if err != nil {
			return 0, fmt.Errorf("open: %w", err)
		}
		defer func() { _ = f.Close() }()

		bufSize := p.enc.chunkSize
		if p.cdcEnabled() && bufSize < cdcMaxSize {
			bufSize = cdcMaxSize
		}
		bp = getChunkBuf(bufSize)
		buf = (*bp)[:bufSize]
		defer putChunkBuf(bp)
	}

	gcm, gcmErr := p.getGCM()
	if gcmErr != nil {
		return 0, fmt.Errorf("gcm: %w", gcmErr)
	}

	tryCompress := p.compressor != nil && !isLikelyIncompressible(filePath)
	var uploaded int64
	chunkIdx := 0

	for chunkIdx < len(chunks) {
		if ctx.Err() != nil {
			return uploaded, ctx.Err()
		}

		c := chunks[chunkIdx]
		var chunkBytes []byte
		if useMemChunks {
			// No file is being read, so an already-present chunk can be
			// skipped without touching anything.
			if prevChunkMap[c.Hash] {
				skipped++
				chunkIdx++
				continue
			}
			// These bytes were hashed by the same pass that produced
			// c.Hash — the consistency check is inherent, no re-hash.
			chunkBytes = chunkData[chunkIdx]
		} else {
			// The file must be read sequentially even for chunks that are
			// skipped, otherwise the offset desyncs from the chunk list.
			readSize := c.Size
			if readSize > int64(len(buf)) {
				readSize = int64(len(buf))
			}
			n, readErr := io.ReadFull(f, buf[:readSize])
			if readErr != nil && readErr != io.EOF {
				if readErr == io.ErrUnexpectedEOF {
					// File was truncated/modified since the manifest was built:
					// we requested chunks[chunkIdx].Size bytes but got fewer.
					// Uploading the partial buffer would store data under a hash
					// that does not match the bytes, corrupting the blob store.
					// Surface as an error so the caller can re-process the file.
					return uploaded, fmt.Errorf("read chunk %d: file truncated (expected %d bytes, got %d): %w", chunkIdx, readSize, n, readErr)
				}
				return uploaded, fmt.Errorf("read chunk %d: %w", chunkIdx, readErr)
			}
			if n == 0 {
				break
			}
			if prevChunkMap[c.Hash] {
				skipped++
				chunkIdx++
				continue
			}
			chunkBytes = buf[:n]
			// Verify the chunk content still matches the hash computed earlier
			// (during hashFileWithCDC/hashFileWithChunks). If the file was
			// modified in place between the hash pass and this read, storing
			// the new content under the old hash would corrupt the content-
			// addressed blob store. Treat as a fatal error so the caller can
			// re-process the file.
			actualHash := fmt.Sprintf("%x", sha256.Sum256(chunkBytes))
			if actualHash != c.Hash {
				return uploaded, fmt.Errorf("chunk %d content changed since hash (expected %s, got %s): file modified during backup", chunkIdx, c.Hash[:12], actualHash[:12])
			}
		}

		toStore := chunkBytes
		if tryCompress && len(chunkBytes) >= 65536 {
			if compressed, cerr := p.compressor.Compress(chunkBytes); cerr == nil && len(compressed) < len(chunkBytes) {
				toStore = compressed
			}
		}

		var blobData []byte
		if gcm == nil {
			blobData = toStore
		} else {
			iv, err := newSmallBlobIV()
			if err != nil {
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
		uploaded += int64(len(chunkBytes))
		chunkIdx++
	}

	return uploaded, nil
}
