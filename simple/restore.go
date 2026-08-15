// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"log/slog"
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
		// LoadManifestByTimestamp prefix-scans the manifest dir, so it also
		// finds manifests written with a same-second conflict suffix (see
		// SaveManifestWithKey) — a reconstructed ManifestFilePath would miss
		// those.
		m, err = LoadManifestByTimestamp(metaDir, cloudID, r.cfg.Timestamp)
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

	// Recreate the directory skeleton before restoring files. Manifest v2
	// records every directory in Dirs — both dirs containing files and
	// explicitly recorded empty dirs — so iterating the keys rebuilds the
	// full tree. Without this, empty directories (no files inside) would be
	// missing from the restore. The root entry "" maps to TargetDir itself;
	// skip it (safeRestorePath rejects empty paths, and file restore creates
	// parent dirs on demand anyway).
	for dirPath := range m.Dirs {
		if dirPath == "" {
			continue
		}
		targetPath, err := safeRestorePath(r.cfg.TargetDir, dirPath)
		if err != nil {
			return nil, fmt.Errorf("restore directory %s: %w", dirPath, err)
		}
		if err := os.MkdirAll(targetPath, 0755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", targetPath, err)
		}
	}

	for _, file := range m.AllFiles() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Files that were locked or failed during backup are written to
		// the manifest with Status "locked"/"error" and an empty
		// ContentHash — no blob was ever uploaded for them (see
		// pipeline.go). Skip these entries instead of letting store.Get("")
		// abort the whole restore.
		if file.Status == "locked" || file.Status == "error" || file.ContentHash == "" {
			result.SkippedFiles++
			slog.Warn("GBF restore: skipping file that was not backed up",
				"file", file.Name, "status", file.Status, "size", file.Size)
			if r.progress != nil {
				r.progress.FileProcessed(file.Name, file.Size, false, false)
			}
			continue
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
				_ = os.Remove(tmp)
				return nil, fmt.Errorf("rename %s: %w", file.Name, err)
			}
		}

		mtime := file.MtimeTime()
		if !mtime.IsZero() {
			// Restoring mtime is best-effort — if it fails (e.g. readonly
			// target dir) the file content is still correct, so log and
			// continue rather than failing the restore.
			if err := os.Chtimes(targetPath, mtime, mtime); err != nil {
				slog.Warn("GBF restore: chtimes failed",
					"file", file.Name, "error", err)
			}
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

// maxChunkBlobSize bounds one chunk blob read during streamed chunked
// restore. Chunk plaintext never exceeds cdcMaxSize (16 MiB CDC cap; fixed
// chunks are DefaultChunkSize), and compression is applied before
// encryption so the ciphertext adds only magic + IV + AEAD tag plus a small
// expansion margin.
const maxChunkBlobSize = cdcMaxSize + MagicSize + IVSize + TagSize + (1 << 20)

// readAllBounded reads r into buf (reusing its capacity and growing up to
// limit) and returns the filled slice. Blobs larger than limit are rejected
// so a crafted blob cannot force an unbounded allocation.
func readAllBounded(buf []byte, r io.Reader, limit int) ([]byte, error) {
	buf = buf[:0]
	scratch := make([]byte, 128*1024)
	for {
		n, rErr := r.Read(scratch)
		if n > 0 {
			if len(buf)+n > limit {
				return buf, fmt.Errorf("blob exceeds max size %d", limit)
			}
			if len(buf)+n > cap(buf) {
				newCap := cap(buf) * 2
				if newCap < len(buf)+n {
					newCap = len(buf) + n
				}
				grown := make([]byte, len(buf), newCap)
				copy(grown, buf)
				buf = grown
			}
			buf = append(buf, scratch[:n]...)
		}
		if rErr == io.EOF {
			return buf, nil
		}
		if rErr != nil {
			return buf, rErr
		}
	}
}

// decryptChunkBlobStream decrypts one independently encrypted chunk blob
// (GB1 magic + IV + AEAD ciphertext, the format uploadChangedChunks writes)
// from src, verifies the plaintext against expectedHash, and appends it to
// dst. ctBuf and ptBuf are scratch buffers reused across the chunks of one
// file: ctBuf holds the raw blob (read via readAllBounded), ptBuf is the
// AEAD output buffer (gcm.Open appends into it without reallocating).
// Blobs that don't match the single-blob layout (GB2 containers or legacy
// ambiguous IVs whose first 4 bytes look like a chunk count) fall back to
// the full Decrypt path, which tries every interpretation. The possibly
// grown buffers are returned for the next chunk.
func decryptChunkBlobStream(dec *Decryptor, src io.Reader, dst io.Writer, expectedHash string, ctBuf, ptBuf []byte) ([]byte, []byte, error) {
	data, err := readAllBounded(ctBuf, src, maxChunkBlobSize)
	if err != nil {
		return data, ptBuf, fmt.Errorf("read chunk blob: %w", err)
	}

	var plaintext []byte
	if len(data) > MagicSize+IVSize+TagSize &&
		string(data[:MagicSize]) == MagicGB1 &&
		!isChunkCount(data[MagicSize:MagicSize+ChunkCountSize]) {
		// Single-blob layout: magic + IV + ciphertext. newSmallBlobIV
		// guarantees the first 4 IV bytes never parse as a chunk count for
		// blobs written by this engine, so this is the common path.
		block, bErr := aes.NewCipher(dec.key)
		if bErr != nil {
			return data, ptBuf, fmt.Errorf("aes cipher: %w", bErr)
		}
		gcm, gErr := cipher.NewGCM(block)
		if gErr != nil {
			return data, ptBuf, fmt.Errorf("gcm: %w", gErr)
		}
		iv := data[MagicSize : MagicSize+IVSize]
		ciphertext := data[MagicSize+IVSize:]
		opened, oErr := gcm.Open(ptBuf[:0], iv, ciphertext, nil)
		if oErr != nil {
			// Legacy blob with an ambiguous IV — let Decrypt try both
			// GB1 interpretations (small and large) like DownloadBlob did.
			plaintext, err = dec.Decrypt(data)
			if err != nil {
				return data, ptBuf, fmt.Errorf("decrypt chunk blob: %w", err)
			}
		} else {
			plaintext = opened
		}
	} else {
		// GB2 container or malformed/legacy layout: full Decrypt semantics.
		plaintext, err = dec.Decrypt(data)
		if err != nil {
			return data, ptBuf, fmt.Errorf("decrypt chunk blob: %w", err)
		}
	}

	if defaultStreamDecompressor.IsCompressed(plaintext) {
		decompressed, dErr := defaultStreamDecompressor.Decompress(plaintext)
		if dErr != nil {
			return data, ptBuf, fmt.Errorf("decompress chunk blob: %w", dErr)
		}
		plaintext = decompressed
	}

	actualHash := SHA256Bytes(plaintext)
	if actualHash != expectedHash {
		return data, ptBuf, fmt.Errorf("hash mismatch: expected %s, got %s", expectedHash, actualHash)
	}
	if _, err := dst.Write(plaintext); err != nil {
		return data, ptBuf, fmt.Errorf("write chunk: %w", err)
	}
	return data, plaintext, nil
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
		_ = tmpF.Close()
		_ = os.Remove(tmp)
	}()

	// Stream chunk blobs: GetStream + per-chunk decrypt straight into the
	// tmp file. Peak memory is one chunk blob's ciphertext plus its
	// plaintext (AEAD needs the full chunk), with both scratch buffers
	// reused across chunks — instead of a full store.Get copy per chunk.
	// Chunk order, tamper verification (per-chunk SHA-256) and the final
	// fsync/rename semantics are unchanged.
	var ctBuf, ptBuf []byte
	for _, chunk := range file.Chunks {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := r.restoreChunkStream(ctx, chunk.Hash, tmpF, &ctBuf, &ptBuf); err != nil {
			hashLog := chunk.Hash
			if len(hashLog) > 12 {
				hashLog = hashLog[:12]
			}
			return fmt.Errorf("download chunk %s: %w", hashLog, err)
		}
	}
	ctBuf, ptBuf = nil, nil // drop the scratch buffers before the fsync

	// Apply the source file's mode bits to the staged tmp file. A failure
	// here is non-fatal — the file content is already written and durable —
	// so we log and continue rather than failing the whole restore.
	if err := tmpF.Chmod(os.FileMode(file.Mode)); err != nil {
		slog.Warn("GBF restore: chmod tmp file failed",
			"file", file.Name, "mode", file.Mode, "error", err)
	}
	if err := tmpF.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	if err := tmpF.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}

	return os.Rename(tmp, targetPath)
}

// restoreChunkStream fetches one chunk blob via GetStream and streams its
// decryption into dst. If the store cannot stream the blob it falls back
// to the buffered DownloadBlob path with identical decrypt/verify
// semantics.
func (r *SimpleRestore) restoreChunkStream(ctx context.Context, hash string, dst io.Writer, ctBuf, ptBuf *[]byte) error {
	rc, err := r.store.GetStream(ctx, hash)
	if err != nil {
		plaintext, dErr := DownloadBlob(ctx, r.store, r.dec, hash)
		if dErr != nil {
			return dErr
		}
		if _, wErr := dst.Write(plaintext); wErr != nil {
			return fmt.Errorf("write chunk: %w", wErr)
		}
		return nil
	}
	defer func() { _ = rc.Close() }()

	var dErr error
	*ctBuf, *ptBuf, dErr = decryptChunkBlobStream(r.dec, rc, dst, hash, *ctBuf, *ptBuf)
	return dErr
}
