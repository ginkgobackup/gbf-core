// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/ginkgobackup/gbf-core/compress"
	"github.com/ginkgobackup/gbf-core/fsutil"
)

var ErrManifestNotFound = errors.New("manifest not found")

type Manifest struct {
	Version    int             `json:"version"`
	SourceID   int64           `json:"sourceId"`
	CloudID    string          `json:"cloudId,omitempty"`
	SourceName string          `json:"sourceName"`
	SourcePath string          `json:"sourcePath"`
	Timestamp  string          `json:"timestamp"`
	DeviceID   string          `json:"deviceId"`
	Dirs       map[string]*Dir `json:"dirs"`
	Stats      ManifestStats   `json:"stats"`

	// FilePath is the actual on-disk path this manifest was loaded from or
	// written to. It is set by LoadManifest and SaveManifestWithKey and is
	// never serialized. Callers must use this instead of reconstructing the
	// path via ManifestFilePath: a same-second conflict causes the save to
	// write a suffixed filename that ManifestFilePath cannot predict.
	FilePath string `json:"-"`

	fileMap     map[string]FileEntry
	fileMapOnce sync.Once
}

type Dir struct {
	Files   []FileEntry `json:"files"`
	SubDirs []string    `json:"subdirs"`
}

type AliveIndex struct {
	Version int      `json:"version"`
	Hashes  []string `json:"hashes"`
}

func ManifestToAliveIndex(m *Manifest) *AliveIndex {
	hashes := make([]string, 0, m.Stats.FileCount)
	for _, d := range m.Dirs {
		for _, f := range d.Files {
			if len(f.Chunks) > 0 {
				for _, c := range f.Chunks {
					hashes = append(hashes, c.Hash)
				}
			} else if f.ContentHash != "" {
				hashes = append(hashes, f.ContentHash)
			}
		}
	}
	return &AliveIndex{Version: 1, Hashes: hashes}
}

type ChunkRef struct {
	Hash string `json:"hash"`
	Size int64  `json:"size"`
}

type FileEntry struct {
	Name        string     `json:"name"`
	ContentHash string     `json:"contentHash"`
	Size        int64      `json:"size"`
	Mtime       FlexTime   `json:"mtime"`
	Mode        uint32     `json:"mode"`
	Status      string     `json:"status,omitempty"`
	Chunks      []ChunkRef `json:"chunks,omitempty"`
}

type FlexTime string

// Timestamp unit detection thresholds for FlexTime.UnmarshalJSON. Values
// above microsVsNanosThreshold are treated as nanoseconds; values above
// millisVsMicrosThreshold (and below that) as microseconds; values above
// secVsMillisThreshold (and below that) as milliseconds; anything else as
// seconds. All constants are exact integers, so comparisons against them
// are pure int64 arithmetic.
const (
	secVsMillisThreshold    int64 = 100_000_000_000           // 1e11: today's epoch millis start with ~1.7
	millisVsMicrosThreshold int64 = 100_000_000_000_000       // 1e14: today's epoch micros start with ~1.7
	microsVsNanosThreshold  int64 = 1_000_000_000_000_000_000 // 1e18: today's epoch nanos start with ~1.7
)

func (f *FlexTime) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*f = FlexTime(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	s := n.String()
	if iv, err := n.Int64(); err == nil {
		// Heuristic unit detection based on magnitude. Thresholds are chosen
		// so that any plausible present-day timestamp (seconds, millis,
		// micros, or nanos) is decoded with the unit that yields a sane date:
		//   - seconds   today: ~1.7e9
		//   - millis    today: ~1.7e12
		//   - micros    today: ~1.7e15
		//   - nanos     today: ~1.7e18
		// Above microsVsNanosThreshold we must be looking at nanoseconds
		// (epoch micros do not reach 1e18 until year ~33658, so anything
		// larger can only be ns; without this branch a 2026 nanos value
		// ~1.78e18 would be misread as µs and land in year ~58000).
		// Above millisVsMicrosThreshold (and <= 1e18) we must be looking
		// at microseconds (a 2024 millis value ~1.7e12 would otherwise be
		// misread as µs and land in 1970). Above secVsMillisThreshold
		// (and <= 1e14) we must be looking at millis.
		if iv > microsVsNanosThreshold {
			s = time.Unix(0, iv).UTC().Format(time.RFC3339Nano)
		} else if iv > millisVsMicrosThreshold {
			s = time.UnixMicro(iv).UTC().Format(time.RFC3339Nano)
		} else if iv > secVsMillisThreshold {
			s = time.UnixMilli(iv).UTC().Format(time.RFC3339Nano)
		} else {
			s = time.Unix(iv, 0).UTC().Format(time.RFC3339Nano)
		}
	}
	*f = FlexTime(s)
	return nil
}

func (f FileEntry) MtimeMicro() int64 {
	if f.Mtime == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, string(f.Mtime))
	if err != nil {
		return 0
	}
	return t.UnixMicro()
}

func (f FileEntry) MtimeTime() time.Time {
	if f.Mtime == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, string(f.Mtime))
	if err != nil {
		return time.Time{}
	}
	return t
}

type ManifestStats struct {
	FileCount      int   `json:"fileCount"`
	TotalSize      int64 `json:"totalSize"`
	NewFiles       int   `json:"newFiles"`
	ChangedFiles   int   `json:"changedFiles"`
	UnchangedFiles int   `json:"unchangedFiles"`
	// DeletedFiles is the number of paths present in the previous
	// manifest but missing from this one. Cloud/peer snapshot targets
	// are rebuilt from these stats after async sync, so without this
	// field their deleted_count would always be 0 and diverge from the
	// local repo row.
	DeletedFiles int   `json:"deletedFiles"`
	NewBytes     int64 `json:"newBytes"`
	// ScanErrors counts paths that could not be read during the source
	// scan. It is only non-zero for snapshots created with
	// PipelineConfig.AllowScanErrors; such a snapshot is incomplete and is
	// never used as an incremental baseline (see loadPreviousFiles).
	ScanErrors int `json:"scanErrors,omitempty"`
}

func NewManifest(sourceID int64, cloudID, sourceName, sourcePath, deviceID string) *Manifest {
	return &Manifest{
		Version:    2,
		SourceID:   sourceID,
		CloudID:    cloudID,
		SourceName: sourceName,
		SourcePath: sourcePath,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		DeviceID:   deviceID,
		Dirs:       make(map[string]*Dir),
	}
}

func normalizeManifestPath(p string) string {
	p = filepath.ToSlash(p)
	p = strings.TrimPrefix(p, "/")
	return p
}

func (m *Manifest) AddFile(entry FileEntry) {
	p := normalizeManifestPath(entry.Name)
	var dir, base string
	if idx := strings.LastIndex(p, "/"); idx >= 0 {
		dir = p[:idx]
		base = p[idx+1:]
	} else {
		base = p
	}

	d, ok := m.Dirs[dir]
	if !ok {
		d = &Dir{}
		m.Dirs[dir] = d
	}
	entry.Name = base
	d.Files = append(d.Files, entry)

	m.Stats.FileCount++
	m.Stats.TotalSize += entry.Size

	if dir != "" {
		ensureParentDirs(m, dir)
	}
}

func ensureParentDirs(m *Manifest, dirPath string) {
	parts := strings.Split(dirPath, "/")
	for i := range parts {
		parent := strings.Join(parts[:i], "/")
		child := parts[i]
		pd, ok := m.Dirs[parent]
		if !ok {
			pd = &Dir{}
			m.Dirs[parent] = pd
		}
		found := false
		for _, s := range pd.SubDirs {
			if s == child {
				found = true
				break
			}
		}
		if !found {
			pd.SubDirs = append(pd.SubDirs, child)
		}
	}
}

func (m *Manifest) AddEmptyDir(relPath string) {
	p := normalizeManifestPath(relPath)
	if p == "" {
		return
	}
	var parentDir, dirName string
	if idx := strings.LastIndex(p, "/"); idx >= 0 {
		parentDir = p[:idx]
		dirName = p[idx+1:]
	} else {
		dirName = p
	}
	if dirName == "" {
		return
	}
	if _, ok := m.Dirs[p]; !ok {
		m.Dirs[p] = &Dir{}
	}
	if parentDir != "" {
		ensureParentDirs(m, p)
	} else {
		root, ok := m.Dirs[""]
		if !ok {
			root = &Dir{}
			m.Dirs[""] = root
		}
		found := false
		for _, s := range root.SubDirs {
			if s == dirName {
				found = true
				break
			}
		}
		if !found {
			root.SubDirs = append(root.SubDirs, dirName)
		}
	}
}

func (m *Manifest) BuildFileMap() map[string]FileEntry {
	m.fileMapOnce.Do(func() {
		result := make(map[string]FileEntry, m.Stats.FileCount)
		for dirPath, d := range m.Dirs {
			for _, f := range d.Files {
				path := f.Name
				if dirPath != "" {
					path = dirPath + "/" + f.Name
				}
				entry := f
				entry.Name = path
				result[path] = entry
			}
		}
		m.fileMap = result
	})
	return m.fileMap
}

func (m *Manifest) FindFile(filePath string) (FileEntry, bool) {
	// Manifest keys always use "/" as the separator (see normalizeManifestPath
	// and BuildFileMap). On Windows, filepath.Split splits on "\" and would
	// mis-segment a "/"-delimited input. Split on "/" explicitly so behavior
	// is consistent across platforms and matches the manifest's own layout.
	filePath = filepath.ToSlash(filePath)
	var dirPath, fileName string
	if idx := strings.LastIndex(filePath, "/"); idx >= 0 {
		dirPath = filePath[:idx]
		fileName = filePath[idx+1:]
	} else {
		fileName = filePath
	}
	d, ok := m.Dirs[dirPath]
	if !ok {
		return FileEntry{}, false
	}
	for _, f := range d.Files {
		if f.Name == fileName {
			entry := f
			entry.Name = dirPath + "/" + f.Name
			if dirPath == "" {
				entry.Name = f.Name
			}
			return entry, true
		}
	}
	return FileEntry{}, false
}

// FindFileTolerant tries to locate a file when FindFile fails, tolerating
// common path discrepancies between caller-supplied paths and manifest keys.
// It handles: (1) leading-dot differences ("agent/..." vs ".agent/...") and
// (2) case-insensitive matching (important on Windows/case-insensitive FS).
// Callers should always try FindFile first and only fall back to this method.
func (m *Manifest) FindFileTolerant(filePath string) (FileEntry, bool) {
	fileMap := m.BuildFileMap()

	// 1. Try toggling the leading dot on the first path segment.
	alt := toggleLeadingDot(filePath)
	if alt != filePath {
		if entry, ok := fileMap[alt]; ok {
			return entry, true
		}
	}

	// 2. Case-insensitive scan (Windows and case-insensitive FS).
	lower := strings.ToLower(filePath)
	altLower := lower
	if alt != filePath {
		altLower = strings.ToLower(alt)
	}
	for p, entry := range fileMap {
		lp := strings.ToLower(p)
		if lp == lower || lp == altLower {
			return entry, true
		}
	}
	return FileEntry{}, false
}

// toggleLeadingDot prepends "." to the first path segment if it doesn't start
// with one, or strips it if it does. Returns the input unchanged for single-
// segment paths or empty input.
func toggleLeadingDot(p string) string {
	if p == "" {
		return p
	}
	idx := strings.Index(p, "/")
	var dir, rest string
	if idx >= 0 {
		dir, rest = p[:idx], p[idx:]
	} else {
		dir = p
	}
	if strings.HasPrefix(dir, ".") {
		return dir[1:] + rest
	}
	return "." + dir + rest
}

func (m *Manifest) AllFiles() []FileEntry {
	result := make([]FileEntry, 0, m.Stats.FileCount)
	for dirPath, d := range m.Dirs {
		for _, f := range d.Files {
			entry := f
			if dirPath != "" {
				entry.Name = dirPath + "/" + f.Name
			}
			result = append(result, entry)
		}
	}
	return result
}

func ManifestDir(metaDir string, cloudID string) string {
	return filepath.Join(metaDir, "manifests", cloudID)
}

// ErrInvalidCloudID is returned when a cloudID or deviceID contains path
// components that could escape the manifest directory (e.g. ".." segments,
// absolute paths, or Windows drive letters). cloudID may legitimately
// contain "/" (the layout is "deviceID/sourceID"), but it must never resolve
// to a path above the manifest root.
var ErrInvalidCloudID = errors.New("invalid cloudID: path escapes manifest root")

func validateCloudID(cloudID string) error {
	if cloudID == "" {
		return fmt.Errorf("cloudID is empty: %w", ErrInvalidCloudID)
	}
	// Reject absolute paths (Unix or Windows).
	if strings.HasPrefix(cloudID, "/") || strings.HasPrefix(cloudID, "\\") {
		return fmt.Errorf("cloudID is absolute: %q: %w", cloudID, ErrInvalidCloudID)
	}
	if len(cloudID) >= 2 && cloudID[1] == ':' && ((cloudID[0] >= 'A' && cloudID[0] <= 'Z') || (cloudID[0] >= 'a' && cloudID[0] <= 'z')) {
		return fmt.Errorf("cloudID is absolute (Windows drive): %q: %w", cloudID, ErrInvalidCloudID)
	}
	// Reject any path segment equal to ".." — these would escape upward.
	// Split on both '/' and '\\': on Windows a backslash is also a path
	// separator, so `..\..\evil` must be caught here just like `../../evil`.
	for _, seg := range strings.FieldsFunc(cloudID, func(r rune) bool { return r == '/' || r == '\\' }) {
		seg = strings.TrimSpace(seg)
		if seg == ".." {
			return fmt.Errorf("cloudID contains parent reference: %q: %w", cloudID, ErrInvalidCloudID)
		}
	}
	return nil
}

// ManifestPathKey returns the relative manifest directory key for a source.
// The global manifest layout is manifests/{device-fingerprint}/{sourceID}.
func ManifestPathKey(fingerprint, sourceID string) string {
	return fingerprint + "/" + sourceID
}

// ResolveCloudID returns the manifest cloudID for a source, using the device
// fingerprint when available and falling back to the raw sourceID for legacy
// sources without a device ID.
func ResolveCloudID(deviceID string, sourceID int64) string {
	if deviceID == "" {
		return fmt.Sprintf("%d", sourceID)
	}
	return ManifestPathKey(deviceID, fmt.Sprintf("%d", sourceID))
}

// localManifestCompressor uses the manifest decompression limit (256 MiB),
// not the chunk compression-bomb cap (4 MiB). Manifests, alive indexes and
// source registries are application-written, checksum-verified and (for
// manifests) optionally encrypted, so they are trusted payloads that
// legitimately exceed 4 MiB for large sources (e.g. ~200k files ≈ 60 MiB).
// Chunks still use the 4 MiB default via defaultStreamDecompressor.
var localManifestCompressor = compress.NewZstdCompressorWithLimit(1, compress.MaxManifestDecompressedSize, compress.ErrManifestDecompressedTooLarge)

// hookMu guards ManifestDecryptHook. The exported variable is the legacy
// direct-assignment API retained for backward compatibility; the
// setter/getter below are the concurrency-safe API. Both operate on the
// same storage, so it does not matter which one a caller uses.
var (
	hookMu sync.RWMutex

	// ManifestDecryptHook decrypts GKM1-encrypted manifests. It is the
	// original package-level registration API, kept for backward
	// compatibility with callers that assign it directly:
	//
	//	simple.ManifestDecryptHook = decrypt
	//
	// Direct assignment bypasses hookMu and is only safe before any
	// manifest-loading goroutine starts (the usual startup-time
	// registration). New code must use SetManifestDecryptHook /
	// GetManifestDecryptHook, which are safe for concurrent use with
	// manifest loading.
	//
	// Deprecated: Direct assignment is a data race when concurrent
	// manifest loads are running. Use SetManifestDecryptHook instead;
	// this variable will be removed in the next minor version.
	ManifestDecryptHook func(encrypted []byte) ([]byte, error)
)

// SetManifestDecryptHook registers the hook used to decrypt GKM1-encrypted
// manifests. Passing nil clears the hook. Safe for concurrent use with
// manifest loading.
func SetManifestDecryptHook(fn func(encrypted []byte) ([]byte, error)) {
	hookMu.Lock()
	defer hookMu.Unlock()
	ManifestDecryptHook = fn
}

// GetManifestDecryptHook returns the currently registered manifest
// decryption hook, or nil if none is set. Safe for concurrent use.
func GetManifestDecryptHook() func(encrypted []byte) ([]byte, error) {
	hookMu.RLock()
	defer hookMu.RUnlock()
	return ManifestDecryptHook
}

func ManifestFilePath(metaDir string, cloudID string, ts time.Time, deviceID string) string {
	dir := ManifestDir(metaDir, cloudID)
	name := fmt.Sprintf("%d_%s.json.zst", ts.Unix(), deviceID)
	return filepath.Join(dir, name)
}

// SaveManifest writes the manifest and returns the actual path written.
// See SaveManifestWithKey for the same-second conflict behavior.
func SaveManifest(metaDir string, m *Manifest) (string, error) {
	return SaveManifestWithKey(metaDir, m, nil)
}

// manifestSaveMu serializes manifest saves within this process. Saves are
// low-frequency (once per backup run), so this costs nothing and keeps the
// same-second conflict log noise down. Correctness across processes no
// longer depends on it: the final manifest commit goes through
// fsutil.CommitFileNoReplace, which atomically refuses to overwrite an
// existing file EVEN when the contender is another process (see
// TestManifestConcurrentSavesSameSecond and TestManifestCrossProcessSave).
var manifestSaveMu sync.Mutex

// SaveManifestWithKey persists a manifest under
// metaDir/manifests/{cloudID}/{unix}_{deviceID}.json.zst and returns the
// actual path written.
//
// Same-second conflict: the deterministic filename only has second
// resolution, so two backups of the same source completing within one second
// would collide. The manifest is committed with a NO-REPLACE atomic commit:
// if the target name already exists, the commit fails with os.ErrExist and
// the save retries under "{unix}_{deviceID}_{6hex}.json.zst". Unlike a
// Stat-then-write pre-check, this is race-free even against OTHER PROCESSES
// saving into the same repository — on POSIX the commit is link(2)-based,
// on Windows it is MoveFileEx without MOVEFILE_REPLACE_EXISTING. The
// suffixed name remains visible to all readers (prefix scans in
// LoadManifestByTimestamp/ManifestExistsByTimestamp, content matching in
// Delete/TrashManifest, isManifestFile listing). Lexicographically it sorts
// BEHIND the unsuffixed file ('.' = 0x2E < '_' = 0x5F), so LoadLatestManifest
// tie-breaks same-second candidates on file modification time rather than
// filename order to pick the newer one. Callers that reconstruct the path
// via ManifestFilePath only find the FIRST manifest of that second — they
// must use the returned path when they need the exact file just written.
func SaveManifestWithKey(metaDir string, m *Manifest, encryptKey []byte) (string, error) {
	manifestSaveMu.Lock()
	defer manifestSaveMu.Unlock()
	ts, err := time.Parse(time.RFC3339, m.Timestamp)
	if err != nil {
		ts = time.Now()
	}
	cloudID := m.CloudID
	if cloudID == "" {
		cloudID = ManifestPathKey(m.DeviceID, fmt.Sprintf("%d", m.SourceID))
	}
	if err := validateCloudID(cloudID); err != nil {
		return "", err
	}
	if err := validateCloudID(m.DeviceID); err != nil {
		return "", fmt.Errorf("deviceID: %w", err)
	}
	path := ManifestFilePath(metaDir, cloudID, ts, m.DeviceID)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}
	data, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	compressed, err := localManifestCompressor.Compress(data)
	if err != nil {
		return "", fmt.Errorf("compress: %w", err)
	}
	if len(encryptKey) > 0 {
		compressed, err = EncryptManifest(compressed, encryptKey)
		if err != nil {
			return "", fmt.Errorf("encrypt manifest: %w", err)
		}
	}
	sum := sha256.Sum256(compressed)
	checksumHex := hex.EncodeToString(sum[:])

	// Stage the manifest body once (fsynced, unique name so cross-process
	// savers cannot clobber each other's staging file), then commit it
	// with a no-replace atomic move under the primary name — or, when
	// another save (possibly from another process) already claimed that
	// name this second, under a random 6-hex suffix.
	staging := path + "." + uuid.NewString() + ".tmp"
	if err := fsutil.WriteStagingFile(staging, compressed, 0600); err != nil {
		return "", fmt.Errorf("stage manifest: %w", err)
	}

	// Commit attempts are side-effect free: no file is written until the
	// no-replace commit succeeds, so a losing attempt cannot damage the
	// winner's manifest or sidecar. (Writing the sidecar BEFORE the
	// commit — the pre-no-replace order — would clobber and then orphan
	// the winner's sidecar on same-second conflicts; see
	// TestSaveManifestSameSecondConflict.)
	var finalPath string
	for attempt := 0; ; attempt++ {
		candidate := path
		if attempt > 0 {
			var b [3]byte
			if _, randErr := rand.Read(b[:]); randErr != nil {
				_ = os.Remove(staging)
				return "", fmt.Errorf("generate conflict suffix: %w", randErr)
			}
			candidate = strings.TrimSuffix(path, ".json.zst") + "_" + hex.EncodeToString(b[:]) + ".json.zst"
			slog.Warn("GBF manifest same-second conflict, retrying with suffix",
				"component", "manifest", "cloud_id", cloudID, "path", filepath.Base(candidate))
		}
		if attempt >= 8 {
			// Astronomically unlikely: 7 suffixed attempts all collided.
			_ = os.Remove(staging)
			return "", fmt.Errorf("manifest same-second conflict: no free name under %s", path)
		}

		err := fsutil.CommitFileNoReplace(staging, candidate)
		if err == nil {
			finalPath = candidate
			break
		}
		if errors.Is(err, os.ErrExist) {
			// Another save (this process or another) claimed the name.
			// Retry under a random suffix — nothing to clean up.
			continue
		}
		_ = os.Remove(staging)
		return "", fmt.Errorf("commit manifest: %w", err)
	}

	// The sidecar is written AFTER the commit. A crash in between leaves a
	// committed manifest without its sidecar, which LoadManifest rejects
	// and LoadLatestManifest skips via its fallback-to-older-manifest
	// logic — the interrupted save is effectively rolled back, and no
	// other save's files are ever damaged. After a successful commit the
	// final name is exclusively ours, so overwriting the sidecar (e.g. a
	// leftover from a crashed attempt) is always safe.
	checksumPath := manifestChecksumPath(finalPath)
	if err := fsutil.WriteFileAtomic(checksumPath, []byte(checksumHex), 0600); err != nil {
		return "", fmt.Errorf("write manifest checksum: %w", err)
	}

	m.FilePath = finalPath
	return finalPath, nil
}

func manifestChecksumPath(manifestPath string) string {
	return manifestPath + ".sha256"
}

func verifyManifestChecksum(manifestPath string, data []byte) error {
	// GKM1-encrypted manifests carry their own integrity protection via
	// AES-256-GCM authentication. When the .sha256 sidecar is missing
	// (common in mesh-backup peer-receive repos where manifests are
	// uploaded as opaque blobs without their sidecar checksum files),
	// the GCM tag is sufficient to detect tampering. Skip the sidecar
	// requirement for encrypted manifests so they can be loaded.
	if len(data) >= MagicSize && string(data[:MagicSize]) == GKM1Magic {
		checksumPath := manifestChecksumPath(manifestPath)
		if _, err := os.Stat(checksumPath); os.IsNotExist(err) {
			return nil
		}
		// Sidecar exists — verify it for defense in depth.
	}
	checksumPath := manifestChecksumPath(manifestPath)
	expectedBytes, err := os.ReadFile(checksumPath)
	if err != nil {
		if os.IsNotExist(err) {
			// A manifest without a sidecar checksum is not trustworthy: an
			// attacker (or a partial sync) can tamper with the manifest body
			// without detection. Reject it instead of silently accepting.
			return fmt.Errorf("manifest checksum missing: %s", checksumPath)
		}
		return fmt.Errorf("read manifest checksum: %w", err)
	}
	expected := strings.TrimSpace(string(expectedBytes))
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if !strings.EqualFold(expected, actual) {
		return fmt.Errorf("manifest checksum mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if err := verifyManifestChecksum(path, data); err != nil {
		return nil, err
	}
	m, err := LoadManifestFromData(data)
	if err != nil {
		return nil, err
	}
	m.FilePath = path
	return m, nil
}

func LoadManifestFromData(data []byte) (*Manifest, error) {
	if len(data) >= MagicSize && string(data[:MagicSize]) == GKM1Magic {
		hook := GetManifestDecryptHook()
		if hook == nil {
			return nil, fmt.Errorf("manifest is encrypted (GKM1) but no decrypt hook registered")
		}
		var err error
		data, err = hook(data)
		if err != nil {
			return nil, fmt.Errorf("decrypt manifest: %w", err)
		}
	}
	if localManifestCompressor.IsCompressed(data) {
		decompressed, err := localManifestCompressor.Decompress(data)
		if err != nil {
			return nil, fmt.Errorf("decompress: %w", err)
		}
		data = decompressed
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if m.Version < 2 {
		migrateV1Manifest(&m, data)
	}
	return &m, nil
}

func migrateV1Manifest(m *Manifest, raw []byte) {
	type v1FileEntry struct {
		Path        string     `json:"path"`
		ContentHash string     `json:"contentHash"`
		Size        int64      `json:"size"`
		Mtime       string     `json:"mtime"`
		Mode        uint32     `json:"mode"`
		Status      string     `json:"status,omitempty"`
		Chunks      []ChunkRef `json:"chunks,omitempty"`
	}
	type v1EmptyDir struct {
		RelPath string `json:"relPath"`
		Name    string `json:"name"`
	}
	type v1Manifest struct {
		Files     []v1FileEntry `json:"files"`
		EmptyDirs []v1EmptyDir  `json:"emptyDirs"`
	}

	var v1 v1Manifest
	if err := json.Unmarshal(raw, &v1); err != nil {
		return
	}

	m.Version = 2
	m.Dirs = make(map[string]*Dir)
	m.Stats = ManifestStats{}
	for _, f := range v1.Files {
		m.AddFile(FileEntry{
			Name:        f.Path,
			ContentHash: f.ContentHash,
			Size:        f.Size,
			Mtime:       FlexTime(f.Mtime),
			Mode:        f.Mode,
			Status:      f.Status,
			Chunks:      f.Chunks,
		})
	}
	for _, ed := range v1.EmptyDirs {
		m.AddEmptyDir(ed.RelPath)
	}
}

func isManifestFile(name string) bool {
	if strings.Contains(name, ".alive.") {
		return false
	}
	return strings.HasSuffix(name, ".json.zst") || strings.HasSuffix(name, ".json")
}

// readManifestDirEntries returns the non-directory entries of dir in ReadDir
// order. The raw os.ReadDir error is passed through so each caller keeps its
// own missing-directory semantics (not-found sentinel, empty result, or
// plain error).
func readManifestDirEntries(dir string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []os.DirEntry
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, e)
		}
	}
	return files, nil
}

// readManifestFiles is readManifestDirEntries restricted to entries whose
// names pass isManifestFile.
func readManifestFiles(dir string) ([]os.DirEntry, error) {
	entries, err := readManifestDirEntries(dir)
	if err != nil {
		return nil, err
	}
	var files []os.DirEntry
	for _, e := range entries {
		if isManifestFile(e.Name()) {
			files = append(files, e)
		}
	}
	return files, nil
}

// forEachManifest loads every entry (as returned by readManifestFiles) and
// hands the parsed manifest to fn; iteration stops early once fn returns
// true. Load failures are accumulated as "name: error" strings and returned
// so callers keep their own error-reporting behavior.
func forEachManifest(dir string, entries []os.DirEntry, fn func(m *Manifest, name string) bool) []string {
	var loadErrors []string
	for _, e := range entries {
		m, err := LoadManifest(filepath.Join(dir, e.Name()))
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", e.Name(), err))
			continue
		}
		if fn(m, e.Name()) {
			break
		}
	}
	return loadErrors
}

func ManifestExistsByTimestamp(metaDir string, cloudID string, unixSec int64) bool {
	entries, err := readManifestFiles(ManifestDir(metaDir, cloudID))
	if err != nil {
		return false
	}
	prefix := fmt.Sprintf("%d_", unixSec)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			return true
		}
	}
	return false
}

func LoadManifestByTimestamp(metaDir string, cloudID string, timestamp string) (*Manifest, error) {
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return nil, fmt.Errorf("parse timestamp %q: %w", timestamp, err)
	}
	dir := ManifestDir(metaDir, cloudID)
	entries, err := readManifestFiles(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrManifestNotFound
		}
		return nil, fmt.Errorf("readdir: %w", err)
	}
	prefix := fmt.Sprintf("%d_", ts.Unix())
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		return LoadManifest(filepath.Join(dir, e.Name()))
	}
	return nil, ErrManifestNotFound
}

func LoadLatestManifest(metaDir string, cloudID string) (*Manifest, error) {
	dir := ManifestDir(metaDir, cloudID)
	entries, err := readManifestFiles(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrManifestNotFound
		}
		return nil, fmt.Errorf("readdir: %w", err)
	}

	type candidate struct {
		name    string
		unixSec int64
		modNano int64
	}
	var candidates []candidate
	for _, e := range entries {
		ts, parseErr := ParseManifestFilenameTimestamp(e.Name())
		if parseErr != nil {
			continue
		}
		var unixSec int64
		if t, pErr := time.Parse(time.RFC3339, ts); pErr == nil {
			unixSec = t.Unix()
		}
		var modNano int64
		if info, iErr := e.Info(); iErr == nil {
			modNano = info.ModTime().UnixNano()
		}
		candidates = append(candidates, candidate{name: e.Name(), unixSec: unixSec, modNano: modNano})
	}
	if len(candidates) == 0 {
		return nil, ErrManifestNotFound
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].unixSec != candidates[j].unixSec {
			return candidates[i].unixSec > candidates[j].unixSec
		}
		// Same-second conflicts carry a random 6-hex suffix (see
		// SaveManifestWithKey), so filename order within one second is
		// arbitrary. Tie-break on file modification time, which reflects
		// the actual write order; the name stays as the final tie-break
		// for filesystems with coarse mtime granularity.
		if candidates[i].modNano != candidates[j].modNano {
			return candidates[i].modNano > candidates[j].modNano
		}
		return candidates[i].name > candidates[j].name
	})
	// Try candidates newest-first instead of committing to the first one.
	// If the newest manifest fails to load (crash between the manifest and
	// checksum writes from an older code version, partial sync, bit rot),
	// falling back to the previous snapshot keeps incremental backups and
	// restores working instead of hard-failing until someone deletes the
	// broken file by hand.
	var firstErr error
	for _, cand := range candidates {
		m, loadErr := LoadManifest(filepath.Join(dir, cand.name))
		if loadErr == nil {
			return m, nil
		}
		if firstErr == nil {
			firstErr = loadErr
		}
		slog.Warn("GBF manifest load failed, trying older candidate",
			"component", "manifest", "cloud_id", cloudID,
			"file", cand.name, "error", loadErr.Error())
	}
	return nil, fmt.Errorf("load latest manifest: newest candidate %q failed (%w) and %d older candidate(s) also failed", candidates[0].name, firstErr, len(candidates)-1)
}

func ListManifests(metaDir string, cloudID string) ([]*Manifest, []string, error) {
	dir := ManifestDir(metaDir, cloudID)
	entries, err := readManifestFiles(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("readdir: %w", err)
	}
	var result []*Manifest
	loadErrors := forEachManifest(dir, entries, func(m *Manifest, _ string) bool {
		result = append(result, m)
		return false
	})
	if len(loadErrors) > 0 {
		slog.Warn("GBF manifest load errors during ListManifests",
			"component", "manifest",
			"cloud_id", cloudID,
			"errors", loadErrors,
			"loaded", len(result),
			"failed", len(loadErrors))
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp > result[j].Timestamp
	})
	return result, loadErrors, nil
}

func ListManifestTimestamps(metaDir string, cloudID string) ([]string, error) {
	dir := ManifestDir(metaDir, cloudID)
	entries, err := readManifestFiles(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("readdir: %w", err)
	}
	var result []string
	for _, e := range entries {
		ts, parseErr := ParseManifestFilenameTimestamp(e.Name())
		if parseErr != nil {
			continue
		}
		result = append(result, ts)
	}
	sort.Strings(result)
	return result, nil
}

func ParseManifestFilenameTimestamp(filename string) (string, error) {
	name := filename
	if idx := strings.LastIndex(name, "."); idx > 0 {
		name = name[:idx]
	}
	if idx := strings.LastIndex(name, "."); idx > 0 {
		name = name[:idx]
	}
	parts := strings.SplitN(name, "_", 2)
	if len(parts) < 1 {
		return "", fmt.Errorf("invalid manifest filename: %s", filename)
	}
	unixSec, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return "", fmt.Errorf("parse unix timestamp from %s: %w", filename, err)
	}
	return time.Unix(unixSec, 0).UTC().Format(time.RFC3339), nil
}

func DeleteManifest(metaDir string, cloudID string, timestamp, deviceID string) error {
	return deleteOrTrashManifest(metaDir, cloudID, timestamp, deviceID, false)
}

func ManifestTrashDir(metaDir string, cloudID string) string {
	return filepath.Join(metaDir, "trash", cloudID)
}

func TrashManifest(metaDir string, cloudID string, timestamp, deviceID string) error {
	return deleteOrTrashManifest(metaDir, cloudID, timestamp, deviceID, true)
}

// moveOrDeleteOneManifest moves the manifest file at srcPath into dstDir
// (trash mode) or deletes it in place, in both cases handling its .sha256
// sidecar the same way so the two files never get separated. dstDir is only
// used when trash is true and must already exist.
func moveOrDeleteOneManifest(srcPath, dstDir string, trash bool) error {
	if trash {
		dstPath := filepath.Join(dstDir, filepath.Base(srcPath))
		if err := renameWithFallback(srcPath, dstPath); err != nil {
			return err
		}
		srcChecksumPath := manifestChecksumPath(srcPath)
		dstChecksumPath := manifestChecksumPath(dstPath)
		if _, statErr := os.Stat(srcChecksumPath); statErr == nil {
			_ = renameWithFallback(srcChecksumPath, dstChecksumPath)
		}
		return nil
	}
	_ = os.Remove(manifestChecksumPath(srcPath))
	return os.Remove(srcPath)
}

// deleteOrTrashManifest finds the manifest matching timestamp+deviceID and
// either deletes it (together with its checksum sidecar) or moves it to the
// source's trash directory. The two operations share every step except the
// final remove vs rename.
func deleteOrTrashManifest(metaDir string, cloudID string, timestamp, deviceID string, trash bool) error {
	srcDir := ManifestDir(metaDir, cloudID)
	entries, err := readManifestFiles(srcDir)
	if err != nil {
		return fmt.Errorf("readdir: %w", err)
	}
	var matched string
	loadErrors := forEachManifest(srcDir, entries, func(m *Manifest, name string) bool {
		if m.Timestamp == timestamp && m.DeviceID == deviceID {
			matched = name
			return true
		}
		return false
	})
	if matched != "" {
		srcPath := filepath.Join(srcDir, matched)
		if trash {
			dstDir := ManifestTrashDir(metaDir, cloudID)
			if err := os.MkdirAll(dstDir, 0755); err != nil {
				return fmt.Errorf("create trash dir: %w", err)
			}
			return moveOrDeleteOneManifest(srcPath, dstDir, true)
		}
		return moveOrDeleteOneManifest(srcPath, "", false)
	}
	if len(loadErrors) > 0 {
		action := "DeleteManifest"
		if trash {
			action = "TrashManifest"
		}
		slog.Warn("GBF manifest load errors during "+action,
			"component", "manifest",
			"cloud_id", cloudID,
			"errors", loadErrors)
	}
	return fmt.Errorf("manifest not found: %s/%s", timestamp, deviceID)
}

func CleanTrashManifests(metaDir string, maxAge time.Duration) (int, error) {
	trashBase := filepath.Join(metaDir, "trash")
	now := time.Now()
	cleaned := 0
	err := filepath.Walk(trashBase, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if now.Sub(info.ModTime()) > maxAge {
			if removeErr := os.Remove(path); removeErr == nil {
				cleaned++
			}
		}
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return cleaned, fmt.Errorf("walk trash: %w", err)
	}
	return cleaned, nil
}

func renameWithFallback(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}
	if !isCrossDeviceError(err) {
		return err
	}
	srcFile, openErr := os.Open(src)
	if openErr != nil {
		return fmt.Errorf("rename fallback open: %w", openErr)
	}
	defer func() { _ = srcFile.Close() }()
	dstDir := filepath.Dir(dst)
	if mkErr := os.MkdirAll(dstDir, 0755); mkErr != nil {
		return fmt.Errorf("rename fallback mkdir: %w", mkErr)
	}
	dstFile, createErr := os.Create(dst)
	if createErr != nil {
		return fmt.Errorf("rename fallback create: %w", createErr)
	}
	defer func() { _ = dstFile.Close() }()
	if _, copyErr := io.Copy(dstFile, srcFile); copyErr != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("rename fallback copy: %w", copyErr)
	}
	if removeErr := os.Remove(src); removeErr != nil {
		slog.Warn("rename fallback: source file not removed after copy", "src", src, "error", removeErr)
	}
	return nil
}

func isCrossDeviceError(err error) bool {
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		errno, ok := linkErr.Err.(syscall.Errno)
		if !ok {
			return false
		}
		return errno == syscall.EXDEV
	}
	return false
}

func TrashAllSourceManifests(metaDir string, cloudID string) (int, error) {
	return deleteOrTrashAllManifests(metaDir, cloudID, true)
}

func DeleteAllSourceManifests(metaDir string, cloudID string) (int, error) {
	return deleteOrTrashAllManifests(metaDir, cloudID, false)
}

// deleteOrTrashAllManifests moves (trash) or deletes every manifest of a
// source — checksum sidecars included — then removes the now-empty source
// directory.
func deleteOrTrashAllManifests(metaDir string, cloudID string, trash bool) (int, error) {
	srcDir := ManifestDir(metaDir, cloudID)
	entries, err := readManifestFiles(srcDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("readdir: %w", err)
	}
	var dstDir string
	if trash {
		dstDir = ManifestTrashDir(metaDir, cloudID)
		if err := os.MkdirAll(dstDir, 0755); err != nil {
			return 0, fmt.Errorf("create trash dir: %w", err)
		}
	}
	count := 0
	for _, e := range entries {
		srcPath := filepath.Join(srcDir, e.Name())
		opErr := moveOrDeleteOneManifest(srcPath, dstDir, trash)
		if opErr != nil {
			if trash {
				slog.Warn("trash manifest move failed", "component", "manifest", "file", e.Name(), "error", opErr)
			} else {
				slog.Warn("delete manifest failed", "component", "manifest", "file", e.Name(), "error", opErr)
			}
			continue
		}
		count++
	}
	remaining, _ := os.ReadDir(srcDir)
	if len(remaining) == 0 {
		_ = os.Remove(srcDir)
	}
	return count, nil
}

func DeleteSourceRegistry(metaDir string, cloudID string) error {
	if err := validateCloudID(cloudID); err != nil {
		return err
	}
	srcPath := filepath.Join(sourceRegistriesDir(metaDir), cloudID+".json.zst")
	if _, err := os.Stat(srcPath); os.IsNotExist(err) {
		return nil
	}
	return os.Remove(srcPath)
}

func LoadTrashSourceRegistry(metaDir string, cloudID string) (*SourceRegistry, error) {
	if err := validateCloudID(cloudID); err != nil {
		return nil, err
	}
	dir := filepath.Join(metaDir, "trash", "_sources")
	path := filepath.Join(dir, cloudID+".json.zst")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trash source registry: %w", err)
	}
	if localManifestCompressor.IsCompressed(data) {
		data, err = localManifestCompressor.Decompress(data)
		if err != nil {
			return nil, fmt.Errorf("decompress trash source registry: %w", err)
		}
	}
	var reg SourceRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("unmarshal trash source registry: %w", err)
	}
	return &reg, nil
}

func ListTrashSourceIDs(metaDir string) ([]string, error) {
	trashBase := filepath.Join(metaDir, "trash")
	entries, err := os.ReadDir(trashBase)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("readdir trash: %w", err)
	}
	var result []string
	for _, e := range entries {
		if e.IsDir() && e.Name() != "_sources" {
			result = append(result, e.Name())
		}
	}
	return result, nil
}

func CleanTrashManifestsForSource(metaDir string, cloudID string, maxAge time.Duration) (int, error) {
	dir := ManifestTrashDir(metaDir, cloudID)
	entries, err := readManifestDirEntries(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("readdir: %w", err)
	}
	now := time.Now()
	cleaned := 0
	for _, e := range entries {
		info, statErr := e.Info()
		if statErr != nil {
			continue
		}
		if now.Sub(info.ModTime()) > maxAge {
			if removeErr := os.Remove(filepath.Join(dir, e.Name())); removeErr == nil {
				cleaned++
			}
		}
	}
	remaining, _ := os.ReadDir(dir)
	if len(remaining) == 0 {
		_ = os.Remove(dir)
		cleanTrashSourceRegistry(metaDir, cloudID)
	}
	return cleaned, nil
}

func cleanTrashSourceRegistry(metaDir string, cloudID string) {
	dir := filepath.Join(metaDir, "trash", "_sources")
	path := filepath.Join(dir, cloudID+".json.zst")
	_ = os.Remove(path)
	remaining, _ := os.ReadDir(dir)
	if len(remaining) == 0 {
		_ = os.Remove(dir)
	}
}

func ListTrashManifests(metaDir string, cloudID string) ([]*Manifest, []string, error) {
	dir := ManifestTrashDir(metaDir, cloudID)
	entries, err := readManifestFiles(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("readdir: %w", err)
	}
	var result []*Manifest
	loadErrors := forEachManifest(dir, entries, func(m *Manifest, _ string) bool {
		result = append(result, m)
		return false
	})
	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp > result[j].Timestamp
	})
	return result, loadErrors, nil
}

func ListSourceCloudIDs(manifestsDir string) ([]string, error) {
	entries, err := os.ReadDir(manifestsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("readdir: %w", err)
	}
	var result []string
	seen := make(map[string]bool)
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "_sources" {
			continue
		}
		// With the global {fingerprint}/{sourceID} layout, recurse one level.
		subDir := filepath.Join(manifestsDir, e.Name())
		subEntries, subErr := os.ReadDir(subDir)
		if subErr != nil {
			continue
		}
		for _, se := range subEntries {
			if !se.IsDir() {
				continue
			}
			key := ManifestPathKey(e.Name(), se.Name())
			if !seen[key] {
				seen[key] = true
				result = append(result, key)
			}
		}
	}
	return result, nil
}

func CollectAliveHashes(manifests []*Manifest) map[string]bool {
	alive := make(map[string]bool)
	for _, m := range manifests {
		for _, d := range m.Dirs {
			for _, f := range d.Files {
				if len(f.Chunks) > 0 {
					for _, c := range f.Chunks {
						alive[c.Hash] = true
					}
				} else if f.ContentHash != "" {
					alive[f.ContentHash] = true
				}
			}
		}
	}
	return alive
}

func CollectAliveHashesStreaming(metaDir string, cloudID string) (map[string]bool, []string, error) {
	dir := ManifestDir(metaDir, cloudID)
	entries, err := readManifestFiles(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]bool), nil, nil
		}
		return nil, nil, fmt.Errorf("readdir: %w", err)
	}

	alive := make(map[string]bool)
	var loadErrors []string
	for _, e := range entries {
		hashes, err := extractHashesFromManifestFile(filepath.Join(dir, e.Name()))
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", e.Name(), err))
			continue
		}
		for _, h := range hashes {
			alive[h] = true
		}
	}
	return alive, loadErrors, nil
}

func extractHashesFromManifestFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if err := verifyManifestChecksum(path, data); err != nil {
		return nil, err
	}
	if len(data) >= MagicSize && string(data[:MagicSize]) == GKM1Magic {
		hook := GetManifestDecryptHook()
		if hook == nil {
			return nil, fmt.Errorf("manifest is encrypted (GKM1) but no decrypt hook registered")
		}
		data, err = hook(data)
		if err != nil {
			return nil, fmt.Errorf("decrypt manifest: %w", err)
		}
	}
	if localManifestCompressor.IsCompressed(data) {
		data, err = localManifestCompressor.Decompress(data)
		if err != nil {
			return nil, fmt.Errorf("decompress: %w", err)
		}
	}
	hashes, err := extractHashesFromJSON(data)
	if err != nil {
		return nil, err
	}
	return hashes, nil
}

func extractHashesFromJSON(data []byte) ([]string, error) {
	type fileEntryLite struct {
		ContentHash string `json:"contentHash"`
		Chunks      []struct {
			Hash string `json:"hash"`
		} `json:"chunks"`
	}
	type dirLite struct {
		Files []fileEntryLite `json:"files"`
	}
	type manifestLite struct {
		Version int                 `json:"version"`
		Dirs    map[string]*dirLite `json:"dirs"`
		Files   []fileEntryLite     `json:"files"`
	}
	var m manifestLite
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest JSON: %w", err)
	}
	var hashes []string
	if len(m.Dirs) > 0 {
		for _, d := range m.Dirs {
			for _, f := range d.Files {
				if len(f.Chunks) > 0 {
					for _, c := range f.Chunks {
						if c.Hash != "" {
							hashes = append(hashes, c.Hash)
						}
					}
				} else if f.ContentHash != "" {
					hashes = append(hashes, f.ContentHash)
				}
			}
		}
	}
	for _, f := range m.Files {
		if len(f.Chunks) > 0 {
			for _, c := range f.Chunks {
				if c.Hash != "" {
					hashes = append(hashes, c.Hash)
				}
			}
		} else if f.ContentHash != "" {
			hashes = append(hashes, f.ContentHash)
		}
	}
	return hashes, nil
}

type SourceRegistry struct {
	CloudID       string             `json:"cloudId"`
	Name          string             `json:"name"`
	Path          string             `json:"path"`
	DeviceID      string             `json:"deviceId"`
	Hostname      string             `json:"hostname,omitempty"`
	OS            string             `json:"os,omitempty"`
	Pins          []RegistryPin      `json:"pins,omitempty"`
	Notes         []RegistryNote     `json:"notes,omitempty"`
	Snapshots     []RegistrySnapshot `json:"snapshots,omitempty"`
	Settings      *RegistrySettings  `json:"settings,omitempty"`
	LastSnapshot  string             `json:"lastSnapshot"`
	SnapshotCount int                `json:"snapshotCount"`
	CreatedAt     string             `json:"createdAt"`
}

// RegistryPin represents a pinned snapshot in a source registry. It is a
// value type so the registry can be serialized without referencing the
// higher-level snapshot domain package. SnapshotTime and CreatedAt are
// Unix microseconds, matching the snapshot domain's time representation.
type RegistryPin struct {
	RepoPath     string `json:"repoPath"`
	SnapshotTime int64  `json:"snapshotTime"`
	Note         string `json:"note,omitempty"`
	CreatedAt    int64  `json:"createdAt,omitempty"`
}

// RegistryNote represents a snapshot note stored in a source registry. It
// mirrors snapshot.SnapshotNote but is a value type so the registry can be
// serialized without importing the snapshot domain package.
type RegistryNote struct {
	RepoPath       string `json:"repoPath"`
	SnapshotTime   int64  `json:"snapshotTime"`
	Content        string `json:"content,omitempty"`
	PushedFiles    string `json:"pushedFiles,omitempty"`
	Source         string `json:"source,omitempty"`
	CreatedAt      int64  `json:"createdAt,omitempty"`
	AuthorDeviceID string `json:"authorDeviceId,omitempty"`
	AuthorName     string `json:"authorName,omitempty"`
}

// RegistrySettings captures a source's user-facing settings so they can be
// round-tripped through the source registry (e.g. for cross-device import).
// All fields are optional; absent fields preserve the existing settings.
type RegistrySettings struct {
	Schedule        string   `json:"schedule,omitempty"`
	ScheduleConfig  string   `json:"scheduleConfig,omitempty"`
	Retention       string   `json:"retention,omitempty"`
	RetentionCustom string   `json:"retentionCustom,omitempty"`
	Excludes        []string `json:"excludes,omitempty"`
	EnableAI        bool     `json:"enableAi,omitempty"`
	WatchMode       string   `json:"watchMode,omitempty"`
}

// RegistrySnapshot represents a snapshot entry embedded in the source
// registry. It is a value type so the registry can be serialized without
// importing the snapshot domain package. Timestamp is RFC3339; FileCount
// and TotalSize mirror the snapshot domain fields of the same name.
type RegistrySnapshot struct {
	Timestamp string `json:"timestamp"`
	FileCount int64  `json:"fileCount,omitempty"`
	TotalSize int64  `json:"totalSize,omitempty"`
}

func sourceRegistriesDir(metaDir string) string {
	return filepath.Join(metaDir, "manifests", "_sources")
}

func SaveSourceRegistry(metaDir string, reg *SourceRegistry) error {
	if err := validateCloudID(reg.CloudID); err != nil {
		return fmt.Errorf("source registry cloudID: %w", err)
	}
	dir := sourceRegistriesDir(metaDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir sources registry: %w", err)
	}
	data, err := json.Marshal(reg)
	if err != nil {
		return fmt.Errorf("marshal source registry: %w", err)
	}
	compressed, err := localManifestCompressor.Compress(data)
	if err != nil {
		return fmt.Errorf("compress source registry: %w", err)
	}
	// CloudID may contain path separators (it's a path key like "dev1/42"),
	// so the final filename can be nested. Make sure the full parent dir
	// exists before writing the tmp file.
	path := filepath.Join(dir, reg.CloudID+".json.zst")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir source registry parent: %w", err)
	}
	// Use WriteFileAtomic for fsync + atomic rename + parent dir sync,
	// consistent with SaveManifestWithKey and SaveGEK1KeyFile.
	if err := fsutil.WriteFileAtomic(path, compressed, 0600); err != nil {
		return fmt.Errorf("write source registry: %w", err)
	}
	return nil
}

func LoadSourceRegistry(metaDir string, cloudID string) (*SourceRegistry, error) {
	if err := validateCloudID(cloudID); err != nil {
		return nil, err
	}
	dir := sourceRegistriesDir(metaDir)
	path := filepath.Join(dir, cloudID+".json.zst")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read source registry: %w", err)
	}
	if localManifestCompressor.IsCompressed(data) {
		data, err = localManifestCompressor.Decompress(data)
		if err != nil {
			return nil, fmt.Errorf("decompress source registry: %w", err)
		}
	}
	var reg SourceRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("unmarshal source registry: %w", err)
	}
	return &reg, nil
}

func ListSourceRegistries(metaDir string) ([]*SourceRegistry, error) {
	dir := sourceRegistriesDir(metaDir)
	// Walk recursively: when a deviceID is set, ResolveCloudID returns
	// "<deviceID>/<sourceID>", so the registry file lives in a per-device
	// subdirectory. A flat ReadDir would skip those subdirectories and
	// silently drop every source that has a device fingerprint.
	var result []*SourceRegistry
	walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("walk source registries: %w", err)
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".json.zst") {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return nil
		}
		cloudID := strings.TrimSuffix(filepath.ToSlash(rel), ".json.zst")
		reg, loadErr := LoadSourceRegistry(metaDir, cloudID)
		if loadErr != nil {
			slog.Warn("source registry load failed", "cloud_id", cloudID, "error", loadErr)
			return nil
		}
		result = append(result, reg)
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk source registries: %w", walkErr)
	}
	return result, nil
}
