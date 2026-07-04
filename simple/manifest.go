// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
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

	"github.com/ginkgobackup/gbf-core/compress"
	"github.com/ginkgobackup/gbf-core/fsutil"
	"github.com/google/uuid"
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
		// so that any plausible present-day timestamp (seconds, millis, or
		// micros) is decoded with the unit that yields a sane date:
		//   - seconds   today: ~1.7e9
		//   - millis    today: ~1.7e12
		//   - micros    today: ~1.7e15
		// With iv > 1e14 we must be looking at microseconds (a 2024 millis
		// value ~1.7e12 would otherwise be misread as µs and land in 1970).
		// With iv > 1e11 (and <= 1e14) we must be looking at millis.
		if iv > 1e14 {
			s = time.UnixMicro(iv).UTC().Format(time.RFC3339Nano)
		} else if iv > 1e11 {
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
	NewBytes       int64 `json:"newBytes"`
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
	dirPath, fileName := filepath.Split(filePath)
	dirPath = strings.TrimRight(dirPath, "/")
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

var localManifestCompressor = compress.NewZstdCompressor(1)

var ManifestDecryptHook func(encrypted []byte) ([]byte, error)

func SetManifestDecryptHook(fn func([]byte) ([]byte, error)) {
	ManifestDecryptHook = fn
}

func ManifestFilePath(metaDir string, cloudID string, ts time.Time, deviceID string) string {
	dir := ManifestDir(metaDir, cloudID)
	name := fmt.Sprintf("%d_%s.json.zst", ts.Unix(), deviceID)
	return filepath.Join(dir, name)
}

func SaveManifest(metaDir string, m *Manifest) error {
	return SaveManifestWithKey(metaDir, m, nil)
}

func SaveManifestWithKey(metaDir string, m *Manifest, encryptKey []byte) error {
	ts, err := time.Parse(time.RFC3339, m.Timestamp)
	if err != nil {
		ts = time.Now()
	}
	cloudID := m.CloudID
	if cloudID == "" {
		cloudID = ManifestPathKey(m.DeviceID, fmt.Sprintf("%d", m.SourceID))
	}
	path := ManifestFilePath(metaDir, cloudID, ts, m.DeviceID)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	compressed, err := localManifestCompressor.Compress(data)
	if err != nil {
		return fmt.Errorf("compress: %w", err)
	}
	if len(encryptKey) > 0 {
		compressed, err = EncryptManifest(compressed, encryptKey)
		if err != nil {
			return fmt.Errorf("encrypt manifest: %w", err)
		}
	}
	sum := sha256.Sum256(compressed)
	checksumHex := hex.EncodeToString(sum[:])

	if err := fsutil.WriteFileAtomic(path, compressed, 0600); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	checksumPath := manifestChecksumPath(path)
	if err := fsutil.WriteFileAtomic(checksumPath, []byte(checksumHex), 0600); err != nil {
		return fmt.Errorf("write manifest checksum: %w", err)
	}

	return nil
}

func manifestChecksumPath(manifestPath string) string {
	return manifestPath + ".sha256"
}

func verifyManifestChecksum(manifestPath string, data []byte) error {
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
	return LoadManifestFromData(data)
}

func LoadManifestFromData(data []byte) (*Manifest, error) {
	if len(data) >= MagicSize && string(data[:MagicSize]) == GKM1Magic {
		if ManifestDecryptHook == nil {
			return nil, fmt.Errorf("manifest is encrypted (GKM1) but no decrypt hook registered")
		}
		var err error
		data, err = ManifestDecryptHook(data)
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

func ManifestExistsByTimestamp(metaDir string, cloudID string, unixSec int64) bool {
	dir := ManifestDir(metaDir, cloudID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	prefix := fmt.Sprintf("%d_", unixSec)
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), prefix) && isManifestFile(e.Name()) {
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
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrManifestNotFound
		}
		return nil, fmt.Errorf("readdir: %w", err)
	}
	prefix := fmt.Sprintf("%d_", ts.Unix())
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		return LoadManifest(filepath.Join(dir, e.Name()))
	}
	return nil, ErrManifestNotFound
}

func LoadLatestManifest(metaDir string, cloudID string) (*Manifest, error) {
	dir := ManifestDir(metaDir, cloudID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrManifestNotFound
		}
		return nil, fmt.Errorf("readdir: %w", err)
	}
	if len(entries) == 0 {
		return nil, ErrManifestNotFound
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() > entries[j].Name()
	})
	for _, e := range entries {
		if e.IsDir() || !isManifestFile(e.Name()) {
			continue
		}
		return LoadManifest(filepath.Join(dir, e.Name()))
	}
	return nil, ErrManifestNotFound
}

func ListManifests(metaDir string, cloudID string) ([]*Manifest, []string, error) {
	dir := ManifestDir(metaDir, cloudID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("readdir: %w", err)
	}
	var result []*Manifest
	var loadErrors []string
	for _, e := range entries {
		if e.IsDir() || !isManifestFile(e.Name()) {
			continue
		}
		m, err := LoadManifest(filepath.Join(dir, e.Name()))
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", e.Name(), err))
			continue
		}
		result = append(result, m)
	}
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
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("readdir: %w", err)
	}
	var result []string
	for _, e := range entries {
		if e.IsDir() || !isManifestFile(e.Name()) {
			continue
		}
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
	dir := ManifestDir(metaDir, cloudID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("readdir: %w", err)
	}
	var loadErrors []string
	for _, e := range entries {
		if e.IsDir() || !isManifestFile(e.Name()) {
			continue
		}
		m, err := LoadManifest(filepath.Join(dir, e.Name()))
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", e.Name(), err))
			continue
		}
		if m.Timestamp == timestamp && m.DeviceID == deviceID {
			manifestPath := filepath.Join(dir, e.Name())
			_ = os.Remove(manifestChecksumPath(manifestPath))
			return os.Remove(manifestPath)
		}
	}
	if len(loadErrors) > 0 {
		slog.Warn("GBF manifest load errors during DeleteManifest",
			"component", "manifest",
			"cloud_id", cloudID,
			"errors", loadErrors)
	}
	return fmt.Errorf("manifest not found: %s/%s", timestamp, deviceID)
}

func ManifestTrashDir(metaDir string, cloudID string) string {
	return filepath.Join(metaDir, "trash", cloudID)
}

func TrashManifest(metaDir string, cloudID string, timestamp, deviceID string) error {
	srcDir := ManifestDir(metaDir, cloudID)
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("readdir: %w", err)
	}
	var loadErrors []string
	for _, e := range entries {
		if e.IsDir() || !isManifestFile(e.Name()) {
			continue
		}
		m, err := LoadManifest(filepath.Join(srcDir, e.Name()))
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", e.Name(), err))
			continue
		}
		if m.Timestamp == timestamp && m.DeviceID == deviceID {
			dstDir := ManifestTrashDir(metaDir, cloudID)
			if err := os.MkdirAll(dstDir, 0755); err != nil {
				return fmt.Errorf("create trash dir: %w", err)
			}
			srcPath := filepath.Join(srcDir, e.Name())
			dstPath := filepath.Join(dstDir, e.Name())
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
	}
	if len(loadErrors) > 0 {
		slog.Warn("GBF manifest load errors during TrashManifest",
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
	defer srcFile.Close()
	dstDir := filepath.Dir(dst)
	if mkErr := os.MkdirAll(dstDir, 0755); mkErr != nil {
		return fmt.Errorf("rename fallback mkdir: %w", mkErr)
	}
	dstFile, createErr := os.Create(dst)
	if createErr != nil {
		return fmt.Errorf("rename fallback create: %w", createErr)
	}
	defer dstFile.Close()
	if _, copyErr := io.Copy(dstFile, srcFile); copyErr != nil {
		os.Remove(dst)
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
	srcDir := ManifestDir(metaDir, cloudID)
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("readdir: %w", err)
	}
	dstDir := ManifestTrashDir(metaDir, cloudID)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return 0, fmt.Errorf("create trash dir: %w", err)
	}
	moved := 0
	for _, e := range entries {
		if e.IsDir() || !isManifestFile(e.Name()) {
			continue
		}
		srcPath := filepath.Join(srcDir, e.Name())
		dstPath := filepath.Join(dstDir, e.Name())
		if err := renameWithFallback(srcPath, dstPath); err != nil {
			slog.Warn("trash manifest move failed", "component", "manifest", "file", e.Name(), "error", err)
			continue
		}
		moved++
	}
	remaining, _ := os.ReadDir(srcDir)
	if len(remaining) == 0 {
		os.Remove(srcDir)
	}
	return moved, nil
}

func DeleteAllSourceManifests(metaDir string, cloudID string) (int, error) {
	srcDir := ManifestDir(metaDir, cloudID)
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("readdir: %w", err)
	}
	deleted := 0
	for _, e := range entries {
		if e.IsDir() || !isManifestFile(e.Name()) {
			continue
		}
		if err := os.Remove(filepath.Join(srcDir, e.Name())); err != nil {
			slog.Warn("delete manifest failed", "component", "manifest", "file", e.Name(), "error", err)
			continue
		}
		deleted++
	}
	remaining, _ := os.ReadDir(srcDir)
	if len(remaining) == 0 {
		os.Remove(srcDir)
	}
	return deleted, nil
}

func DeleteSourceRegistry(metaDir string, cloudID string) error {
	srcPath := filepath.Join(sourceRegistriesDir(metaDir), cloudID+".json.zst")
	if _, err := os.Stat(srcPath); os.IsNotExist(err) {
		return nil
	}
	return os.Remove(srcPath)
}

func LoadTrashSourceRegistry(metaDir string, cloudID string) (*SourceRegistry, error) {
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
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("readdir: %w", err)
	}
	now := time.Now()
	cleaned := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
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
		os.Remove(dir)
		cleanTrashSourceRegistry(metaDir, cloudID)
	}
	return cleaned, nil
}

func cleanTrashSourceRegistry(metaDir string, cloudID string) {
	dir := filepath.Join(metaDir, "trash", "_sources")
	path := filepath.Join(dir, cloudID+".json.zst")
	os.Remove(path)
	remaining, _ := os.ReadDir(dir)
	if len(remaining) == 0 {
		os.Remove(dir)
	}
}

func ListTrashManifests(metaDir string, cloudID string) ([]*Manifest, []string, error) {
	dir := ManifestTrashDir(metaDir, cloudID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("readdir: %w", err)
	}
	var result []*Manifest
	var loadErrors []string
	for _, e := range entries {
		if e.IsDir() || !isManifestFile(e.Name()) {
			continue
		}
		m, err := LoadManifest(filepath.Join(dir, e.Name()))
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", e.Name(), err))
			continue
		}
		result = append(result, m)
	}
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
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]bool), nil, nil
		}
		return nil, nil, fmt.Errorf("readdir: %w", err)
	}

	alive := make(map[string]bool)
	var loadErrors []string
	for _, e := range entries {
		if e.IsDir() || !isManifestFile(e.Name()) {
			continue
		}
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
		if ManifestDecryptHook == nil {
			return nil, fmt.Errorf("manifest is encrypted (GKM1) but no decrypt hook registered")
		}
		data, err = ManifestDecryptHook(data)
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
	tmp := path + "." + uuid.New().String() + ".tmp"
	if err := os.WriteFile(tmp, compressed, 0600); err != nil {
		return fmt.Errorf("write source registry: %w", err)
	}
	return os.Rename(tmp, path)
}

func LoadSourceRegistry(metaDir string, cloudID string) (*SourceRegistry, error) {
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
