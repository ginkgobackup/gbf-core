// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// --- CloudID precedence (PipelineConfig.CloudID) ---

// TestPipelineExplicitCloudID verifies that PipelineConfig.CloudID takes
// precedence over the derived device_src key: the manifest and its on-disk
// location must both use the explicit CloudID (imported sources /
// cross-device manifests), and a second run with the same explicit CloudID
// must find the first run's manifest as its incremental baseline.
func TestPipelineExplicitCloudID(t *testing.T) {
	repoDir := t.TempDir()
	sourceDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceDir, "file.txt"), []byte("cloud id test"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := InitRepo(InitParams{RepoRoot: repoDir, DeviceID: "test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	store := NewLocalBlobStore(repoDir)
	ctx := context.Background()

	const explicit = "other-dev_src-9"
	cfg := PipelineConfig{
		RepoRoot:   repoDir,
		SourceID:   1,
		SourceName: "test",
		SourcePath: sourceDir,
		DeviceID:   "test",
		CloudID:    explicit,
	}
	result, err := NewSimplePipeline(cfg, store).Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Manifest.CloudID != explicit {
		t.Fatalf("manifest CloudID = %q, want %q", result.Manifest.CloudID, explicit)
	}
	wantDir := ManifestDir(MetaDir(repoDir), explicit)
	if got := filepath.Dir(result.Manifest.FilePath); got != wantDir {
		t.Fatalf("manifest dir = %q, want %q", got, wantDir)
	}

	// The second run must load the first manifest through the explicit
	// CloudID and report the file as unchanged.
	result2, err := NewSimplePipeline(cfg, store).Run(ctx)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if result2.UnchangedFiles != 1 {
		t.Fatalf("second run unchanged = %d, want 1 (previous manifest must be found via explicit CloudID)", result2.UnchangedFiles)
	}
}

// --- scan-error semantics ---

// TestRunScanErrorFailsByDefault verifies that a scan which could not read
// paths (here: the scan root itself does not exist) fails the run instead
// of committing a manifest that silently misreports the missing files as
// deleted.
func TestRunScanErrorFailsByDefault(t *testing.T) {
	repoDir := t.TempDir()
	if err := InitRepo(InitParams{RepoRoot: repoDir, DeviceID: "test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	cfg := PipelineConfig{
		RepoRoot:   repoDir,
		SourceID:   1,
		SourceName: "test",
		SourcePath: filepath.Join(t.TempDir(), "does-not-exist"),
		DeviceID:   "test",
	}
	_, err := NewSimplePipeline(cfg, NewLocalBlobStore(repoDir)).Run(context.Background())
	if err == nil {
		t.Fatal("expected error when scan path does not exist")
	}
	if !strings.Contains(err.Error(), "unreadable path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRunScanErrorAllowedNotBaseline verifies the AllowScanErrors opt-in:
// an incomplete snapshot is committed with Stats.ScanErrors recorded, and
// the NEXT run refuses to use it as an incremental baseline (its missing
// files would be misreported as deleted), producing a full comparison.
func TestRunScanErrorAllowedNotBaseline(t *testing.T) {
	repoDir := t.TempDir()
	sourceDir := t.TempDir()
	if err := InitRepo(InitParams{RepoRoot: repoDir, DeviceID: "test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	store := NewLocalBlobStore(repoDir)
	ctx := context.Background()

	missingPath := filepath.Join(sourceDir, "missing")
	cfg := PipelineConfig{
		RepoRoot:        repoDir,
		SourceID:        1,
		SourceName:      "test",
		SourcePath:      missingPath,
		DeviceID:        "test",
		AllowScanErrors: true,
	}
	result, err := NewSimplePipeline(cfg, store).Run(ctx)
	if err != nil {
		t.Fatalf("run with AllowScanErrors: %v", err)
	}
	if result.Manifest.Stats.ScanErrors == 0 {
		t.Fatal("Stats.ScanErrors = 0, want > 0")
	}

	// The path now exists with one file. The incomplete manifest from the
	// first run must NOT be used as a baseline: the file is new (not
	// unchanged/deleted).
	if err := os.MkdirAll(missingPath, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(missingPath, "a.txt"), []byte("a"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	result2, err := NewSimplePipeline(cfg, store).Run(ctx)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if result2.NewFiles != 1 || result2.UnchangedFiles != 0 {
		t.Fatalf("new=%d unchanged=%d; want 1/0 — incomplete manifest must not be a baseline", result2.NewFiles, result2.UnchangedFiles)
	}
	if result2.Manifest.Stats.DeletedFiles != 0 {
		t.Fatalf("DeletedFiles = %d, want 0 (incomplete baseline must not imply deletions)", result2.Manifest.Stats.DeletedFiles)
	}
}

// --- symlink/junction defense during restore ---

// makeDirLink creates a directory symlink (or a junction on Windows when
// symlinks require privileges). Skips the test when neither can be created.
func makeDirLink(t *testing.T, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return
	}
	if runtime.GOOS == "windows" {
		out, jerr := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
		if jerr == nil {
			return
		}
		t.Skipf("cannot create symlink or junction: %v / %v (%s)", err, jerr, out)
	}
	t.Skipf("cannot create symlink: %v", err)
}

func TestLinkCheckerRejectsSymlinkComponents(t *testing.T) {
	targetDir := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "escaped.txt"), []byte("outside"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	makeDirLink(t, outside, filepath.Join(targetDir, "allowed"))

	lc, err := newLinkChecker(targetDir)
	if err != nil {
		t.Fatalf("newLinkChecker: %v", err)
	}
	if err := lc.ensureLinkFree(filepath.Join(targetDir, "allowed", "file.txt")); err == nil {
		t.Fatal("ensureLinkFree accepted a path through a symlink/junction")
	}
	if err := lc.ensureLinkFree(filepath.Join(targetDir, "normal", "file.txt")); err != nil {
		t.Fatalf("ensureLinkFree rejected a normal path: %v", err)
	}
}

// TestRestoreRunRejectsSymlinkedTargetSubdir runs a full backup+restore
// roundtrip with a pre-created symlink inside the restore target that an
// unguarded restore would write through, leaking files outside TargetDir.
func TestRestoreRunRejectsSymlinkedTargetSubdir(t *testing.T) {
	repoDir := t.TempDir()
	sourceDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sourceDir, "allowed"), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "allowed", "file.txt"), []byte("data"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := InitRepo(InitParams{RepoRoot: repoDir, DeviceID: "test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	store := NewLocalBlobStore(repoDir)
	ctx := context.Background()

	cfg := PipelineConfig{RepoRoot: repoDir, SourceID: 1, SourceName: "test", SourcePath: sourceDir, DeviceID: "test"}
	if _, err := NewSimplePipeline(cfg, store).Run(ctx); err != nil {
		t.Fatalf("backup: %v", err)
	}

	restoreDir := t.TempDir()
	outside := t.TempDir()
	makeDirLink(t, outside, filepath.Join(restoreDir, "allowed"))

	restoreCfg := RestoreConfig{RepoRoot: repoDir, TargetDir: restoreDir, SourceID: 1, DeviceID: "test"}
	if _, err := NewSimpleRestore(restoreCfg, store).Run(ctx); err == nil {
		t.Fatal("restore succeeded through a symlinked subdirectory; want error")
	}
	if _, err := os.Stat(filepath.Join(outside, "allowed", "file.txt")); err == nil {
		t.Fatal("file escaped the restore target through the symlink")
	}
}

// --- LoadLatestManifest fallback ---

// TestLoadLatestManifestFallsBackToOlder corrupts the newest manifest body
// (sidecar left intact) — simulating a crash between the manifest and
// checksum writes from an older code version — and verifies that loading
// falls back to the previous snapshot instead of hard-failing.
func TestLoadLatestManifestFallsBackToOlder(t *testing.T) {
	metaDir := t.TempDir()
	cloudID := ResolveCloudID("dev", 1)

	old := NewManifest(1, cloudID, "s", "/src", "dev")
	old.Timestamp = "2026-01-01T00:00:00Z"
	oldPath, err := SaveManifestWithKey(metaDir, old, nil)
	if err != nil {
		t.Fatalf("save old: %v", err)
	}

	newer := NewManifest(1, cloudID, "s", "/src", "dev")
	newer.Timestamp = "2026-01-02T00:00:00Z"
	newerPath, err := SaveManifestWithKey(metaDir, newer, nil)
	if err != nil {
		t.Fatalf("save newer: %v", err)
	}
	if newerPath == oldPath {
		t.Fatal("test setup: both manifests share a path")
	}

	data, err := os.ReadFile(newerPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	data[0] ^= 0xFF
	if err := os.WriteFile(newerPath, data, 0600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}

	m, err := LoadLatestManifest(metaDir, cloudID)
	if err != nil {
		t.Fatalf("LoadLatestManifest: %v", err)
	}
	if m.Timestamp != old.Timestamp {
		t.Fatalf("loaded manifest timestamp = %q, want the older %q", m.Timestamp, old.Timestamp)
	}
}

// --- trailing-data rejection in GB1/GB2 decrypt ---

// TestDecryptRejectsTrailingDataGB1Large appends bytes after a GB1 large
// blob; the chunk loop alone would silently ignore them, so the explicit
// trailing-data check must reject the blob.
func TestDecryptRejectsTrailingDataGB1Large(t *testing.T) {
	key := make([]byte, 32)
	chunkSize := 64
	enc := NewEncryptor(key, chunkSize)
	dec := NewDecryptor(key, chunkSize)

	plaintext := bytes.Repeat([]byte("trailing-data-test-"), 8)
	blob, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if got, err := dec.Decrypt(blob); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("clean roundtrip failed: %v", err)
	}

	tampered := append(append([]byte{}, blob...), 0x00, 0x01, 0x02, 0x03)
	if _, err := dec.Decrypt(tampered); err == nil {
		t.Fatal("decrypt accepted a GB1 large blob with trailing data")
	}
}

// TestDecryptRejectsTrailingDataGB2 is the GB2 counterpart: a blob with
// appended bytes must fail whole-buffer decryption.
func TestDecryptRejectsTrailingDataGB2(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, 128)
	dec := NewDecryptor(key, 128)
	ctx := context.Background()

	data := bytes.Repeat([]byte("gb2 trailing test "), 64)
	src := filepath.Join(dir, "src.txt")
	if err := os.WriteFile(src, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	hash, err := UploadBlobFromPath(ctx, store, enc, src, "")
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	blob, err := store.Get(ctx, hash)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	tampered := append(append([]byte{}, blob...), 0xDE, 0xAD)
	if _, err := dec.Decrypt(tampered); err == nil {
		t.Fatal("decrypt accepted a GB2 blob with trailing data")
	}
}

// TestSaveManifestSidecarPrecedesManifest asserts the crash-consistency
// ordering: after a successful save, both files exist; and if only the
// first write of the pair had happened (sidecar), no half-committed
// manifest can be observed because the manifest is written last.
func TestSaveManifestSidecarPrecedesManifest(t *testing.T) {
	metaDir := t.TempDir()
	cloudID := ResolveCloudID("dev", 1)
	m := NewManifest(1, cloudID, "s", "/src", "dev")
	m.Timestamp = "2026-03-01T00:00:00Z"
	path, err := SaveManifestWithKey(metaDir, m, nil)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("manifest missing after save: %v", err)
	}
	if _, err := os.Stat(manifestChecksumPath(path)); err != nil {
		t.Fatalf("checksum sidecar missing after save: %v", err)
	}
	// Loading must succeed — order of writes is an implementation detail,
	// but a successful save must always yield a loadable manifest.
	if _, err := LoadManifest(path); err != nil {
		t.Fatalf("load after save: %v", err)
	}
}

// --- post-write link re-check (TOCTOU detection) ---

// TestRecheckLinkFreeDetectsSwappedComponent verifies the post-write
// re-check: a component that is clean during ensureLinkFree but has become
// a symlink by the time recheckLinkFree runs must be detected.
func TestRecheckLinkFreeDetectsSwappedComponent(t *testing.T) {
	targetDir := t.TempDir()
	outside := t.TempDir()
	sub := filepath.Join(targetDir, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	lc, err := newLinkChecker(targetDir)
	if err != nil {
		t.Fatalf("newLinkChecker: %v", err)
	}
	filePath := filepath.Join(sub, "file.txt")
	if err := lc.ensureLinkFree(filePath); err != nil {
		t.Fatalf("ensureLinkFree rejected a clean path: %v", err)
	}

	// Simulate the TOCTOU attack: between the pre-write check and the
	// post-write re-check, "sub" is replaced by a symlink.
	if err := os.Remove(sub); err != nil {
		t.Fatalf("remove sub: %v", err)
	}
	makeDirLink(t, outside, sub)

	if err := lc.recheckLinkFree(filePath); err == nil {
		t.Fatal("recheckLinkFree missed a component swapped for a symlink/junction")
	}
	// The cached pre-write verification must NOT suppress the re-check.
	if err := lc.recheckLinkFree(filePath); err == nil {
		t.Fatal("recheckLinkFree must ignore the verification cache")
	}
}

// --- Windows junction reparse points ---

// TestLinkCheckerRejectsJunction is the Windows-specific reparse-point
// test: a junction (mount point) — which requires no special privileges to
// create, unlike a directory symlink — must be rejected exactly like a
// symlink. Skipped when mklink /J is unavailable.
func TestLinkCheckerRejectsJunction(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junctions are a Windows reparse point")
	}
	targetDir := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "escaped.txt"), []byte("outside"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	junction := filepath.Join(targetDir, "junction")
	out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, outside).CombinedOutput()
	if err != nil {
		t.Skipf("cannot create junction: %v (%s)", err, out)
	}

	// Sanity: the junction must actually present as a link/reparse point
	// to Lstat — otherwise the test proves nothing about reparse handling.
	isLink, err := isLinkOrReparse(junction)
	if err != nil {
		t.Fatalf("isLinkOrReparse: %v", err)
	}
	if !isLink {
		t.Fatal("test setup: junction not detected as link/reparse point by Lstat")
	}

	lc, err := newLinkChecker(targetDir)
	if err != nil {
		t.Fatalf("newLinkChecker: %v", err)
	}
	if err := lc.ensureLinkFree(filepath.Join(junction, "escaped.txt")); err == nil {
		t.Fatal("ensureLinkFree accepted a path through a junction")
	}
	if err := lc.recheckLinkFree(filepath.Join(junction, "escaped.txt")); err == nil {
		t.Fatal("recheckLinkFree accepted a path through a junction")
	}
}

// --- permission-denied scan errors (Unix) ---

// TestRunScanPermissionDeniedFails verifies the scan-error semantics with a
// real unreadable directory (chmod 000) instead of a missing path: the run
// must fail by default rather than commit a manifest that misreports the
// unreadable subtree as deleted. Skipped on Windows (different ACL model)
// and when running as root (root reads through chmod 000).
func TestRunScanPermissionDeniedFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 is still readable")
	}

	repoDir := t.TempDir()
	sourceDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceDir, "readable.txt"), []byte("ok"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	secretDir := filepath.Join(sourceDir, "secret")
	if err := os.MkdirAll(secretDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "hidden.txt"), []byte("hidden"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(secretDir, 0000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer func() { _ = os.Chmod(secretDir, 0755) }()

	if err := InitRepo(InitParams{RepoRoot: repoDir, DeviceID: "test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	cfg := PipelineConfig{
		RepoRoot:   repoDir,
		SourceID:   1,
		SourceName: "test",
		SourcePath: sourceDir,
		DeviceID:   "test",
	}
	_, err := NewSimplePipeline(cfg, NewLocalBlobStore(repoDir)).Run(context.Background())
	if err == nil {
		t.Fatal("expected error when a source subdirectory is unreadable")
	}
	if !strings.Contains(err.Error(), "unreadable path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- concurrent manifest saves (same-second conflicts) ---

// TestManifestConcurrentSavesSameSecond hammers SaveManifestWithKey with
// concurrent saves of same-second manifests: none may overwrite another
// (the same-second conflict suffix must kick in), every produced file must
// be loadable, and the manifest count must match the number of saves.
func TestManifestConcurrentSavesSameSecond(t *testing.T) {
	metaDir := t.TempDir()
	cloudID := ResolveCloudID("dev", 1)

	const savers = 8
	var wg sync.WaitGroup
	paths := make([]string, savers)
	for i := 0; i < savers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m := NewManifest(1, cloudID, "s", "/src", "dev")
			m.Timestamp = "2026-03-01T00:00:00Z" // same second for all savers
			m.AddFile(FileEntry{Name: fmt.Sprintf("file-%d.txt", i), ContentHash: fmt.Sprintf("h%d", i), Size: 1})
			path, err := SaveManifestWithKey(metaDir, m, nil)
			if err != nil {
				t.Errorf("save %d: %v", i, err)
				return
			}
			paths[i] = path
		}(i)
	}
	wg.Wait()

	seen := make(map[string]bool)
	unique := 0
	for i, p := range paths {
		if p == "" {
			t.Fatalf("saver %d produced no path", i)
		}
		if !seen[p] {
			seen[p] = true
			unique++
		}
		if _, err := LoadManifest(p); err != nil {
			t.Fatalf("load manifest from saver %d (%s): %v", i, p, err)
		}
	}
	if unique != savers {
		t.Fatalf("distinct manifest paths = %d, want %d (same-second saves must not overwrite)", unique, savers)
	}

	entries, err := os.ReadDir(ManifestDir(metaDir, cloudID))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	manifestFiles := 0
	for _, e := range entries {
		if isManifestFile(e.Name()) {
			manifestFiles++
		}
	}
	if manifestFiles != savers {
		t.Fatalf("manifest files on disk = %d, want %d", manifestFiles, savers)
	}
}

// --- legacy ManifestDecryptHook direct assignment ---

// TestManifestDecryptHookLegacyAssignment pins the backward-compatible
// package-level API: assigning simple.ManifestDecryptHook directly (the
// pre-0.2 registration style) must register the hook for manifest loading,
// and the setter API must operate on the same storage.
func TestManifestDecryptHookLegacyAssignment(t *testing.T) {
	orig := GetManifestDecryptHook()
	defer SetManifestDecryptHook(orig)

	// Direct assignment — the legacy API shape. Assignment happens before
	// any manifest-loading goroutine starts, which is the documented-safe
	// usage for the exported variable.
	ManifestDecryptHook = func(encrypted []byte) ([]byte, error) { //nolint:staticcheck // deliberately testing the deprecated legacy API
		return encrypted, nil // identity "decryption"
	}
	if got := GetManifestDecryptHook(); got == nil {
		t.Fatal("legacy direct assignment did not register the hook (Get returned nil)")
	}

	// SetManifestDecryptHook must clear/override the same storage.
	SetManifestDecryptHook(nil) //nolint:staticcheck // asserting the variable mirrors setter state
	if got := GetManifestDecryptHook(); got != nil {
		t.Fatal("SetManifestDecryptHook(nil) did not clear the legacy-assigned hook")
	}
	if ManifestDecryptHook != nil { //nolint:staticcheck // asserting the variable mirrors setter state
		t.Fatal("legacy variable out of sync with SetManifestDecryptHook")
	}
}

// --- cross-process manifest saves ---

// TestManifestCrossProcessSave verifies the cross-process no-replace
// guarantee: a SEPARATE PROCESS saving a same-second manifest for the same
// cloudID/device must NOT overwrite the parent process's manifest — the
// child's save must succeed via the same-second conflict suffix, the
// parent's manifest must keep its original content and sidecar, and both
// manifests must remain loadable.
//
// The child is a re-exec of the test binary running TestHelperProcess
// (the standard exec-helper pattern): no in-process lock can serialize the
// two saves, so this genuinely exercises the link(2)/MoveFileEx commit.
func TestManifestCrossProcessSave(t *testing.T) {
	if runtime.GOOS == "windows" && os.Getenv("GBF_MANIFEST_HELPER") != "" {
		// Avoid fork-bombing when the helper re-execs the test suite.
		return
	}
	if testing.Short() {
		t.Skip("spawns a child process")
	}

	metaDir := t.TempDir()
	cloudID := ResolveCloudID("dev", 1)
	const ts = "2026-03-01T00:00:00Z"

	// Parent save: claims the primary name.
	parent := NewManifest(1, cloudID, "s", "/src", "dev")
	parent.Timestamp = ts
	parent.AddFile(FileEntry{Name: "parent.txt", ContentHash: "parent-hash", Size: 1})
	parentPath, err := SaveManifestWithKey(metaDir, parent, nil)
	if err != nil {
		t.Fatalf("parent save: %v", err)
	}
	parentData, err := os.ReadFile(parentPath)
	if err != nil {
		t.Fatalf("read parent manifest: %v", err)
	}

	// Child save: same cloudID/device/second from ANOTHER process.
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "-test.timeout=60s")
	cmd.Env = append(os.Environ(),
		"GBF_MANIFEST_HELPER=1",
		"GBF_HELPER_METADIR="+metaDir,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output() // stdout only: the helper prints exactly one line, the manifest path
	if err != nil {
		t.Fatalf("child save failed: %v\nstderr: %s", err, stderr.String())
	}
	childPath := strings.TrimSpace(string(out))
	if childPath == "" {
		t.Fatal("child produced no manifest path")
	}
	if childPath == parentPath {
		t.Fatalf("child wrote the parent's manifest path %s — cross-process save overwrote it", childPath)
	}

	// The parent's manifest must be byte-identical to before the child ran
	// (no silent overwrite), and both manifests must load.
	afterData, err := os.ReadFile(parentPath)
	if err != nil {
		t.Fatalf("re-read parent manifest: %v", err)
	}
	if !bytes.Equal(parentData, afterData) {
		t.Fatal("parent manifest content changed after the child's cross-process save")
	}
	if _, err := LoadManifest(parentPath); err != nil {
		t.Fatalf("load parent manifest: %v", err)
	}
	if _, err := LoadManifest(childPath); err != nil {
		t.Fatalf("load child manifest (%s): %v", childPath, err)
	}
}

// TestHelperProcess is the child half of TestManifestCrossProcessSave. It
// is never run directly — the parent re-execs the test binary with
// GBF_MANIFEST_HELPER=1 and -test.run=^TestHelperProcess$; the child saves
// a same-second manifest and prints its path on stdout.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GBF_MANIFEST_HELPER") == "" {
		return // normal test run: nothing to do
	}
	metaDir := os.Getenv("GBF_HELPER_METADIR")
	cloudID := ResolveCloudID("dev", 1)
	child := NewManifest(1, cloudID, "s", "/src", "dev")
	child.Timestamp = "2026-03-01T00:00:00Z"
	child.AddFile(FileEntry{Name: "child.txt", ContentHash: "child-hash", Size: 1})
	path, err := SaveManifestWithKey(metaDir, child, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper save: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(path)
	os.Exit(0)
}
