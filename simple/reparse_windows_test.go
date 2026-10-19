// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

//go:build windows

package simple

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func makeJunction(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Skipf("mklink /J unavailable: %v (%s)", err, out)
	}
}

func TestIsReparseLinkJunction(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	makeJunction(t, target, link)
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat junction: %v", err)
	}
	if !isReparseLink(info, link) {
		t.Fatal("junction was not recognized as a reparse link")
	}
}

func TestPipelineSkipsJunction(t *testing.T) {
	repo := t.TempDir()
	src := t.TempDir()
	if err := InitRepo(InitParams{RepoRoot: repo, DeviceID: "dev"}); err != nil {
		t.Fatalf("init repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "real.txt"), []byte("real"), 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	target := filepath.Join(src, "target")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "inside.txt"), []byte("inside"), 0644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(src, "link")
	makeJunction(t, target, link)

	p := NewSimplePipeline(PipelineConfig{
		RepoRoot:   repo,
		SourceID:   1,
		CloudID:    "dev/1",
		SourceName: "src",
		SourcePath: src,
		ScanPath:   src,
		DeviceID:   "dev",
		DataDir:    t.TempDir(),
	}, NewLocalBlobStore(repo))
	defer p.Close()
	result, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("pipeline run: %v", err)
	}
	if result.SkippedLinks == 0 {
		t.Fatal("junction was not skipped")
	}
}
