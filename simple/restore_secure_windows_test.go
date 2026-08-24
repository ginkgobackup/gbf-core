//go:build windows

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWinDirEnsureDirDetectsSwappedComponent pins the empty-directory
// defense on Windows: MkdirAll follows pre-existing symlink/junction
// components, so EnsureDir re-verifies all components AFTER the mkdir —
// a directory swapped for a link mid-restore must abort the skeleton pass.
func TestWinDirEnsureDirDetectsSwappedComponent(t *testing.T) {
	targetDir := t.TempDir()
	outside := t.TempDir()
	sub := filepath.Join(targetDir, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	root, err := openSecureDir(targetDir)
	if err != nil {
		t.Fatalf("openSecureDir: %v", err)
	}
	child, err := root.Child("sub")
	if err != nil {
		t.Fatalf("Child: %v", err)
	}

	// Swap the directory for a symlink/junction between Child() and
	// EnsureDir() (makeDirLink falls back to a junction — creating a
	// directory symlink on Windows needs developer mode/admin).
	if err := os.Remove(sub); err != nil {
		t.Fatalf("remove: %v", err)
	}
	makeDirLink(t, outside, sub)

	if err := child.EnsureDir(); err == nil {
		t.Fatal("EnsureDir accepted a directory swapped for a symlink (empty-dir TOCTOU not detected)")
	}
}
