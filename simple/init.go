// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"fmt"
	"os"
)

type InitParams struct {
	RepoRoot string
	DeviceID string
}

func InitRepo(params InitParams) error {
	if IsGBRepo(params.RepoRoot) {
		return fmt.Errorf("repository already initialized at %s", params.RepoRoot)
	}
	metaDir := MetaDir(params.RepoRoot)
	dirs := []string{
		metaDir,
		metaDir + "/manifests",
		params.RepoRoot + "/gb",
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	cfg := DefaultConfig(params.DeviceID)

	// Derive a per-repo CDC polynomial from crypto/rand so chunk boundaries
	// are stable for this repo but not shared with every other installation.
	pol, err := GenerateCDCPolynomial()
	if err != nil {
		return fmt.Errorf("derive cdc polynomial: %w", err)
	}
	cfg.CDCPolynomial = pol

	if err := SaveConfig(params.RepoRoot, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	return nil
}
