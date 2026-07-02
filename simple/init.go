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
	if err := SaveConfig(params.RepoRoot, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	return nil
}
