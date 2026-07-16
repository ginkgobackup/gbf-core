// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ginkgobackup/gbf-core/fsutil"
	"github.com/google/uuid"
)

type RepoConfig struct {
	Version         int    `json:"version"`
	Format          string `json:"format"`
	RepositoryID    string `json:"repositoryId"`
	Encrypted       bool   `json:"encrypted"`
	HashAlgorithm   string `json:"hashAlgorithm"`
	CipherAlgorithm string `json:"cipherAlgorithm"`
	// ChunkSize is deprecated and never read: the engine always operates at
	// DefaultChunkSize (4 MiB). The GB1 large-blob wire format stores no
	// chunk-size metadata — chunk boundaries are implicit, so encryptor and
	// decryptor must agree on the chunk size a priori — which makes a
	// per-repo configurable chunk size unsafe to honor for reading existing
	// blobs. The field is kept only so config files written by older
	// versions still parse; DefaultConfig keeps writing DefaultChunkSize.
	// Deprecated: do not use; the effective chunk size is DefaultChunkSize.
	ChunkSize       int    `json:"chunkSize"`
	DisableCDC      bool   `json:"disable_cdc,omitempty"`
	// CDCPolynomial is the content-defined chunking polynomial persisted
	// at repo init. Each repo derives its own polynomial so chunk boundaries
	// are stable for that repo but not shared across all installations.
	CDCPolynomial uint64 `json:"cdcPolynomial,omitempty"`
	Created       string `json:"created"`
	DeviceID      string `json:"deviceId"`
}

const (
	FormatGBF         = "gbf"
	FormatGBLegacy    = "gb"
	DefaultChunkSize  = 4 * 1024 * 1024
	DefaultHashAlgo   = "sha256"
	DefaultCipherAlgo = "aes-256-gcm"
	ConfigVersion     = 1
	MetaDirName       = ".ginkgo-backup"
)

func MetaDir(repoRoot string) string {
	return filepath.Join(repoRoot, MetaDirName)
}

func ConfigPath(repoRoot string) string {
	return filepath.Join(MetaDir(repoRoot), "config.json")
}

func DefaultConfig(deviceID string) *RepoConfig {
	return &RepoConfig{
		Version:         ConfigVersion,
		Format:          FormatGBF,
		RepositoryID:    uuid.New().String(),
		Encrypted:       false,
		HashAlgorithm:   DefaultHashAlgo,
		CipherAlgorithm: DefaultCipherAlgo,
		ChunkSize:       DefaultChunkSize,
		Created:         time.Now().UTC().Format(time.RFC3339),
		DeviceID:        deviceID,
	}
}

func SaveConfig(repoRoot string, cfg *RepoConfig) error {
	path := ConfigPath(repoRoot)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := fsutil.WriteFileAtomic(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func LoadConfig(repoRoot string) (*RepoConfig, error) {
	path := ConfigPath(repoRoot)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	var cfg RepoConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &cfg, nil
}

func ManifestsDir(metaDir string) string {
	return filepath.Join(metaDir, "manifests")
}

func IsGBRepo(repoRoot string) bool {
	cfg, err := LoadConfig(repoRoot)
	if err == nil && (cfg.Format == FormatGBF || cfg.Format == FormatGBLegacy) {
		return true
	}
	manifestsDir := ManifestsDir(MetaDir(repoRoot))
	if entries, err := os.ReadDir(manifestsDir); err == nil && len(entries) > 0 {
		return true
	}
	return false
}
