// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"context"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"github.com/restic/chunker"
)

const (
	cdcAverageBits = 22               // ~4 MiB average chunk size
	cdcMinSize     = 1 * 1024 * 1024  // 1 MiB
	cdcMaxSize     = 16 * 1024 * 1024 // 16 MiB
)

// cdcPolynomial is the global fallback CDC polynomial, stored atomically so
// concurrent pipelines reading the fallback (instances constructed without
// a per-instance polynomial) never race with SetCDCPolynomial. Pipelines
// created via NewSimplePipeline carry their own copy and don't read this.
var cdcPolynomial atomic.Uint64

// SetCDCPolynomial sets the CDC polynomial used for content-defined chunking.
// This must be called before any backup operation to ensure consistent
// chunk boundaries across incremental backups. The polynomial should be
// stored in the repo config and loaded at startup. The store is atomic and
// safe for concurrent use with pipelines reading the fallback polynomial.
func SetCDCPolynomial(pol uint64) {
	cdcPolynomial.Store(pol)
}

// LoadCDCPolynomial reads the persisted CDC polynomial from the repo config
// and returns it. Repos without a persisted polynomial (legacy v0.1) get a
// freshly derived one, which is persisted back to the config so subsequent
// runs stay consistent. The polynomial is returned to the caller rather
// than registered globally: pipelines must carry their own copy so two
// concurrent pipelines targeting different repos can never read each
// other's polynomial out of the package global.
func LoadCDCPolynomial(repoRoot string) (chunker.Pol, error) {
	cfg, err := LoadConfig(repoRoot)
	if err != nil {
		return 0, fmt.Errorf("load config for cdc polynomial: %w", err)
	}
	if cfg.CDCPolynomial == 0 {
		pol, err := GenerateCDCPolynomial()
		if err != nil {
			return 0, fmt.Errorf("derive fallback cdc polynomial: %w", err)
		}
		cfg.CDCPolynomial = pol
		if err := SaveConfig(repoRoot, cfg); err != nil {
			return 0, fmt.Errorf("persist fallback cdc polynomial: %w", err)
		}
	}
	return chunker.Pol(cfg.CDCPolynomial), nil
}

// LoadCDCPolynomialFromConfig reads the persisted CDC polynomial from the
// repo config and registers it globally via SetCDCPolynomial. Call this
// before running the backup pipeline against a repo so chunk boundaries
// match the polynomial the repo was initialized with.
//
// Kept for backward compatibility; new code should prefer LoadCDCPolynomial
// and hold the result per-instance — the global is shared state, so two
// pipelines targeting different repos can still observe each other's
// polynomial through the fallback read (the access itself is atomic and
// race-free, but the semantics remain last-writer-wins).
func LoadCDCPolynomialFromConfig(repoRoot string) error {
	pol, err := LoadCDCPolynomial(repoRoot)
	if err != nil {
		return err
	}
	SetCDCPolynomial(uint64(pol))
	return nil
}

// GenerateCDCPolynomial derives a random CDC polynomial from crypto/rand.
// Each repository should generate its own polynomial during initialization
// and persist it in the repo config to ensure stable chunk boundaries.
func GenerateCDCPolynomial() (uint64, error) {
	pol, err := chunker.DerivePolynomial(crypto_rand.Reader)
	if err != nil {
		return 0, fmt.Errorf("derive cdc polynomial: %w", err)
	}
	return uint64(pol), nil
}

func (p *SimplePipeline) cdcEnabled() bool {
	if os.Getenv("GINKGO_CDC") == "0" {
		return false
	}
	if os.Getenv("GINKGO_CDC") == "1" {
		return true
	}
	return !p.cfg.DisableCDC
}

// hashFileWithCDC content-hash chunks a file with CDC boundaries. When
// retain is true each chunk's plaintext is copied out and returned so the
// upload pass can store the exact hashed bytes without re-reading; the
// retention is abandoned mid-file if the file grew past
// inMemoryChunkThreshold since the scan (the chunk hashes stay valid —
// they describe the bytes actually read). The scratch buffer is pooled.
func (p *SimplePipeline) hashFileWithCDC(ctx context.Context, filePath string, size int64, retain bool) (string, []ChunkRef, [][]byte, error) {
	f, err := openFileWithRetry(ctx, filePath)
	if err != nil {
		return "", nil, nil, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Prefer the per-instance polynomial (set in NewSimplePipeline) so that
	// concurrent pipelines targeting different repos don't clobber each
	// other. Fall back to the global (read atomically) if the instance
	// wasn't initialized (e.g. tests constructing SimplePipeline directly
	// without going through NewSimplePipeline).
	pol := p.cdcPolynomial
	if pol == 0 {
		pol = chunker.Pol(cdcPolynomial.Load())
	}
	c := chunker.NewWithBoundaries(f, pol, cdcMinSize, cdcMaxSize)
	c.SetAverageBits(cdcAverageBits)

	h := sha256.New()
	var chunks []ChunkRef
	var retained [][]byte
	retainedBytes := 0
	bp := getChunkBuf(cdcMaxSize)
	defer putChunkBuf(bp)
	buf := (*bp)[:0]

	for {
		if ctx.Err() != nil {
			return "", nil, nil, ctx.Err()
		}
		chunk, err := c.Next(buf[:0])
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, nil, fmt.Errorf("chunk: %w", err)
		}
		data := chunk.Data
		h.Write(data)
		ch := sha256.Sum256(data)
		chunks = append(chunks, ChunkRef{
			Hash: hex.EncodeToString(ch[:]),
			Size: int64(len(data)),
		})
		if retain {
			if retainedBytes+len(data) > inMemoryChunkThreshold {
				// File grew beyond the threshold since the scan: drop the
				// retained bytes (the upload pass falls back to re-reading)
				// but keep hashing to complete the chunk list.
				retained = nil
				retain = false
				continue
			}
			cp := make([]byte, len(data))
			copy(cp, data)
			retained = append(retained, cp)
			retainedBytes += len(cp)
		}
	}

	contentHash := hex.EncodeToString(h.Sum(nil))
	return contentHash, chunks, retained, nil
}
