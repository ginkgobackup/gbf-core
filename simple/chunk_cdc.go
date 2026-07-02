// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"os"

	"github.com/restic/chunker"
)

const (
	cdcAverageBits = 22               // ~4 MiB average chunk size
	cdcMinSize     = 1 * 1024 * 1024  // 1 MiB
	cdcMaxSize     = 16 * 1024 * 1024 // 16 MiB
)

var cdcPolynomial chunker.Pol

func init() {
	pol, err := chunker.DerivePolynomial(rand.New(rand.NewSource(0x123456789ABCDEF)))
	if err != nil {
		panic(fmt.Sprintf("derive cdc polynomial: %v", err))
	}
	cdcPolynomial = pol
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

func (p *SimplePipeline) hashFileWithCDC(ctx context.Context, filePath string, size int64) (string, []ChunkRef, error) {
	f, err := openFileWithRetry(ctx, filePath)
	if err != nil {
		return "", nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	c := chunker.NewWithBoundaries(f, cdcPolynomial, cdcMinSize, cdcMaxSize)
	c.SetAverageBits(cdcAverageBits)

	h := sha256.New()
	var chunks []ChunkRef
	buf := make([]byte, 0, cdcMaxSize)

	for {
		if ctx.Err() != nil {
			return "", nil, ctx.Err()
		}
		chunk, err := c.Next(buf[:0])
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, fmt.Errorf("chunk: %w", err)
		}
		data := chunk.Data
		h.Write(data)
		ch := sha256.Sum256(data)
		chunks = append(chunks, ChunkRef{
			Hash: hex.EncodeToString(ch[:]),
			Size: int64(len(data)),
		})
	}

	contentHash := hex.EncodeToString(h.Sum(nil))
	return contentHash, chunks, nil
}
