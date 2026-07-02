// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/ginkgobackup/gbf-core/compress"
)

type HashResult struct {
	Hash string
	Size int64
}

func SHA256File(path string) (*HashResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return nil, fmt.Errorf("hash: %w", err)
	}
	return &HashResult{
		Hash: hex.EncodeToString(h.Sum(nil)),
		Size: size,
	}, nil
}

func SHA256Bytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func UploadBlob(ctx context.Context, store SimpleBlobStore, enc *Encryptor, plaintext []byte) (string, error) {
	contentHash := SHA256Bytes(plaintext)
	exists, err := store.Exists(ctx, contentHash)
	if err != nil {
		return "", fmt.Errorf("exists check: %w", err)
	}
	if exists {
		return contentHash, nil
	}
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	if err := store.Put(ctx, contentHash, ciphertext); err != nil {
		return "", fmt.Errorf("put: %w", err)
	}
	return contentHash, nil
}

var defaultDecompressor = compress.NewZstdCompressor(1)

func DownloadBlob(ctx context.Context, store SimpleBlobStore, dec *Decryptor, hash string) ([]byte, error) {
	ciphertext, err := store.Get(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("get: %w", err)
	}
	plaintext, err := dec.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	if defaultDecompressor.IsCompressed(plaintext) {
		decompressed, derr := defaultDecompressor.Decompress(plaintext)
		if derr != nil {
			return nil, fmt.Errorf("decompress: %w", derr)
		}
		plaintext = decompressed
	}
	actualHash := SHA256Bytes(plaintext)
	if actualHash != hash {
		return nil, fmt.Errorf("hash mismatch: expected %s, got %s", hash, actualHash)
	}
	return plaintext, nil
}
