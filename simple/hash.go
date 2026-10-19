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
	defer func() { _ = f.Close() }()
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

// restoreDecompress reverses the optional pre-encryption compression step.
// Blobs of compressible content hold a zstd frame as their plaintext, while
// blobs of files that are already compressed (see isLikelyIncompressible)
// hold the file bytes verbatim. A user file that is itself a zstd frame —
// for example a .zst archive — therefore also starts with the zstd magic,
// and decompressing it would return data the user never stored.
//
// expectedHash disambiguates the two cases: when it is available the stored
// plaintext is accepted as-is if it already hashes to it, and decompressed
// bytes are accepted only when THEY hash to it. Otherwise the original
// plaintext is returned and the caller's existing hash check fails the
// restore, so a corrupt or wrong-object blob is still rejected. With no
// expected hash (legacy callers) every detected frame is decompressed,
// preserving the historical behavior.
func restoreDecompress(plaintext []byte, expectedHash string) ([]byte, error) {
	if !defaultDecompressor.IsCompressed(plaintext) {
		return plaintext, nil
	}
	if expectedHash == "" {
		decompressed, err := defaultDecompressor.Decompress(plaintext)
		if err != nil {
			return nil, fmt.Errorf("decompress: %w", err)
		}
		return decompressed, nil
	}
	if SHA256Bytes(plaintext) == expectedHash {
		return plaintext, nil
	}
	decompressed, err := defaultDecompressor.Decompress(plaintext)
	if err == nil && SHA256Bytes(decompressed) == expectedHash {
		return decompressed, nil
	}
	return plaintext, nil
}

func DownloadBlob(ctx context.Context, store SimpleBlobStore, dec *Decryptor, hash string) ([]byte, error) {
	ciphertext, err := store.Get(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("get: %w", err)
	}
	plaintext, err := dec.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	plaintext, err = restoreDecompress(plaintext, hash)
	if err != nil {
		return nil, err
	}
	actualHash := SHA256Bytes(plaintext)
	if actualHash != hash {
		return nil, fmt.Errorf("hash mismatch: expected %s, got %s", hash, actualHash)
	}
	return plaintext, nil
}
