// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"context"
	"io"
)

type BlobInfo struct {
	Hash    string
	ModTime int64
	Size    int64
}

type SimpleBlobStore interface {
	Put(ctx context.Context, hash string, data []byte) error
	Get(ctx context.Context, hash string) ([]byte, error)
	PutStream(ctx context.Context, hash string, r io.Reader, size int64) error
	GetStream(ctx context.Context, hash string) (io.ReadCloser, error)
	Exists(ctx context.Context, hash string) (bool, error)
	List(ctx context.Context, prefix string) ([]string, error)
	ListWithModTime(ctx context.Context, prefix string) ([]BlobInfo, error)
	Delete(ctx context.Context, hash string) error
	Close() error
}
