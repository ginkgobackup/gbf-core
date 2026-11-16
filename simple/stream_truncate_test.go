// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestEncryptReaderToWriterRejectsTruncatedInput pins the guard added to
// the streaming encryptor: the chunk count/header is derived from the size
// observed by the scan, so a source that yields fewer bytes (the file shrank
// between scan and upload, or the reader ended early) must fail the upload
// instead of producing a blob whose header promises chunks that were never
// written.
func TestEncryptReaderToWriterRejectsTruncatedInput(t *testing.T) {
	const chunkSize = 1024
	content := bytes.Repeat([]byte("ginkgo"), 4096) // 4 chunks at 1 KiB

	tests := []struct {
		name string
		src  io.Reader
		size int64
		want string
	}{
		{
			name: "empty source",
			src:  bytes.NewReader(nil),
			size: int64(len(content)),
			want: "truncated",
		},
		{
			name: "partial chunk before the end",
			src:  io.LimitReader(bytes.NewReader(content), int64(8*chunkSize+500)),
			size: int64(len(content)),
			want: "unexpected EOF",
		},
		{
			name: "missing final chunks",
			src:  io.LimitReader(bytes.NewReader(content), int64(len(content))-chunkSize),
			size: int64(len(content)),
			want: "truncated",
		},
		{
			name: "short final chunk",
			src:  io.LimitReader(bytes.NewReader(content), int64(len(content))-1),
			size: int64(len(content)),
			want: "file size changed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewEncryptor(make([]byte, 32), chunkSize)
			var out bytes.Buffer
			err := encryptReaderToWriter(enc, tt.src, tt.size, &out, nil, nil)
			if err == nil {
				t.Fatal("expected truncated upload to fail")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

// TestEncryptReaderToWriterExactSize verifies the guard does not reject a
// source that delivers exactly the declared size, and that the resulting
// blob still decrypts back to the original plaintext.
func TestEncryptReaderToWriterExactSize(t *testing.T) {
	const chunkSize = 1024
	content := bytes.Repeat([]byte("ginkgo"), 4096)

	key := make([]byte, 32)
	enc := NewEncryptor(key, chunkSize)
	dec := NewDecryptor(key, chunkSize)

	var out bytes.Buffer
	if err := encryptReaderToWriter(enc, bytes.NewReader(content), int64(len(content)), &out, nil, nil); err != nil {
		t.Fatalf("exact-size upload failed: %v", err)
	}
	got, err := dec.Decrypt(out.Bytes())
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(got), len(content))
	}
}
