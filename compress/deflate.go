// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package compress

import (
	"bytes"
	"compress/zlib"
	"io"
)

type DeflateCompressor struct {
	level int
}

func NewDeflateCompressor(level int) *DeflateCompressor {
	if level < 1 || level > 9 {
		level = 9
	}
	return &DeflateCompressor{level: level}
}

func (c *DeflateCompressor) Type() CompressorType { return CompressDeflate }

func (c *DeflateCompressor) Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, c.level)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		w.Close()
		return nil, err
	}
	w.Close()
	return buf.Bytes(), nil
}

func (c *DeflateCompressor) Decompress(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	// Cap output to prevent compression bombs. io.LimitReader returns
	// MaxDecompressedSize+1 bytes when the stream exceeds the cap, which
	// we detect and reject.
	lr := io.LimitReader(r, MaxDecompressedSize+1)
	decompressed, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if len(decompressed) > MaxDecompressedSize {
		return nil, ErrDecompressedTooLarge
	}
	return decompressed, nil
}

// zlib header starts with 0x78 followed by a flag byte.
func (c *DeflateCompressor) IsCompressed(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x78
}
