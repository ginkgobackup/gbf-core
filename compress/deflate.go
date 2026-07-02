// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package compress

import (
	"bytes"
	"compress/flate"
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
	w, err := flate.NewWriter(&buf, c.level)
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
	r := flate.NewReader(bytes.NewReader(data))
	decompressed, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		return nil, err
	}
	return decompressed, nil
}

// zlib header starts with 0x78 followed by a flag byte.
func (c *DeflateCompressor) IsCompressed(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x78
}
