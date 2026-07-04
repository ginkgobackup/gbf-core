// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package compress

import (
	"bytes"
	"io"

	"github.com/klauspost/compress/s2"
)

type S2Compressor struct {
	level int
}

func NewS2Compressor(level int) *S2Compressor {
	if level < 0 || level > 1 {
		level = 1
	}
	return &S2Compressor{level: level}
}

func (c *S2Compressor) Type() CompressorType { return CompressS2 }

func (c *S2Compressor) Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	var w *s2.Writer
	if c.level == 1 {
		w = s2.NewWriter(&buf, s2.WriterBetterCompression())
	} else {
		w = s2.NewWriter(&buf)
	}
	if _, err := w.Write(data); err != nil {
		w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *S2Compressor) Decompress(data []byte) ([]byte, error) {
	r := s2.NewReader(bytes.NewReader(data))
	// Cap output to prevent compression bombs.
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

// s2 stream magic bytes (two variants supported by the reader).
// The S2 stream identifier chunk is 4 bytes of chunk header followed by
// 6 bytes of identifier ("S2sTwO" or "sNaPpY"), for a 10-byte prefix.
var s2Magic = []byte("\xff\x06\x00\x00S2sTwO")
var s2MagicSnappy = []byte("\xff\x06\x00\x00sNaPpY")

func (c *S2Compressor) IsCompressed(data []byte) bool {
	if len(data) < 10 {
		return false
	}
	return string(data[:10]) == string(s2Magic) || string(data[:10]) == string(s2MagicSnappy)
}
