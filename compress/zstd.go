// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package compress

import (
	"runtime"

	"github.com/klauspost/compress/zstd"
)

type CompressorType string

const (
	CompressNone    CompressorType = "none"
	CompressZstd    CompressorType = "zstd"
	CompressS2      CompressorType = "s2"
	CompressDeflate CompressorType = "deflate"
)

type Compressor interface {
	Type() CompressorType
	Compress(data []byte) ([]byte, error)
	Decompress(data []byte) ([]byte, error)
	IsCompressed(data []byte) bool
}

type ZstdCompressor struct {
	level int
	encs  chan *zstd.Encoder
	decs  chan *zstd.Decoder
}

func NewZstdCompressor(level int) *ZstdCompressor {
	if level < 1 || level > 22 {
		level = 1
	}
	n := runtime.NumCPU()
	if n < 2 {
		n = 2
	}
	if n > 8 {
		n = 8
	}
	encs := make(chan *zstd.Encoder, n)
	decs := make(chan *zstd.Decoder, n)
	for i := 0; i < n; i++ {
		enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)))
		dec, _ := zstd.NewReader(nil)
		encs <- enc
		decs <- dec
	}
	return &ZstdCompressor{level: level, encs: encs, decs: decs}
}

func (c *ZstdCompressor) Type() CompressorType { return CompressZstd }

func (c *ZstdCompressor) Compress(data []byte) ([]byte, error) {
	enc := <-c.encs
	defer func() { c.encs <- enc }()
	outCap := len(data)
	if outCap > 65536 {
		outCap = len(data) / 2
	}
	compressed := enc.EncodeAll(data, make([]byte, 0, outCap))
	return compressed, nil
}

func (c *ZstdCompressor) Decompress(data []byte) ([]byte, error) {
	dec := <-c.decs
	defer func() { c.decs <- dec }()
	decompressed, err := dec.DecodeAll(data, nil)
	return decompressed, err
}

var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

func (c *ZstdCompressor) IsCompressed(data []byte) bool {
	return len(data) >= 4 && string(data[:4]) == string(zstdMagic)
}

func DefaultCompressor() *ZstdCompressor {
	return NewZstdCompressor(1)
}

func NewCompressor(ct CompressorType, level int) Compressor {
	switch ct {
	case CompressNone:
		return &NoneCompressor{}
	case CompressS2:
		return NewS2Compressor(level)
	case CompressDeflate:
		return NewDeflateCompressor(level)
	case CompressZstd:
		return NewZstdCompressor(level)
	default:
		return NewZstdCompressor(3)
	}
}
