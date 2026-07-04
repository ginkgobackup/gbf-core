// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package compress

import (
	"fmt"
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

// MaxDecompressedSize caps the output of every Decompress call. Backed-up
// chunks are bounded by DefaultChunkSize, so legitimate payloads decompress
// to at most ~DefaultChunkSize. A crafted blob (compression bomb) could
// otherwise expand to gigabytes and OOM the process. The cap is generous
// (4 MiB) to allow for manifest payloads and future chunk-size changes.
const MaxDecompressedSize = 4 * 1024 * 1024

// ErrDecompressedTooLarge is returned when a Decompress call would produce
// more than MaxDecompressedSize bytes.
var ErrDecompressedTooLarge = fmt.Errorf("decompressed output exceeds %d bytes", MaxDecompressedSize)

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
		enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)), zstd.WithEncoderCRC(true))
		if err != nil {
			panic(fmt.Sprintf("compress: create zstd encoder: %v", err))
		}
		// WithDecoderMaxMemory caps the memory a crafted zstd stream is
		// allowed to allocate during decoding, blocking compression bombs.
		dec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(uint64(MaxDecompressedSize)))
		if err != nil {
			panic(fmt.Sprintf("compress: create zstd decoder: %v", err))
		}
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
	if err != nil {
		// zstd returns a generic "decompression failed" when the
		// WithDecoderMaxOutputSize cap is hit; normalize to our sentinel.
		if decompressed == nil && len(data) > 0 {
			return nil, ErrDecompressedTooLarge
		}
		return nil, err
	}
	return decompressed, nil
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
