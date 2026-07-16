// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package compress

import (
	"errors"
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

// MaxDecompressedSize caps the output of every chunk Decompress call.
// CDC chunks are bounded by cdcMaxSize (16 MiB), but small files (< 50 MiB
// streaming threshold) may be stored as a single blob without chunking, so
// we need a larger cap. 128 MiB safely handles legitimate files while still
// blocking extreme compression bombs. Manifests use MaxManifestDecompressedSize.
const MaxDecompressedSize = 128 * 1024 * 1024

// MaxManifestDecompressedSize caps the output of manifest (and manifest-like
// metadata such as alive indexes and source registries) decompression.
// Manifests are written by the application itself — checksum-verified and
// optionally encrypted — so the compression-bomb threat that justifies the
// tight chunk cap does not apply here. A source with millions of files
// produces a manifest well beyond 4 MiB (e.g. ~200k files ≈ 60 MiB), so we
// allow up to 256 MiB: comfortably above any realistic single-source
// manifest while still bounding peak memory.
const MaxManifestDecompressedSize = 256 * 1024 * 1024

// ErrDecompressedTooLarge is returned when a chunk Decompress call would
// produce more than MaxDecompressedSize bytes.
var ErrDecompressedTooLarge = fmt.Errorf("decompressed output exceeds %d bytes", MaxDecompressedSize)

// ErrManifestDecompressedTooLarge is returned when a manifest decompress
// call would produce more than MaxManifestDecompressedSize bytes. The
// distinct sentinel and message make manifest-size problems easy to
// distinguish from chunk compression-bomb defense.
var ErrManifestDecompressedTooLarge = fmt.Errorf("manifest exceeds decompression limit %d bytes", MaxManifestDecompressedSize)

type Compressor interface {
	Type() CompressorType
	Compress(data []byte) ([]byte, error)
	Decompress(data []byte) ([]byte, error)
	IsCompressed(data []byte) bool
}

type ZstdCompressor struct {
	level       int
	maxOutput   int64
	tooLargeErr error
	encs        chan *zstd.Encoder
	decs        chan *zstd.Decoder
}

func NewZstdCompressor(level int) *ZstdCompressor {
	return NewZstdCompressorWithLimit(level, MaxDecompressedSize, ErrDecompressedTooLarge)
}

// NewZstdCompressorWithLimit creates a zstd compressor whose Decompress
// allows up to maxOutput bytes of decompressed data and returns tooLargeErr
// when that limit is exceeded. Use this for application-written payloads
// (manifests, alive indexes, source registries) that legitimately exceed
// the chunk cap — pass MaxManifestDecompressedSize and
// ErrManifestDecompressedTooLarge. For chunk/blob decompression, prefer
// NewZstdCompressor which uses the compression-bomb-defense default.
func NewZstdCompressorWithLimit(level int, maxOutput int64, tooLargeErr error) *ZstdCompressor {
	if level < 1 || level > 22 {
		level = 1
	}
	if maxOutput <= 0 {
		maxOutput = MaxDecompressedSize
	}
	if tooLargeErr == nil {
		tooLargeErr = ErrDecompressedTooLarge
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
		// For manifest compressors the cap is raised to maxOutput so large
		// sources (hundreds of thousands of files) can still be loaded.
		dec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(uint64(maxOutput)))
		if err != nil {
			panic(fmt.Sprintf("compress: create zstd decoder: %v", err))
		}
		encs <- enc
		decs <- dec
	}
	return &ZstdCompressor{level: level, maxOutput: maxOutput, tooLargeErr: tooLargeErr, encs: encs, decs: decs}
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
		// Only resource-limit failures map to the too-large sentinel:
		// ErrDecoderSizeExceeded is the WithDecoderMaxMemory cap, and
		// ErrWindowSizeExceeded is the derived max-window cap (the window
		// memory a stream would force us to allocate). Everything else is
		// an ordinary decode failure (corruption, truncated input, bad
		// magic) and must surface as-is — previously any failure with
		// non-empty input was misreported as a compression bomb.
		if errors.Is(err, zstd.ErrDecoderSizeExceeded) || errors.Is(err, zstd.ErrWindowSizeExceeded) {
			return nil, c.tooLargeErr
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
