// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package compress

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestNoneCompressorRoundtrip(t *testing.T) {
	c := &NoneCompressor{}
	if c.Type() != CompressNone {
		t.Fatalf("Type: got %q, want %q", c.Type(), CompressNone)
	}
	data := []byte("any data at all")
	compressed, err := c.Compress(data)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	if !bytes.Equal(compressed, data) {
		t.Fatalf("none should return input unchanged: got %q, want %q", compressed, data)
	}
	decompressed, err := c.Decompress(compressed)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(decompressed, data) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", decompressed, data)
	}
	if c.IsCompressed(data) {
		t.Fatal("NoneCompressor.IsCompressed should always return false")
	}
}

func TestZstdCompressorRoundtrip(t *testing.T) {
	c := NewZstdCompressor(3)
	if c.Type() != CompressZstd {
		t.Fatalf("Type: got %q, want %q", c.Type(), CompressZstd)
	}
	data := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog. ", 1000))
	compressed, err := c.Compress(data)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	if len(compressed) >= len(data) {
		t.Fatalf("zstd should reduce compressible data: got %d bytes, input %d", len(compressed), len(data))
	}
	if !c.IsCompressed(compressed) {
		t.Fatal("IsCompressed should detect zstd magic")
	}
	decompressed, err := c.Decompress(compressed)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(decompressed, data) {
		t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(decompressed), len(data))
	}
}

func TestZstdCompressorEmptyInput(t *testing.T) {
	c := NewZstdCompressor(1)
	compressed, err := c.Compress(nil)
	if err != nil {
		t.Fatalf("compress nil: %v", err)
	}
	decompressed, err := c.Decompress(compressed)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if len(decompressed) != 0 {
		t.Fatalf("empty roundtrip: got %d bytes, want 0", len(decompressed))
	}
}

func TestZstdCompressorLevelClamped(t *testing.T) {
	// Out-of-range levels should be clamped to 1, not panic.
	c := NewZstdCompressor(0)
	if c.level != 1 {
		t.Fatalf("level 0 should clamp to 1, got %d", c.level)
	}
	c = NewZstdCompressor(99)
	if c.level != 1 {
		t.Fatalf("level 99 should clamp to 1, got %d", c.level)
	}
}

func TestZstdDecompressGarbageReturnsError(t *testing.T) {
	c := NewZstdCompressor(1)
	_, err := c.Decompress([]byte("not zstd data at all"))
	if err == nil {
		t.Fatal("expected error decompressing non-zstd data")
	}
	if errors.Is(err, ErrDecompressedTooLarge) {
		t.Fatal("garbage input must not be misreported as exceeding the size limit")
	}
}

// A corrupted-but-validly-framed zstd payload is a decode failure, not a
// compression bomb: it must not surface as ErrDecompressedTooLarge.
func TestZstdDecompressCorruptedDataNotReportedAsTooLarge(t *testing.T) {
	c := NewZstdCompressor(1)
	data := []byte(strings.Repeat("compressible payload for corruption test. ", 500))
	compressed, err := c.Compress(data)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	corrupted := bytes.Clone(compressed)
	corrupted[len(corrupted)/2] ^= 0xFF
	corrupted[len(corrupted)-2] ^= 0xFF
	_, err = c.Decompress(corrupted)
	if err == nil {
		t.Fatal("expected error decompressing corrupted data")
	}
	if errors.Is(err, ErrDecompressedTooLarge) {
		t.Fatalf("corrupted data must surface as a decode error, got size-limit sentinel: %v", err)
	}
}

// A payload whose decompressed size genuinely exceeds the configured cap
// must still map to the too-large sentinel.
func TestZstdDecompressOverLimitReturnsSentinel(t *testing.T) {
	c := NewZstdCompressorWithLimit(1, 1024, ErrDecompressedTooLarge)
	compressed, err := c.Compress(make([]byte, 64*1024))
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	_, err = c.Decompress(compressed)
	if !errors.Is(err, ErrDecompressedTooLarge) {
		t.Fatalf("expected ErrDecompressedTooLarge, got %v", err)
	}
}

func TestZstdIsCompressedRejectsForeignMagic(t *testing.T) {
	c := NewZstdCompressor(1)
	if c.IsCompressed([]byte{0x28, 0xb5, 0x2f, 0xfe}) {
		t.Fatal("IsCompressed should reject mismatched 4th byte")
	}
	if c.IsCompressed([]byte{0x28, 0xb5, 0x2f}) {
		t.Fatal("IsCompressed should reject short input")
	}
}

func TestDeflateCompressorRoundtrip(t *testing.T) {
	c := NewDeflateCompressor(9)
	if c.Type() != CompressDeflate {
		t.Fatalf("Type: got %q, want %q", c.Type(), CompressDeflate)
	}
	data := []byte(strings.Repeat("deflatable content ", 500))
	compressed, err := c.Compress(data)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	if len(compressed) >= len(data) {
		t.Fatalf("deflate should reduce compressible data: got %d, input %d", len(compressed), len(data))
	}
	if !c.IsCompressed(compressed) {
		t.Fatal("IsCompressed should detect zlib header")
	}
	decompressed, err := c.Decompress(compressed)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(decompressed, data) {
		t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(decompressed), len(data))
	}
}

func TestDeflateCompressorLevelClamped(t *testing.T) {
	c := NewDeflateCompressor(0)
	if c.level != 9 {
		t.Fatalf("level 0 should clamp to 9, got %d", c.level)
	}
	c = NewDeflateCompressor(15)
	if c.level != 9 {
		t.Fatalf("level 15 should clamp to 9, got %d", c.level)
	}
}

func TestS2CompressorRoundtrip(t *testing.T) {
	c := NewS2Compressor(1)
	if c.Type() != CompressS2 {
		t.Fatalf("Type: got %q, want %q", c.Type(), CompressS2)
	}
	data := []byte(strings.Repeat("s2 compressible payload ", 800))
	compressed, err := c.Compress(data)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	decompressed, err := c.Decompress(compressed)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(decompressed, data) {
		t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(decompressed), len(data))
	}
}

// TestS2IsCompressedOnSelfProducedOutput verifies that IsCompressed detects
// output produced by the same Compressor. If this fails, either the magic
// check in s2.go is wrong or the writer is producing output without the
// expected stream identifier.
func TestS2IsCompressedOnSelfProducedOutput(t *testing.T) {
	c := NewS2Compressor(1)
	data := []byte(strings.Repeat("s2 compressible payload ", 800))
	compressed, err := c.Compress(data)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	// S2 stream output should begin with the stream identifier chunk. If
	// this assertion fails, the source code in compress/s2.go needs review.
	if !c.IsCompressed(compressed) {
		t.Fatalf("IsCompressed does not detect own output (first bytes: % x)", compressed[:min(12, len(compressed))])
	}
}

func TestS2CompressorLevelClamped(t *testing.T) {
	c := NewS2Compressor(-1)
	if c.level != 1 {
		t.Fatalf("level -1 should clamp to 1, got %d", c.level)
	}
	c = NewS2Compressor(5)
	if c.level != 1 {
		t.Fatalf("level 5 should clamp to 1, got %d", c.level)
	}
}

func TestNewCompressorFactory(t *testing.T) {
	tests := []struct {
		ct   CompressorType
		want CompressorType
	}{
		{CompressNone, CompressNone},
		{CompressZstd, CompressZstd},
		{CompressDeflate, CompressDeflate},
		{CompressS2, CompressS2},
		{CompressorType("unknown"), CompressZstd}, // default falls back to zstd
	}
	for _, tt := range tests {
		c := NewCompressor(tt.ct, 1)
		if c.Type() != tt.want {
			t.Errorf("NewCompressor(%q): got %q, want %q", tt.ct, c.Type(), tt.want)
		}
	}
}

func TestDefaultCompressorIsZstd(t *testing.T) {
	c := DefaultCompressor()
	if c.Type() != CompressZstd {
		t.Fatalf("DefaultCompressor: got %q, want %q", c.Type(), CompressZstd)
	}
}
