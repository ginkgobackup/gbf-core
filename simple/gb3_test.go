// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// gb3TestChunkSize is deliberately tiny so the GB3 trigger (chunkCount >=
// MaxChunkCount) is reachable in a few MiB instead of the ~390 GiB a
// DefaultChunkSize blob would need. The format is chunk-size agnostic.
const gb3TestChunkSize = 64

// gb3TriggerSize returns a plaintext length whose chunk count at
// gb3TestChunkSize is just over MaxChunkCount, forcing the GB3 path.
func gb3TriggerSize() int {
	return MaxChunkCount*gb3TestChunkSize + gb3TestChunkSize
}

func gb3Pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + 7)
	}
	return b
}

func TestGB3HeaderRoundTrip(t *testing.T) {
	hdr := encodeGB3Header(GB3FlagChunkCompressed, GB3CompressZstd, 1<<20, 12345)
	if len(hdr) != GB3HeaderSize {
		t.Fatalf("header size = %d, want %d", len(hdr), GB3HeaderSize)
	}
	got, err := ParseGB3Header(hdr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Version != GB3Version {
		t.Errorf("version = %d, want %d", got.Version, GB3Version)
	}
	if got.Flags != GB3FlagChunkCompressed {
		t.Errorf("flags = %d, want %d", got.Flags, GB3FlagChunkCompressed)
	}
	if got.HashAlg != GB3HashSHA256 || got.EncryptionAlg != GB3EncryptAESGCM || got.ChunkingAlg != GB3ChunkingFixed {
		t.Errorf("algorithm descriptors = %d/%d/%d", got.HashAlg, got.EncryptionAlg, got.ChunkingAlg)
	}
	if got.CompressionAlg != GB3CompressZstd {
		t.Errorf("compression = %d, want %d", got.CompressionAlg, GB3CompressZstd)
	}
	if got.ChunkSize != 1<<20 {
		t.Errorf("chunk size = %d, want %d", got.ChunkSize, 1<<20)
	}
	if got.PlaintextSize != 12345 {
		t.Errorf("plaintext size = %d, want 12345", got.PlaintextSize)
	}
	if got.ChunkCount() != 1 {
		t.Errorf("chunk count = %d, want 1", got.ChunkCount())
	}
}

func TestParseGB3HeaderRejects(t *testing.T) {
	good := func() []byte { return encodeGB3Header(0, GB3CompressNone, 1024, 4096) }

	tests := []struct {
		name   string
		mutate func(h []byte) []byte
	}{
		{"too short", func(h []byte) []byte { return h[:GB3HeaderSize-1] }},
		{"bad magic", func(h []byte) []byte { h[0] = 'X'; return h }},
		{"bad version", func(h []byte) []byte { h[gb3OffVersion] = GB3Version + 1; return h }},
		{"bad hash alg", func(h []byte) []byte { h[gb3OffHashAlg] = 9; return h }},
		{"bad compression alg", func(h []byte) []byte { h[gb3OffCompressAlg] = 9; return h }},
		{"bad encryption alg", func(h []byte) []byte { h[gb3OffEncryptAlg] = 9; return h }},
		{"bad chunking alg", func(h []byte) []byte { h[gb3OffChunkingAlg] = 9; return h }},
		{"zero chunk size", func(h []byte) []byte {
			binary.BigEndian.PutUint32(h[gb3OffChunkSize:], 0)
			return h
		}},
		{"oversized chunk size", func(h []byte) []byte {
			binary.BigEndian.PutUint32(h[gb3OffChunkSize:], MaxGB3ChunkSize+1)
			return h
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseGB3Header(tt.mutate(good())); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestIsEncryptedBlob(t *testing.T) {
	tests := []struct {
		data []byte
		want bool
	}{
		{[]byte(MagicGB1), true},
		{[]byte(MagicGB2), true},
		{[]byte(MagicGB3), true},
		{[]byte(GKM1Magic), false},
		{[]byte("GB"), false},
		{nil, false},
	}
	for _, tt := range tests {
		if got := IsEncryptedBlob(tt.data); got != tt.want {
			t.Errorf("IsEncryptedBlob(%q) = %v, want %v", tt.data, got, tt.want)
		}
	}
}

// TestGB3EncryptDecryptRoundTrip drives the in-memory encryptor past the
// legacy chunk-count ceiling and checks the resulting GB3 blob decrypts
// byte-for-byte through the matching Decrypt path.
func TestGB3EncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 0x5A
	enc := NewEncryptor(key, gb3TestChunkSize)
	dec := NewDecryptor(key, gb3TestChunkSize)
	plaintext := gb3Pattern(gb3TriggerSize())

	blob, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if got := string(blob[:MagicSize]); got != MagicGB3 {
		t.Fatalf("magic = %q, want %q", got, MagicGB3)
	}
	hdr, err := ParseGB3Header(blob)
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	if hdr.ChunkSize != gb3TestChunkSize {
		t.Errorf("chunk size = %d, want %d", hdr.ChunkSize, gb3TestChunkSize)
	}
	if hdr.PlaintextSize != uint64(len(plaintext)) {
		t.Errorf("plaintext size = %d, want %d", hdr.PlaintextSize, len(plaintext))
	}
	if hdr.ChunkCount() <= MaxChunkCount {
		t.Errorf("chunk count = %d, want > %d", hdr.ChunkCount(), MaxChunkCount)
	}

	decrypted, err := dec.Decrypt(blob)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(decrypted), len(plaintext))
	}

	if through, err := DecryptIfEncrypted(blob, key); err != nil {
		t.Fatalf("DecryptIfEncrypted: %v", err)
	} else if !bytes.Equal(through, plaintext) {
		t.Fatal("DecryptIfEncrypted roundtrip mismatch")
	}
}

// TestGB3StreamRoundTrip covers the streaming writer/reader pair used by
// UploadBlobFromPath/DownloadBlobToFile when a blob is too large for the
// legacy header.
func TestGB3StreamRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 0x33
	enc := NewEncryptor(key, gb3TestChunkSize)
	dec := NewDecryptor(key, gb3TestChunkSize)

	data := gb3Pattern(gb3TriggerSize())
	srcPath := filepath.Join(t.TempDir(), "gb3-stream.bin")
	if err := os.WriteFile(srcPath, data, 0644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	f, err := os.Open(srcPath)
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	defer func() { _ = f.Close() }()

	var blob bytes.Buffer
	if err := encryptFileToWriter(enc, f, &blob, nil, nil); err != nil {
		t.Fatalf("encryptFileToWriter: %v", err)
	}
	if got := string(blob.Bytes()[:MagicSize]); got != MagicGB3 {
		t.Fatalf("magic = %q, want %q", got, MagicGB3)
	}

	var out bytes.Buffer
	if err := decryptStreamToFile(dec, bytes.NewReader(blob.Bytes()), &out); err != nil {
		t.Fatalf("decryptStreamToFile: %v", err)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("stream roundtrip mismatch: got %d bytes, want %d", out.Len(), len(data))
	}
}

// TestGB3StreamDecryptsCompressedChunks builds a GB3 blob by hand whose
// chunks carry the compressed flag and verifies the streaming decoder
// decompresses each one. The natural writer only compresses chunks of at
// least 64 KiB, which cannot co-occur with the tiny chunk size needed to
// reach MaxChunkCount in a test, so the blob is assembled manually.
func TestGB3StreamDecryptsCompressedChunks(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 0x77
	dec := NewDecryptor(key, gb3TestChunkSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}

	chunks := [][]byte{
		bytes.Repeat([]byte("compress me "), 6),
		[]byte("short tail"),
	}
	var plaintext []byte
	for _, c := range chunks {
		plaintext = append(plaintext, c...)
	}

	var blob bytes.Buffer
	blob.Write(encodeGB3Header(GB3FlagChunkCompressed, GB3CompressZstd, gb3TestChunkSize, uint64(len(plaintext))))
	for i, c := range chunks {
		compressed, cerr := defaultStreamCompressor.Compress(c)
		if cerr != nil {
			t.Fatalf("compress chunk %d: %v", i, cerr)
		}
		iv := make([]byte, IVSize)
		if _, err := rand.Read(iv); err != nil {
			t.Fatalf("iv: %v", err)
		}
		ct := gcm.Seal(nil, iv, compressed, nil)
		var sizeBuf [ChunkCountSize]byte
		binary.BigEndian.PutUint32(sizeBuf[:], uint32(len(ct)))
		blob.Write(sizeBuf[:])
		blob.WriteByte(GB3FlagChunkCompressed)
		blob.Write(iv)
		blob.Write(ct)
	}

	var out bytes.Buffer
	if err := decryptStreamToFile(dec, bytes.NewReader(blob.Bytes()), &out); err != nil {
		t.Fatalf("decryptStreamToFile: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Fatalf("compressed chunk roundtrip mismatch: got %q, want %q", out.Bytes(), plaintext)
	}
}

// TestGB3RejectsTrailingAndTamperedData ensures a GB3 blob is only accepted
// when it is complete and intact.
func TestGB3RejectsTrailingAndTamperedData(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 0x11
	enc := NewEncryptor(key, gb3TestChunkSize)
	dec := NewDecryptor(key, gb3TestChunkSize)

	blob, err := enc.Encrypt(gb3Pattern(gb3TriggerSize()))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	withTrailing := append(append([]byte{}, blob...), 0xAB)
	if _, err := dec.Decrypt(withTrailing); err == nil {
		t.Fatal("expected error for trailing data")
	}

	tampered := append([]byte{}, blob...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := dec.Decrypt(tampered); err == nil {
		t.Fatal("expected error for tampered chunk")
	}
}
