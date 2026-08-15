// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptorZeroLengthKey(t *testing.T) {
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	plaintext := []byte("small data with zero key")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	decrypted, err := dec.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptorInvalidMagic(t *testing.T) {
	key := make([]byte, 32)
	dec := NewDecryptor(key, DefaultChunkSize)
	data := []byte("XXXX" + string(make([]byte, 40)))
	_, err := dec.Decrypt(data)
	if err == nil {
		t.Fatal("expected error for invalid magic")
	}
}

func TestDecryptorTruncatedData(t *testing.T) {
	key := make([]byte, 32)
	dec := NewDecryptor(key, DefaultChunkSize)
	_, err := dec.Decrypt([]byte("GB"))
	if err == nil {
		t.Fatal("expected error for data too short")
	}
	_, err = dec.Decrypt([]byte(MagicGB1))
	if err == nil {
		t.Fatal("expected error for magic-only data")
	}
	_, err = dec.Decrypt(append([]byte(MagicGB1), make([]byte, 5)...))
	if err == nil {
		t.Fatal("expected error for small blob too short")
	}
}

func TestDecryptorWrongKeyLarge(t *testing.T) {
	key1 := make([]byte, 32)
	key1[0] = 0xAA
	key2 := make([]byte, 32)
	key2[0] = 0xBB
	enc := NewEncryptor(key1, DefaultChunkSize)
	dec := NewDecryptor(key2, DefaultChunkSize)
	plaintext := make([]byte, DefaultChunkSize*2+100)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	_, err = dec.Decrypt(ciphertext)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestEncryptDecryptManifestRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte(`{"source_id":1,"files":[{"path":"test.txt"}]}`)
	encrypted, err := EncryptManifest(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt manifest: %v", err)
	}
	if string(encrypted[:4]) != GKM1Magic {
		t.Fatalf("magic mismatch: got %q, want %q", encrypted[:4], GKM1Magic)
	}
	decrypted, err := DecryptManifest(encrypted, key)
	if err != nil {
		t.Fatalf("decrypt manifest: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptManifestWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 0xFF
	plaintext := []byte("manifest data")
	encrypted, err := EncryptManifest(plaintext, key1)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	_, err = DecryptManifest(encrypted, key2)
	if err == nil {
		t.Fatal("expected error decrypting manifest with wrong key")
	}
}

func TestDecryptManifestInvalidData(t *testing.T) {
	key := make([]byte, 32)
	_, err := DecryptManifest([]byte("NOPE"), key)
	if err == nil {
		t.Fatal("expected error for non-GKM1 data")
	}
	_, err = DecryptManifest([]byte("GKM"), key)
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestDecryptIfEncryptedGKM1(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("manifest content")
	encrypted, err := EncryptManifest(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	decrypted, err := DecryptIfEncrypted(encrypted, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptIfEncryptedGB1(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("blob content")
	enc := NewEncryptor(key, DefaultChunkSize)
	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	decrypted, err := DecryptIfEncrypted(encrypted, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptIfEncryptedPlain(t *testing.T) {
	key := make([]byte, 32)
	// Plaintext longer than MagicSize with bytes that don't match any known
	// magic should now error rather than silently passing through. This is
	// the C3.3 fix: an unknown 4-byte prefix is treated as a corrupted
	// encrypted blob, not as plaintext.
	plain := []byte("plain text data")
	_, err := DecryptIfEncrypted(plain, key)
	if err == nil {
		t.Fatal("expected error for plaintext with unknown magic prefix")
	}
}

func TestDecryptIfEncryptedShortData(t *testing.T) {
	key := make([]byte, 32)
	short := []byte("abc")
	result, err := DecryptIfEncrypted(short, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, short) {
		t.Fatalf("mismatch: got %q, want %q", result, short)
	}
}

func TestDecryptIfEncryptedEmptyKeyGB1(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("blob data")
	enc := NewEncryptor(key, DefaultChunkSize)
	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	_, err = DecryptIfEncrypted(encrypted, nil)
	if err == nil {
		t.Fatal("expected error for GB1 data with empty key")
	}
}

func TestDecryptIfEncryptedEmptyKeyPlain(t *testing.T) {
	// Same as TestDecryptIfEncryptedPlain: plaintext with unknown magic
	// prefix should error regardless of whether a key is provided.
	plain := []byte("plain data")
	_, err := DecryptIfEncrypted(plain, nil)
	if err == nil {
		t.Fatal("expected error for plaintext with unknown magic prefix")
	}
}

func TestIsChunkCount(t *testing.T) {
	tests := []struct {
		value uint32
		want  bool
	}{
		{0, false},
		{1, true},
		{99999, true},
		{100000, false},
		{100001, false},
	}
	for _, tt := range tests {
		buf := make([]byte, ChunkCountSize)
		binary.BigEndian.PutUint32(buf, tt.value)
		got := isChunkCount(buf)
		if got != tt.want {
			t.Errorf("isChunkCount(%d) = %v, want %v", tt.value, got, tt.want)
		}
	}
}

func TestIsChunkCountShortBuf(t *testing.T) {
	if isChunkCount([]byte{0, 0}) {
		t.Error("isChunkCount with short buffer should return false")
	}
}

func TestCustomChunkSize(t *testing.T) {
	key := make([]byte, 32)
	chunkSize := 1024
	enc := NewEncryptor(key, chunkSize)
	dec := NewDecryptor(key, chunkSize)
	plaintext := make([]byte, chunkSize*3+500)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	decrypted, err := dec.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("mismatch: length got %d, want %d", len(decrypted), len(plaintext))
	}
}

func TestCustomChunkSizeSmallData(t *testing.T) {
	key := make([]byte, 32)
	chunkSize := 1024
	enc := NewEncryptor(key, chunkSize)
	dec := NewDecryptor(key, chunkSize)
	plaintext := []byte("tiny")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	decrypted, err := dec.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEmptyPlaintextEncryption(t *testing.T) {
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	plaintext := []byte{}
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(ciphertext[:MagicSize]) != MagicGB1 {
		t.Fatalf("magic mismatch: got %q", ciphertext[:MagicSize])
	}
	decrypted, err := dec.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("mismatch: got %d bytes, want 0", len(decrypted))
	}
}

func TestDecryptStream(t *testing.T) {
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	plaintext := []byte("stream test data")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	r := bytes.NewReader(ciphertext)
	decrypted, err := dec.DecryptStream(r)
	if err != nil {
		t.Fatalf("decrypt stream: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// buildSmallBlobWithIV constructs a GB1 small blob with a caller-chosen IV,
// replicating what pre-rejection-sampling encoders could emit when the
// random IV's first 4 bytes landed in the chunk-count range (1..99999).
func buildSmallBlobWithIV(t *testing.T, key, plaintext, iv []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	blob := append([]byte(MagicGB1), iv...)
	blob = append(blob, gcm.Seal(nil, iv, plaintext, nil)...)
	return blob
}

// Regression test for the GB1 small/large heuristic ambiguity: a legacy
// small blob whose random IV looks like a chunk count must still decrypt —
// the decryptor falls back to the small interpretation when the large one
// fails AEAD authentication.
func TestDecryptGB1SmallBlobWithChunkCountIV(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	dec := NewDecryptor(key, DefaultChunkSize)
	plaintext := []byte("legacy small blob with an IV that looks like a chunk count")
	for _, count := range []uint32{1, 42, 99999} {
		iv := make([]byte, IVSize)
		binary.BigEndian.PutUint32(iv[:ChunkCountSize], count)
		for i := ChunkCountSize; i < IVSize; i++ {
			iv[i] = byte(i * 7)
		}
		if !isChunkCount(iv[:ChunkCountSize]) {
			t.Fatalf("test setup: iv %v not in chunk-count range", iv[:4])
		}
		blob := buildSmallBlobWithIV(t, key, plaintext, iv)
		decrypted, err := dec.Decrypt(blob)
		if err != nil {
			t.Fatalf("decrypt ambiguous small blob (iv prefix %d): %v", count, err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("iv prefix %d: mismatch: got %q, want %q", count, decrypted, plaintext)
		}
	}
}

// Same ambiguity through the streaming decrypt path (decryptStreamToFile):
// chunk 0 fails AEAD and the stream ends within the first chunk read, so
// the whole blob is reinterpreted as a small blob.
func TestDecryptStreamGB1SmallBlobWithChunkCountIV(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(255 - i)
	}
	dec := NewDecryptor(key, DefaultChunkSize)
	plaintext := make([]byte, 100000) // comfortably below chunkSize, non-trivial size
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}
	iv := make([]byte, IVSize)
	binary.BigEndian.PutUint32(iv[:ChunkCountSize], 1234)
	for i := ChunkCountSize; i < IVSize; i++ {
		iv[i] = byte(i * 3)
	}
	blob := buildSmallBlobWithIV(t, key, plaintext, iv)

	var out bytes.Buffer
	if err := decryptStreamToFile(dec, bytes.NewReader(blob), &out); err != nil {
		t.Fatalf("decryptStreamToFile ambiguous small blob: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Fatalf("mismatch: got %d bytes, want %d", out.Len(), len(plaintext))
	}
}

// Newly written small blobs must never be ambiguous: the IV's first 4 bytes
// are rejection-sampled outside the chunk-count range.
func TestEncryptSmallBlobIVNeverAmbiguous(t *testing.T) {
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	plaintext := []byte("small blob iv sampling check")
	for i := 0; i < 200; i++ {
		blob, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if string(blob[:MagicSize]) != MagicGB1 {
			t.Fatalf("magic mismatch: got %q", blob[:MagicSize])
		}
		if isChunkCount(blob[MagicSize : MagicSize+ChunkCountSize]) {
			t.Fatalf("small blob iv prefix falls in chunk-count range: %v", blob[MagicSize:MagicSize+ChunkCountSize])
		}
	}
}

// TestGB2StreamRoundtrip covers the GB2 streaming wire format end to end:
// UploadBlobFromPath on a compressible multi-chunk file produces a MagicGB2
// blob via encryptFileToWriter (tryCompress=true); the blob is then restored
// through both the whole-buffer Decryptor (DownloadBlob) and the streaming
// decryptGB2StreamToFile path (DownloadBlobToFile). It also pins down the
// wire layout itself: GB2 magic, a chunk count > 1, per-chunk storedSize and
// compressed flags, and effective compression.
func TestGB2StreamRoundtrip(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	ctx := context.Background()

	// Highly compressible content spanning multiple chunks.
	block := bytes.Repeat([]byte("gbf gb2 wire format roundtrip "), 4096) // ~116 KiB
	data := bytes.Repeat(block, (2*DefaultChunkSize/len(block))+2)
	src := filepath.Join(dir, "gb2-roundtrip.txt")
	if err := os.WriteFile(src, data, 0644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	hash, err := UploadBlobFromPath(ctx, store, enc, src, "")
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if want := SHA256Bytes(data); hash != want {
		t.Fatalf("hash = %q, want %q", hash, want)
	}

	blob, err := store.Get(ctx, hash)
	if err != nil {
		t.Fatalf("get blob: %v", err)
	}
	if got := string(blob[:MagicSize]); got != MagicGB2 {
		t.Fatalf("magic = %q, want %q", got, MagicGB2)
	}
	chunkCount := binary.BigEndian.Uint32(blob[MagicSize : MagicSize+ChunkCountSize])
	if chunkCount < 2 {
		t.Fatalf("chunkCount = %d, want >= 2 (content spans multiple chunks)", chunkCount)
	}
	// Wire layout per chunk: storedSize (4 bytes) + flags (1 byte) + IV +
	// ciphertext. The content is highly compressible, so the first chunk
	// must carry the compressed flag and a storedSize below chunkSize.
	firstStored := binary.BigEndian.Uint32(blob[MagicSize+ChunkCountSize : MagicSize+2*ChunkCountSize])
	if int64(firstStored) >= int64(DefaultChunkSize) {
		t.Fatalf("first chunk storedSize = %d, want < %d for a compressed chunk", firstStored, DefaultChunkSize)
	}
	firstFlags := blob[MagicSize+2*ChunkCountSize]
	if firstFlags != 1 {
		t.Fatalf("first chunk flags = %d, want 1 (compressed)", firstFlags)
	}
	if len(blob) >= len(data) {
		t.Fatalf("expected compressed blob smaller than plaintext: blob %d bytes, plaintext %d bytes", len(blob), len(data))
	}

	// Whole-blob decrypt (Decryptor.decryptLargeV2).
	got, err := DownloadBlob(ctx, store, dec, hash)
	if err != nil {
		t.Fatalf("download blob: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("whole-blob decrypt mismatch: got %d bytes, want %d", len(got), len(data))
	}

	// Streaming decrypt (decryptGB2StreamToFile via DownloadBlobToFile).
	target := filepath.Join(dir, "restored.txt")
	if err := DownloadBlobToFile(ctx, store, dec, hash, target, 0644); err != nil {
		t.Fatalf("download to file: %v", err)
	}
	restored, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, data) {
		t.Fatalf("stream decrypt mismatch: got %d bytes, want %d", len(restored), len(data))
	}
}
