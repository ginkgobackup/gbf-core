// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
	"encoding/binary"
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
	plain := []byte("plain text data")
	result, err := DecryptIfEncrypted(plain, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, plain) {
		t.Fatalf("mismatch: got %q, want %q", result, plain)
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
	plain := []byte("plain data")
	result, err := DecryptIfEncrypted(plain, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, plain) {
		t.Fatalf("mismatch: got %q, want %q", result, plain)
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
