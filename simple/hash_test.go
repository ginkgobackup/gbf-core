// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestSHA256File(t *testing.T) {
	dir := t.TempDir()
	content := []byte("hello sha256 file test")
	fp := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(fp, content, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := SHA256File(fp)
	if err != nil {
		t.Fatalf("SHA256File: %v", err)
	}

	h := sha256.Sum256(content)
	expected := hex.EncodeToString(h[:])
	if result.Hash != expected {
		t.Errorf("Hash = %q, want %q", result.Hash, expected)
	}
	if result.Size != int64(len(content)) {
		t.Errorf("Size = %d, want %d", result.Size, len(content))
	}
}

func TestSHA256File_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(fp, []byte{}, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := SHA256File(fp)
	if err != nil {
		t.Fatalf("SHA256File: %v", err)
	}

	expected := SHA256Bytes([]byte{})
	if result.Hash != expected {
		t.Errorf("Hash = %q, want %q", result.Hash, expected)
	}
	if result.Size != 0 {
		t.Errorf("Size = %d, want 0", result.Size)
	}
}

func TestSHA256File_NotFound(t *testing.T) {
	_, err := SHA256File("/nonexistent/path/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestSHA256Bytes_KnownValue(t *testing.T) {
	data := []byte("hello world")
	hash := SHA256Bytes(data)

	h := sha256.Sum256(data)
	expected := hex.EncodeToString(h[:])

	if hash != expected {
		t.Errorf("SHA256Bytes = %q, want %q", hash, expected)
	}
}

func TestSHA256Bytes_Empty(t *testing.T) {
	hash := SHA256Bytes([]byte{})
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}

	h := sha256.Sum256([]byte{})
	expected := hex.EncodeToString(h[:])
	if hash != expected {
		t.Errorf("SHA256Bytes([]byte{}) = %q, want %q", hash, expected)
	}
}

func TestSHA256Bytes_Length(t *testing.T) {
	data := []byte("test")
	hash := SHA256Bytes(data)
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}
}

func TestSHA256Bytes_Deterministic(t *testing.T) {
	data := []byte("deterministic test")
	hash1 := SHA256Bytes(data)
	hash2 := SHA256Bytes(data)
	if hash1 != hash2 {
		t.Errorf("hashes differ: %q vs %q", hash1, hash2)
	}
}

func TestSHA256Bytes_DifferentInputs(t *testing.T) {
	hash1 := SHA256Bytes([]byte("input a"))
	hash2 := SHA256Bytes([]byte("input b"))
	if hash1 == hash2 {
		t.Error("different inputs produced same hash")
	}
}

func TestUploadBlob_NewBlob(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	ctx := context.Background()

	plaintext := []byte("new blob content")
	hash, err := UploadBlob(ctx, store, enc, plaintext)
	if err != nil {
		t.Fatalf("UploadBlob: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}

	expectedHash := SHA256Bytes(plaintext)
	if hash != expectedHash {
		t.Errorf("hash = %q, want %q", hash, expectedHash)
	}

	exists, err := store.Exists(ctx, hash)
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	if !exists {
		t.Error("blob should exist after upload")
	}
}

func TestUploadBlob_Dedup(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	ctx := context.Background()

	plaintext := []byte("dedup content")
	hash1, err := UploadBlob(ctx, store, enc, plaintext)
	if err != nil {
		t.Fatalf("first upload: %v", err)
	}
	hash2, err := UploadBlob(ctx, store, enc, plaintext)
	if err != nil {
		t.Fatalf("second upload: %v", err)
	}
	if hash1 != hash2 {
		t.Errorf("hashes differ: %q vs %q", hash1, hash2)
	}
}

func TestUploadBlob_DifferentContent(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	ctx := context.Background()

	hash1, err := UploadBlob(ctx, store, enc, []byte("content a"))
	if err != nil {
		t.Fatalf("upload a: %v", err)
	}
	hash2, err := UploadBlob(ctx, store, enc, []byte("content b"))
	if err != nil {
		t.Fatalf("upload b: %v", err)
	}
	if hash1 == hash2 {
		t.Error("different content should produce different hashes")
	}
}

func TestDownloadBlob_Encrypted(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	ctx := context.Background()

	plaintext := []byte("encrypted download test")
	hash, err := UploadBlob(ctx, store, enc, plaintext)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}

	got, err := DownloadBlob(ctx, store, dec, hash)
	if err != nil {
		t.Fatalf("DownloadBlob: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("data mismatch: got %q, want %q", string(got), string(plaintext))
	}
}

func TestDownloadBlob_EncryptedLargeFile(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	ctx := context.Background()

	plaintext := make([]byte, DefaultChunkSize+100)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	hash, err := UploadBlob(ctx, store, enc, plaintext)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}

	got, err := DownloadBlob(ctx, store, dec, hash)
	if err != nil {
		t.Fatalf("DownloadBlob: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("data mismatch: length got %d, want %d", len(got), len(plaintext))
	}
}

func TestDownloadBlob_WrongKey(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key1 := make([]byte, 32)
	key1[0] = 1
	key2 := make([]byte, 32)
	key2[0] = 2
	enc := NewEncryptor(key1, DefaultChunkSize)
	dec := NewDecryptor(key2, DefaultChunkSize)
	ctx := context.Background()

	plaintext := []byte("wrong key test")
	hash, err := UploadBlob(ctx, store, enc, plaintext)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}

	_, err = DownloadBlob(ctx, store, dec, hash)
	if err == nil {
		t.Error("expected error with wrong decryption key")
	}
}

func TestDownloadBlob_NotFound(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	dec := NewDecryptor(nil, DefaultChunkSize)
	ctx := context.Background()

	fakeHash := SHA256Bytes([]byte("nonexistent"))
	_, err := DownloadBlob(ctx, store, dec, fakeHash)
	if err == nil {
		t.Error("expected error for nonexistent blob")
	}
}

func TestDownloadBlob_HashMismatch(t *testing.T) {
	dir := t.TempDir()
	store := NewLocalBlobStore(dir)
	key := make([]byte, 32)
	enc := NewEncryptor(key, DefaultChunkSize)
	dec := NewDecryptor(key, DefaultChunkSize)
	ctx := context.Background()

	realData := []byte("real content")
	ciphertext, err := enc.Encrypt(realData)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	wrongHash := SHA256Bytes([]byte("different content"))
	if err := store.Put(ctx, wrongHash, ciphertext); err != nil {
		t.Fatalf("put: %v", err)
	}

	_, err = DownloadBlob(ctx, store, dec, wrongHash)
	if err == nil {
		t.Error("expected hash mismatch error")
	}
}

func TestHashResult_Fields(t *testing.T) {
	dir := t.TempDir()
	content := []byte("field test")
	fp := filepath.Join(dir, "field.txt")
	if err := os.WriteFile(fp, content, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := SHA256File(fp)
	if err != nil {
		t.Fatalf("SHA256File: %v", err)
	}

	if result.Hash == "" {
		t.Error("Hash is empty")
	}
	if result.Size != int64(len(content)) {
		t.Errorf("Size = %d, want %d", result.Size, len(content))
	}
}

func TestSHA256Bytes_LargeInput(t *testing.T) {
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	hash := SHA256Bytes(data)
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}

	h := sha256.Sum256(data)
	expected := hex.EncodeToString(h[:])
	if hash != expected {
		t.Errorf("hash mismatch for large input")
	}
}
