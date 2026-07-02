// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestDeriveKeyFromPasswordDeterministic(t *testing.T) {
	salt := []byte("fixed-salt-for-test-00000000001")
	key1 := DeriveKeyFromPassword("mypassword", salt)
	key2 := DeriveKeyFromPassword("mypassword", salt)
	if !bytes.Equal(key1, key2) {
		t.Fatal("same password + salt should produce same key")
	}
	if len(key1) != Argon2KeyLen {
		t.Fatalf("key length: got %d, want %d", len(key1), Argon2KeyLen)
	}
}

func TestDeriveKeyFromPasswordDifferentSalt(t *testing.T) {
	salt1 := []byte("salt-one-00000000000000000000000")
	salt2 := []byte("salt-two-00000000000000000000000")
	key1 := DeriveKeyFromPassword("samepassword", salt1)
	key2 := DeriveKeyFromPassword("samepassword", salt2)
	if bytes.Equal(key1, key2) {
		t.Fatal("different salts should produce different keys")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	if len(salt1) != SaltSize {
		t.Fatalf("salt length: got %d, want %d", len(salt1), SaltSize)
	}
	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	if bytes.Equal(salt1, salt2) {
		t.Fatal("two generated salts should differ")
	}
}

func TestGenerateRandomKey(t *testing.T) {
	key1, err := GenerateRandomKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("key length: got %d, want 32", len(key1))
	}
	key2, err := GenerateRandomKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if bytes.Equal(key1, key2) {
		t.Fatal("two generated keys should differ")
	}
}

func TestSaveLoadKeyFileRoundtrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, MetaDirName), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	salt := make([]byte, SaltSize)
	for i := range salt {
		salt[i] = byte(SaltSize - i)
	}
	if err := SaveKeyFile(dir, key, salt); err != nil {
		t.Fatalf("save: %v", err)
	}
	kf, err := LoadKeyFile(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	loadedKey, err := kf.DecodeKey()
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	if !bytes.Equal(loadedKey, key) {
		t.Fatalf("key mismatch: got %x, want %x", loadedKey, key)
	}
	loadedSalt, err := kf.DecodeSalt()
	if err != nil {
		t.Fatalf("decode salt: %v", err)
	}
	if !bytes.Equal(loadedSalt, salt) {
		t.Fatalf("salt mismatch: got %x, want %x", loadedSalt, salt)
	}
}

func TestKeyFileDecodeKey(t *testing.T) {
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i)
	}
	kf := &KeyFile{
		Key: base64.StdEncoding.EncodeToString(validKey),
	}
	decoded, err := kf.DecodeKey()
	if err != nil {
		t.Fatalf("decode valid key: %v", err)
	}
	if !bytes.Equal(decoded, validKey) {
		t.Fatalf("key mismatch")
	}
}

func TestKeyFileDecodeKeyInvalidBase64(t *testing.T) {
	kf := &KeyFile{Key: "not-valid-base64!!!"}
	_, err := kf.DecodeKey()
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestKeyFileDecodeKeyWrongLength(t *testing.T) {
	shortKey := make([]byte, 16)
	kf := &KeyFile{Key: base64.StdEncoding.EncodeToString(shortKey)}
	_, err := kf.DecodeKey()
	if err == nil {
		t.Fatal("expected error for wrong key length")
	}
}

func TestKeyFileDecodeSalt(t *testing.T) {
	salt := make([]byte, SaltSize)
	for i := range salt {
		salt[i] = byte(i)
	}
	kf := &KeyFile{
		Salt: base64.StdEncoding.EncodeToString(salt),
	}
	decoded, err := kf.DecodeSalt()
	if err != nil {
		t.Fatalf("decode valid salt: %v", err)
	}
	if !bytes.Equal(decoded, salt) {
		t.Fatalf("salt mismatch")
	}
}

func TestKeyFileDecodeSaltInvalidBase64(t *testing.T) {
	kf := &KeyFile{Salt: "!!!invalid!!!"}
	_, err := kf.DecodeSalt()
	if err == nil {
		t.Fatal("expected error for invalid base64 salt")
	}
}

func TestInitRepoWithPassword(t *testing.T) {
	dir := t.TempDir()
	if err := InitRepoWithPassword(dir, "device-1", "secretpassword"); err != nil {
		t.Fatalf("init with password: %v", err)
	}
	if !IsGBRepo(dir) {
		t.Fatal("should be GB repo")
	}
	keyPath := KeyFilePath(dir)
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("repo.key should exist")
	}
	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.Encrypted {
		t.Fatal("config should mark repo as encrypted")
	}
}

func TestInitRepoWithKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := InitRepoWithKeyFile(dir, "device-2"); err != nil {
		t.Fatalf("init with key file: %v", err)
	}
	if !IsGBRepo(dir) {
		t.Fatal("should be GB repo")
	}
	keyPath := KeyFilePath(dir)
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("repo.key should exist")
	}
	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.Encrypted {
		t.Fatal("config should mark repo as encrypted")
	}
}

func TestUnlockRepoWithPassword(t *testing.T) {
	dir := t.TempDir()
	password := "correct-password"
	if err := InitRepoWithPassword(dir, "device-1", password); err != nil {
		t.Fatalf("init: %v", err)
	}
	key, err := UnlockRepoWithPassword(dir, password)
	if err != nil {
		t.Fatalf("unlock with correct password: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length: got %d, want 32", len(key))
	}
}

func TestUnlockRepoWithPasswordWrong(t *testing.T) {
	dir := t.TempDir()
	if err := InitRepoWithPassword(dir, "device-1", "real-password"); err != nil {
		t.Fatalf("init: %v", err)
	}
	_, err := UnlockRepoWithPassword(dir, "wrong-password")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestUnlockRepoWithKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := InitRepoWithKeyFile(dir, "device-1"); err != nil {
		t.Fatalf("init: %v", err)
	}
	key, err := UnlockRepoWithKeyFile(dir)
	if err != nil {
		t.Fatalf("unlock with key file: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length: got %d, want 32", len(key))
	}
	kf, err := LoadKeyFile(dir)
	if err != nil {
		t.Fatalf("load key file: %v", err)
	}
	storedKey, err := kf.DecodeKey()
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	if !bytes.Equal(key, storedKey) {
		t.Fatal("unlocked key should match stored key")
	}
}

func TestKeyFilePath(t *testing.T) {
	root := "/tmp/testrepo"
	expected := filepath.Join(root, MetaDirName, "repo.key")
	got := KeyFilePath(root)
	if got != expected {
		t.Fatalf("key file path: got %q, want %q", got, expected)
	}
}

func TestEqualKeysConstantTime(t *testing.T) {
	a := make([]byte, 32)
	b := make([]byte, 32)
	if !equalKeys(a, b) {
		t.Fatal("identical zero keys should be equal")
	}
	a[15] = 0x01
	if equalKeys(a, b) {
		t.Fatal("different keys should not be equal")
	}
	if equalKeys(a, nil) {
		t.Fatal("different length keys should not be equal")
	}
	if equalKeys(nil, b) {
		t.Fatal("different length keys should not be equal")
	}
}

func TestUnlockRepoWithPasswordDerivesConsistently(t *testing.T) {
	dir := t.TempDir()
	password := "test-password"
	if err := InitRepoWithPassword(dir, "device-1", password); err != nil {
		t.Fatalf("init: %v", err)
	}
	key1, err := UnlockRepoWithPassword(dir, password)
	if err != nil {
		t.Fatalf("first unlock: %v", err)
	}
	key2, err := UnlockRepoWithPassword(dir, password)
	if err != nil {
		t.Fatalf("second unlock: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("same password should always derive same key")
	}
}

func TestLoadKeyFileMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadKeyFile(dir)
	if err == nil {
		t.Fatal("expected error loading missing key file")
	}
}

func TestSaveKeyFileAtomic(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, MetaDirName), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	key := make([]byte, 32)
	salt := make([]byte, SaltSize)
	if err := SaveKeyFile(dir, key, salt); err != nil {
		t.Fatalf("save: %v", err)
	}
	tmpPath := KeyFilePath(dir) + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatal("tmp file should be cleaned up after save")
	}
}
