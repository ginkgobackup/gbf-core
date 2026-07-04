// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
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

func TestKeyFilePath(t *testing.T) {
	root := "/tmp/testrepo"
	expected := filepath.Join(root, MetaDirName, "repo.key")
	got := KeyFilePath(root)
	if got != expected {
		t.Fatalf("key file path: got %q, want %q", got, expected)
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

func TestGEK1KeyFileNotPlaintext(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, MetaDirName), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	if err := SaveGEK1KeyFile(dir, masterKey, "password"); err != nil {
		t.Fatalf("save: %v", err)
	}
	data, err := os.ReadFile(KeyFilePath(dir))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(data) < 4 || data[0] != 'G' || data[1] != 'E' || data[2] != 'K' || data[3] != 1 {
		t.Fatal("key file should have GEK1 magic header")
	}
	if len(data) <= 4+SaltSize {
		t.Fatal("key file should contain encrypted key data beyond header+salt")
	}
	for i := 4 + SaltSize; i < len(data); i++ {
		if data[i] != 0 {
			break
		}
		if i == len(data)-1 {
			t.Fatal("key file contains only zero bytes after salt — likely not encrypted")
		}
	}
}
