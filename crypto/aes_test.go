// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/ginkgobackup/gbf-core/vault"
)

func TestAES_RoundTrip(t *testing.T) {
	e := NewAESEncryptor()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	plaintext := []byte("hello AES-GCM encryption test")
	ciphertext, err := e.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(ciphertext) <= len(plaintext) {
		t.Errorf("ciphertext should be larger than plaintext (includes nonce+tag)")
	}

	decrypted, err := e.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("roundtrip mismatch")
	}
}

func TestAES_WrongKey(t *testing.T) {
	e := NewAESEncryptor()
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	if _, err := rand.Read(key1); err != nil {
		t.Fatalf("rand.Read key1: %v", err)
	}
	if _, err := rand.Read(key2); err != nil {
		t.Fatalf("rand.Read key2: %v", err)
	}

	plaintext := []byte("secret data")
	ciphertext, _ := e.Encrypt(plaintext, key1)

	_, err := e.Decrypt(ciphertext, key2)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}

func TestDeriveKey(t *testing.T) {
	e := NewAESEncryptor()
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("rand.Read masterKey: %v", err)
	}

	key1, err := e.DeriveKey(masterKey, "config-v1")
	if err != nil {
		t.Fatalf("derive key 1: %v", err)
	}
	key2, err := e.DeriveKey(masterKey, "config-v1")
	if err != nil {
		t.Fatalf("derive key 2: %v", err)
	}
	key3, err := e.DeriveKey(masterKey, "blob-v1")
	if err != nil {
		t.Fatalf("derive key 3: %v", err)
	}

	if len(key1) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key1))
	}
	if string(key1) != string(key2) {
		t.Error("same purpose should produce same key")
	}
	if string(key1) == string(key3) {
		t.Error("different purpose should produce different key")
	}
}

func TestAESEncryptor_InterfaceCheck(t *testing.T) {
	var _ vault.Encryptor = (*AESEncryptor)(nil)
}
