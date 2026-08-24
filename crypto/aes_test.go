// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package crypto

import (
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	"github.com/ginkgobackup/gbf-core/vault"
)

// cacheSize returns the current number of cached AEAD instances.
func cacheSize(e *AESEncryptor) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.cache)
}

// TestAESEncryptorGCMCacheCap pins the bounded-cache behavior: more than
// maxGCMCacheEntries distinct keys must still round-trip (extra keys are
// served uncached), and the cache entry count must never exceed the cap.
func TestAESEncryptorGCMCacheCap(t *testing.T) {
	e := NewAESEncryptor()
	for i := 0; i < maxGCMCacheEntries+16; i++ {
		key := []byte(fmt.Sprintf("%032d", i)) // exactly 32 bytes, distinct
		ct, err := e.Encrypt([]byte("payload"), key)
		if err != nil {
			t.Fatalf("encrypt key %d: %v", i, err)
		}
		pt, err := e.Decrypt(ct, key)
		if err != nil {
			t.Fatalf("decrypt key %d: %v", i, err)
		}
		if string(pt) != "payload" {
			t.Fatalf("roundtrip mismatch for key %d", i)
		}
	}
	if n := cacheSize(e); n > maxGCMCacheEntries {
		t.Fatalf("cache size = %d, want <= %d", n, maxGCMCacheEntries)
	}
}

// TestAESEncryptorGCMCacheCapStrict verifies the cap is a STRICT bound:
// under concurrent inserts of distinct keys the cache must never exceed
// maxGCMCacheEntries — not even transiently — and every key must still
// round-trip (the overflow keys are simply served uncached).
func TestAESEncryptorGCMCacheCapStrict(t *testing.T) {
	e := NewAESEncryptor()
	const workers = 8
	const keysPerWorker = 96 // 8*96 = 768 distinct keys > 256 cap

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < keysPerWorker; i++ {
				key := []byte(fmt.Sprintf("%032d", w*keysPerWorker+i))
				ct, err := e.Encrypt([]byte("payload"), key)
				if err != nil {
					t.Errorf("encrypt key %d: %v", w*keysPerWorker+i, err)
					return
				}
				pt, err := e.Decrypt(ct, key)
				if err != nil {
					t.Errorf("decrypt key %d: %v", w*keysPerWorker+i, err)
					return
				}
				if string(pt) != "payload" {
					t.Errorf("roundtrip mismatch for key %d", w*keysPerWorker+i)
					return
				}
				if n := cacheSize(e); n > maxGCMCacheEntries {
					t.Errorf("cache size = %d exceeds strict cap %d", n, maxGCMCacheEntries)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	if n := cacheSize(e); n > maxGCMCacheEntries {
		t.Fatalf("final cache size = %d, want <= %d", n, maxGCMCacheEntries)
	}
}

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
