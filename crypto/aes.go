// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"

	"github.com/ginkgobackup/gbf-core/vault"
)

var _ vault.Encryptor = (*AESEncryptor)(nil)

// maxGCMCacheEntries caps how many AEAD instances are cached. A long-lived
// process cycling through many distinct master keys would otherwise grow
// the cache without bound. Once the cap is reached, additional keys are
// served without caching (AEAD construction is cheap relative to GCM
// sealing, so this is a graceful degradation, not an error). The cap is a
// strict bound: insertions happen under e.mu with the size checked first,
// so the cache never exceeds maxGCMCacheEntries entries, even transiently
// under concurrency.
const maxGCMCacheEntries = 256

type AESEncryptor struct {
	mu    sync.Mutex
	cache map[string]*gcmEntry
}

type gcmEntry struct {
	gcm  cipher.AEAD
	once sync.Once
	err  error
}

func NewAESEncryptor() *AESEncryptor {
	return &AESEncryptor{cache: make(map[string]*gcmEntry)}
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (e *AESEncryptor) getGCM(key []byte) (cipher.AEAD, error) {
	// Use SHA-256 of the key as the cache key instead of the raw key bytes.
	// This avoids retaining the actual secret key material in the map.
	hash := sha256.Sum256(key)
	keyStr := string(hash[:])

	e.mu.Lock()
	entry, ok := e.cache[keyStr]
	if !ok {
		if len(e.cache) >= maxGCMCacheEntries {
			// Cache full: serve this key uncached. Holding the mutex only
			// for the map access keeps the critical section tiny.
			e.mu.Unlock()
			return newGCM(key)
		}
		entry = &gcmEntry{}
		e.cache[keyStr] = entry
	}
	e.mu.Unlock()

	// AEAD construction happens outside the lock; sync.Once collapses
	// concurrent construction for the same key.
	entry.once.Do(func() {
		entry.gcm, entry.err = newGCM(key)
	})
	if entry.err != nil {
		// Don't cache failed constructions — a bad key (wrong length)
		// would otherwise permanently occupy a cache slot.
		e.mu.Lock()
		if cur, ok := e.cache[keyStr]; ok && cur == entry {
			delete(e.cache, keyStr)
		}
		e.mu.Unlock()
		return nil, entry.err
	}
	return entry.gcm, nil
}

func (e *AESEncryptor) Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	gcm, err := e.getGCM(key)
	if err != nil {
		return nil, fmt.Errorf("aes init: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (e *AESEncryptor) Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	gcm, err := e.getGCM(key)
	if err != nil {
		return nil, fmt.Errorf("aes init: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	plaintext, err := gcm.Open(nil, nonce, ciphertext[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}

	return plaintext, nil
}

func (e *AESEncryptor) DeriveKey(masterKey []byte, purpose string) ([]byte, error) {
	reader := hkdf.New(sha256.New, masterKey, []byte(purpose), nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("hkdf derive key: %w", err)
	}
	return key, nil
}
