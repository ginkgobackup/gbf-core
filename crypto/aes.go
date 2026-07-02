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

type AESEncryptor struct {
	cache sync.Map
}

type gcmEntry struct {
	gcm  cipher.AEAD
	once sync.Once
	err  error
}

func NewAESEncryptor() *AESEncryptor {
	return &AESEncryptor{}
}

func (e *AESEncryptor) getGCM(key []byte) (cipher.AEAD, error) {
	// Use SHA-256 of the key as the cache key instead of the raw key bytes.
	// This avoids retaining the actual secret key material in the map.
	hash := sha256.Sum256(key)
	keyStr := string(hash[:])
	if v, ok := e.cache.Load(keyStr); ok {
		entry := v.(*gcmEntry)
		entry.once.Do(func() {
			var block cipher.Block
			block, entry.err = aes.NewCipher(key)
			if entry.err != nil {
				return
			}
			entry.gcm, entry.err = cipher.NewGCM(block)
		})
		return entry.gcm, entry.err
	}

	entry := &gcmEntry{}
	entry.once.Do(func() {
		var block cipher.Block
		block, entry.err = aes.NewCipher(key)
		if entry.err != nil {
			return
		}
		entry.gcm, entry.err = cipher.NewGCM(block)
	})
	if entry.err != nil {
		return nil, entry.err
	}

	actual, _ := e.cache.LoadOrStore(keyStr, entry)
	return actual.(*gcmEntry).gcm, nil
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
