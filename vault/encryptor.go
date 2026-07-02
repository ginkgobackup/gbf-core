// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package vault

// Encryptor defines the contract for local-first encryption.
// Keys are never transmitted; all operations happen on the local machine.
type Encryptor interface {
	Encrypt(plaintext []byte, key []byte) ([]byte, error)
	Decrypt(ciphertext []byte, key []byte) ([]byte, error)
	DeriveKey(masterKey []byte, purpose string) ([]byte, error)
}
