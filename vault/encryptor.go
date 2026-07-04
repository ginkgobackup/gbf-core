// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package vault

// Encryptor defines the contract for raw, single-block AEAD encryption.
//
// This interface is intentionally distinct from simple.Encryptor: the
// vault.Encryptor is stateless, takes the key per call, and produces a
// bare nonce||ciphertext blob without any framing. crypto.AESEncryptor
// implements this interface and also exposes HKDF key derivation
// (DeriveKey).
//
// Note: the main backup path does not currently route through
// vault.Encryptor. Manifests are encrypted directly with the master key
// by simple.EncryptManifest, and blob encryption goes through
// simple.Encryptor. This interface is retained as a reusable AEAD
// primitive for future callers.
//
// simple.Encryptor, in contrast, is a stateful encryptor bound to a fixed
// master key and chunk size; it emits the GB1/GB2 on-disk format with
// magic bytes, chunk counts, and per-chunk IVs. The two are not
// interchangeable and intentionally do not share an interface — see
// simple/doc.go for the format encryptor contract.
type Encryptor interface {
	Encrypt(plaintext []byte, key []byte) ([]byte, error)
	Decrypt(ciphertext []byte, key []byte) ([]byte, error)
	DeriveKey(masterKey []byte, purpose string) ([]byte, error)
}
