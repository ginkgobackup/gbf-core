// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

func TestDeriveMetadataKeyDeterministicAndDistinct(t *testing.T) {
	master := []byte("0123456789abcdef0123456789abcdef")
	k1 := DeriveMetadataKey(master)
	k2 := DeriveMetadataKey(master)
	if !bytes.Equal(k1, k2) {
		t.Fatal("metadata key derivation must be deterministic")
	}
	if len(k1) != 32 {
		t.Fatalf("metadata key length = %d, want 32", len(k1))
	}
	if bytes.Equal(k1, master) {
		t.Fatal("metadata key must differ from the raw master key")
	}
	other := DeriveMetadataKey([]byte("another-master-key-0123456789ab"))
	if bytes.Equal(k1, other) {
		t.Fatal("different master keys must derive different metadata keys")
	}
}

func TestManifestKeySeparationRoundTrip(t *testing.T) {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatalf("rand: %v", err)
	}
	msg := []byte("manifest payload for key separation")

	sealed, err := EncryptManifest(msg, master)
	if err != nil {
		t.Fatalf("EncryptManifest: %v", err)
	}
	got, err := DecryptManifest(sealed, master)
	if err != nil {
		t.Fatalf("DecryptManifest: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("round trip mismatch")
	}

	// The sealed blob must NOT be decryptable with the raw master key
	// directly (proving the metadata key is actually in use).
	if _, err := decryptWithRawKey(sealed, master); err == nil {
		t.Fatal("manifest sealed under metadata key must not open with the raw master key")
	}

	// A different master key must fail.
	other := make([]byte, 32)
	if _, err := rand.Read(other); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := DecryptManifest(sealed, other); err == nil {
		t.Fatal("manifest must not decrypt under a different master key")
	}
}

// decryptWithRawKey replicates the legacy (pre-key-separation) manifest
// encryption so the compatibility fallback and the "metadata key in use"
// assertion can both be tested.
func decryptWithRawKey(data, master []byte) ([]byte, error) {
	if len(data) < MagicSize || string(data[:MagicSize]) != GKM1Magic {
		return nil, ErrManifestNotFound
	}
	return NewDecryptor(master, DefaultChunkSize).decryptSmall(data[MagicSize:])
}

func TestLegacyManifestDecryptFallback(t *testing.T) {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatalf("rand: %v", err)
	}
	msg := []byte("legacy manifest encrypted under the raw master key")

	// Encrypt the way pre-separation code did: raw master key, GKM1
	// framing (magic + IV + ciphertext).
	block, err := aes.NewCipher(master)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	iv := make([]byte, IVSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("iv: %v", err)
	}
	ct := gcm.Seal(nil, iv, msg, nil)
	legacy := append([]byte(GKM1Magic), iv...)
	legacy = append(legacy, ct...)

	got, err := DecryptManifest(legacy, master)
	if err != nil {
		t.Fatalf("legacy manifest must decrypt via fallback: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("legacy round trip mismatch")
	}
}
