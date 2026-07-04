// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	MagicGB1       = "GB1\x00"
	MagicGB2       = "GB2\x00"
	GKM1Magic      = "GKM1"
	MagicSize      = 4
	IVSize         = 12
	TagSize        = 16
	ChunkCountSize = 4
	FlagsSize      = 1
)

// Encryptor is the on-disk format encryptor: a stateful AEAD wrapper bound
// to a single master key and chunk size. Its Encrypt/Decrypt methods emit
// and parse the GB1/GB2 chunked blob format (magic bytes + chunk count +
// per-chunk IV+ciphertext), not raw AEAD. It is intentionally distinct from
// vault.Encryptor, which is the stateless single-block AEAD interface used
// for HKDF-derived subkeys (manifests, etc.). See vault/encryptor.go.
type Encryptor struct {
	key       []byte
	chunkSize int
}

func NewEncryptor(key []byte, chunkSize int) *Encryptor {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	return &Encryptor{key: key, chunkSize: chunkSize}
}

func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) < e.chunkSize {
		return e.encryptSmall(plaintext)
	}
	return e.encryptLarge(plaintext)
}

func (e *Encryptor) encryptSmall(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	iv := make([]byte, IVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("iv: %w", err)
	}
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	result := make([]byte, 0, MagicSize+IVSize+len(ciphertext))
	result = append(result, MagicGB1...)
	result = append(result, iv...)
	result = append(result, ciphertext...)
	return result, nil
}

func (e *Encryptor) encryptLarge(plaintext []byte) ([]byte, error) {
	chunkCount := (len(plaintext) + e.chunkSize - 1) / e.chunkSize
	result := make([]byte, 0, MagicSize+ChunkCountSize+len(plaintext)+chunkCount*(IVSize+TagSize)+len(plaintext)*2/10)
	result = append(result, MagicGB1...)
	countBuf := make([]byte, ChunkCountSize)
	binary.BigEndian.PutUint32(countBuf, uint32(chunkCount))
	result = append(result, countBuf...)
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	for i := 0; i < chunkCount; i++ {
		start := i * e.chunkSize
		end := start + e.chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk := plaintext[start:end]
		iv := make([]byte, IVSize)
		if _, err := rand.Read(iv); err != nil {
			return nil, fmt.Errorf("iv chunk %d: %w", i, err)
		}
		encrypted := gcm.Seal(nil, iv, chunk, nil)
		result = append(result, iv...)
		result = append(result, encrypted...)
	}
	return result, nil
}

type Decryptor struct {
	key       []byte
	chunkSize int
}

func NewDecryptor(key []byte, chunkSize int) *Decryptor {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	return &Decryptor{key: key, chunkSize: chunkSize}
}

func (d *Decryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < MagicSize {
		return nil, fmt.Errorf("data too short: %d bytes", len(ciphertext))
	}
	magic := string(ciphertext[:MagicSize])
	data := ciphertext[MagicSize:]
	switch magic {
	case MagicGB2:
		return d.decryptLargeV2(data)
	case MagicGB1:
		if len(data) > ChunkCountSize && isChunkCount(data[:ChunkCountSize]) {
			return d.decryptLarge(data)
		}
		return d.decryptSmall(data)
	default:
		return nil, fmt.Errorf("invalid magic: %q", magic)
	}
}

func isChunkCount(buf []byte) bool {
	if len(buf) < ChunkCountSize {
		return false
	}
	v := binary.BigEndian.Uint32(buf)
	return v > 0 && v < 100000
}

func (d *Decryptor) decryptSmall(data []byte) ([]byte, error) {
	if len(data) < IVSize+TagSize {
		return nil, fmt.Errorf("small blob too short: %d bytes", len(data))
	}
	iv := data[:IVSize]
	ciphertext := data[IVSize:]
	block, err := aes.NewCipher(d.key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

func (d *Decryptor) decryptLarge(data []byte) ([]byte, error) {
	chunkCount := binary.BigEndian.Uint32(data[:ChunkCountSize])
	data = data[ChunkCountSize:]
	block, err := aes.NewCipher(d.key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	var plaintext []byte
	for i := uint32(0); i < chunkCount; i++ {
		if len(data) < IVSize {
			return nil, fmt.Errorf("chunk %d: missing IV", i)
		}
		iv := data[:IVSize]
		data = data[IVSize:]
		estimatedChunkSize := d.chunkSize + TagSize
		chunkEnd := estimatedChunkSize
		if chunkEnd > len(data) {
			chunkEnd = len(data)
		}
		encrypted := data[:chunkEnd]
		decrypted, err := gcm.Open(nil, iv, encrypted, nil)
		if err != nil {
			return nil, fmt.Errorf("decrypt chunk %d: %w", i, err)
		}
		plaintext = append(plaintext, decrypted...)
		data = data[chunkEnd:]
	}
	return plaintext, nil
}

func (d *Decryptor) decryptLargeV2(data []byte) ([]byte, error) {
	if len(data) < ChunkCountSize {
		return nil, fmt.Errorf("gb2 data too short: %d bytes", len(data))
	}
	chunkCount := binary.BigEndian.Uint32(data[:ChunkCountSize])
	if chunkCount == 0 || chunkCount >= 100000 {
		return nil, fmt.Errorf("gb2 invalid chunk count: %d", chunkCount)
	}
	data = data[ChunkCountSize:]

	block, err := aes.NewCipher(d.key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	var plaintext []byte
	for i := uint32(0); i < chunkCount; i++ {
		if len(data) < ChunkCountSize+FlagsSize {
			return nil, fmt.Errorf("chunk %d: missing size header", i)
		}
		storedSize := binary.BigEndian.Uint32(data[:ChunkCountSize])
		compressed := data[ChunkCountSize] != 0
		data = data[ChunkCountSize+FlagsSize:]

		if len(data) < IVSize {
			return nil, fmt.Errorf("chunk %d: missing IV", i)
		}
		iv := data[:IVSize]
		data = data[IVSize:]

		if len(data) < int(storedSize) {
			return nil, fmt.Errorf("chunk %d: missing ciphertext", i)
		}
		encrypted := data[:storedSize]
		data = data[storedSize:]

		decrypted, err := gcm.Open(nil, iv, encrypted, nil)
		if err != nil {
			return nil, fmt.Errorf("decrypt chunk %d: %w", i, err)
		}
		if compressed {
			decompressed, derr := defaultStreamDecompressor.Decompress(decrypted)
			if derr != nil {
				return nil, fmt.Errorf("decompress chunk %d: %w", i, derr)
			}
			decrypted = decompressed
		}
		plaintext = append(plaintext, decrypted...)
	}
	return plaintext, nil
}

func (d *Decryptor) DecryptStream(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return d.Decrypt(data)
}

func EncryptManifest(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	iv := make([]byte, IVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("iv: %w", err)
	}
	ct := gcm.Seal(nil, iv, plaintext, nil)
	result := make([]byte, 0, MagicSize+IVSize+len(ct))
	result = append(result, []byte(GKM1Magic)...)
	result = append(result, iv...)
	result = append(result, ct...)
	return result, nil
}

func DecryptManifest(data []byte, key []byte) ([]byte, error) {
	if len(data) < MagicSize || string(data[:MagicSize]) != GKM1Magic {
		return nil, fmt.Errorf("not a GKM1 manifest")
	}
	return NewDecryptor(key, DefaultChunkSize).decryptSmall(data[MagicSize:])
}

func DecryptIfEncrypted(data []byte, key []byte) ([]byte, error) {
	if len(data) < MagicSize {
		return data, nil
	}
	magic := string(data[:MagicSize])
	if magic == GKM1Magic {
		return DecryptManifest(data, key)
	}
	if magic != MagicGB1 && magic != MagicGB2 {
		return nil, fmt.Errorf("unknown magic %q: expected GB1, GB2, or GKM1", magic)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("encrypted blob requires key but none provided (magic %q)", magic)
	}
	return NewDecryptor(key, DefaultChunkSize).Decrypt(data)
}
