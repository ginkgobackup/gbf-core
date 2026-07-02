// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

const (
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024
	Argon2Threads = 4
	Argon2KeyLen  = 32
	SaltSize      = 32
	GEK1Magic     = "GEK1"
)

type KeyFile struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	Key        string `json:"key"`
	Salt       string `json:"salt"`
	WrappedKey string `json:"wrappedKey,omitempty"`
}

func DeriveKeyFromPassword(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

func KeyFilePath(repoRoot string) string {
	return filepath.Join(MetaDir(repoRoot), "repo.key")
}

func SaveKeyFile(repoRoot string, key []byte, salt []byte) error {
	kf := KeyFile{
		Version:   1,
		Algorithm: "aes-256-gcm",
		Key:       base64.StdEncoding.EncodeToString(key),
		Salt:      base64.StdEncoding.EncodeToString(salt),
	}
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	path := KeyFilePath(repoRoot)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return os.Rename(tmp, path)
}

func EncodeGEK1KeyFile(masterKey []byte, password string) ([]byte, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}
	encKey := DeriveKeyFromPassword(password, salt)
	block, aesErr := aes.NewCipher(encKey)
	if aesErr != nil {
		return nil, fmt.Errorf("create cipher: %w", aesErr)
	}
	gcm, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		return nil, fmt.Errorf("create gcm: %w", gcmErr)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	encryptedKey := gcm.Seal(nonce, nonce, masterKey, nil)
	keyFileData := make([]byte, 4+len(salt)+len(encryptedKey))
	keyFileData[0] = 'G'
	keyFileData[1] = 'E'
	keyFileData[2] = 'K'
	keyFileData[3] = 1
	copy(keyFileData[4:], salt)
	copy(keyFileData[4+len(salt):], encryptedKey)
	return keyFileData, nil
}

func SaveGEK1KeyFile(repoRoot string, masterKey []byte, password string) error {
	keyFileData, err := EncodeGEK1KeyFile(masterKey, password)
	if err != nil {
		return err
	}
	path := KeyFilePath(repoRoot)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, keyFileData, 0600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return os.Rename(tmp, path)
}

func LoadKeyFile(repoRoot string) (*KeyFile, error) {
	path := KeyFilePath(repoRoot)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(data) >= 4 && data[0] == 'G' && data[1] == 'E' && data[2] == 'K' && data[3] == 1 {
		return nil, fmt.Errorf("GEK1 encrypted key file requires password unlock (use UnlockRepoWithPassword)")
	}
	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &kf, nil
}

func (kf *KeyFile) DecodeKey() ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(kf.Key)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: %d", len(key))
	}
	return key, nil
}

func (kf *KeyFile) DecodeSalt() ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(kf.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	return salt, nil
}

func InitRepoWithPassword(repoRoot string, deviceID string, password string) error {
	if err := InitRepo(InitParams{RepoRoot: repoRoot, DeviceID: deviceID}); err != nil {
		return err
	}
	masterKey, err := GenerateRandomKey()
	if err != nil {
		return err
	}
	if err := SaveGEK1KeyFile(repoRoot, masterKey, password); err != nil {
		return err
	}
	cfg, err := LoadConfig(repoRoot)
	if err != nil {
		return err
	}
	cfg.Encrypted = true
	return SaveConfig(repoRoot, cfg)
}

func InitRepoWithKeyFile(repoRoot string, deviceID string) error {
	if err := InitRepo(InitParams{RepoRoot: repoRoot, DeviceID: deviceID}); err != nil {
		return err
	}
	masterKey, err := GenerateRandomKey()
	if err != nil {
		return err
	}
	salt, err := GenerateSalt()
	if err != nil {
		return err
	}
	if err := SaveKeyFile(repoRoot, masterKey, salt); err != nil {
		return err
	}
	cfg, err := LoadConfig(repoRoot)
	if err != nil {
		return err
	}
	cfg.Encrypted = true
	return SaveConfig(repoRoot, cfg)
}

func UnlockRepoWithPassword(repoRoot string, password string) ([]byte, error) {
	path := KeyFilePath(repoRoot)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	if len(data) > 0 && data[0] == '{' {
		return unlockJSONKeyFile(data, password)
	}

	if len(data) >= 4 && data[0] == 'G' && data[1] == 'E' && data[2] == 'K' && data[3] == 1 {
		return unlockGEK1KeyFile(data, password)
	}

	return nil, fmt.Errorf("unsupported key file format")
}

func unlockJSONKeyFile(data []byte, password string) ([]byte, error) {
	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	salt, err := kf.DecodeSalt()
	if err != nil {
		return nil, err
	}
	derivedKey := DeriveKeyFromPassword(password, salt)
	storedKey, err := kf.DecodeKey()
	if err != nil {
		return nil, err
	}
	if !equalKeys(derivedKey, storedKey) {
		return nil, fmt.Errorf("incorrect password")
	}
	return derivedKey, nil
}

func unlockGEK1KeyFile(data []byte, password string) ([]byte, error) {
	if len(data) < 4+SaltSize {
		return nil, fmt.Errorf("invalid GEK1 key file: too short")
	}
	salt := data[4 : 4+SaltSize]
	encryptedKey := data[4+SaltSize:]
	return DecryptGEK1MasterKey(salt, encryptedKey, password)
}

func DecryptGEK1MasterKey(salt []byte, encryptedKey []byte, password string) ([]byte, error) {
	encKey := DeriveKeyFromPassword(password, salt)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(encryptedKey) < gcm.NonceSize()+gcm.Overhead() {
		return nil, fmt.Errorf("encrypted key data too short")
	}
	nonce := encryptedKey[:gcm.NonceSize()]
	ciphertext := encryptedKey[gcm.NonceSize():]
	masterKey, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("wrong password or corrupted key file")
	}
	return masterKey, nil
}

func UnlockRepoWithKeyFile(repoRoot string) ([]byte, error) {
	kf, err := LoadKeyFile(repoRoot)
	if err != nil {
		return nil, err
	}
	return kf.DecodeKey()
}

func equalKeys(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := byte(0)
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
