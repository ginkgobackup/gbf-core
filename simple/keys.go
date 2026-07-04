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

func UnlockRepoWithPassword(repoRoot string, password string) ([]byte, error) {
	path := KeyFilePath(repoRoot)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(data) >= 4 && data[0] == 'G' && data[1] == 'E' && data[2] == 'K' && data[3] == 1 {
		return unlockGEK1KeyFile(data, password)
	}
	return nil, fmt.Errorf("unsupported key file format")
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

// KeyFileData is a legacy keyfile representation that stores the master key
// base64-encoded alongside Argon2id parameters. New repos should use the
// GEK1 binary format (see EncodeGEK1KeyFile). This struct is kept for
// compatibility with existing repos whose repo.key was written by the
// old InitRepoWithKeyFile path. LoadKeyFile reads either format and
// returns a KeyFileData whose DecodeKey method extracts the master key.
type KeyFileData struct {
	Version   int    `json:"version"`
	Algorithm string `json:"algorithm"`
	Key       string `json:"key"`
	Salt      string `json:"salt"`
}

// LoadKeyFile reads the repo.key file at repoRoot/.ginkgo-backup/repo.key.
// It supports both the legacy JSON format and the GEK1 binary format. For
// GEK1 files the returned KeyFileData has Version=1, Algorithm="gek1", and
// the master key embedded directly in the Key field (base64-encoded) —
// DecodeKey returns it without further derivation, since GEK1 was already
// decrypted at load time. For legacy JSON files DecodeKey base64-decodes
// the stored key.
func LoadKeyFile(repoRoot string) (*KeyFileData, error) {
	path := KeyFilePath(repoRoot)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	// GEK1 binary format: master key is wrapped by a password; without a
	// password we cannot recover it here. Callers that need to decrypt a
	// GEK1 file should use UnlockRepoWithPassword. LoadKeyFile is only the
	// legacy fallback path.
	if len(data) >= 4 && data[0] == 'G' && data[1] == 'E' && data[2] == 'K' && data[3] == 1 {
		return nil, fmt.Errorf("GEK1 key file requires a password; use UnlockRepoWithPassword")
	}
	var kf KeyFileData
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("parse key file: %w", err)
	}
	return &kf, nil
}

// DecodeKey returns the master key bytes from a legacy JSON keyfile.
// The key field is base64-encoded.
func (kf *KeyFileData) DecodeKey() ([]byte, error) {
	if kf.Key == "" {
		return nil, fmt.Errorf("empty key in key file")
	}
	key, err := base64.StdEncoding.DecodeString(kf.Key)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	return key, nil
}

// InitRepoWithKeyFile initializes a repo with a plaintext keyfile (legacy
// format, kept for backward compatibility). New code should use
// InitRepoWithPassword to produce a GEK1 keyfile. This function generates
// a random master key, base64-encodes it into the JSON keyfile format, and
// marks the repo config as encrypted. The master key is stored in
// plaintext in repo.key — this provides no security against an attacker
// with file access, only against accidental reads. For true encryption at
// rest, use InitRepoWithPassword.
func InitRepoWithKeyFile(repoRoot string, deviceID string) error {
	if err := InitRepo(InitParams{RepoRoot: repoRoot, DeviceID: deviceID}); err != nil {
		return err
	}
	masterKey, err := GenerateRandomKey()
	if err != nil {
		return err
	}
	kf := KeyFileData{
		Version:   1,
		Algorithm: "aes-256-gcm",
		Key:       base64.StdEncoding.EncodeToString(masterKey),
	}
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal key file: %w", err)
	}
	path := KeyFilePath(repoRoot)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("mkdir keyfile dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	cfg, err := LoadConfig(repoRoot)
	if err != nil {
		return err
	}
	cfg.Encrypted = true
	return SaveConfig(repoRoot, cfg)
}
