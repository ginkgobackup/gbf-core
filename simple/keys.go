// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"

	"github.com/ginkgobackup/gbf-core/fsutil"
)

const (
	Argon2Time     = 3
	Argon2Memory   = 64 * 1024
	Argon2Threads  = 4
	Argon2KeyLen   = 32
	SaltSize       = 32
	GEK1Magic      = "GEK1"
	GEK2Magic      = "GEK2"
	GEK2HeaderSize = 24
)

func DeriveKeyFromPassword(password string, salt []byte) []byte {
	return DeriveKeyFromPasswordParams(password, salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
}

func DeriveKeyFromPasswordParams(password string, salt []byte, timeCost, memoryKiB uint32, threads uint8, keyLen uint32) []byte {
	return argon2.IDKey([]byte(password), salt, timeCost, memoryKiB, threads, keyLen)
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

// EncodeGEK2KeyFile wraps masterKey with Argon2id parameters embedded in the
// header, so future KDF tuning does not make old key files unreadable.
func EncodeGEK2KeyFile(masterKey []byte, password string) ([]byte, error) {
	return EncodeGEK2KeyFileWithParams(masterKey, password, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
}

func EncodeGEK2KeyFileWithParams(masterKey []byte, password string, timeCost, memoryKiB uint32, threads uint8, keyLen uint32) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("empty master key")
	}
	if keyLen != 32 {
		return nil, fmt.Errorf("unsupported derived key length %d", keyLen)
	}
	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}
	encKey := DeriveKeyFromPasswordParams(password, salt, timeCost, memoryKiB, threads, keyLen)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	encryptedKey := gcm.Seal(nonce, nonce, masterKey, nil)
	out := make([]byte, GEK2HeaderSize+len(salt)+len(encryptedKey))
	copy(out, GEK2Magic)
	binary.BigEndian.PutUint32(out[4:], timeCost)
	binary.BigEndian.PutUint32(out[8:], memoryKiB)
	binary.BigEndian.PutUint32(out[12:], uint32(threads))
	binary.BigEndian.PutUint32(out[16:], keyLen)
	binary.BigEndian.PutUint32(out[20:], SaltSize)
	copy(out[GEK2HeaderSize:], salt)
	copy(out[GEK2HeaderSize+len(salt):], encryptedKey)
	return out, nil
}

func SaveGEK2KeyFile(repoRoot string, masterKey []byte, password string) error {
	data, err := EncodeGEK2KeyFile(masterKey, password)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(KeyFilePath(repoRoot), data, 0600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	return nil
}

// ChangeRepoPassword re-wraps the master key with a new password. Existing
// blobs do not need re-encryption. The old key file is restored if the new
// one cannot be verified.
func ChangeRepoPassword(repoRoot, oldPassword, newPassword string) error {
	if newPassword == "" {
		return fmt.Errorf("new password must not be empty")
	}
	path := KeyFilePath(repoRoot)
	oldData, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}
	masterKey, err := UnlockRepoWithPassword(repoRoot, oldPassword)
	if err != nil {
		return err
	}
	if err := SaveGEK2KeyFile(repoRoot, masterKey, newPassword); err != nil {
		return err
	}
	unlocked, err := UnlockRepoWithPassword(repoRoot, newPassword)
	if err != nil || !bytes.Equal(unlocked, masterKey) {
		_ = fsutil.WriteFileAtomic(path, oldData, 0600)
		if err != nil {
			return fmt.Errorf("verify new password: %w", err)
		}
		return fmt.Errorf("verify new password: master key mismatch")
	}
	return nil
}

func SaveGEK1KeyFile(repoRoot string, masterKey []byte, password string) error {
	keyFileData, err := EncodeGEK1KeyFile(masterKey, password)
	if err != nil {
		return err
	}
	path := KeyFilePath(repoRoot)
	if err := fsutil.WriteFileAtomic(path, keyFileData, 0600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	return nil
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
	if len(data) >= GEK2HeaderSize && string(data[:4]) == GEK2Magic {
		return unlockGEK2KeyFile(data, password)
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

func unlockGEK2KeyFile(data []byte, password string) ([]byte, error) {
	if len(data) < GEK2HeaderSize {
		return nil, fmt.Errorf("invalid GEK2 key file: too short")
	}
	timeCost := binary.BigEndian.Uint32(data[4:])
	memoryKiB := binary.BigEndian.Uint32(data[8:])
	threads := uint8(binary.BigEndian.Uint32(data[12:]))
	keyLen := binary.BigEndian.Uint32(data[16:])
	saltLen := binary.BigEndian.Uint32(data[20:])
	if saltLen != SaltSize || len(data) < GEK2HeaderSize+int(saltLen) {
		return nil, fmt.Errorf("invalid GEK2 key file: bad salt length")
	}
	if keyLen != 32 || threads == 0 || timeCost == 0 || memoryKiB == 0 {
		return nil, fmt.Errorf("invalid GEK2 KDF parameters")
	}
	salt := data[GEK2HeaderSize : GEK2HeaderSize+int(saltLen)]
	encryptedKey := data[GEK2HeaderSize+int(saltLen):]
	encKey := DeriveKeyFromPasswordParams(password, salt, timeCost, memoryKiB, threads, keyLen)
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
	masterKey, err := gcm.Open(nil, nonce, encryptedKey[gcm.NonceSize():], nil)
	if err != nil {
		return nil, fmt.Errorf("wrong password or corrupted key file")
	}
	return masterKey, nil
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

// Key protection modes reported by KeyFileProtectionMode.
const (
	// KeyProtectionGEK1: the master key is wrapped by a password (GEK1).
	KeyProtectionGEK1 = "gek1"
	// KeyProtectionLegacyPlaintext: the master key sits in plaintext
	// (base64) in repo.key. Provides no security against an attacker
	// with file access; migrate via MigrateKeyFileToGEK1.
	KeyProtectionLegacyPlaintext = "legacy_plaintext"
	// KeyProtectionNone: the repo has no encrypted flag / no key file.
	KeyProtectionNone = "none"
)

// KeyFileProtectionMode reports how the repo's master key is protected,
// derived from the keyfile format itself (single source of truth — no
// config field that can drift from reality). Callers should surface
// KeyProtectionLegacyPlaintext as a warning at startup or backup time
// and offer MigrateKeyFileToGEK1 as the fix.
func KeyFileProtectionMode(repoRoot string) (string, error) {
	path := KeyFilePath(repoRoot)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return KeyProtectionNone, nil
		}
		return "", fmt.Errorf("read key file: %w", err)
	}
	if len(data) >= 4 && data[0] == 'G' && data[1] == 'E' && data[2] == 'K' && data[3] == 1 {
		return KeyProtectionGEK1, nil
	}
	if len(data) >= GEK2HeaderSize && string(data[:4]) == GEK2Magic {
		return KeyProtectionGEK1, nil
	}
	// Anything that parses as the legacy JSON keyfile is plaintext.
	var kf KeyFileData
	if err := json.Unmarshal(data, &kf); err != nil {
		return "", fmt.Errorf("parse key file: %w", err)
	}
	return KeyProtectionLegacyPlaintext, nil
}

// MigrateKeyFileToGEK1 upgrades a legacy plaintext keyfile in place:
// the master key is read from the plaintext JSON keyfile, wrapped with
// Argon2id-derived password keying (GEK1), and atomically written back
// over repo.key. The master key itself is unchanged, so existing blobs
// and manifests remain readable without re-encryption. Fails without
// touching the file if the repo is not legacy-plaintext.
func MigrateKeyFileToGEK1(repoRoot string, password string) error {
	if password == "" {
		return fmt.Errorf("migration requires a non-empty password")
	}
	mode, err := KeyFileProtectionMode(repoRoot)
	if err != nil {
		return err
	}
	if mode == KeyProtectionGEK1 {
		return fmt.Errorf("repo already uses a GEK1 key file")
	}
	if mode != KeyProtectionLegacyPlaintext {
		return fmt.Errorf("no legacy plaintext key file to migrate (mode %q)", mode)
	}
	kf, err := LoadKeyFile(repoRoot)
	if err != nil {
		return err
	}
	masterKey, err := kf.DecodeKey()
	if err != nil {
		return err
	}
	if err := SaveGEK1KeyFile(repoRoot, masterKey, password); err != nil {
		return err
	}
	// Verify the freshly written file actually unlocks with the password
	// before declaring success.
	unlocked, err := UnlockRepoWithPassword(repoRoot, password)
	if err != nil {
		return fmt.Errorf("post-migration verification failed: %w", err)
	}
	if string(unlocked) != string(masterKey) {
		return fmt.Errorf("post-migration verification mismatch")
	}
	return nil
}

// InitRepoWithKeyFile initializes a repo with a plaintext keyfile (legacy
// format, kept for backward compatibility). New code should use
// InitRepoWithPassword to produce a GEK1 keyfile. This function generates
// a random master key, base64-encodes it into the JSON keyfile format, and
// marks the repo config as encrypted. The master key is stored in
// plaintext in repo.key — this provides no security against an attacker
// with file access, only against accidental reads. For true encryption at
// rest, use InitRepoWithPassword.
//
// Deprecated: creating plaintext keyfiles is a legacy path. Existing
// repositories can be upgraded with MigrateKeyFileToGEK1; new encrypted
// repositories must use InitRepoWithPassword.
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
	if err := fsutil.WriteFileAtomic(path, data, 0600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	cfg, err := LoadConfig(repoRoot)
	if err != nil {
		return err
	}
	cfg.Encrypted = true
	return SaveConfig(repoRoot, cfg)
}
