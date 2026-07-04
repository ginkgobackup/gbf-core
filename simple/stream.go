// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ginkgobackup/gbf-core/compress"
	"github.com/google/uuid"
)

var defaultStreamDecompressor = compress.NewZstdCompressor(1)

// defaultStreamCompressor is the package-level shared compressor for the
// streaming upload path. Reusing a single compressor avoids creating a fresh
// encoder/decoder pool (one goroutine per CPU, capped at 8) on every call to
// UploadBlobFromPath — which would leak goroutines and grow memory pressure
// during large backups of many small files.
var defaultStreamCompressor = compress.NewZstdCompressor(1)

func UploadBlobFromPath(ctx context.Context, store SimpleBlobStore, enc *Encryptor, filePath string, knownHash string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	var contentHash string
	if knownHash != "" {
		contentHash = knownHash
	} else {
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return "", fmt.Errorf("hash: %w", err)
		}
		contentHash = hex.EncodeToString(h.Sum(nil))
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return "", fmt.Errorf("seek: %w", err)
		}
	}

	exists, err := store.Exists(ctx, contentHash)
	if err != nil {
		return "", fmt.Errorf("exists check: %w", err)
	}
	if exists {
		return contentHash, nil
	}

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat: %w", err)
	}

	compressor := defaultStreamCompressor

	if info.Size() < int64(enc.chunkSize) {
		data, err := io.ReadAll(f)
		if err != nil {
			return "", fmt.Errorf("read: %w", err)
		}
		if len(data) >= 65536 && !isLikelyIncompressible(filePath) {
			if compressed, cerr := compressor.Compress(data); cerr == nil && len(compressed) < len(data) {
				data = compressed
			}
		}
		return UploadBlob(ctx, store, enc, data)
	}

	tmpPath := filepath.Join(os.TempDir(), "gbf-tmp-"+uuid.New().String()+".tmp")
	tmpF, err := os.Create(tmpPath)
	if err != nil {
		return "", fmt.Errorf("create tmp: %w", err)
	}
	defer func() {
		tmpF.Close()
		os.Remove(tmpPath)
	}()

	var streamCompressor *compress.ZstdCompressor
	if !isLikelyIncompressible(filePath) {
		streamCompressor = defaultStreamCompressor
	}
	if err := encryptFileToWriter(enc, f, tmpF, streamCompressor); err != nil {
		return "", fmt.Errorf("stream encrypt: %w", err)
	}

	if err := tmpF.Sync(); err != nil {
		return "", fmt.Errorf("sync: %w", err)
	}
	tmpF.Close()

	tmpF2, err := os.Open(tmpPath)
	if err != nil {
		return "", fmt.Errorf("reopen tmp: %w", err)
	}
	defer tmpF2.Close()

	tmpInfo, err := tmpF2.Stat()
	if err != nil {
		return "", fmt.Errorf("stat tmp: %w", err)
	}

	if err := store.PutStream(ctx, contentHash, tmpF2, tmpInfo.Size()); err != nil {
		return "", fmt.Errorf("put stream: %w", err)
	}

	return contentHash, nil
}

func encryptFileToWriter(enc *Encryptor, src *os.File, dst io.Writer, compressor *compress.ZstdCompressor) error {
	block, err := aes.NewCipher(enc.key)
	if err != nil {
		return fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm: %w", err)
	}

	info, err := src.Stat()
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	chunkCount := uint32((info.Size() + int64(enc.chunkSize) - 1) / int64(enc.chunkSize))
	if chunkCount >= MaxChunkCount {
		return fmt.Errorf("encryptFileToWriter: chunk count %d exceeds MaxChunkCount %d (file too large for chunk size %d; increase chunk size)", chunkCount, MaxChunkCount, enc.chunkSize)
	}

	tryCompress := compressor != nil
	magic := MagicGB1
	if tryCompress {
		magic = MagicGB2
	}

	if _, err := dst.Write([]byte(magic)); err != nil {
		return fmt.Errorf("write magic: %w", err)
	}
	countBuf := make([]byte, ChunkCountSize)
	binary.BigEndian.PutUint32(countBuf, chunkCount)
	if _, err := dst.Write(countBuf); err != nil {
		return fmt.Errorf("write count: %w", err)
	}

	buf := make([]byte, enc.chunkSize)
	for i := uint32(0); i < chunkCount; i++ {
		n, err := io.ReadFull(src, buf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return fmt.Errorf("read chunk %d: %w", i, err)
		}
		if n == 0 {
			break
		}
		chunk := buf[:n]

		toStore := chunk
		compressed := false
		if tryCompress && len(chunk) >= 65536 {
			if c, cerr := compressor.Compress(chunk); cerr == nil && len(c) < len(chunk) {
				toStore = c
				compressed = true
			}
		}

		iv := make([]byte, IVSize)
		if _, err := rand.Read(iv); err != nil {
			return fmt.Errorf("iv chunk %d: %w", i, err)
		}
		encrypted := gcm.Seal(nil, iv, toStore, nil)

		if tryCompress {
			sizeBuf := make([]byte, ChunkCountSize)
			binary.BigEndian.PutUint32(sizeBuf, uint32(len(encrypted)))
			if _, err := dst.Write(sizeBuf); err != nil {
				return fmt.Errorf("write size %d: %w", i, err)
			}
			flags := byte(0)
			if compressed {
				flags = 1
			}
			if _, err := dst.Write([]byte{flags}); err != nil {
				return fmt.Errorf("write flags %d: %w", i, err)
			}
		}

		if _, err := dst.Write(iv); err != nil {
			return fmt.Errorf("write iv %d: %w", i, err)
		}
		if _, err := dst.Write(encrypted); err != nil {
			return fmt.Errorf("write chunk %d: %w", i, err)
		}
	}
	return nil
}

func DownloadBlobToFile(ctx context.Context, store SimpleBlobStore, dec *Decryptor, hash string, targetPath string, mode uint32) error {
	rc, err := store.GetStream(ctx, hash)
	if err != nil {
		ciphertext, err2 := store.Get(ctx, hash)
		if err2 != nil {
			return fmt.Errorf("get: %w", err2)
		}
		plaintext, err2 := dec.Decrypt(ciphertext)
		if err2 != nil {
			return fmt.Errorf("decrypt: %w", err2)
		}
		if defaultStreamDecompressor.IsCompressed(plaintext) {
			decompressed, derr := defaultStreamDecompressor.Decompress(plaintext)
			if derr != nil {
				return fmt.Errorf("decompress: %w", derr)
			}
			plaintext = decompressed
		}
		actualHash := SHA256Bytes(plaintext)
		if actualHash != hash {
			return fmt.Errorf("hash mismatch: expected %s, got %s", hash, actualHash)
		}
		dir := filepath.Dir(targetPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("mkdir: %w", err)
		}
		tmp := targetPath + "." + uuid.New().String() + ".tmp"
		if err := os.WriteFile(tmp, plaintext, os.FileMode(mode)); err != nil {
			return fmt.Errorf("write: %w", err)
		}
		return os.Rename(tmp, targetPath)
	}
	defer rc.Close()

	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp := targetPath + "." + uuid.New().String() + ".tmp"
	tmpF, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	defer func() {
		tmpF.Close()
		os.Remove(tmp)
	}()

	if err := decryptStreamToFile(dec, rc, tmpF); err != nil {
		return fmt.Errorf("stream decrypt: %w", err)
	}

	if err := tmpF.Chmod(os.FileMode(mode)); err != nil {
	}
	if err := tmpF.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	tmpF.Close()

	return os.Rename(tmp, targetPath)
}

func decryptStreamToFile(dec *Decryptor, src io.Reader, dst io.Writer) error {
	magicBuf := make([]byte, MagicSize)
	if _, err := io.ReadFull(src, magicBuf); err != nil {
		return fmt.Errorf("read magic: %w", err)
	}
	magic := string(magicBuf)
	if magic == MagicGB2 {
		return decryptGB2StreamToFile(dec, src, dst)
	}
	if magic != MagicGB1 {
		return fmt.Errorf("invalid magic: %q", magic)
	}

	countBuf := make([]byte, ChunkCountSize)
	if _, err := io.ReadFull(src, countBuf); err != nil {
		data := append(magicBuf[MagicSize:], countBuf...)
		return decryptSmallStream(dec, data, src, dst)
	}

	if !isChunkCount(countBuf) {
		ivBuf := make([]byte, IVSize-len(countBuf))
		if _, err := io.ReadFull(src, ivBuf); err != nil {
			return fmt.Errorf("read iv: %w", err)
		}
		ivData := append(countBuf, ivBuf...)
		return decryptSmallStreamFromIV(dec, ivData, src, dst)
	}

	chunkCount := binary.BigEndian.Uint32(countBuf)
	block, err := aes.NewCipher(dec.key)
	if err != nil {
		return fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm: %w", err)
	}

	for i := uint32(0); i < chunkCount; i++ {
		iv := make([]byte, IVSize)
		if _, err := io.ReadFull(src, iv); err != nil {
			return fmt.Errorf("read iv chunk %d: %w", i, err)
		}
		encryptedBuf := make([]byte, dec.chunkSize+TagSize)
		n, err := io.ReadFull(src, encryptedBuf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return fmt.Errorf("read chunk %d: %w", i, err)
		}
		encrypted := encryptedBuf[:n]
		decrypted, err := gcm.Open(nil, iv, encrypted, nil)
		if err != nil {
			return fmt.Errorf("decrypt chunk %d: %w", i, err)
		}
		if _, err := dst.Write(decrypted); err != nil {
			return fmt.Errorf("write chunk %d: %w", i, err)
		}
	}
	return nil
}

func decryptGB2StreamToFile(dec *Decryptor, src io.Reader, dst io.Writer) error {
	countBuf := make([]byte, ChunkCountSize)
	if _, err := io.ReadFull(src, countBuf); err != nil {
		return fmt.Errorf("read chunk count: %w", err)
	}
	chunkCount := binary.BigEndian.Uint32(countBuf)
	if chunkCount == 0 || chunkCount >= MaxChunkCount {
		return fmt.Errorf("invalid chunk count: %d", chunkCount)
	}

	block, err := aes.NewCipher(dec.key)
	if err != nil {
		return fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm: %w", err)
	}

	for i := uint32(0); i < chunkCount; i++ {
		headerBuf := make([]byte, ChunkCountSize+FlagsSize)
		if _, err := io.ReadFull(src, headerBuf); err != nil {
			return fmt.Errorf("read chunk %d header: %w", i, err)
		}
		storedSize := binary.BigEndian.Uint32(headerBuf[:ChunkCountSize])
		compressed := headerBuf[ChunkCountSize] != 0

		// Bound storedSize to prevent a crafted blob from triggering an
		// OOM via make([]byte, storedSize). Each chunk is at most
		// chunkSize + TagSize of ciphertext, plus a small margin for
		// compression expansion.
		if storedSize > uint32(MaxStoredSize) {
			return fmt.Errorf("chunk %d: storedSize %d exceeds max %d", i, storedSize, MaxStoredSize)
		}

		iv := make([]byte, IVSize)
		if _, err := io.ReadFull(src, iv); err != nil {
			return fmt.Errorf("read iv chunk %d: %w", i, err)
		}

		encryptedBuf := make([]byte, storedSize)
		if _, err := io.ReadFull(src, encryptedBuf); err != nil {
			return fmt.Errorf("read chunk %d: %w", i, err)
		}

		decrypted, err := gcm.Open(nil, iv, encryptedBuf, nil)
		if err != nil {
			return fmt.Errorf("decrypt chunk %d: %w", i, err)
		}
		if compressed {
			decompressed, derr := defaultStreamDecompressor.Decompress(decrypted)
			if derr != nil {
				return fmt.Errorf("decompress chunk %d: %w", i, derr)
			}
			decrypted = decompressed
		}
		if _, err := dst.Write(decrypted); err != nil {
			return fmt.Errorf("write chunk %d: %w", i, err)
		}
	}
	return nil
}

// readBoundedSmall reads the remainder of a GB1 small blob from src into a
// single buffer prefixed by initialData. The total is capped at MaxBlobSize:
// a crafted blob could otherwise be arbitrarily large and exhaust memory
// via io.ReadAll.
func readBoundedSmall(initialData []byte, src io.Reader) ([]byte, error) {
	lr := io.LimitReader(src, MaxBlobSize+1-int64(len(initialData)))
	rest, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	all := append(initialData, rest...)
	if len(all) > MaxBlobSize {
		return nil, fmt.Errorf("blob exceeds MaxBlobSize %d", MaxBlobSize)
	}
	return all, nil
}

func decryptSmallStream(dec *Decryptor, initialData []byte, src io.Reader, dst io.Writer) error {
	all, err := readBoundedSmall(initialData, src)
	if err != nil {
		return err
	}
	plaintext, err := dec.decryptSmall(all)
	if err != nil {
		return err
	}
	_, err = dst.Write(plaintext)
	return err
}

func decryptSmallStreamFromIV(dec *Decryptor, ivData []byte, src io.Reader, dst io.Writer) error {
	all, err := readBoundedSmall(ivData, src)
	if err != nil {
		return err
	}
	plaintext, err := dec.decryptSmall(all)
	if err != nil {
		return err
	}
	_, err = dst.Write(plaintext)
	return err
}
