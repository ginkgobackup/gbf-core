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
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
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

// UploadBlobFromPath encrypts the file at filePath and stores it under its
// content hash. The hash is computed in the same pass that reads the file
// for encryption (single-pass), so the blob key always matches the bytes
// actually stored even if the source file is modified concurrently.
//
// When knownHash is non-empty it is trusted as the expected content hash:
// the upload short-circuits if the blob already exists, and otherwise the
// hash computed during the encryption pass is verified against it — a
// mismatch (file changed since the caller hashed it) fails the upload
// instead of silently storing content under a stale key.
func UploadBlobFromPath(ctx context.Context, store SimpleBlobStore, enc *Encryptor, filePath string, knownHash string) (string, error) {
	// Fast path: the caller already knows the hash, so dedup can be decided
	// without touching the file at all.
	if knownHash != "" {
		exists, err := store.Exists(ctx, knownHash)
		if err != nil {
			return "", fmt.Errorf("exists check: %w", err)
		}
		if exists {
			return knownHash, nil
		}
	}

	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat: %w", err)
	}

	compressor := defaultStreamCompressor

	if info.Size() < int64(enc.chunkSize) {
		// Single read: hash exactly the bytes that get encrypted, so the
		// blob key can never diverge from the stored content. The read is
		// capped at MaxBlobSize minus the small-blob framing overhead —
		// the same ceiling readBoundedSmall/DecryptStream enforce on the
		// ciphertext — so a file that grew past chunkSize after the scan
		// fails loudly here instead of producing a small blob that no
		// restore path can decrypt back.
		const smallLimit = MaxBlobSize - (MagicSize + IVSize + TagSize)
		data, err := io.ReadAll(io.LimitReader(f, smallLimit+1))
		if err != nil {
			return "", fmt.Errorf("read: %w", err)
		}
		if len(data) > smallLimit {
			return "", fmt.Errorf("file grew past chunk size since scan: read %d bytes, exceeds small-blob limit %d", len(data), smallLimit)
		}
		contentHash := SHA256Bytes(data)
		if knownHash != "" && knownHash != contentHash {
			return "", fmt.Errorf("content changed since hash was computed: expected %s, got %s", knownHash, contentHash)
		}
		exists, err := store.Exists(ctx, contentHash)
		if err != nil {
			return "", fmt.Errorf("exists check: %w", err)
		}
		if exists {
			return contentHash, nil
		}
		if len(data) >= 65536 && !isLikelyIncompressible(filePath) {
			if compressed, cerr := compressor.Compress(data); cerr == nil && len(compressed) < len(data) {
				data = compressed
			}
		}
		// Content addressing convention: the blob name is always the hash
		// of the raw, uncompressed content (contentHash computed above).
		// Compression is a storage-layer detail only — DownloadBlob
		// decompresses after decrypt and verifies against the original
		// content hash. UploadBlob cannot be used here: it derives the
		// blob name from the (possibly compressed) bytes it is given,
		// which would break both the download-side hash check and dedup
		// against the pipeline path (see hashAndEncryptFile).
		ciphertext, err := enc.Encrypt(data)
		if err != nil {
			return "", fmt.Errorf("encrypt: %w", err)
		}
		if err := store.Put(ctx, contentHash, ciphertext); err != nil {
			return "", fmt.Errorf("put: %w", err)
		}
		return contentHash, nil
	}

	// Large path: hash the plaintext in the same pass that encrypts it,
	// writing the ciphertext to a tmp file first.
	tmpPath := filepath.Join(os.TempDir(), "gbf-tmp-"+uuid.New().String()+".tmp")
	tmpF, err := os.Create(tmpPath)
	if err != nil {
		return "", fmt.Errorf("create tmp: %w", err)
	}
	defer func() {
		_ = tmpF.Close()
		_ = os.Remove(tmpPath)
	}()

	var streamCompressor *compress.ZstdCompressor
	if !isLikelyIncompressible(filePath) {
		streamCompressor = defaultStreamCompressor
	}
	h := sha256.New()
	if err := encryptFileToWriter(enc, f, tmpF, streamCompressor, h); err != nil {
		return "", fmt.Errorf("stream encrypt: %w", err)
	}
	contentHash := hex.EncodeToString(h.Sum(nil))
	if knownHash != "" && knownHash != contentHash {
		return "", fmt.Errorf("content changed since hash was computed: expected %s, got %s", knownHash, contentHash)
	}

	if err := tmpF.Sync(); err != nil {
		return "", fmt.Errorf("sync: %w", err)
	}
	if err := tmpF.Close(); err != nil {
		return "", fmt.Errorf("close tmp: %w", err)
	}

	tmpF2, err := os.Open(tmpPath)
	if err != nil {
		return "", fmt.Errorf("reopen tmp: %w", err)
	}
	defer func() { _ = tmpF2.Close() }()

	tmpInfo, err := tmpF2.Stat()
	if err != nil {
		return "", fmt.Errorf("stat tmp: %w", err)
	}

	// Dedup check after the fact: for an unknown hash the only way to know
	// it is to read the file, which we just did as part of encrypting.
	exists, err := store.Exists(ctx, contentHash)
	if err != nil {
		return "", fmt.Errorf("exists check: %w", err)
	}
	if exists {
		return contentHash, nil
	}

	if err := store.PutStream(ctx, contentHash, tmpF2, tmpInfo.Size()); err != nil {
		return "", fmt.Errorf("put stream: %w", err)
	}

	return contentHash, nil
}

// encryptFileToWriter streams src through the chunked encryptor into dst.
// If plainHash is non-nil it is fed the plaintext of every chunk exactly as
// read from src, letting the caller compute the content hash in the same
// pass as the encryption (no second read of the source).
func encryptFileToWriter(enc *Encryptor, src *os.File, dst io.Writer, compressor *compress.ZstdCompressor, plainHash hash.Hash) error {
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
	chunkSize := int64(enc.chunkSize)
	chunkCount := uint64((info.Size() + chunkSize - 1) / chunkSize)
	// GB1/GB2 disambiguate small blobs from large ones via the 4-byte chunk
	// count, so a blob with chunkCount >= MaxChunkCount could be misread as
	// a small blob. The legacy formats therefore cannot represent it. Such
	// oversized blobs are written in the self-describing GB3 format, whose
	// magic unambiguously marks a chunked blob and whose header carries the
	// chunk size and plaintext size explicitly, lifting the ~390 GiB limit.
	useGB3 := chunkCount >= MaxChunkCount

	tryCompress := compressor != nil

	if useGB3 {
		compressAlg := byte(GB3CompressNone)
		var headerFlags byte
		if tryCompress {
			compressAlg = GB3CompressZstd
			headerFlags = GB3FlagChunkCompressed
		}
		hdr := encodeGB3Header(headerFlags, compressAlg, uint32(enc.chunkSize), uint64(info.Size()))
		if _, err := dst.Write(hdr); err != nil {
			return fmt.Errorf("write gb3 header: %w", err)
		}
	} else {
		magic := MagicGB1
		if tryCompress {
			magic = MagicGB2
		}
		if _, err := dst.Write([]byte(magic)); err != nil {
			return fmt.Errorf("write magic: %w", err)
		}
		countBuf := make([]byte, ChunkCountSize)
		binary.BigEndian.PutUint32(countBuf, uint32(chunkCount))
		if _, err := dst.Write(countBuf); err != nil {
			return fmt.Errorf("write count: %w", err)
		}
	}

	bp := getChunkBuf(enc.chunkSize)
	defer putChunkBuf(bp)
	buf := (*bp)[:enc.chunkSize]
	for i := uint64(0); i < chunkCount; i++ {
		n, err := io.ReadFull(src, buf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return fmt.Errorf("read chunk %d: %w", i, err)
		}
		if n == 0 {
			break
		}
		chunk := buf[:n]
		if plainHash != nil {
			plainHash.Write(chunk)
		}

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

		if tryCompress || useGB3 {
			sizeBuf := make([]byte, ChunkCountSize)
			binary.BigEndian.PutUint32(sizeBuf, uint32(len(encrypted)))
			if _, err := dst.Write(sizeBuf); err != nil {
				return fmt.Errorf("write size %d: %w", i, err)
			}
			flags := byte(0)
			if compressed {
				flags = GB3FlagChunkCompressed
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

// verifyingWriter wraps a restore destination and tracks the SHA-256 and
// byte count of the plaintext actually written, so streaming restore paths
// can verify the decrypted content against the content-addressed hash.
// AEAD success proves the blob is intact — not that the blob's plaintext is
// the content the manifest references (e.g. a blob stored under the wrong
// hash by an upstream bug, or a hash-keyed store returning the wrong
// object).
type verifyingWriter struct {
	w io.Writer
	h hash.Hash
	n int64
}

func (vw *verifyingWriter) Write(p []byte) (int, error) {
	n, err := vw.w.Write(p)
	if n > 0 {
		// hash.Hash.Write never returns an error.
		vw.h.Write(p[:n])
		vw.n += int64(n)
	}
	return n, err
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
	defer func() { _ = rc.Close() }()

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
		_ = tmpF.Close()
		_ = os.Remove(tmp)
	}()

	vw := &verifyingWriter{w: tmpF, h: sha256.New()}
	if err := decryptStreamToFile(dec, rc, vw); err != nil {
		return fmt.Errorf("stream decrypt: %w", err)
	}
	// The streaming path verifies the decrypted plaintext against the
	// content-addressed hash, matching the buffered path above.
	if got := hex.EncodeToString(vw.h.Sum(nil)); got != hash {
		return fmt.Errorf("restored content hash mismatch: expected %s, got %s", hash, got)
	}

	// Apply the source file's mode bits to the staged tmp file. Non-fatal
	// — content is already written, so log and continue on failure.
	if err := tmpF.Chmod(os.FileMode(mode)); err != nil {
		slog.Warn("GBF stream restore: chmod tmp file failed",
			"path", targetPath, "mode", mode, "error", err)
	}
	if err := tmpF.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	if err := tmpF.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}

	return os.Rename(tmp, targetPath)
}

func decryptStreamToFile(dec *Decryptor, src io.Reader, dst io.Writer) error {
	magicBuf := make([]byte, MagicSize)
	if _, err := io.ReadFull(src, magicBuf); err != nil {
		return fmt.Errorf("read magic: %w", err)
	}
	magic := string(magicBuf)
	if magic == MagicGB3 {
		return decryptGB3StreamToFile(dec, src, dst)
	}
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
		n, readErr := io.ReadFull(src, encryptedBuf)
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			return fmt.Errorf("read chunk %d: %w", i, readErr)
		}
		encrypted := encryptedBuf[:n]
		decrypted, err := gcm.Open(nil, iv, encrypted, nil)
		if err != nil {
			// A legacy small blob whose random IV's first 4 bytes look like
			// a chunk count lands here: chunk 0 fails AEAD because the data
			// was never chunked. If the stream also ended within the first
			// chunk read (a genuine multi-chunk blob fills the buffer), the
			// whole blob fits in what we've read — reinterpret it as a small
			// blob. AEAD only authenticates for the correct interpretation,
			// so trying both is sound, and nothing has hit dst yet. New
			// small blobs avoid this path entirely (see newSmallBlobIV).
			if i == 0 && (errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF)) {
				smallData := make([]byte, 0, ChunkCountSize+IVSize+len(encrypted))
				smallData = append(smallData, countBuf...)
				smallData = append(smallData, iv...)
				smallData = append(smallData, encrypted...)
				if plaintext, serr := dec.decryptSmall(smallData); serr == nil {
					if werr := writeSmallPlaintext(dst, plaintext); werr != nil {
						return fmt.Errorf("write small blob: %w", werr)
					}
					return nil
				}
			}
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

// decryptGB3StreamToFile decrypts a GB3 blob from a stream. Unlike the GB1
// streaming decoder it does not need the small/large heuristic: the magic
// unambiguously marks a chunked blob and the header carries the chunk size
// and chunk count, so blobs are not bounded by MaxChunkCount. Each chunk is
// framed GB2-style: storedSize(4B) || flags(1B) || IV(12B) || ciphertext.
func decryptGB3StreamToFile(dec *Decryptor, src io.Reader, dst io.Writer) error {
	rest := make([]byte, GB3HeaderSize-MagicSize)
	if _, err := io.ReadFull(src, rest); err != nil {
		return fmt.Errorf("read gb3 header: %w", err)
	}
	full := make([]byte, GB3HeaderSize)
	copy(full, MagicGB3)
	copy(full[MagicSize:], rest)
	hdr, err := ParseGB3Header(full)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(dec.key)
	if err != nil {
		return fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm: %w", err)
	}

	maxStored := int64(hdr.ChunkSize) + TagSize + 1024
	chunkCount := hdr.ChunkCount()
	for i := uint64(0); i < chunkCount; i++ {
		headerBuf := make([]byte, ChunkCountSize+FlagsSize)
		if _, err := io.ReadFull(src, headerBuf); err != nil {
			return fmt.Errorf("read chunk %d header: %w", i, err)
		}
		storedSize := binary.BigEndian.Uint32(headerBuf[:ChunkCountSize])
		compressed := headerBuf[ChunkCountSize]&GB3FlagChunkCompressed != 0

		if int64(storedSize) > maxStored {
			return fmt.Errorf("chunk %d: storedSize %d exceeds max %d", i, storedSize, maxStored)
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

// writeSmallPlaintext writes a decrypted GB1 small blob to dst, applying
// the same IsCompressed→Decompress step as the buffered DownloadBlob path.
// The pipeline (hashAndEncryptFile) and UploadBlobFromPath compress
// small-blob plaintext before encryption while keying the blob by the hash
// of the RAW content — without this step the streaming small-blob path
// would write zstd frames and fail the content-hash verification.
func writeSmallPlaintext(dst io.Writer, plaintext []byte) error {
	if defaultStreamDecompressor.IsCompressed(plaintext) {
		decompressed, err := defaultStreamDecompressor.Decompress(plaintext)
		if err != nil {
			return fmt.Errorf("decompress: %w", err)
		}
		plaintext = decompressed
	}
	_, err := dst.Write(plaintext)
	return err
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
	return writeSmallPlaintext(dst, plaintext)
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
	return writeSmallPlaintext(dst, plaintext)
}
