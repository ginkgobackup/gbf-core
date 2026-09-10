// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"golang.org/x/crypto/hkdf"
)

const (
	MagicGB1       = "GB1\x00"
	MagicGB2       = "GB2\x00"
	MagicGB3       = "GB3\x00"
	GKM1Magic      = "GKM1"
	MagicSize      = 4
	IVSize         = 12
	TagSize        = 16
	ChunkCountSize = 4
	FlagsSize      = 1
	// MaxChunkCount is the upper bound on chunk counts accepted by the
	// legacy (GB1/GB2) decryptor (see isChunkCount). It must match the
	// threshold used to disambiguate GB1 small vs large blobs. encryptLarge
	// refuses to write blobs with chunkCount >= MaxChunkCount so a legit
	// large blob is never misread as small; the reverse ambiguity (a small
	// blob whose random IV looks like a chunk count) is avoided for new
	// blobs by newSmallBlobIV and tolerated for legacy blobs by the AEAD
	// fallback in Decrypt. With the default 4 MiB chunk size, 100000 chunks
	// ≈ 390 GiB. Blobs larger than that are written in the self-describing
	// GB3 format (see below), which is not subject to this limit because its
	// magic unambiguously marks a chunked blob.
	MaxChunkCount = 100000
	// GB3HeaderSize is the fixed size, in bytes, of the GB3 self-describing
	// header (magic + version + algorithm descriptors + chunk size +
	// plaintext size). GB3 lifts the legacy ~390 GiB per-blob limit by
	// making the chunked layout explicit instead of inferring it from a
	// magic + chunk-count heuristic.
	GB3HeaderSize = 24
	// GB3Version is the format version written into new GB3 headers.
	GB3Version = 1
	// MaxGB3ChunkSize bounds the chunk size a GB3 reader accepts. The
	// streaming reader allocates one ciphertext buffer per chunk, so a
	// crafted header claiming a multi-gigabyte chunk would be a memory
	// exhaustion vector. 64 MiB is 16x the default and far above any
	// realistic configuration.
	MaxGB3ChunkSize = 64 * 1024 * 1024
	// GB3 flag bits (header offset 5).
	GB3FlagChunkCompressed = 1 << 0
	// GB3 algorithm identifiers. Zero means "none" where applicable.
	GB3HashSHA256     = 1
	GB3CompressNone   = 0
	GB3CompressZstd   = 1
	GB3EncryptAESGCM  = 1
	GB3ChunkingFixed  = 1
	GB3KeyVersionCur  = 1
	gb3OffVersion     = 4
	gb3OffFlags       = 5
	gb3OffHashAlg     = 6
	gb3OffCompressAlg = 7
	gb3OffEncryptAlg  = 8
	gb3OffChunkingAlg = 9
	gb3OffKeyVersion  = 10
	gb3OffChunkSize   = 12
	gb3OffPlainSize   = 16
	// MaxStoredSize is the upper bound on the per-chunk storedSize header
	// in GB2 blobs. It bounds the size of any single make() in the
	// decryptor to prevent OOM via a crafted blob. We allow chunkSize +
	// TagSize plus a 1 KiB margin to accommodate compression expansion
	// in pathological cases.
	MaxStoredSize = DefaultChunkSize + TagSize + 1024
	// MaxBlobSize bounds the total input read by DecryptStream and the
	// decryptSmall* streaming helpers. A crafted/corrupt blob could
	// otherwise be arbitrarily large and exhaust memory via io.ReadAll.
	// The legit small-blob path produces at most chunkSize + IVSize +
	// TagSize bytes; we add 1 MiB of headroom for safety.
	MaxBlobSize = DefaultChunkSize + IVSize + TagSize + 1<<20
)

// Encryptor is the on-disk format encryptor: a stateful AEAD wrapper bound
// to a single master key and chunk size. Its Encrypt/Decrypt methods emit
// and parse the GB1/GB2 chunked blob format (magic bytes + chunk count +
// per-chunk IV+ciphertext), not raw AEAD. It is intentionally distinct from
// vault.Encryptor, which is the stateless single-block AEAD interface in
// crypto/. The main backup path does not currently route through
// vault.Encryptor: manifests are encrypted directly with the master key
// by EncryptManifest below. See vault/encryptor.go.
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

// newSmallBlobIV returns a random GCM IV whose first 4 bytes never fall in
// the chunk-count range (1..MaxChunkCount-1) used to distinguish GB1 large
// blobs from small ones. Rejection sampling keeps newly written small blobs
// unambiguous on the wire; the collision probability is ~1/43000 per IV, so
// the expected number of retries is negligible. Small blobs written before
// this scheme may still be ambiguous — the decryptor handles those by trying
// the other interpretation when AEAD authentication fails (see Decrypt).
func newSmallBlobIV() ([]byte, error) {
	iv := make([]byte, IVSize)
	for {
		if _, err := rand.Read(iv); err != nil {
			return nil, fmt.Errorf("iv: %w", err)
		}
		if !isChunkCount(iv[:ChunkCountSize]) {
			return iv, nil
		}
	}
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
	iv, err := newSmallBlobIV()
	if err != nil {
		return nil, err
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
	if chunkCount >= MaxChunkCount {
		// The decryptor uses isChunkCount (v < 100000) to distinguish
		// GB1 small from GB1 large; producing a blob whose chunkCount
		// falls outside that range would make it undecryptable. Emit the
		// self-describing GB3 format instead, which is not subject to
		// that limit.
		return e.encryptLargeV3(plaintext)
	}
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

// encryptLargeV3 encodes plaintext as a GB3 blob. It is chosen when the
// legacy GB1 layout cannot represent the chunk count (>= MaxChunkCount).
// Chunks are framed GB2-style (storedSize || flags || IV || ciphertext) and
// the header records the chunk size and plaintext length, so the decryptor
// needs no small/large heuristic. The in-memory encryptor performs no
// compression, so the per-chunk flags are always zero.
func (e *Encryptor) encryptLargeV3(plaintext []byte) ([]byte, error) {
	chunkCount := (len(plaintext) + e.chunkSize - 1) / e.chunkSize
	if uint64(chunkCount) > math.MaxUint32 {
		return nil, fmt.Errorf("encryptLargeV3: chunk count %d overflows uint32 for chunk size %d", chunkCount, e.chunkSize)
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	perChunk := ChunkCountSize + FlagsSize + IVSize + e.chunkSize + TagSize
	result := make([]byte, 0, GB3HeaderSize+len(plaintext)+chunkCount*perChunk)
	result = append(result, encodeGB3Header(0, GB3CompressNone, uint32(e.chunkSize), uint64(len(plaintext)))...)

	sizeBuf := make([]byte, ChunkCountSize)
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
		binary.BigEndian.PutUint32(sizeBuf, uint32(len(encrypted)))
		result = append(result, sizeBuf...)
		result = append(result, 0)
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
	case MagicGB3:
		return d.decryptLargeV3(ciphertext)
	case MagicGB2:
		return d.decryptLargeV2(data)
	case MagicGB1:
		// The small-vs-large split is a heuristic: large blobs start with a
		// chunk count in 1..MaxChunkCount-1, small blobs with a random IV.
		// Legacy small blobs (~1/43000 of them) have an IV whose first 4
		// bytes look like a chunk count. AEAD authentication only succeeds
		// for the correct interpretation, so when the primary parse fails we
		// fall back to the other one — trying both is cryptographically
		// sound. Newly written small blobs avoid the ambiguity entirely via
		// IV rejection sampling (see newSmallBlobIV).
		if len(data) > ChunkCountSize && isChunkCount(data[:ChunkCountSize]) {
			plaintext, err := d.decryptLarge(data)
			if err == nil {
				return plaintext, nil
			}
			if plaintext, serr := d.decryptSmall(data); serr == nil {
				return plaintext, nil
			}
			return nil, err
		}
		plaintext, err := d.decryptSmall(data)
		if err == nil {
			return plaintext, nil
		}
		if len(data) > ChunkCountSize {
			if plaintext, lerr := d.decryptLarge(data); lerr == nil {
				return plaintext, nil
			}
		}
		return nil, err
	default:
		return nil, fmt.Errorf("invalid magic: %q", magic)
	}
}

func isChunkCount(buf []byte) bool {
	if len(buf) < ChunkCountSize {
		return false
	}
	v := binary.BigEndian.Uint32(buf)
	return v > 0 && v < MaxChunkCount
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
	// A legitimately written GB1 large blob always holds at least one chunk
	// (encryptLarge only runs on plaintext >= chunkSize). Rejecting 0 also
	// keeps the small-blob fallback in Decrypt from "successfully" parsing
	// zero-padded garbage as an empty large blob.
	if chunkCount == 0 || chunkCount >= MaxChunkCount {
		return nil, fmt.Errorf("gb1 invalid chunk count: %d", chunkCount)
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
	// A legitimately written blob is fully consumed by the chunk loop;
	// leftover bytes mean the blob was truncated or has data appended,
	// which the chunked GCM authentication cannot detect.
	if len(data) != 0 {
		return nil, fmt.Errorf("gb1 trailing data after final chunk: %d bytes", len(data))
	}
	return plaintext, nil
}

func (d *Decryptor) decryptLargeV2(data []byte) ([]byte, error) {
	if len(data) < ChunkCountSize {
		return nil, fmt.Errorf("gb2 data too short: %d bytes", len(data))
	}
	chunkCount := binary.BigEndian.Uint32(data[:ChunkCountSize])
	if chunkCount == 0 || chunkCount >= MaxChunkCount {
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

		// Bound storedSize to prevent a crafted blob from triggering
		// an OOM via a huge allocation. Each chunk is at most
		// chunkSize + TagSize of ciphertext, plus a small margin for
		// compression expansion.
		if storedSize > uint32(MaxStoredSize) {
			return nil, fmt.Errorf("chunk %d: storedSize %d exceeds max %d", i, storedSize, MaxStoredSize)
		}

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
	// Same trailing-data check as GB1: the blob must be fully consumed.
	if len(data) != 0 {
		return nil, fmt.Errorf("gb2 trailing data after final chunk: %d bytes", len(data))
	}
	return plaintext, nil
}

// GB3Header is the parsed form of a GB3 self-describing header. Unlike the
// GB1/GB2 layouts, every parameter a reader needs (chunk size, algorithm
// descriptors, plaintext length) is encoded explicitly, so the reader no
// longer has to infer the layout from a magic byte plus a chunk-count
// heuristic. That is what allows GB3 blobs to exceed the legacy
// MaxChunkCount (~390 GiB at the default chunk size) boundary.
type GB3Header struct {
	Version        byte
	Flags          byte
	HashAlg        byte
	CompressionAlg byte
	EncryptionAlg  byte
	ChunkingAlg    byte
	KeyVersion     uint16
	ChunkSize      uint32
	PlaintextSize  uint64
}

// ChunkCount returns the number of chunks implied by the header. It is
// derived from PlaintextSize and ChunkSize, both of which ParseGB3Header
// validates, so the result never wraps for a well-formed header.
func (h *GB3Header) ChunkCount() uint64 {
	if h.ChunkSize == 0 {
		return 0
	}
	return (h.PlaintextSize + uint64(h.ChunkSize) - 1) / uint64(h.ChunkSize)
}

// encodeGB3Header builds the fixed GB3HeaderSize-byte self-describing header.
func encodeGB3Header(flags, compressAlg byte, chunkSize uint32, plaintextSize uint64) []byte {
	h := make([]byte, GB3HeaderSize)
	copy(h, MagicGB3)
	h[gb3OffVersion] = GB3Version
	h[gb3OffFlags] = flags
	h[gb3OffHashAlg] = GB3HashSHA256
	h[gb3OffCompressAlg] = compressAlg
	h[gb3OffEncryptAlg] = GB3EncryptAESGCM
	h[gb3OffChunkingAlg] = GB3ChunkingFixed
	binary.BigEndian.PutUint16(h[gb3OffKeyVersion:], GB3KeyVersionCur)
	binary.BigEndian.PutUint32(h[gb3OffChunkSize:], chunkSize)
	binary.BigEndian.PutUint64(h[gb3OffPlainSize:], plaintextSize)
	return h
}

// ParseGB3Header validates and parses a GB3 header. data must start at the
// magic byte and contain at least GB3HeaderSize bytes. Every field a reader
// relies on is checked so a corrupt or downgraded blob fails fast and
// clearly instead of being mis-decrypted.
func ParseGB3Header(data []byte) (*GB3Header, error) {
	if len(data) < GB3HeaderSize {
		return nil, fmt.Errorf("gb3 header too short: %d bytes", len(data))
	}
	if string(data[:MagicSize]) != MagicGB3 {
		return nil, fmt.Errorf("not a GB3 blob: magic %q", data[:MagicSize])
	}
	h := &GB3Header{
		Version:        data[gb3OffVersion],
		Flags:          data[gb3OffFlags],
		HashAlg:        data[gb3OffHashAlg],
		CompressionAlg: data[gb3OffCompressAlg],
		EncryptionAlg:  data[gb3OffEncryptAlg],
		ChunkingAlg:    data[gb3OffChunkingAlg],
		KeyVersion:     binary.BigEndian.Uint16(data[gb3OffKeyVersion:]),
		ChunkSize:      binary.BigEndian.Uint32(data[gb3OffChunkSize:]),
		PlaintextSize:  binary.BigEndian.Uint64(data[gb3OffPlainSize:]),
	}
	if h.Version != GB3Version {
		return nil, fmt.Errorf("unsupported gb3 version %d", h.Version)
	}
	if h.HashAlg != GB3HashSHA256 {
		return nil, fmt.Errorf("unsupported gb3 hash algorithm %d", h.HashAlg)
	}
	if h.EncryptionAlg != GB3EncryptAESGCM {
		return nil, fmt.Errorf("unsupported gb3 encryption algorithm %d", h.EncryptionAlg)
	}
	if h.ChunkingAlg != GB3ChunkingFixed {
		return nil, fmt.Errorf("unsupported gb3 chunking algorithm %d", h.ChunkingAlg)
	}
	if h.CompressionAlg != GB3CompressNone && h.CompressionAlg != GB3CompressZstd {
		return nil, fmt.Errorf("unsupported gb3 compression algorithm %d", h.CompressionAlg)
	}
	if h.ChunkSize == 0 {
		return nil, fmt.Errorf("gb3 invalid chunk size 0")
	}
	if h.ChunkSize > MaxGB3ChunkSize {
		return nil, fmt.Errorf("gb3 chunk size %d exceeds max %d", h.ChunkSize, MaxGB3ChunkSize)
	}
	if h.ChunkCount() > math.MaxUint32 {
		return nil, fmt.Errorf("gb3 chunk count overflows uint32")
	}
	return h, nil
}

// IsEncryptedBlob reports whether data starts with a GBF encryption magic
// (GB1, GB2, or GB3). It lets callers outside this package classify a blob
// without duplicating the magic constants and without hard-coding a single
// format generation.
func IsEncryptedBlob(data []byte) bool {
	if len(data) < MagicSize {
		return false
	}
	switch string(data[:MagicSize]) {
	case MagicGB1, MagicGB2, MagicGB3:
		return true
	default:
		return false
	}
}

// decryptLargeV3 decrypts a GB3 blob. The chunked layout is deliberately the
// same per-chunk framing as GB2 (storedSize + flags + IV + ciphertext) but
// is decoded against the explicit chunk size and chunk count from the
// self-describing header, so it is not bounded by MaxChunkCount.
func (d *Decryptor) decryptLargeV3(full []byte) ([]byte, error) {
	hdr, err := ParseGB3Header(full)
	if err != nil {
		return nil, err
	}
	chunkCount := hdr.ChunkCount()
	// ChunkCount is checked against MaxUint32 by ParseGB3Header.
	data := full[GB3HeaderSize:]

	block, err := aes.NewCipher(d.key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	maxStored := int64(hdr.ChunkSize) + TagSize + 1024
	var plaintext []byte
	for i := uint64(0); i < chunkCount; i++ {
		if len(data) < ChunkCountSize+FlagsSize {
			return nil, fmt.Errorf("gb3 chunk %d: missing size header", i)
		}
		storedSize := binary.BigEndian.Uint32(data[:ChunkCountSize])
		compressed := data[ChunkCountSize]&GB3FlagChunkCompressed != 0
		data = data[ChunkCountSize+FlagsSize:]
		if int64(storedSize) > maxStored {
			return nil, fmt.Errorf("gb3 chunk %d: storedSize %d exceeds max %d", i, storedSize, maxStored)
		}
		if len(data) < IVSize {
			return nil, fmt.Errorf("gb3 chunk %d: missing IV", i)
		}
		iv := data[:IVSize]
		data = data[IVSize:]
		if len(data) < int(storedSize) {
			return nil, fmt.Errorf("gb3 chunk %d: missing ciphertext", i)
		}
		encrypted := data[:storedSize]
		data = data[storedSize:]
		decrypted, err := gcm.Open(nil, iv, encrypted, nil)
		if err != nil {
			return nil, fmt.Errorf("gb3 decrypt chunk %d: %w", i, err)
		}
		if compressed {
			decompressed, derr := defaultStreamDecompressor.Decompress(decrypted)
			if derr != nil {
				return nil, fmt.Errorf("gb3 decompress chunk %d: %w", i, derr)
			}
			decrypted = decompressed
		}
		plaintext = append(plaintext, decrypted...)
	}
	// Same trailing-data check as GB1/GB2: the blob must be fully consumed.
	if len(data) != 0 {
		return nil, fmt.Errorf("gb3 trailing data after final chunk: %d bytes", len(data))
	}
	return plaintext, nil
}

func (d *Decryptor) DecryptStream(r io.Reader) ([]byte, error) {
	// Cap input to prevent a malicious/corrupt blob from exhausting memory
	// via an unbounded io.ReadAll.
	lr := io.LimitReader(r, MaxBlobSize+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(data) > MaxBlobSize {
		return nil, fmt.Errorf("blob exceeds MaxBlobSize %d", MaxBlobSize)
	}
	return d.Decrypt(data)
}

// metadataKeyPurpose is the HKDF salt separating the manifest encryption
// key from other keys derived from the same repo master key. Blobs keep
// using the raw master key for now (GB1/GB2 have no key-version field to
// signal a change); manifests move to a purpose-derived key so metadata
// and data no longer share one key. The salt string matches the
// convention of crypto.AESEncryptor.DeriveKey.
const metadataKeyPurpose = "gbf/metadata-key/v1"

// DeriveMetadataKey derives the manifest encryption key from the repo
// master key via HKDF-SHA256. Deterministic: the same master key always
// yields the same metadata key, so decryption needs no extra state.
func DeriveMetadataKey(masterKey []byte) []byte {
	reader := hkdf.New(sha256.New, masterKey, []byte(metadataKeyPurpose), nil)
	key := make([]byte, 32)
	// HKDF-SHA256 never errors on a 32-byte read from a non-empty secret.
	_, _ = io.ReadFull(reader, key)
	return key
}

func EncryptManifest(plaintext []byte, key []byte) ([]byte, error) {
	// Manifests are always encrypted under the purpose-derived metadata
	// key, never the raw master key (see DeriveMetadataKey).
	key = DeriveMetadataKey(key)
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
	payload := data[MagicSize:]
	// Current manifests are encrypted under the HKDF-derived metadata key.
	if plaintext, err := NewDecryptor(DeriveMetadataKey(key), DefaultChunkSize).decryptSmall(payload); err == nil {
		return plaintext, nil
	}
	// Legacy manifests (written before key separation) were encrypted
	// under the raw master key. GCM authentication makes the fallback
	// unambiguous; the first attempt fails fast for the wrong key.
	return NewDecryptor(key, DefaultChunkSize).decryptSmall(payload)
}

func DecryptIfEncrypted(data []byte, key []byte) ([]byte, error) {
	if len(data) < MagicSize {
		return data, nil
	}
	magic := string(data[:MagicSize])
	if magic == GKM1Magic {
		return DecryptManifest(data, key)
	}
	if !IsEncryptedBlob(data) {
		return nil, fmt.Errorf("unknown magic %q: expected GB1, GB2, GB3, or GKM1", magic)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("encrypted blob requires key but none provided (magic %q)", magic)
	}
	return NewDecryptor(key, DefaultChunkSize).Decrypt(data)
}
