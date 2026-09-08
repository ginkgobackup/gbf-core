// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// registryPathFor returns the on-disk path of a source registry file,
// mirroring the layout used by SaveSourceRegistry.
func registryPathFor(t *testing.T, metaDir, cloudID string) string {
	t.Helper()
	return filepath.Join(sourceRegistriesDir(metaDir), cloudID+".json.zst")
}

func TestSourceRegistryEnvelopeWritten(t *testing.T) {
	dir := t.TempDir()
	reg := &SourceRegistry{CloudID: "7", Name: "Env", Path: "/x"}

	if err := SaveSourceRegistry(dir, reg); err != nil {
		t.Fatalf("save: %v", err)
	}
	raw, err := os.ReadFile(registryPathFor(t, dir, "7"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(string(raw), RegistryEnvelopeMagic) {
		t.Fatalf("saved registry does not start with %q envelope magic", RegistryEnvelopeMagic)
	}

	// Envelope decode round-trip.
	decoded, err := DecodeSourceRegistry(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.CloudID != "7" || decoded.Name != "Env" {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestDecodeSourceRegistryLegacyFormats(t *testing.T) {
	reg := &SourceRegistry{CloudID: "legacy", Name: "Old", Path: "/old"}

	// Legacy layout 1: bare zstd-compressed JSON (pre-envelope writers).
	data, err := localManifestCompressor.Compress(mustMarshalJSON(t, reg))
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	if _, err := DecodeSourceRegistry(data); err != nil {
		t.Fatalf("legacy zstd decode: %v", err)
	}

	// Legacy layout 2: plain (uncompressed) JSON.
	if _, err := DecodeSourceRegistry(mustMarshalJSON(t, reg)); err != nil {
		t.Fatalf("legacy plain JSON decode: %v", err)
	}
}

func TestDecodeSourceRegistryChecksumMismatch(t *testing.T) {
	reg := &SourceRegistry{CloudID: "9", Name: "Corrupt", Path: "/c"}
	encoded, err := EncodeSourceRegistry(reg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Corrupt one payload byte (after magic + 32-byte checksum).
	encoded[len(encoded)-1] ^= 0xFF
	if _, err := DecodeSourceRegistry(encoded); err == nil {
		t.Fatal("expected checksum mismatch error, got nil")
	}
}

func TestLoadSourceRegistryRejectsIdentityMismatch(t *testing.T) {
	dir := t.TempDir()
	// Save a registry under cloudID "a", then load it as "b": the file
	// content claims a different identity than requested.
	if err := SaveSourceRegistry(dir, &SourceRegistry{CloudID: "a", Name: "A"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := os.Rename(registryPathFor(t, dir, "a"), registryPathFor(t, dir, "b")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	_, err := LoadSourceRegistry(dir, "b")
	if err == nil {
		t.Fatal("expected identity mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListSourceRegistriesPartialFailure(t *testing.T) {
	dir := t.TempDir()
	metaDir := dir

	// One healthy registry.
	if err := SaveSourceRegistry(metaDir, &SourceRegistry{CloudID: "good", Name: "Good"}); err != nil {
		t.Fatalf("save good: %v", err)
	}
	// One corrupt registry: valid envelope magic, corrupted payload.
	encoded, err := EncodeSourceRegistry(&SourceRegistry{CloudID: "bad", Name: "Bad"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	encoded[len(encoded)-1] ^= 0xFF
	badPath := registryPathFor(t, metaDir, "bad")
	if err := os.MkdirAll(filepath.Dir(badPath), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(badPath, encoded, 0600); err != nil {
		t.Fatalf("write bad: %v", err)
	}

	list, err := ListSourceRegistries(metaDir)
	if err == nil {
		t.Fatal("expected SourceRegistryLoadError, got nil")
	}
	var loadErr *SourceRegistryLoadError
	if !errors.As(err, &loadErr) {
		t.Fatalf("expected *SourceRegistryLoadError, got %T: %v", err, err)
	}
	if len(list) != 1 {
		t.Fatalf("partial results: got %d registries, want 1 (the good one)", len(list))
	}
	if list[0].CloudID != "good" {
		t.Fatalf("partial results: got %q, want good", list[0].CloudID)
	}
	if len(loadErr.Failures) != 1 || loadErr.Failures[0].CloudID != "bad" {
		t.Fatalf("failures: %+v", loadErr.Failures)
	}
	if loadErr.Error() == "" {
		t.Fatal("error message must not be empty")
	}
}

func mustMarshalJSON(t *testing.T, reg *SourceRegistry) []byte {
	t.Helper()
	data, err := json.Marshal(reg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}
