// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"bytes"
	"testing"
)

func TestKeyFileProtectionModeDetection(t *testing.T) {
	dir := t.TempDir()

	// No key file at all.
	mode, err := KeyFileProtectionMode(dir)
	if err != nil || mode != KeyProtectionNone {
		t.Fatalf("no keyfile: mode=%q err=%v, want none", mode, err)
	}

	// Legacy plaintext.
	if err := InitRepoWithKeyFile(dir, "dev1"); err != nil {
		t.Fatalf("init legacy: %v", err)
	}
	mode, err = KeyFileProtectionMode(dir)
	if err != nil || mode != KeyProtectionLegacyPlaintext {
		t.Fatalf("legacy: mode=%q err=%v, want legacy_plaintext", mode, err)
	}
}

func TestMigrateKeyFileToGEK1(t *testing.T) {
	dir := t.TempDir()
	if err := InitRepoWithKeyFile(dir, "dev1"); err != nil {
		t.Fatalf("init legacy: %v", err)
	}
	// Capture the legacy master key: migration must preserve it.
	kf, err := LoadKeyFile(dir)
	if err != nil {
		t.Fatalf("load legacy keyfile: %v", err)
	}
	masterBefore, err := kf.DecodeKey()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if err := MigrateKeyFileToGEK1(dir, ""); err == nil {
		t.Fatal("empty password must be rejected")
	}

	if err := MigrateKeyFileToGEK1(dir, "correct horse battery staple"); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Mode flipped to GEK1.
	mode, err := KeyFileProtectionMode(dir)
	if err != nil || mode != KeyProtectionGEK1 {
		t.Fatalf("after migrate: mode=%q err=%v, want gek1", mode, err)
	}

	// The master key is unchanged — existing data stays readable.
	masterAfter, err := UnlockRepoWithPassword(dir, "correct horse battery staple")
	if err != nil {
		t.Fatalf("unlock after migration: %v", err)
	}
	if !bytes.Equal(masterBefore, masterAfter) {
		t.Fatal("migration must preserve the master key")
	}

	// Wrong password fails.
	if _, err := UnlockRepoWithPassword(dir, "wrong"); err == nil {
		t.Fatal("wrong password must not unlock")
	}

	// Migrating again is rejected.
	if err := MigrateKeyFileToGEK1(dir, "x"); err == nil {
		t.Fatal("re-migration of a GEK1 repo must fail")
	}
}

func TestMigrateKeyFileToGEK1RejectsNonLegacy(t *testing.T) {
	dir := t.TempDir()
	if err := InitRepo(InitParams{RepoRoot: dir, DeviceID: "dev1"}); err != nil {
		t.Fatalf("init plain: %v", err)
	}
	if err := MigrateKeyFileToGEK1(dir, "pw"); err == nil {
		t.Fatal("plain repo without keyfile must not migrate")
	}
}
