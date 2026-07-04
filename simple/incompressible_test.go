// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import "testing"

func TestIsLikelyIncompressibleByExtension(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Image formats
		{"photo.jpg", true},
		{"photo.JPEG", true}, // case-insensitive
		{"photo.png", true},
		{"pic.webp", true},
		{"raw.cr2", true},

		// Video formats
		{"clip.mp4", true},
		{"movie.mkv", true},
		{"trailer.mov", true},

		// Audio formats
		{"song.mp3", true},
		{"track.flac", true},
		{"voice.opus", true},

		// Archives
		{"backup.zip", true},
		{"data.tar.gz", true}, // .gz extension matches
		{"blob.zst", true},

		// Disk images
		{"disc.iso", true},
		{"disk.vmdk", true},
		{"snapshot.qcow2", true},

		// Documents
		{"doc.pdf", true},
		{"sheet.xlsx", true},
		{"book.epub", true},

		// Binaries
		{"app.exe", true},
		{"lib.so", true},
		{"pkg.deb", true},

		// Compressible
		{"notes.txt", false},
		{"config.json", false},
		{"source.go", false},
		{"readme.md", false},
		{"empty", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isLikelyIncompressible(tt.path); got != tt.want {
			t.Errorf("isLikelyIncompressible(%q): got %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsLikelyIncompressibleByName(t *testing.T) {
	// OS swap/hibernation files matched by basename regardless of path.
	if !isLikelyIncompressible("C:/Windows/pagefile.sys") {
		t.Error("pagefile.sys should be incompressible")
	}
	if !isLikelyIncompressible("/var/hiberfil.sys") {
		t.Error("hiberfil.sys should be incompressible")
	}
	if !isLikelyIncompressible("swapfile.sys") {
		t.Error("swapfile.sys should be incompressible")
	}
	// Case-insensitive on the basename.
	if !isLikelyIncompressible("PAGEFILE.SYS") {
		t.Error("PAGEFILE.SYS should be incompressible (case-insensitive)")
	}
}

func TestIncompressibleExtsIsMutableForExtension(t *testing.T) {
	// Callers may extend the default list at init time.
	original := incompressibleExts[".myext"]
	defer func() {
		if original {
			incompressibleExts[".myext"] = true
		} else {
			delete(incompressibleExts, ".myext")
		}
	}()

	if isLikelyIncompressible("file.myext") {
		t.Fatal(".myext should not be incompressible before extension")
	}
	incompressibleExts[".myext"] = true
	if !isLikelyIncompressible("file.myext") {
		t.Fatal(".myext should be incompressible after extension")
	}
}
