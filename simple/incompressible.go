// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"path/filepath"
	"strings"
)

// incompressibleExts lists file extensions whose contents are already
// compressed (or otherwise entropy-dense) and would not benefit from a
// second compression pass before encryption. The pipeline uses this list to
// skip the per-blob compressor and write these files verbatim into the
// encrypted blob store, which saves CPU without changing the on-disk format.
//
// This is the default list, embedded in the binary so the engine has no
// runtime file dependency. Callers that need to extend it (e.g. to add
// custom container formats) can do so at init time by mutating the map
// directly, since the read path takes the lock-free fast path on the
// package-level variable. If concurrent mutation is required, callers
// should wrap access in their own mutex.
//
// Keeping the list in source (rather than loading from a config file) is
// deliberate: it guarantees the same defaults across every installation,
// avoids a config-IO failure mode on the backup hot path, and lets the list
// evolve with version control alongside the format itself.
var incompressibleExts = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
	".tiff": true, ".tif": true, ".webp": true, ".heic": true, ".heif": true,
	".avif": true, ".ico": true, ".raw": true, ".cr2": true, ".nef": true,
	".orf": true, ".arw": true, ".dng": true, ".rw2": true,
	".psd": true, ".psb": true,

	".mp4": true, ".avi": true, ".mkv": true, ".mov": true, ".wmv": true,
	".flv": true, ".webm": true, ".m4v": true, ".mpg": true, ".mpeg": true,
	".3gp": true, ".3g2": true, ".ts": true, ".mts": true, ".vob": true,
	".m2ts": true, ".rm": true, ".rmvb": true,

	".mp3": true, ".aac": true, ".flac": true, ".ogg": true, ".wma": true,
	".m4a": true, ".wav": true, ".opus": true, ".aiff": true, ".alac": true,
	".amr": true, ".ape": true, ".wv": true, ".tta": true,

	".zip": true, ".zipx": true, ".rar": true, ".rar5": true, ".7z": true,
	".gz": true, ".bz2": true, ".xz": true, ".zst": true, ".lz4": true,
	".tar": true, ".tgz": true, ".lz": true, ".lzma": true,
	".br": true, ".sz": true, ".cab": true, ".arj": true, ".ace": true,
	".lha": true, ".lzh": true, ".arc": true, ".uha": true, ".kgb": true,
	".z": true, ".zz": true, ".sit": true, ".sitx": true, ".brotli": true,

	".iso": true, ".dmg": true, ".img": true, ".bin": true, ".nrg": true,
	".mdf": true, ".mds": true, ".ccd": true, ".sub": true,
	".vmdk": true, ".vdi": true, ".vhd": true, ".vhdx": true,
	".qcow2": true, ".qcow": true, ".qed": true,
	".ova": true, ".ovf": true, ".xva": true,
	".wim": true, ".esd": true, ".squashfs": true, ".cramfs": true,
	".gho": true, ".tib": true, ".tibx": true, ".vbk": true, ".vib": true,
	".adi": true, ".fbk": true, ".sna": true,

	".pdf": true, ".docx": true, ".xlsx": true, ".pptx": true,
	".odt": true, ".ods": true, ".odp": true, ".doc": true, ".xls": true,
	".ppt": true, ".epub": true, ".mobi": true, ".azw3": true,
	".cbr": true, ".cbz": true,

	".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".jar": true, ".war": true, ".apk": true, ".ipa": true,
	".deb": true, ".rpm": true, ".pkg": true, ".msi": true,
	".app": true, ".appx": true, ".msix": true, ".nupkg": true,
}

// incompressibleNames lists specific filenames (matched case-insensitively
// on the basename) that should bypass compression regardless of extension.
// These are typically OS-managed swap/hibernation files whose contents are
// either already compressed by the OS or meaningless to compress.
var incompressibleNames = map[string]bool{
	"pagefile.sys": true,
	"hiberfil.sys": true,
	"swapfile.sys": true,
}

// isLikelyIncompressible reports whether the file at path is likely to be
// already compressed (or otherwise entropy-dense) and should skip the
// per-blob compression step. The decision is based on a case-insensitive
// match against the extension and basename. False positives (a file with a
// .jpg extension that is actually plaintext) cost only the compression
// savings; false negatives (a .txt file that is already gzipped) cost only
// the redundant compression CPU.
func isLikelyIncompressible(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if incompressibleExts[ext] {
		return true
	}
	name := strings.ToLower(filepath.Base(path))
	return incompressibleNames[name]
}
