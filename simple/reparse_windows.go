// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

//go:build windows

package simple

import (
	"os"
	"syscall"
)

// isReparseLink reports whether path is a symlink or junction. Windows reports
// junctions as regular files with FILE_ATTRIBUTE_REPARSE_POINT and IsDir()
// false, so the mode bit alone is not enough. Cloud placeholder reparse points
// (OneDrive/CfAPI) also carry the attribute but are not links; os.Readlink
// distinguishes them from junctions/symlinks.
func isReparseLink(info os.FileInfo, path string) bool {
	if info == nil {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok || data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return false
	}
	_, err := os.Readlink(path)
	return err == nil
}
