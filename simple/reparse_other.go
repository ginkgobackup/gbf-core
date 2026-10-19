// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

//go:build !windows

package simple

import "os"

func isReparseLink(info os.FileInfo, path string) bool {
	return info != nil && info.Mode()&os.ModeSymlink != 0
}
