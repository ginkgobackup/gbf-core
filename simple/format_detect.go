// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"os"
	"path/filepath"
	"strings"
)

type RepoFormat int

const (
	RepoFormatUnknown RepoFormat = iota
	RepoFormatGBF
)

func DetectRepoFormat(repoRoot string) RepoFormat {
	gbConfig := filepath.Join(repoRoot, MetaDirName, "config.json")
	if _, err := os.Stat(gbConfig); err == nil {
		if IsGBRepo(repoRoot) {
			return RepoFormatGBF
		}
	}
	return RepoFormatUnknown
}

func (f RepoFormat) String() string {
	switch f {
	case RepoFormatGBF:
		return "gbf"
	default:
		return "unknown"
	}
}

func MatchExclude(relPath string, excludes []string) bool {
	for _, pattern := range excludes {
		if matchGlob(pattern, relPath) {
			return true
		}
	}
	return false
}

func matchGlob(pattern, path string) bool {
	if pattern == path {
		return true
	}
	if strings.HasPrefix(pattern, "**/") {
		suffix := pattern[3:]
		if strings.HasSuffix(path, "/"+suffix) || path == suffix || strings.Contains(path, "/"+suffix+"/") {
			return true
		}
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := pattern[:len(pattern)-3]
		if strings.HasPrefix(path, prefix+"/") || path == prefix {
			return true
		}
	}
	if strings.Contains(pattern, "**") {
		parts := strings.SplitN(pattern, "**", 2)
		if len(parts) == 2 {
			if strings.HasPrefix(path, parts[0]) && strings.HasSuffix(path, parts[1]) {
				return true
			}
		}
	}
	matched, err := filepath.Match(pattern, filepath.Base(path))
	if err == nil && matched {
		return true
	}
	matched, err = filepath.Match(pattern, path)
	if err == nil && matched {
		return true
	}
	if strings.HasPrefix(path, pattern) {
		return true
	}
	return false
}
