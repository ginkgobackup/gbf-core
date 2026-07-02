// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package fsutil

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const IgnoreFileName = ".ginkgo-backupignore"

var caseInsensitiveFS = runtime.GOOS == "windows" || runtime.GOOS == "darwin"

func normalizeForMatch(s string) string {
	if caseInsensitiveFS {
		return strings.ToLower(s)
	}
	return s
}

func LoadIgnoreFile(root string) []string {
	ignorePath := filepath.Join(root, IgnoreFileName)
	data, err := os.ReadFile(ignorePath)
	if err != nil {
		return nil
	}

	var patterns []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns
}

func MergeExcludes(sourceExcludes []string, ignoreFilePatterns []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, p := range sourceExcludes {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	for _, p := range ignoreFilePatterns {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}

type SizeFilter struct {
	Op    string
	Bytes int64
}

func ParseSizeFilter(s string) (SizeFilter, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "size:") {
		return SizeFilter{}, false
	}
	rest := s[5:]
	var op string
	switch {
	case strings.HasPrefix(rest, ">="):
		op = ">="
		rest = rest[2:]
	case strings.HasPrefix(rest, "<="):
		op = "<="
		rest = rest[2:]
	case strings.HasPrefix(rest, ">"):
		op = ">"
		rest = rest[1:]
	case strings.HasPrefix(rest, "<"):
		op = "<"
		rest = rest[1:]
	default:
		return SizeFilter{}, false
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return SizeFilter{}, false
	}
	var multiplier int64 = 1
	lower := strings.ToLower(rest)
	switch {
	case strings.HasSuffix(lower, "gb"):
		multiplier = 1024 * 1024 * 1024
		rest = rest[:len(rest)-2]
	case strings.HasSuffix(lower, "mb"):
		multiplier = 1024 * 1024
		rest = rest[:len(rest)-2]
	case strings.HasSuffix(lower, "kb"):
		multiplier = 1024
		rest = rest[:len(rest)-2]
	case strings.HasSuffix(lower, "b"):
		rest = rest[:len(rest)-1]
	}
	val, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
	if err != nil {
		return SizeFilter{}, false
	}
	return SizeFilter{Op: op, Bytes: val * multiplier}, true
}

func IsSizeExcluded(size int64, sizeFilters []SizeFilter) bool {
	for _, f := range sizeFilters {
		switch f.Op {
		case ">":
			if size > f.Bytes {
				return true
			}
		case ">=":
			if size >= f.Bytes {
				return true
			}
		case "<":
			if size < f.Bytes {
				return true
			}
		case "<=":
			if size <= f.Bytes {
				return true
			}
		}
	}
	return false
}

func SplitExcludePatterns(patterns []string) (positives []string, negatives []string, sizeFilters []SizeFilter) {
	for _, p := range patterns {
		if strings.HasPrefix(p, "!") {
			negatives = append(negatives, strings.TrimPrefix(p, "!"))
		} else if sf, ok := ParseSizeFilter(p); ok {
			sizeFilters = append(sizeFilters, sf)
		} else {
			positives = append(positives, p)
		}
	}
	return
}

func IsExcluded(relPath string, positives []string, negatives []string) bool {
	relPath = normalizeForMatch(relPath)
	matched := false
	for _, pat := range positives {
		if MatchPattern(relPath, normalizeForMatch(pat)) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, pat := range negatives {
		if MatchPattern(relPath, normalizeForMatch(pat)) {
			return false
		}
	}
	return true
}

func ShouldSkipDir(relPath string, positives []string, negatives []string) bool {
	if !IsExcluded(relPath, positives, negatives) {
		return false
	}
	normPath := normalizeForMatch(relPath)
	for _, neg := range negatives {
		neg = normalizeForMatch(neg)
		if neg == normPath || strings.HasPrefix(normPath, neg+"/") {
			return false
		}
	}
	return true
}

func MatchPattern(relPath string, pattern string) bool {
	if strings.Contains(pattern, "**") {
		return matchGlobstar(relPath, pattern)
	}

	hasGlob := strings.ContainsAny(pattern, "*?[")
	if !hasGlob {
		if strings.HasSuffix(pattern, "/") {
			dirName := strings.TrimSuffix(pattern, "/")
			if relPath == dirName || strings.HasPrefix(relPath, dirName+"/") {
				return true
			}
			if strings.Contains(relPath, "/"+dirName+"/") || strings.HasSuffix(relPath, "/"+dirName) {
				return true
			}
			return false
		}
		if relPath == pattern || strings.HasPrefix(relPath, pattern+"/") {
			return true
		}
		if strings.Contains(relPath, "/"+pattern+"/") || strings.HasSuffix(relPath, "/"+pattern) {
			return true
		}
		return false
	}
	matched, _ := path.Match(pattern, filepath.Base(relPath))
	if matched {
		return true
	}
	matched, _ = path.Match(pattern, relPath)
	return matched
}

func matchGlobstar(relPath string, pattern string) bool {
	if pattern == "**" {
		return true
	}

	if strings.HasPrefix(pattern, "**/") {
		suffix := pattern[3:]
		if MatchPattern(relPath, suffix) {
			return true
		}
		parts := strings.Split(relPath, "/")
		for i := 1; i < len(parts); i++ {
			subPath := strings.Join(parts[i:], "/")
			if MatchPattern(subPath, suffix) {
				return true
			}
		}
		return false
	}

	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		if relPath == prefix || strings.HasPrefix(relPath, prefix+"/") {
			return true
		}
		if strings.Contains(relPath, "/"+prefix+"/") {
			return true
		}
		return false
	}

	if idx := strings.Index(pattern, "/**/"); idx >= 0 {
		prefix := pattern[:idx]
		suffix := pattern[idx+4:]
		parts := strings.Split(relPath, "/")
		for i := 0; i < len(parts); i++ {
			prefixPath := strings.Join(parts[:i+1], "/")
			if prefixPath == prefix || strings.Contains(prefixPath, "/"+prefix) && i > 0 {
				remaining := strings.Join(parts[i+1:], "/")
				if remaining == "" {
					continue
				}
				if MatchPattern(remaining, suffix) {
					return true
				}
			}
		}
		return false
	}

	matched, _ := path.Match(pattern, filepath.Base(relPath))
	if matched {
		return true
	}
	matched, _ = path.Match(pattern, relPath)
	return matched
}
