// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	ignoreContent := "# comment line\n\ntmp/\n*.log\n!important.log\n"
	if err := os.WriteFile(filepath.Join(dir, IgnoreFileName), []byte(ignoreContent), 0644); err != nil {
		t.Fatalf("write ignore: %v", err)
	}
	patterns := LoadIgnoreFile(dir)
	// Comment and blank lines are skipped.
	if len(patterns) != 3 {
		t.Fatalf("got %d patterns, want 3: %v", len(patterns), patterns)
	}
	want := []string{"tmp/", "*.log", "!important.log"}
	for i, p := range want {
		if patterns[i] != p {
			t.Errorf("pattern[%d]: got %q, want %q", i, patterns[i], p)
		}
	}
}

func TestLoadIgnoreFileMissingReturnsNil(t *testing.T) {
	dir := t.TempDir()
	if got := LoadIgnoreFile(dir); got != nil {
		t.Fatalf("missing file should return nil, got %v", got)
	}
}

func TestMergeExcludesDeduplicates(t *testing.T) {
	a := []string{"foo/", "bar.txt"}
	b := []string{"bar.txt", "baz/"}
	merged := MergeExcludes(a, b)
	if len(merged) != 3 {
		t.Fatalf("got %d patterns, want 3: %v", len(merged), merged)
	}
	seen := map[string]bool{}
	for _, p := range merged {
		if seen[p] {
			t.Errorf("duplicate pattern %q", p)
		}
		seen[p] = true
	}
}

func TestParseSizeFilter(t *testing.T) {
	tests := []struct {
		input    string
		wantOp   string
		wantSize int64
		wantOk   bool
	}{
		{"size:>1mb", ">", 1024 * 1024, true},
		{"size:>=1mb", ">=", 1024 * 1024, true},
		{"size:<500kb", "<", 500 * 1024, true},
		{"size:<=2gb", "<=", 2 * 1024 * 1024 * 1024, true},
		{"size:>100b", ">", 100, true},
		{"size:>100", ">", 100, true},
		{"size:>=50", ">=", 50, true},
		{"not-a-size-filter", "", 0, false},
		{"size:", "", 0, false},
		{"size:>abc", "", 0, false},
		{"size:>", "", 0, false},
	}
	for _, tt := range tests {
		f, ok := ParseSizeFilter(tt.input)
		if ok != tt.wantOk {
			t.Errorf("ParseSizeFilter(%q): ok got %v, want %v", tt.input, ok, tt.wantOk)
			continue
		}
		if !tt.wantOk {
			continue
		}
		if f.Op != tt.wantOp {
			t.Errorf("ParseSizeFilter(%q): Op got %q, want %q", tt.input, f.Op, tt.wantOp)
		}
		if f.Bytes != tt.wantSize {
			t.Errorf("ParseSizeFilter(%q): Bytes got %d, want %d", tt.input, f.Bytes, tt.wantSize)
		}
	}
}

func TestIsSizeExcluded(t *testing.T) {
	filters := []SizeFilter{
		{Op: ">", Bytes: 100},
		{Op: "<=", Bytes: 10},
	}
	tests := []struct {
		size int64
		want bool
	}{
		{50, false},
		{10, true},  // 10 <= 10 → excluded
		{9, true},   // 9 <= 10 → excluded
		{101, true}, // 101 > 100 → excluded
		{100, false},
		{11, false}, // 11 not > 100 and not <= 10
	}
	for _, tt := range tests {
		if got := IsSizeExcluded(tt.size, filters); got != tt.want {
			t.Errorf("IsSizeExcluded(%d): got %v, want %v", tt.size, got, tt.want)
		}
	}
}

func TestSplitExcludePatterns(t *testing.T) {
	patterns := []string{"foo/", "!bar.txt", "size:>1mb", "baz/"}
	pos, neg, size := SplitExcludePatterns(patterns)
	if len(pos) != 2 || pos[0] != "foo/" || pos[1] != "baz/" {
		t.Errorf("positives: got %v", pos)
	}
	if len(neg) != 1 || neg[0] != "bar.txt" {
		t.Errorf("negatives: got %v", neg)
	}
	if len(size) != 1 || size[0].Op != ">" || size[0].Bytes != 1024*1024 {
		t.Errorf("size filters: got %v", size)
	}
}

func TestIsExcludedMatchesAndNegates(t *testing.T) {
	pos := []string{"*.log", "tmp/"}
	neg := []string{"important.log"}
	tests := []struct {
		path string
		want bool
	}{
		{"debug.log", true},
		{"subdir/info.log", true},
		{"tmp/foo.txt", true},
		{"important.log", false}, // negated
		{"notes.txt", false},     // no pattern matched
	}
	for _, tt := range tests {
		if got := IsExcluded(tt.path, pos, neg); got != tt.want {
			t.Errorf("IsExcluded(%q): got %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsExcludedEmptyPatterns(t *testing.T) {
	if IsExcluded("anything", nil, nil) {
		t.Fatal("empty patterns should not exclude")
	}
}

func TestMatchPatternExactPath(t *testing.T) {
	if !MatchPattern("foo/bar.txt", "foo/bar.txt") {
		t.Fatal("exact path should match")
	}
	if MatchPattern("foo/baz.txt", "foo/bar.txt") {
		t.Fatal("non-matching exact path should not match")
	}
}

func TestMatchPatternDirPrefix(t *testing.T) {
	if !MatchPattern("tmp/file.txt", "tmp/") {
		t.Fatal("file under tmp/ should match tmp/")
	}
	if !MatchPattern("tmp/sub/file.txt", "tmp/") {
		t.Fatal("nested file under tmp/ should match tmp/")
	}
	if MatchPattern("other/file.txt", "tmp/") {
		t.Fatal("file outside tmp/ should not match tmp/")
	}
}

func TestMatchPatternGlob(t *testing.T) {
	if !MatchPattern("debug.log", "*.log") {
		t.Fatal("*.log should match debug.log")
	}
	if MatchPattern("debug.txt", "*.log") {
		t.Fatal("*.log should not match debug.txt")
	}
}

func TestMatchPatternGlobstar(t *testing.T) {
	tests := []struct {
		path    string
		pattern string
		want    bool
	}{
		{"a/b/c/log.txt", "**", true},
		{"log.txt", "**/log.txt", true},
		{"a/b/log.txt", "**/log.txt", true},
		// "tmp/**" treated as a path; pattern "tmp" matches because the path
		// starts with "tmp/".
		{"tmp/**", "tmp", true},
		{"tmp/sub/file.txt", "tmp/**", true},
		{"tmp/file.txt", "tmp/**", true},
		{"a/b/c", "a/**/c", true},
		{"a/x/y/c", "a/**/c", true},
		{"a/x/y/d", "a/**/c", false},
	}
	for _, tt := range tests {
		got := MatchPattern(tt.path, tt.pattern)
		if got != tt.want {
			t.Errorf("MatchPattern(%q, %q): got %v, want %v", tt.path, tt.pattern, got, tt.want)
		}
	}
}

func TestShouldSkipDir(t *testing.T) {
	pos := []string{"tmp/"}
	neg := []string{"tmp/keep/"}
	// tmp/ excluded, no negation → skip.
	if !ShouldSkipDir("tmp/", pos, neg) {
		t.Fatal("tmp/ should be skipped")
	}
	// tmp/keep/ matched by negation → do not skip (need to descend).
	if ShouldSkipDir("tmp/keep/", pos, neg) {
		t.Fatal("tmp/keep/ should not be skipped due to negation")
	}
	// tmp/keep/sub is under a negated parent → not skipped.
	if ShouldSkipDir("tmp/keep/sub", pos, neg) {
		t.Fatal("tmp/keep/sub should not be skipped")
	}
}
