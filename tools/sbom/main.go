// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type module struct {
	Path    string
	Version string
	Main    bool
	Replace *module
}

type moduleGraph struct {
	Modules []module `json:"-"`
}

func main() {
	output := flag.String("output", "", "output SPDX JSON file")
	flag.Parse()
	if *output == "" {
		fatal("-output is required")
	}

	cmd := exec.Command("go", "list", "-m", "-json", "all")
	data, err := cmd.Output()
	if err != nil {
		fatal("go list -m: %v", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	var modules []module
	for {
		var m module
		err := decoder.Decode(&m)
		if err == io.EOF {
			break
		}
		if err != nil {
			fatal("decode module list: %v", err)
		}
		modules = append(modules, m)
	}

	document := map[string]any{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              "gbf-core dependency SBOM",
		"documentNamespace": fmt.Sprintf("https://github.com/ginkgobackup/gbf-core/sbom/%d", time.Now().UTC().UnixNano()),
		"creationInfo": map[string]any{
			"created":  time.Now().UTC().Format(time.RFC3339),
			"creators": []string{"Tool: gbf-core/tools/sbom"},
		},
		"packages": make([]map[string]any, 0, len(modules)),
	}
	packages := document["packages"].([]map[string]any)
	for _, m := range modules {
		id := "SPDXRef-" + sanitize(m.Path)
		pkg := map[string]any{
			"SPDXID":           id,
			"name":             m.Path,
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed":    false,
			"licenseConcluded": "NOASSERTION",
			"licenseDeclared":  "NOASSERTION",
		}
		if m.Version != "" {
			pkg["versionInfo"] = m.Version
		}
		if m.Replace != nil {
			pkg["externalRefs"] = []map[string]any{{
				"referenceCategory": "OTHER",
				"referenceType":     "replacement-module",
				"referenceLocator":  m.Replace.Path,
			}}
		}
		packages = append(packages, pkg)
	}
	document["packages"] = packages
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		fatal("encode SBOM: %v", err)
	}
	if err := os.WriteFile(*output, append(encoded, '\n'), 0644); err != nil {
		fatal("write SBOM: %v", err)
	}
}

func sanitize(path string) string {
	var b strings.Builder
	for _, r := range path {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
