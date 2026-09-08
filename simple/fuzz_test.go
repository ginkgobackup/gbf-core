// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"testing"
)

func FuzzLoadManifestFromData(f *testing.F) {
	f.Add([]byte(`{"version":2,"sourceId":1,"dirs":{},"stats":{}}`))
	f.Add([]byte("GKM1"))
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = LoadManifestFromData(data)
	})
}

func FuzzExtractHashesFromJSON(f *testing.F) {
	f.Add([]byte(`{"version":2,"dirs":{}}`))
	f.Add([]byte(`{"files":[{"contentHash":"abc"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = extractHashesFromJSON(data)
	})
}
