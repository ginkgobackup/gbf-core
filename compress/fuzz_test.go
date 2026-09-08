// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package compress

import "testing"

func FuzzZstdDecompress(f *testing.F) {
	c := NewZstdCompressor(1)
	for _, seed := range [][]byte{nil, {}, []byte("not zstd"), []byte{0x28, 0xb5, 0x2f, 0xfd}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = c.Decompress(data)
	})
}
