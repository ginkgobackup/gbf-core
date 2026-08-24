// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package compress

// NoneCompressor is the identity Compressor. Per the Compressor alias
// contract, Compress and Decompress return the input slice itself (no
// copy); callers must not modify the returned buffer.
type NoneCompressor struct{}

func (c *NoneCompressor) Type() CompressorType { return CompressNone }

func (c *NoneCompressor) Compress(data []byte) ([]byte, error) {
	return data, nil
}

func (c *NoneCompressor) Decompress(data []byte) ([]byte, error) {
	return data, nil
}

func (c *NoneCompressor) IsCompressed(data []byte) bool {
	return false
}
