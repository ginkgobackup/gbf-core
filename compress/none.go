// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package compress

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
