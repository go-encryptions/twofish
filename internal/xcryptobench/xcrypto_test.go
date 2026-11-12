// Package xcryptobench runs the same 1 KiB block-by-block benchmark as the
// parent module's BenchmarkEncrypt / BenchmarkDecrypt over the deprecated
// golang.org/x/crypto/twofish, so abbench can interleave the two. It is a
// separate module so that x/crypto is not a dependency of the cipher.
package xcryptobench

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/twofish"
)

func benchBlock(b *testing.B, dec bool) {
	c, _ := twofish.NewCipher(bytes.Repeat([]byte{7}, 32))
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for o := 0; o < len(buf); o += 16 {
			if dec {
				c.Decrypt(buf[o:o+16], buf[o:o+16])
			} else {
				c.Encrypt(buf[o:o+16], buf[o:o+16])
			}
		}
	}
}

func BenchmarkEncrypt(b *testing.B) { benchBlock(b, false) }
func BenchmarkDecrypt(b *testing.B) { benchBlock(b, true) }
