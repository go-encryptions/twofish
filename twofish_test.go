package twofish

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// scanner reads "Name = value" (Botan) and "NAME=value" (the reference KATs)
// lines and calls f for each one.
func scan(t testing.TB, path string, f func(name string, val []byte)) {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		name, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		name, val = strings.TrimSpace(name), strings.TrimSpace(val)
		switch name {
		case "Key", "In", "Out", "KEY", "PT", "CT":
			f(name, unhex(t, val))
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
}

type vector struct{ key, in, out []byte }

// readVectors parses a file of vectors: Botan's "Key/In/Out" (which may hold
// several blocks per vector) or the reference KATs' "KEY/PT/CT".
func readVectors(t testing.TB, path string) []vector {
	t.Helper()
	var vs []vector
	var cur vector
	scan(t, path, func(name string, b []byte) {
		switch name {
		case "Key", "KEY":
			// ecb_vk states its fixed plaintext once per key size, before the keys.
			cur = vector{key: b, in: cur.in}
		case "In", "PT":
			cur.in = b
		case "Out", "CT":
			cur.out = b
			vs = append(vs, cur)
		}
	})
	return vs
}

func checkVectors(t *testing.T, path string, wantMin int) {
	t.Helper()
	vs := readVectors(t, path)
	if len(vs) < wantMin {
		t.Fatalf("%s: only %d vectors parsed, want at least %d", path, len(vs), wantMin)
	}
	for _, v := range vs {
		c, err := NewCipher(v.key)
		if err != nil {
			t.Fatal(err)
		}
		if len(v.in) == 0 || len(v.in)%16 != 0 || len(v.in) != len(v.out) {
			t.Fatalf("bad vector lengths %d/%d", len(v.in), len(v.out))
		}
		got := make([]byte, len(v.in))
		for o := 0; o < len(got); o += 16 {
			c.Encrypt(got[o:], v.in[o:])
		}
		if !bytes.Equal(got, v.out) {
			t.Fatalf("key %x: encrypt = %x, want %x", v.key, got, v.out)
		}
		for o := 0; o < len(got); o += 16 {
			c.Decrypt(got[o:], v.out[o:])
		}
		if !bytes.Equal(got, v.in) {
			t.Fatalf("key %x: decrypt = %x, want %x", v.key, got, v.in)
		}
	}
	t.Logf("%s: %d vectors", path, len(vs))
}

// The reference implementation's known-answer tests (twofish-kat.zip of the
// designers): ecb_tbl (tables and MDS), ecb_vk (variable key), ecb_vt
// (variable plaintext); 147, 576 and 384 vectors over the three key sizes.
func TestKATTables(t *testing.T)      { checkVectors(t, "testdata/kat/ecb_tbl.txt", 147) }
func TestKATVariableKey(t *testing.T) { checkVectors(t, "testdata/kat/ecb_vk.txt", 576) }
func TestKATVariableText(t *testing.T) {
	checkVectors(t, "testdata/kat/ecb_vt.txt", 384)
}

// Botan's src/tests/data/block/twofish.vec.
func TestBotanVectors(t *testing.T) { checkVectors(t, "testdata/botan-twofish.vec", 50) }

// Differential corpus produced by internal/genbotan from the installed
// `botan cipher` (Twofish/CBC/NoPadding with a zero IV on one block).
func TestBotanDifferential(t *testing.T) { checkVectors(t, "testdata/botan-diff.vec", 600) }

// The Monte Carlo tests of the reference KATs: per key size, 400 outer
// iterations of 10000 chained encryptions (or decryptions) each, the key of the
// next iteration being the key XOR the last 16, 24 or 32 bytes of ciphertext
// (of the plaintext, for decryption) made of the last two outputs.
func monteCarlo(t *testing.T, path string, dec bool) {
	t.Helper()
	type rec struct{ key, pt, ct []byte }
	var recs []rec
	var cur rec
	scan(t, path, func(name string, b []byte) {
		switch name {
		case "KEY":
			cur = rec{key: b}
		case "PT":
			cur.pt = b
			if dec {
				recs = append(recs, cur)
			}
		case "CT":
			cur.ct = b
			if !dec {
				recs = append(recs, cur)
			}
		}
	})
	if len(recs) != 1200 {
		t.Fatalf("%d records, want 1200", len(recs))
	}
	iters := 400
	if testing.Short() {
		iters = 10
	}
	for ks := 0; ks < 3; ks++ {
		keyLen := 16 + 8*ks
		in := make([]byte, 16) // the input of the first call: all zero
		var last []byte
		key := make([]byte, keyLen)
		for i := 0; i < iters; i++ {
			r := recs[400*ks+i]
			if !bytes.Equal(r.key, key) {
				t.Fatalf("size %d I=%d: key %x, want %x", keyLen, i, key, r.key)
			}
			c, err := NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			buf := append([]byte(nil), in...)
			for j := 0; j < 10000; j++ {
				if dec {
					c.Decrypt(buf, buf)
				} else {
					c.Encrypt(buf, buf)
				}
				if j == 9998 {
					last = append(last[:0], buf...)
				}
			}
			// last holds the output of call 9999, buf that of call 10000.
			want := r.ct
			if dec {
				want = r.pt
			}
			if !bytes.Equal(buf, want) {
				t.Fatalf("size %d I=%d: got %x, want %x", keyLen, i, buf, want)
			}
			// New key: key ^ (tail of the second-to-last output || last output).
			tail := append(append([]byte(nil), last...), buf...)
			tail = tail[len(tail)-keyLen:]
			for k := range key {
				key[k] ^= tail[k]
			}
			in = buf
		}
	}
}

func TestMonteCarloEncrypt(t *testing.T) { monteCarlo(t, "testdata/kat/ecb_e_m.txt", false) }
func TestMonteCarloDecrypt(t *testing.T) { monteCarlo(t, "testdata/kat/ecb_d_m.txt", true) }

func TestKeySize(t *testing.T) {
	for n := 0; n <= 64; n++ {
		c, err := NewCipher(make([]byte, n))
		if n == 16 || n == 24 || n == 32 {
			if err != nil || c.BlockSize() != 16 {
				t.Fatalf("key %d: %v", n, err)
			}
			continue
		}
		var kse KeySizeError
		if c != nil || !errors.As(err, &kse) || int(kse) != n {
			t.Fatalf("key %d: got %v, %v", n, c, err)
		}
		if !strings.Contains(err.Error(), "invalid key size") {
			t.Fatal(err)
		}
	}
}

func TestPanics(t *testing.T) {
	c, _ := NewCipher(make([]byte, 16))
	for name, f := range map[string]func(){
		"enc short src": func() { c.Encrypt(make([]byte, 16), make([]byte, 15)) },
		"enc short dst": func() { c.Encrypt(make([]byte, 15), make([]byte, 16)) },
		"dec short src": func() { c.Decrypt(make([]byte, 16), make([]byte, 15)) },
		"dec short dst": func() { c.Decrypt(make([]byte, 15), make([]byte, 16)) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}

type blocksCipher interface {
	cipher.Block
	EncryptBlocks(dst, src []byte)
	DecryptBlocks(dst, src []byte)
}

// EncryptBlocks and DecryptBlocks must equal block-by-block Encrypt and
// Decrypt for every length around the 4-block batch, for every key size, out
// of place and in place.
func TestBlocks(t *testing.T) {
	for _, keyLen := range []int{16, 24, 32} {
		key := make([]byte, keyLen)
		for i := range key {
			key[i] = byte(i*7 + keyLen)
		}
		b, _ := NewCipher(key)
		c, ok := b.(blocksCipher)
		if !ok {
			t.Fatal("no EncryptBlocks/DecryptBlocks")
		}
		for n := 0; n <= 11; n++ {
			src := make([]byte, 16*n)
			for i := range src {
				src[i] = byte(i*31 + n)
			}
			want := make([]byte, len(src))
			for o := 0; o < len(src); o += 16 {
				c.Encrypt(want[o:], src[o:])
			}
			got := make([]byte, len(src))
			c.EncryptBlocks(got, src)
			if !bytes.Equal(got, want) {
				t.Fatalf("key %d, %d blocks: EncryptBlocks differs", keyLen, n)
			}
			c.DecryptBlocks(got, want)
			if !bytes.Equal(got, src) {
				t.Fatalf("key %d, %d blocks: DecryptBlocks differs", keyLen, n)
			}
			buf := append([]byte(nil), src...)
			c.EncryptBlocks(buf, buf)
			if !bytes.Equal(buf, want) {
				t.Fatalf("key %d, %d blocks: in-place EncryptBlocks differs", keyLen, n)
			}
			c.DecryptBlocks(buf, buf)
			if !bytes.Equal(buf, src) {
				t.Fatalf("key %d, %d blocks: in-place DecryptBlocks differs", keyLen, n)
			}
		}
	}
}

func TestBlocksPanics(t *testing.T) {
	b, _ := NewCipher(make([]byte, 16))
	c := b.(blocksCipher)
	for name, f := range map[string]func(){
		"enc partial block": func() { c.EncryptBlocks(make([]byte, 32), make([]byte, 17)) },
		"enc short dst":     func() { c.EncryptBlocks(make([]byte, 16), make([]byte, 32)) },
		"dec partial block": func() { c.DecryptBlocks(make([]byte, 32), make([]byte, 17)) },
		"dec short dst":     func() { c.DecryptBlocks(make([]byte, 16), make([]byte, 32)) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}

func TestInPlace(t *testing.T) {
	c, _ := NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	pt := []byte("sixteen byte blk")
	want := make([]byte, 16)
	c.Encrypt(want, pt)
	buf := append([]byte(nil), pt...)
	c.Encrypt(buf, buf)
	if !bytes.Equal(buf, want) {
		t.Fatal("in-place encrypt differs")
	}
	c.Decrypt(buf, buf)
	if !bytes.Equal(buf, pt) {
		t.Fatal("in-place decrypt differs")
	}
}

func roundTrip(t testing.TB, c cipher.Block, p []byte) {
	ct := make([]byte, 16)
	c.Encrypt(ct, p)
	back := make([]byte, 16)
	c.Decrypt(back, ct)
	if !bytes.Equal(back, p) {
		t.Fatalf("round trip failed: %x -> %x -> %x", p, ct, back)
	}
}

func FuzzRoundTrip(f *testing.F) {
	f.Add(make([]byte, 16), make([]byte, 16))
	f.Add(make([]byte, 24), []byte("0123456789abcdef"))
	f.Add(bytes.Repeat([]byte{0xff}, 32), bytes.Repeat([]byte{0xa5}, 16))
	f.Fuzz(func(t *testing.T, key, block []byte) {
		if len(block) < 16 {
			return
		}
		c, err := NewCipher(key)
		if n := len(key); n != 16 && n != 24 && n != 32 {
			if err == nil {
				t.Fatal("bad key accepted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		roundTrip(t, c, block[:16])
		a, b := make([]byte, 16), make([]byte, 16)
		c.Encrypt(a, block[:16])
		c.Encrypt(b, block[:16])
		if !bytes.Equal(a, b) {
			t.Fatal("encrypt not deterministic")
		}
	})
}

func benchBlock(b *testing.B, dec bool) {
	c, _ := NewCipher(bytes.Repeat([]byte{7}, 32))
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

// benchBlocks is the shape of `botan speed`: one 1 KiB buffer, 64 blocks per
// call, ECB-style.
func benchBlocks(b *testing.B, dec bool) {
	c, _ := NewCipher(bytes.Repeat([]byte{7}, 32))
	bc := c.(blocksCipher)
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if dec {
			bc.DecryptBlocks(buf, buf)
		} else {
			bc.EncryptBlocks(buf, buf)
		}
	}
}

func BenchmarkEncrypt(b *testing.B)       { benchBlock(b, false) }
func BenchmarkDecrypt(b *testing.B)       { benchBlock(b, true) }
func BenchmarkEncryptBlocks(b *testing.B) { benchBlocks(b, false) }
func BenchmarkDecryptBlocks(b *testing.B) { benchBlocks(b, true) }
