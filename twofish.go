// Package twofish implements the Twofish block cipher (Schneier, Kelsey,
// Whiting, Wagner, Hall and Ferguson, 1998) as a crypto/cipher.Block: 16-byte
// blocks and 16-, 24- or 32-byte keys.
//
// The implementation is table-driven. Key setup expands the key-dependent
// S-boxes and the MDS matrix into four 256-entry tables of 32-bit words (the
// "full keying" option of the paper), so one round costs eight table look-ups.
// Those look-ups index memory with secret-dependent addresses, so this package
// is NOT constant-time, in Encrypt, Decrypt and in the key schedule.
package twofish

import (
	"crypto/cipher"
	"encoding/binary"
	"math/bits"
	"strconv"
)

// BlockSize is the Twofish block size in bytes.
const BlockSize = 16

// KeySizeError reports a key that is not 16, 24 or 32 bytes long.
type KeySizeError int

func (k KeySizeError) Error() string {
	return "twofish: invalid key size " + strconv.Itoa(int(k))
}

// gmul multiplies a and b in GF(2)[x] modulo the degree-8 polynomial poly
// (given with its x^8 term).
func gmul(a, b byte, poly uint16) byte {
	var r uint16
	x := uint16(a)
	for ; b != 0; b >>= 1 {
		if b&1 != 0 {
			r ^= x
		}
		x <<= 1
		if x&0x100 != 0 {
			x ^= poly
		}
	}
	return byte(r)
}

const (
	polyMDS = 0x169 // x^8 + x^6 + x^5 + x^3 + 1, the field of the MDS matrix
	polyRS  = 0x14d // x^8 + x^6 + x^3 + x^2 + 1, the field of the RS code
)

// mdsMatrix is the MDS matrix of section 4.2 of the paper.
var mdsMatrix = [4][4]byte{
	{0x01, 0xef, 0x5b, 0x5b},
	{0x5b, 0xef, 0xef, 0x01},
	{0xef, 0x5b, 0x01, 0xef},
	{0xef, 0x01, 0xef, 0x5b},
}

// rsMatrix is the Reed-Solomon matrix of section 4.3 of the paper.
var rsMatrix = [4][8]byte{
	{0x01, 0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e},
	{0xa4, 0x56, 0x82, 0xf3, 0x1e, 0xc6, 0x68, 0xe5},
	{0x02, 0xa1, 0xfc, 0xc1, 0x47, 0xae, 0x3d, 0x19},
	{0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e, 0x03},
}

// The 4-bit tables t0..t3 of the q-permutations (section 4.3.5 of the paper).
var qTables = [2][4][16]byte{
	{
		{8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4},
		{14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13},
		{11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1},
		{13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10},
	},
	{
		{2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5},
		{1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8},
		{4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15},
		{11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10},
	},
}

var (
	// q[0] and q[1] are the permutations q0 and q1.
	q [2][256]byte
	// mds[j][y] is the contribution of byte y at position j to MDS*(y0..y3),
	// as a little-endian word.
	mds [4][256]uint32
	// perm[j][stage] is the q-permutation applied to byte j at each of the five
	// stages of h (Figure 2 of the paper), innermost first.
	perm [4][5]*[256]byte
)

func rotr4(b byte) byte { return (b>>1 | b<<3) & 0x0f }

func init() {
	for n := range qTables {
		t := &qTables[n]
		for x := 0; x < 256; x++ {
			a0, b0 := byte(x>>4), byte(x&15)
			a1 := a0 ^ b0
			b1 := a0 ^ rotr4(b0) ^ (8*a0)&15
			a2, b2 := t[0][a1], t[1][b1]
			a3 := a2 ^ b2
			b3 := a2 ^ rotr4(b2) ^ (8*a2)&15
			a4, b4 := t[2][a3], t[3][b3]
			q[n][x] = b4<<4 | a4
		}
	}
	for j := 0; j < 4; j++ {
		for y := 0; y < 256; y++ {
			var w uint32
			for r := 0; r < 4; r++ {
				w |= uint32(gmul(byte(y), mdsMatrix[r][j], polyMDS)) << (8 * r)
			}
			mds[j][y] = w
		}
	}
	for j, seq := range [4][5]int{{1, 1, 0, 0, 1}, {0, 1, 1, 0, 0}, {0, 0, 0, 1, 1}, {1, 0, 1, 1, 0}} {
		for st, n := range seq {
			perm[j][st] = &q[n]
		}
	}
}

// qchain is byte j of the function h of the paper (Figure 2) before the MDS
// matrix: x goes through k+1 q-permutations, with the key words l[k-1], ...,
// l[0] XORed in between them.
func qchain(j int, x byte, l []uint32) byte {
	k := len(l)
	for st := 4 - k; st < 5; st++ {
		x = perm[j][st][x]
		if i := st - (4 - k); i < k {
			x ^= byte(l[k-1-i] >> (8 * j))
		}
	}
	return x
}

// h is the function h of the paper: the q-chains of the four bytes of x and
// the MDS matrix.
func h(x uint32, l []uint32) uint32 {
	var r uint32
	for j := 0; j < 4; j++ {
		r ^= mds[j][qchain(j, byte(x>>(8*j)), l)]
	}
	return r
}

type block struct {
	s [4][256]uint32 // the key-dependent S-boxes with the MDS matrix folded in
	k [40]uint32     // K_0..K_39: input whitening, output whitening, 32 round keys
}

// NewCipher returns a Twofish cipher.Block for a 16-, 24- or 32-byte key.
func NewCipher(key []byte) (cipher.Block, error) {
	n := len(key)
	if n != 16 && n != 24 && n != 32 {
		return nil, KeySizeError(n)
	}
	k := n / 8
	var me, mo, sw [4]uint32
	for i := 0; i < k; i++ {
		me[i] = binary.LittleEndian.Uint32(key[8*i:])
		mo[i] = binary.LittleEndian.Uint32(key[8*i+4:])
		// s_i = RS * (key bytes 8i .. 8i+7); the S-boxes use s_(k-1) first.
		var w uint32
		for r := 0; r < 4; r++ {
			var b byte
			for c := 0; c < 8; c++ {
				b ^= gmul(key[8*i+c], rsMatrix[r][c], polyRS)
			}
			w |= uint32(b) << (8 * r)
		}
		sw[k-1-i] = w
	}
	c := new(block)
	for i := 0; i < 20; i++ {
		rho := uint32(i) * 0x02020202
		a := h(rho, me[:k])
		b := bits.RotateLeft32(h(rho+0x01010101, mo[:k]), 8)
		c.k[2*i] = a + b
		c.k[2*i+1] = bits.RotateLeft32(a+2*b, 9)
	}
	for j := 0; j < 4; j++ {
		for x := 0; x < 256; x++ {
			c.s[j][x] = mds[j][qchain(j, byte(x), sw[:k])]
		}
	}
	return c, nil
}

func (c *block) BlockSize() int { return BlockSize }

// g returns the two g-function outputs for a and b, with the rotation of b by
// 8 bits folded into the table indices, then the pseudo-Hadamard transform
// and the round keys: (t0, t1) of the paper's F function.
func (c *block) f(a, b, k1, k2 uint32) (uint32, uint32) {
	t0 := c.s[0][byte(a)] ^ c.s[1][byte(a>>8)] ^ c.s[2][byte(a>>16)] ^ c.s[3][byte(a>>24)]
	t1 := c.s[0][byte(b>>24)] ^ c.s[1][byte(b)] ^ c.s[2][byte(b>>8)] ^ c.s[3][byte(b>>16)]
	t0 += t1
	t1 += t0
	return t0 + k1, t1 + k2
}

// Encrypt encrypts the first block of src into dst. dst and src must overlap
// entirely or not at all.
func (c *block) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("twofish: input not full block")
	}
	if len(dst) < BlockSize {
		panic("twofish: output not full block")
	}
	a := binary.LittleEndian.Uint32(src) ^ c.k[0]
	b := binary.LittleEndian.Uint32(src[4:]) ^ c.k[1]
	cc := binary.LittleEndian.Uint32(src[8:]) ^ c.k[2]
	d := binary.LittleEndian.Uint32(src[12:]) ^ c.k[3]
	for r := 8; r < 40; r += 4 {
		t0, t1 := c.f(a, b, c.k[r], c.k[r+1])
		cc = bits.RotateLeft32(cc^t0, -1)
		d = bits.RotateLeft32(d, 1) ^ t1
		t0, t1 = c.f(cc, d, c.k[r+2], c.k[r+3])
		a = bits.RotateLeft32(a^t0, -1)
		b = bits.RotateLeft32(b, 1) ^ t1
	}
	binary.LittleEndian.PutUint32(dst, cc^c.k[4])
	binary.LittleEndian.PutUint32(dst[4:], d^c.k[5])
	binary.LittleEndian.PutUint32(dst[8:], a^c.k[6])
	binary.LittleEndian.PutUint32(dst[12:], b^c.k[7])
}

// Decrypt decrypts the first block of src into dst. dst and src must overlap
// entirely or not at all.
func (c *block) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("twofish: input not full block")
	}
	if len(dst) < BlockSize {
		panic("twofish: output not full block")
	}
	a := binary.LittleEndian.Uint32(src) ^ c.k[4]
	b := binary.LittleEndian.Uint32(src[4:]) ^ c.k[5]
	cc := binary.LittleEndian.Uint32(src[8:]) ^ c.k[6]
	d := binary.LittleEndian.Uint32(src[12:]) ^ c.k[7]
	for r := 40; r > 8; r -= 4 {
		t0, t1 := c.f(a, b, c.k[r-2], c.k[r-1])
		cc = bits.RotateLeft32(cc, 1) ^ t0
		d = bits.RotateLeft32(d^t1, -1)
		t0, t1 = c.f(cc, d, c.k[r-4], c.k[r-3])
		a = bits.RotateLeft32(a, 1) ^ t0
		b = bits.RotateLeft32(b^t1, -1)
	}
	binary.LittleEndian.PutUint32(dst, cc^c.k[0])
	binary.LittleEndian.PutUint32(dst[4:], d^c.k[1])
	binary.LittleEndian.PutUint32(dst[8:], a^c.k[2])
	binary.LittleEndian.PutUint32(dst[12:], b^c.k[3])
}
