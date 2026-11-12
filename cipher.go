package twofish

import (
	"encoding/binary"
	"math/bits"
)

func (c *block) BlockSize() int { return BlockSize }

// g0 is the g function of the paper on the word that enters the round
// unrotated: four look-ups, one per byte, in the tables that fold the S-boxes
// and the MDS matrix together.
func (c *block) g0(x uint32) uint32 {
	return c.s[0][byte(x)] ^ c.s[1][byte(x>>8)] ^ c.s[2][byte(x>>16)] ^ c.s[3][x>>24]
}

// g1 is g on the word that the round rotates left by 8 bits: the rotation is
// folded into the choice of table per byte.
func (c *block) g1(x uint32) uint32 {
	return c.s[0][x>>24] ^ c.s[1][byte(x)] ^ c.s[2][byte(x>>8)] ^ c.s[3][byte(x>>16)]
}

// roundKeys is the 32 round keys K_8..K_39 as eight groups of four, one group
// per pair of rounds.
func (c *block) roundKeys() *[8][4]uint32 { return &c.rk }

func check(dst, src []byte) {
	if len(src) < BlockSize {
		panic("twofish: input not full block")
	}
	if len(dst) < BlockSize {
		panic("twofish: output not full block")
	}
}

// Encrypt encrypts the first block of src into dst. dst and src must overlap
// entirely or not at all.
func (c *block) Encrypt(dst, src []byte) {
	check(dst, src)
	a := binary.LittleEndian.Uint32(src) ^ c.k[0]
	b := binary.LittleEndian.Uint32(src[4:]) ^ c.k[1]
	cc := binary.LittleEndian.Uint32(src[8:]) ^ c.k[2]
	d := binary.LittleEndian.Uint32(src[12:]) ^ c.k[3]
	rk := c.roundKeys()
	for i := range rk {
		r := &rk[i]
		// X = g0+g1+K, Y = g0+2*g1+K': the key is added to g1 off the critical
		// path, so each of X and Y is one addition after u = g0+g1.
		x, y := c.g0(a), c.g1(b)
		u, v := x+y, y+r[1]
		cc = bits.RotateLeft32(cc^(u+r[0]), -1)
		d = bits.RotateLeft32(d, 1) ^ (u + v)
		x, y = c.g0(cc), c.g1(d)
		u, v = x+y, y+r[3]
		a = bits.RotateLeft32(a^(u+r[2]), -1)
		b = bits.RotateLeft32(b, 1) ^ (u + v)
	}
	binary.LittleEndian.PutUint32(dst, cc^c.k[4])
	binary.LittleEndian.PutUint32(dst[4:], d^c.k[5])
	binary.LittleEndian.PutUint32(dst[8:], a^c.k[6])
	binary.LittleEndian.PutUint32(dst[12:], b^c.k[7])
}

// Decrypt decrypts the first block of src into dst. dst and src must overlap
// entirely or not at all.
func (c *block) Decrypt(dst, src []byte) {
	check(dst, src)
	a := binary.LittleEndian.Uint32(src) ^ c.k[4]
	b := binary.LittleEndian.Uint32(src[4:]) ^ c.k[5]
	cc := binary.LittleEndian.Uint32(src[8:]) ^ c.k[6]
	d := binary.LittleEndian.Uint32(src[12:]) ^ c.k[7]
	rk := c.roundKeys()
	for i := len(rk) - 1; i >= 0; i-- {
		r := &rk[i]
		x, y := c.g0(a), c.g1(b)
		u, v := x+y, y+r[3]
		cc = bits.RotateLeft32(cc, 1) ^ (u + r[2])
		d = bits.RotateLeft32(d^(u+v), -1)
		x, y = c.g0(cc), c.g1(d)
		u, v = x+y, y+r[1]
		a = bits.RotateLeft32(a, 1) ^ (u + r[0])
		b = bits.RotateLeft32(b^(u+v), -1)
	}
	binary.LittleEndian.PutUint32(dst, cc^c.k[0])
	binary.LittleEndian.PutUint32(dst[4:], d^c.k[1])
	binary.LittleEndian.PutUint32(dst[8:], a^c.k[2])
	binary.LittleEndian.PutUint32(dst[12:], b^c.k[3])
}

func checkBlocks(dst, src []byte) {
	if len(src)%BlockSize != 0 {
		panic("twofish: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("twofish: output smaller than input")
	}
}

// EncryptBlocks encrypts every 16-byte block of src into dst, as in ECB mode.
// It is faster than calling Encrypt on each block: four blocks go through the
// rounds side by side, which hides the latency of the table look-ups. len(src)
// must be a multiple of 16 and dst at least as long; dst and src must overlap
// entirely or not at all.
func (c *block) EncryptBlocks(dst, src []byte) {
	checkBlocks(dst, src)
	rk := c.roundKeys()
	for ; len(src) >= 4*BlockSize; src, dst = src[4*BlockSize:], dst[4*BlockSize:] {
		s, o := src[:64], dst[:64]
		a0 := binary.LittleEndian.Uint32(s) ^ c.k[0]
		b0 := binary.LittleEndian.Uint32(s[4:]) ^ c.k[1]
		c0 := binary.LittleEndian.Uint32(s[8:]) ^ c.k[2]
		d0 := binary.LittleEndian.Uint32(s[12:]) ^ c.k[3]
		a1 := binary.LittleEndian.Uint32(s[16:]) ^ c.k[0]
		b1 := binary.LittleEndian.Uint32(s[20:]) ^ c.k[1]
		c1 := binary.LittleEndian.Uint32(s[24:]) ^ c.k[2]
		d1 := binary.LittleEndian.Uint32(s[28:]) ^ c.k[3]
		a2 := binary.LittleEndian.Uint32(s[32:]) ^ c.k[0]
		b2 := binary.LittleEndian.Uint32(s[36:]) ^ c.k[1]
		c2 := binary.LittleEndian.Uint32(s[40:]) ^ c.k[2]
		d2 := binary.LittleEndian.Uint32(s[44:]) ^ c.k[3]
		a3 := binary.LittleEndian.Uint32(s[48:]) ^ c.k[0]
		b3 := binary.LittleEndian.Uint32(s[52:]) ^ c.k[1]
		c3 := binary.LittleEndian.Uint32(s[56:]) ^ c.k[2]
		d3 := binary.LittleEndian.Uint32(s[60:]) ^ c.k[3]
		for i := range rk {
			r := &rk[i]
			x0, y0 := c.g0(a0), c.g1(b0)
			x1, y1 := c.g0(a1), c.g1(b1)
			x2, y2 := c.g0(a2), c.g1(b2)
			x3, y3 := c.g0(a3), c.g1(b3)
			x0 += y0
			y0 += x0
			x1 += y1
			y1 += x1
			x2 += y2
			y2 += x2
			x3 += y3
			y3 += x3
			c0 = bits.RotateLeft32(c0^(x0+r[0]), -1)
			d0 = bits.RotateLeft32(d0, 1) ^ (y0 + r[1])
			c1 = bits.RotateLeft32(c1^(x1+r[0]), -1)
			d1 = bits.RotateLeft32(d1, 1) ^ (y1 + r[1])
			c2 = bits.RotateLeft32(c2^(x2+r[0]), -1)
			d2 = bits.RotateLeft32(d2, 1) ^ (y2 + r[1])
			c3 = bits.RotateLeft32(c3^(x3+r[0]), -1)
			d3 = bits.RotateLeft32(d3, 1) ^ (y3 + r[1])
			x0, y0 = c.g0(c0), c.g1(d0)
			x1, y1 = c.g0(c1), c.g1(d1)
			x2, y2 = c.g0(c2), c.g1(d2)
			x3, y3 = c.g0(c3), c.g1(d3)
			x0 += y0
			y0 += x0
			x1 += y1
			y1 += x1
			x2 += y2
			y2 += x2
			x3 += y3
			y3 += x3
			a0 = bits.RotateLeft32(a0^(x0+r[2]), -1)
			b0 = bits.RotateLeft32(b0, 1) ^ (y0 + r[3])
			a1 = bits.RotateLeft32(a1^(x1+r[2]), -1)
			b1 = bits.RotateLeft32(b1, 1) ^ (y1 + r[3])
			a2 = bits.RotateLeft32(a2^(x2+r[2]), -1)
			b2 = bits.RotateLeft32(b2, 1) ^ (y2 + r[3])
			a3 = bits.RotateLeft32(a3^(x3+r[2]), -1)
			b3 = bits.RotateLeft32(b3, 1) ^ (y3 + r[3])
		}
		binary.LittleEndian.PutUint32(o, c0^c.k[4])
		binary.LittleEndian.PutUint32(o[4:], d0^c.k[5])
		binary.LittleEndian.PutUint32(o[8:], a0^c.k[6])
		binary.LittleEndian.PutUint32(o[12:], b0^c.k[7])
		binary.LittleEndian.PutUint32(o[16:], c1^c.k[4])
		binary.LittleEndian.PutUint32(o[20:], d1^c.k[5])
		binary.LittleEndian.PutUint32(o[24:], a1^c.k[6])
		binary.LittleEndian.PutUint32(o[28:], b1^c.k[7])
		binary.LittleEndian.PutUint32(o[32:], c2^c.k[4])
		binary.LittleEndian.PutUint32(o[36:], d2^c.k[5])
		binary.LittleEndian.PutUint32(o[40:], a2^c.k[6])
		binary.LittleEndian.PutUint32(o[44:], b2^c.k[7])
		binary.LittleEndian.PutUint32(o[48:], c3^c.k[4])
		binary.LittleEndian.PutUint32(o[52:], d3^c.k[5])
		binary.LittleEndian.PutUint32(o[56:], a3^c.k[6])
		binary.LittleEndian.PutUint32(o[60:], b3^c.k[7])
	}
	for ; len(src) > 0; src, dst = src[BlockSize:], dst[BlockSize:] {
		c.Encrypt(dst, src)
	}
}

// DecryptBlocks is EncryptBlocks for decryption.
func (c *block) DecryptBlocks(dst, src []byte) {
	checkBlocks(dst, src)
	rk := c.roundKeys()
	for ; len(src) >= 4*BlockSize; src, dst = src[4*BlockSize:], dst[4*BlockSize:] {
		s, o := src[:64], dst[:64]
		a0 := binary.LittleEndian.Uint32(s) ^ c.k[4]
		b0 := binary.LittleEndian.Uint32(s[4:]) ^ c.k[5]
		c0 := binary.LittleEndian.Uint32(s[8:]) ^ c.k[6]
		d0 := binary.LittleEndian.Uint32(s[12:]) ^ c.k[7]
		a1 := binary.LittleEndian.Uint32(s[16:]) ^ c.k[4]
		b1 := binary.LittleEndian.Uint32(s[20:]) ^ c.k[5]
		c1 := binary.LittleEndian.Uint32(s[24:]) ^ c.k[6]
		d1 := binary.LittleEndian.Uint32(s[28:]) ^ c.k[7]
		a2 := binary.LittleEndian.Uint32(s[32:]) ^ c.k[4]
		b2 := binary.LittleEndian.Uint32(s[36:]) ^ c.k[5]
		c2 := binary.LittleEndian.Uint32(s[40:]) ^ c.k[6]
		d2 := binary.LittleEndian.Uint32(s[44:]) ^ c.k[7]
		a3 := binary.LittleEndian.Uint32(s[48:]) ^ c.k[4]
		b3 := binary.LittleEndian.Uint32(s[52:]) ^ c.k[5]
		c3 := binary.LittleEndian.Uint32(s[56:]) ^ c.k[6]
		d3 := binary.LittleEndian.Uint32(s[60:]) ^ c.k[7]
		for i := len(rk) - 1; i >= 0; i-- {
			r := &rk[i]
			x0, y0 := c.g0(a0), c.g1(b0)
			x1, y1 := c.g0(a1), c.g1(b1)
			x2, y2 := c.g0(a2), c.g1(b2)
			x3, y3 := c.g0(a3), c.g1(b3)
			x0 += y0
			y0 += x0
			x1 += y1
			y1 += x1
			x2 += y2
			y2 += x2
			x3 += y3
			y3 += x3
			c0 = bits.RotateLeft32(c0, 1) ^ (x0 + r[2])
			d0 = bits.RotateLeft32(d0^(y0+r[3]), -1)
			c1 = bits.RotateLeft32(c1, 1) ^ (x1 + r[2])
			d1 = bits.RotateLeft32(d1^(y1+r[3]), -1)
			c2 = bits.RotateLeft32(c2, 1) ^ (x2 + r[2])
			d2 = bits.RotateLeft32(d2^(y2+r[3]), -1)
			c3 = bits.RotateLeft32(c3, 1) ^ (x3 + r[2])
			d3 = bits.RotateLeft32(d3^(y3+r[3]), -1)
			x0, y0 = c.g0(c0), c.g1(d0)
			x1, y1 = c.g0(c1), c.g1(d1)
			x2, y2 = c.g0(c2), c.g1(d2)
			x3, y3 = c.g0(c3), c.g1(d3)
			x0 += y0
			y0 += x0
			x1 += y1
			y1 += x1
			x2 += y2
			y2 += x2
			x3 += y3
			y3 += x3
			a0 = bits.RotateLeft32(a0, 1) ^ (x0 + r[0])
			b0 = bits.RotateLeft32(b0^(y0+r[1]), -1)
			a1 = bits.RotateLeft32(a1, 1) ^ (x1 + r[0])
			b1 = bits.RotateLeft32(b1^(y1+r[1]), -1)
			a2 = bits.RotateLeft32(a2, 1) ^ (x2 + r[0])
			b2 = bits.RotateLeft32(b2^(y2+r[1]), -1)
			a3 = bits.RotateLeft32(a3, 1) ^ (x3 + r[0])
			b3 = bits.RotateLeft32(b3^(y3+r[1]), -1)
		}
		binary.LittleEndian.PutUint32(o, c0^c.k[0])
		binary.LittleEndian.PutUint32(o[4:], d0^c.k[1])
		binary.LittleEndian.PutUint32(o[8:], a0^c.k[2])
		binary.LittleEndian.PutUint32(o[12:], b0^c.k[3])
		binary.LittleEndian.PutUint32(o[16:], c1^c.k[0])
		binary.LittleEndian.PutUint32(o[20:], d1^c.k[1])
		binary.LittleEndian.PutUint32(o[24:], a1^c.k[2])
		binary.LittleEndian.PutUint32(o[28:], b1^c.k[3])
		binary.LittleEndian.PutUint32(o[32:], c2^c.k[0])
		binary.LittleEndian.PutUint32(o[36:], d2^c.k[1])
		binary.LittleEndian.PutUint32(o[40:], a2^c.k[2])
		binary.LittleEndian.PutUint32(o[44:], b2^c.k[3])
		binary.LittleEndian.PutUint32(o[48:], c3^c.k[0])
		binary.LittleEndian.PutUint32(o[52:], d3^c.k[1])
		binary.LittleEndian.PutUint32(o[56:], a3^c.k[2])
		binary.LittleEndian.PutUint32(o[60:], b3^c.k[3])
	}
	for ; len(src) > 0; src, dst = src[BlockSize:], dst[BlockSize:] {
		c.Decrypt(dst, src)
	}
}
