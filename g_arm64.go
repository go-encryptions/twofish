//go:build arm64 && !twofishflat

package twofish

// g0 is the g function of the paper on the word that enters the round
// unrotated: four look-ups, one per byte, in the tables that fold the S-boxes
// and the MDS matrix together. On arm64 a byte conversion compiles to UBFX plus
// a redundant UXTB, and a left-to-right fold to a chain of three XORs after the
// last load; the masks and the pairwise fold remove one instruction from the
// path of each look-up and one XOR level.
func (c *block) g0(x uint32) uint32 {
	return (c.s[0][x&0xff] ^ c.s[1][x>>8&0xff]) ^ (c.s[2][x>>16&0xff] ^ c.s[3][x>>24])
}

// g1 is g on the word that the round rotates left by 8 bits: the rotation is
// folded into the choice of table per byte.
func (c *block) g1(x uint32) uint32 {
	return (c.s[0][x>>24] ^ c.s[1][x&0xff]) ^ (c.s[2][x>>8&0xff] ^ c.s[3][x>>16&0xff])
}
