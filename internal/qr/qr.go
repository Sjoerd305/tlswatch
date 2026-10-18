// Package qr encodes text as a QR code (ISO/IEC 18004) and draws it as an
// inline SVG. It covers what an authenticator URI needs: byte mode, error
// correction level M, versions 1 to 20 (up to 666 bytes), with no library.
package qr

import (
	"errors"
	"fmt"
	"strings"
)

// ErrTooLong is returned for text that does not fit version 20.
var ErrTooLong = errors.New("qr: text too long")

const maxVersion = 20

// Error correction level M: codewords per block and number of blocks, by
// version (index 0 unused), from table 9 of the standard.
var (
	eccPerBlock = [maxVersion + 1]int{0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26}
	eccBlocks   = [maxVersion + 1]int{0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16}
)

// formatM is the two format bits of level M.
const formatM = 0

// Code is an encoded QR code: Size × Size modules, true being dark.
type Code struct {
	Size    int
	modules [][]bool
	fn      [][]bool // function modules, which data and masks leave alone
}

// Dark reports whether the module at column x, row y is dark.
func (c *Code) Dark(x, y int) bool { return c.modules[y][x] }

// Encode returns the smallest QR code holding text.
func Encode(text string) (*Code, error) {
	data := []byte(text)
	ver := 1
	for ; ver <= maxVersion; ver++ {
		if 4+countBits(ver)+8*len(data) <= dataCodewords(ver)*8 {
			break
		}
	}
	if ver > maxVersion {
		return nil, ErrTooLong
	}
	var bb bitBuffer
	bb.append(0b0100, 4) // byte mode
	bb.append(len(data), countBits(ver))
	for _, b := range data {
		bb.append(int(b), 8)
	}
	capacity := dataCodewords(ver) * 8
	bb.append(0, min(4, capacity-len(bb)))
	bb.append(0, (8-len(bb)%8)%8)
	for pad := 0xEC; len(bb) < capacity; pad ^= 0xEC ^ 0x11 {
		bb.append(pad, 8)
	}
	cw := make([]byte, len(bb)/8)
	for i, bit := range bb {
		if bit {
			cw[i>>3] |= 1 << (7 - i&7)
		}
	}

	c := newCode(ver)
	c.drawCodewords(interleave(ver, cw))
	best, bestPenalty := 0, -1
	for mask := range 8 {
		c.applyMask(mask)
		c.drawFormat(mask)
		if p := c.penalty(); bestPenalty < 0 || p < bestPenalty {
			best, bestPenalty = mask, p
		}
		c.applyMask(mask) // XOR again undoes it
	}
	c.applyMask(best)
	c.drawFormat(best)
	return c, nil
}

// countBits is the width of the byte mode character count.
func countBits(ver int) int {
	if ver <= 9 {
		return 8
	}
	return 16
}

// rawModules is the number of modules that carry codewords, data and
// error correction, at a version.
func rawModules(ver int) int {
	n := (16*ver+128)*ver + 64
	if ver >= 2 {
		align := ver/7 + 2
		n -= (25*align-10)*align - 55
		if ver >= 7 {
			n -= 36
		}
	}
	return n
}

func dataCodewords(ver int) int { return rawModules(ver)/8 - eccPerBlock[ver]*eccBlocks[ver] }

// interleave splits the data codewords into blocks, adds each block's
// error correction and interleaves the result.
func interleave(ver int, data []byte) []byte {
	blocks, eccLen := eccBlocks[ver], eccPerBlock[ver]
	raw := rawModules(ver) / 8
	short := blocks - raw%blocks
	shortLen := raw / blocks
	div := rsDivisor(eccLen)
	var bs [][]byte
	k := 0
	for i := range blocks {
		n := shortLen - eccLen
		if i >= short {
			n++
		}
		b := append([]byte{}, data[k:k+n]...)
		k += n
		ecc := rsRemainder(b, div)
		if i < short {
			b = append(b, 0) // placeholder, skipped below
		}
		bs = append(bs, append(b, ecc...))
	}
	var out []byte
	for i := range bs[0] {
		for j, b := range bs {
			if i != shortLen-eccLen || j >= short {
				out = append(out, b[i])
			}
		}
	}
	return out
}

func newCode(ver int) *Code {
	size := ver*4 + 17
	c := &Code{Size: size, modules: make([][]bool, size), fn: make([][]bool, size)}
	for i := range size {
		c.modules[i] = make([]bool, size)
		c.fn[i] = make([]bool, size)
	}
	for i := range size {
		c.setFn(6, i, i%2 == 0)
		c.setFn(i, 6, i%2 == 0)
	}
	c.finder(3, 3)
	c.finder(size-4, 3)
	c.finder(3, size-4)
	pos := alignment(ver)
	last := len(pos) - 1
	for i, x := range pos {
		for j, y := range pos {
			if i == 0 && j == 0 || i == 0 && j == last || i == last && j == 0 {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					c.setFn(x+dx, y+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	c.drawFormat(0) // reserves the format modules; Encode draws them again
	if ver >= 7 {
		rem := ver
		for range 12 {
			rem = rem<<1 ^ (rem>>11)*0x1F25
		}
		bits := ver<<12 | rem
		for i := range 18 {
			a, b := size-11+i%3, i/3
			c.setFn(a, b, bits>>i&1 == 1)
			c.setFn(b, a, bits>>i&1 == 1)
		}
	}
	return c
}

// alignment returns the centre coordinates of the alignment patterns.
func alignment(ver int) []int {
	if ver == 1 {
		return nil
	}
	n := ver/7 + 2
	step := (ver*4 + n*2 + 1) / (n*2 - 2) * 2
	out := make([]int, n)
	out[0] = 6
	for i, p := n-1, ver*4+17-7; i >= 1; i, p = i-1, p-step {
		out[i] = p
	}
	return out
}

func (c *Code) setFn(x, y int, dark bool) {
	c.modules[y][x] = dark
	c.fn[y][x] = true
}

func (c *Code) finder(x, y int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			xx, yy := x+dx, y+dy
			if xx >= 0 && xx < c.Size && yy >= 0 && yy < c.Size {
				d := max(abs(dx), abs(dy))
				c.setFn(xx, yy, d != 2 && d != 4)
			}
		}
	}
}

// drawFormat draws both copies of the format information for level M and
// mask, and the dark module.
func (c *Code) drawFormat(mask int) {
	data := formatM<<3 | mask
	rem := data
	for range 10 {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	bits := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return bits>>i&1 == 1 }
	for i := range 6 {
		c.setFn(8, i, bit(i))
	}
	c.setFn(8, 7, bit(6))
	c.setFn(8, 8, bit(7))
	c.setFn(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		c.setFn(14-i, 8, bit(i))
	}
	for i := range 8 {
		c.setFn(c.Size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		c.setFn(8, c.Size-15+i, bit(i))
	}
	c.setFn(8, c.Size-8, true)
}

// drawCodewords places the codewords in the zigzag order of the standard.
func (c *Code) drawCodewords(data []byte) {
	i := 0
	for right := c.Size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := range c.Size {
			for j := range 2 {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = c.Size - 1 - vert
				}
				if !c.fn[y][x] && i < len(data)*8 {
					c.modules[y][x] = data[i>>3]>>(7-i&7)&1 == 1
					i++
				}
			}
		}
	}
}

func (c *Code) applyMask(mask int) {
	for y := range c.Size {
		for x := range c.Size {
			var flip bool
			switch mask {
			case 0:
				flip = (x+y)%2 == 0
			case 1:
				flip = y%2 == 0
			case 2:
				flip = x%3 == 0
			case 3:
				flip = (x+y)%3 == 0
			case 4:
				flip = (x/3+y/2)%2 == 0
			case 5:
				flip = x*y%2+x*y%3 == 0
			case 6:
				flip = (x*y%2+x*y%3)%2 == 0
			case 7:
				flip = ((x+y)%2+x*y%3)%2 == 0
			}
			if flip && !c.fn[y][x] {
				c.modules[y][x] = !c.modules[y][x]
			}
		}
	}
}

// penalty scores the symbol by the four rules of the standard; the mask
// with the lowest score is kept.
func (c *Code) penalty() int {
	n := c.Size
	p := 0
	at := func(x, y int, transpose bool) bool {
		if transpose {
			x, y = y, x
		}
		if x < 0 || y < 0 || x >= n || y >= n {
			return false // the quiet zone is light
		}
		return c.modules[y][x]
	}
	finder := []bool{true, false, true, true, true, false, true}
	for _, tr := range []bool{false, true} {
		for y := range n {
			run := 0
			for x := range n {
				if x > 0 && at(x, y, tr) == at(x-1, y, tr) {
					run++
				} else {
					run = 1
				}
				if run == 5 {
					p += 3
				} else if run > 5 {
					p++
				}
			}
			// Rule 3: the finder-like 1:1:3:1:1 pattern with four light
			// modules on either side.
			for x := -4; x < n; x++ {
				match := true
				for k, v := range finder {
					if at(x+k, y, tr) != v {
						match = false
						break
					}
				}
				if !match {
					continue
				}
				before, after := true, true
				for k := 1; k <= 4; k++ {
					before = before && !at(x-k, y, tr)
					after = after && !at(x+6+k, y, tr)
				}
				if before {
					p += 40
				}
				if after {
					p += 40
				}
			}
		}
	}
	dark := 0
	for y := range n {
		for x := range n {
			if c.modules[y][x] {
				dark++
			}
			if x < n-1 && y < n-1 {
				v := c.modules[y][x]
				if v == c.modules[y][x+1] && v == c.modules[y+1][x] && v == c.modules[y+1][x+1] {
					p += 3
				}
			}
		}
	}
	total := n * n
	p += ((abs(dark*20-total*10)+total-1)/total - 1) * 10
	return p
}

// SVG draws the code as an inline SVG with a four-module quiet zone,
// dark modules on white whatever the page theme, so a camera reads it.
// label is its accessible name.
func (c *Code) SVG(label string) string {
	var b strings.Builder
	n := c.Size + 8
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="%s" shape-rendering="crispEdges">`,
		n, n, n*4, n*4, escape(label))
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n)
	for y := range c.Size {
		for x := range c.Size {
			if c.modules[y][x] {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+4, y+4)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}

func escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

type bitBuffer []bool

func (bb *bitBuffer) append(v, n int) {
	for i := n - 1; i >= 0; i-- {
		*bb = append(*bb, v>>i&1 == 1)
	}
}

// rsDivisor is the Reed-Solomon generator polynomial of a degree, highest
// term left out.
func rsDivisor(degree int) []byte {
	out := make([]byte, degree)
	out[degree-1] = 1
	root := byte(1)
	for range degree {
		for j := range out {
			out[j] = gfMul(out[j], root)
			if j+1 < len(out) {
				out[j] ^= out[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return out
}

func rsRemainder(data, div []byte) []byte {
	out := make([]byte, len(div))
	for _, b := range data {
		f := b ^ out[0]
		copy(out, out[1:])
		out[len(out)-1] = 0
		for i, d := range div {
			out[i] ^= gfMul(d, f)
		}
	}
	return out
}

// gfMul multiplies in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1.
func gfMul(x, y byte) byte {
	z := 0
	for i := 7; i >= 0; i-- {
		z = z<<1 ^ (z>>7)*0x11D
		z ^= int(y>>i&1) * int(x)
	}
	return byte(z)
}
