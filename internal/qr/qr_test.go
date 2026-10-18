package qr

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The data capacity of each version at level M, from table 7 of the
// standard: the error correction tables above must add up to it.
func TestCapacity(t *testing.T) {
	want := [maxVersion + 1]int{0, 16, 28, 44, 64, 86, 108, 124, 154, 182, 216, 254, 290, 334, 365, 415, 453, 507, 563, 627, 669}
	for v := 1; v <= maxVersion; v++ {
		if got := dataCodewords(v); got != want[v] {
			t.Errorf("version %d: %d data codewords, want %d", v, got, want[v])
		}
	}
}

func TestEncodeSizes(t *testing.T) {
	for _, tc := range []struct {
		n, ver int
	}{{1, 1}, {14, 1}, {15, 2}, {106, 6}, {107, 7}, {213, 10}, {666, 20}} {
		c, err := Encode(strings.Repeat("a", tc.n))
		if err != nil {
			t.Fatalf("%d bytes: %v", tc.n, err)
		}
		if c.Size != tc.ver*4+17 {
			t.Errorf("%d bytes: size %d, want version %d", tc.n, c.Size, tc.ver)
		}
	}
	if _, err := Encode(strings.Repeat("a", 667)); err != ErrTooLong {
		t.Errorf("667 bytes: %v", err)
	}
}

func TestSVG(t *testing.T) {
	c, err := Encode("otpauth://totp/x")
	if err != nil {
		t.Fatal(err)
	}
	svg := c.SVG(`QR "code"`)
	if !strings.HasPrefix(svg, "<svg ") || !strings.Contains(svg, `aria-label="QR &quot;code&quot;"`) || strings.Contains(svg, "style=") {
		t.Fatalf("svg: %.200s", svg)
	}
}

// TestDecodes reads codes of several versions back with zbarimg, when it
// is installed: the one check that a camera would read them.
func TestDecodes(t *testing.T) {
	zbar, err := exec.LookPath("zbarimg")
	if err != nil {
		t.Skip("zbarimg not installed")
	}
	dir := t.TempDir()
	for _, text := range []string{
		"hi",
		"otpauth://totp/tlswatch:anna%40example.nl?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=tlswatch",
		"otpauth://totp/tlswatch:" + strings.Repeat("long.name", 12) + "%40example.nl?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=tlswatch&algorithm=SHA1&digits=6&period=30",
		strings.Repeat("0123456789abcdef", 40),
	} {
		c, err := Encode(text)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "code.png")
		writePNG(t, c, path)
		out, err := exec.Command(zbar, "-q", "--raw", path).Output()
		if err != nil {
			t.Fatalf("version %d not read: %v", (c.Size-17)/4, err)
		}
		if got := strings.TrimSuffix(string(out), "\n"); got != text {
			t.Errorf("version %d read as %q", (c.Size-17)/4, got)
		}
	}
}

func writePNG(t *testing.T, c *Code, path string) {
	t.Helper()
	const scale = 6
	n := (c.Size + 8) * scale
	img := image.NewGray(image.Rect(0, 0, n, n))
	for y := range n {
		for x := range n {
			mx, my := x/scale-4, y/scale-4
			v := color.Gray{Y: 255}
			if mx >= 0 && my >= 0 && mx < c.Size && my < c.Size && c.Dark(mx, my) {
				v = color.Gray{}
			}
			img.SetGray(x, y, v)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}
