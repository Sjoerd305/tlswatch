package caa

import (
	"bytes"
	"testing"
)

// The CAA answer comes from the network, from whichever resolver answers.

func FuzzParse(f *testing.F) {
	q, id, err := build("example.nl.")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(q, id)
	f.Add([]byte{0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0}, uint16(1))
	f.Fuzz(func(t *testing.T, resp []byte, id uint16) {
		_, _ = parse(resp, id)
	})
}

func FuzzDecode(f *testing.F) {
	f.Add(encode(Record{Flags: 0, Tag: "issue", Value: "letsencrypt.org"}))
	f.Add(encode(Record{Flags: 128, Tag: "iodef", Value: "mailto:x@example.nl"}))
	f.Add([]byte{0, 9, 'i'})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := decode(b)
		if err != nil {
			return
		}
		if !bytes.Equal(encode(r), b) {
			t.Fatalf("decode and encode differ: %x → %+v → %x", b, r, encode(r))
		}
	})
}
