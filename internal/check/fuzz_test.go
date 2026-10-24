package check

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

// FuzzEarliestSCT feeds the embedded SCT list, read from every served leaf
// for the distrust calendar.
func FuzzEarliestSCT(f *testing.F) {
	sct := make([]byte, 47)
	sct[33], sct[40] = 0x01, 0x02
	list := append([]byte{0, byte(len(sct) + 2), 0, byte(len(sct))}, sct...)
	val, _ := asn1.Marshal(list)
	f.Add(val)
	f.Add([]byte{0x04, 0x02, 0x00, 0x00})
	f.Add([]byte{0x04, 0x04, 0x00, 0x02, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, value []byte) {
		at, ok := EarliestSCT(&x509.Certificate{Extensions: []pkix.Extension{{Id: sctOID, Value: value}}})
		if ok == at.IsZero() {
			t.Fatalf("ok %v with time %v", ok, at)
		}
	})
}
