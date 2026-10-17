package ct

import "testing"

// crt.sh writes an issuer DN as text, quoting a value that holds a comma
// (RFC 4514). The CN is what a served certificate is matched on, and the
// organisation is what the issuance shows.
func TestDNPartsQuotedValues(t *testing.T) {
	for _, c := range []struct{ dn, cn, org string }{
		{"C=US, O=Let's Encrypt, CN=R11", "R11", "Let's Encrypt"},
		{"O=Sectigo Limited, CN=Sectigo RSA DV", "Sectigo RSA DV", "Sectigo Limited"},
		{"C=US, O=Internet Security Research Group", "Internet Security Research Group", "Internet Security Research Group"},
		{`C=US, ST=Arizona, L=Scottsdale, O="GoDaddy.com, Inc.", OU=http://certs.godaddy.com/repository/, CN=Go Daddy Secure Certificate Authority - G2`,
			"Go Daddy Secure Certificate Authority - G2", "GoDaddy.com, Inc."},
		{`C=NL, O=Example B.V., CN="Example Issuing CA, G2"`, "Example Issuing CA, G2", "Example B.V."},
	} {
		cn, org := dnParts(c.dn)
		if cn != c.cn || org != c.org {
			t.Errorf("%s: cn %q org %q, want %q %q", c.dn, cn, org, c.cn, c.org)
		}
	}
}

func TestSerialHexSpellings(t *testing.T) {
	for in, want := range map[string]string{" 0A:1B ": "A1B", "0X00FF": "FF", "00 01": "1", "": "0", "abc def": "ABCDEF"} {
		if got := SerialHex(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestDNPartsEscapedComma(t *testing.T) {
	if cn, org := dnParts(`O=Example\, Inc., CN=Example CA`); cn != "Example CA" || org != "Example, Inc." {
		t.Errorf("cn %q org %q", cn, org)
	}
}
