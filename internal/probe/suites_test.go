package probe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
)

// rsaLeaf is a leaf with an RSA key, which the RSA key exchange and the
// ECDHE_RSA suites need; the shared PKI uses ECDSA.
func rsaLeaf(t *testing.T, parent *testCert) *testCert {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return newCert(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "rsa.example"},
		DNSNames:    []string{"rsa.example"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}, parent, k)
}

func classes(cs []SuiteClass) string {
	var s []string
	for _, c := range cs {
		s = append(s, string(c))
	}
	return strings.Join(s, ",")
}

func TestSuiteClasses(t *testing.T) {
	p := newPKI(t)
	leaf := rsaLeaf(t, p.inter)
	cases := []struct {
		name   string
		suites []uint16
		max    uint16
		want   string
	}{
		{"modern server refuses every class", []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305}, 0, ""},
		{"TLS 1.3 only refuses every class", nil, tls.VersionTLS13, ""},
		{"RSA key exchange", []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_128_GCM_SHA256}, 0, "no_pfs"},
		{"CBC with SHA-1", []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}, 0, "cbc_sha1"},
		{"3DES", []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA}, 0, "3des"},
		{"RC4", []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA}, 0, "rc4"},
		{"everything", []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}, 0, "rc4,3des,no_pfs,cbc_sha1"},
	}
	for _, c := range cases {
		cfg := serverConfig(leaf, p.inter)
		cfg.CipherSuites = c.suites
		cfg.MinVersion = tls.VersionTLS12
		if c.max != 0 {
			cfg.MinVersion, cfg.MaxVersion = c.max, c.max
		}
		r := req(serve(t, cfg, nil), TLS)
		r.Legacy = true
		a := single(t, Probe(context.Background(), r))
		if !a.OK || !a.SuitesChecked || classes(a.Suites) != c.want || len(a.SuiteNames) != len(a.Suites) {
			t.Errorf("%s: ok %v checked %v classes %q names %v, want %q", c.name, a.OK, a.SuitesChecked, classes(a.Suites), a.SuiteNames, c.want)
		}
	}
}

func TestSuitesNotTestedUnlessAsked(t *testing.T) {
	p := newPKI(t)
	cfg := serverConfig(rsaLeaf(t, p.inter), p.inter)
	cfg.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}
	a := single(t, Probe(context.Background(), req(serve(t, cfg, nil), TLS)))
	if !a.OK || a.SuitesChecked || a.Suites != nil {
		t.Fatalf("suites tested without Request.Legacy: %+v", a)
	}
}

func TestSuiteClassLabels(t *testing.T) {
	for _, c := range SuiteClasses {
		if c.Label() == string(c) || len(c.Suites()) == 0 {
			t.Errorf("%s: label %q suites %d", c, c.Label(), len(c.Suites()))
		}
		if got, ok := ParseSuiteClass(string(c)); !ok || got != c {
			t.Errorf("%s does not parse back", c)
		}
	}
	if _, ok := ParseSuiteClass("camellia"); ok {
		t.Error("unknown class parsed")
	}
}
