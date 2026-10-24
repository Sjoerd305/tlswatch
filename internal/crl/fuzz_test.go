package crl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// The CRL comes from a URL in the leaf, fetched over plain HTTP, so every
// byte of it is untrusted until its signature is checked.

func FuzzIDPURIs(f *testing.F) {
	f.Add(idp(f, "http://crl.example/a.crl").Value)
	f.Add(idp(f).Value)
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x02, 0xa0, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		_, _ = idpURIs(der)
	})
}

func FuzzCheck(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fuzz CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		f.Fatal(err)
	}
	issuer, _ := x509.ParseCertificate(der)
	c := ca{issuer, key}
	f.Add(c.crl(f))
	f.Add(c.crl(f, idp(f, "http://crl.example/a.crl")))
	f.Add([]byte("-----BEGIN X509 CRL-----\nMAA=\n-----END X509 CRL-----\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Check(data, issuer, "http://crl.example/a.crl")
	})
}
