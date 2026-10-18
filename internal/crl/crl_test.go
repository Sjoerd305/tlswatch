package crl

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, cn string) ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return ca{c, key}
}

// idp is an issuing distribution point naming uris.
func idp(t *testing.T, uris ...string) pkix.Extension {
	t.Helper()
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				for _, u := range uris {
					b.AddASN1(cbasn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes([]byte(u)) })
				}
			})
		})
	})
	return pkix.Extension{Id: oidIssuingDistributionPoint, Critical: true, Value: b.BytesOrPanic()}
}

func (c ca) crl(t *testing.T, exts ...pkix.Extension) []byte {
	t.Helper()
	tpl := &x509.RevocationList{Number: big.NewInt(7), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(42), RevocationTime: time.Now().Add(-2 * time.Hour), ReasonCode: 1}},
		ExtraExtensions:           exts}
	der, err := x509.CreateRevocationList(rand.Reader, tpl, c.cert, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCheck(t *testing.T) {
	iss, other := newCA(t, "Example CA"), newCA(t, "Other CA")
	u := "http://crl.example.nl/7.crl"

	rl, err := Check(iss.crl(t, idp(t, u)), iss.cert, u)
	if err != nil || len(rl.RevokedCertificateEntries) != 1 || Reason(rl.RevokedCertificateEntries[0].ReasonCode) != "key compromise" {
		t.Fatalf("partition for this URL: %v %+v", err, rl)
	}
	// PEM is accepted too, and a CRL without a distribution point covers
	// every URL that names it.
	p := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: iss.crl(t)})
	if _, err := Check(p, iss.cert, u); err != nil {
		t.Fatalf("pem: %v", err)
	}
	for name, c := range map[string]struct {
		data   []byte
		issuer *x509.Certificate
		want   string
	}{
		"another partition": {iss.crl(t, idp(t, "http://crl.example.nl/8.crl")), iss.cert, "a partition for http://crl.example.nl/8.crl"},
		"another issuer":    {other.crl(t), iss.cert, "issued by CN=Other CA"},
		"delta":             {iss.crl(t, pkix.Extension{Id: oidDeltaCRLIndicator, Value: []byte{2, 1, 6}}), iss.cert, "a delta CRL"},
		"garbage":           {[]byte("<html>"), iss.cert, "not a CRL"},
	} {
		if _, err := Check(c.data, c.issuer, u); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Same name, another key: the signature does not verify.
	impostor := newCA(t, "Example CA")
	if _, err := Check(impostor.crl(t), iss.cert, u); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("impostor: %v", err)
	}
}

func TestURL(t *testing.T) {
	c := &x509.Certificate{CRLDistributionPoints: []string{"ldap://dir.example.nl/cn=CA", "http://user:pw@crl.example.nl/a.crl", "http://crl.example.nl/b.crl"}}
	if got := URL(c); got != "http://crl.example.nl/b.crl" {
		t.Fatalf("URL = %q", got)
	}
	if URL(&x509.Certificate{}) != "" {
		t.Fatal("no distribution point")
	}
}

func TestFetch(t *testing.T) {
	ctx := context.Background()
	big := bytes.Repeat([]byte{0}, MaxSize+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok.crl":
			w.Write([]byte("crl bytes"))
		case "/big.crl":
			w.Header().Set("Content-Length", "52428801")
			w.Write(big)
		case "/chunked.crl":
			w.(http.Flusher).Flush()
			w.Write(big)
		case "/ftp":
			http.Redirect(w, r, "ftp://crl.example.nl/a.crl", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := srv.Client()

	if b, err := Fetch(ctx, client, srv.URL+"/ok.crl"); err != nil || string(b) != "crl bytes" {
		t.Fatalf("ok: %q %v", b, err)
	}
	for _, path := range []string{"/big.crl", "/chunked.crl"} {
		if _, err := Fetch(ctx, client, srv.URL+path); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v", path, err)
		}
	}
	if _, err := Fetch(ctx, client, srv.URL+"/missing.crl"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("404: %v", err)
	}
	if _, err := Fetch(ctx, client, srv.URL+"/ftp"); err == nil || !strings.Contains(err.Error(), "ftp") {
		t.Errorf("redirect to ftp: %v", err)
	}
	if _, err := Fetch(ctx, client, "ldap://dir.example.nl/x"); err == nil {
		t.Error("ldap fetched")
	}

	// The dialer refuses what allow refuses.
	refusing := NewClient(func(net.IP) error { return errors.New("not here") })
	if _, err := Fetch(ctx, refusing, srv.URL+"/ok.crl"); err == nil || !strings.Contains(err.Error(), "not here") {
		t.Errorf("refused address: %v", err)
	}
}
