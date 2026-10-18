package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// The target page shows the leaf's CRL status, and the revoked finding.
func TestRevocationOnTargetPage(t *testing.T) {
	hs := newHarness(t)
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Private CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, caKey.Public(), caKey)
	ca, _ := x509.ParseCertificate(der)
	revoked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(24 * time.Hour)}
		if revoked {
			tpl.Number, tpl.ThisUpdate = big.NewInt(2), now
			tpl.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(2), RevocationTime: now.Add(-time.Hour), ReasonCode: 1}}
		}
		b, _ := x509.CreateRevocationList(rand.Reader, tpl, ca, caKey)
		w.Write(b)
	}))
	defer srv.Close()
	hs.srv.Core.CRLClient = srv.Client()
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ = x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "example.org"},
		DNSNames: []string{"example.org"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		CRLDistributionPoints: []string{srv.URL + "/ca.crl"}}, ca, leafKey.Public(), caKey)
	leaf, _ := x509.ParseCertificate(der)

	ctx := context.Background()
	check := func() string {
		t.Helper()
		tg, err := hs.srv.Core.Target(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		r := probe.Result{Host: tg.Host, Port: 443, Protocol: probe.TLS, StartedAt: now,
			Addresses: []probe.Address{{IP: "192.0.2.1", OK: true, Chain: []*x509.Certificate{leaf, ca}, Verified: true, HostnameChecked: true, HostnameOK: true}}}
		hs.srv.Core.RefreshCRLs(ctx, tg, r, nil)
		if _, err := hs.srv.Core.Apply(ctx, tg, r); err != nil {
			t.Fatal(err)
		}
		return hs.do(authz.Viewer, "GET", "/targets/1", nil, false).Body.String()
	}
	page := check()
	if !strings.Contains(page, "<dt>Revocation</dt>") || !strings.Contains(page, `<span class="st sm ok">not revoked</span>`) || !strings.Contains(page, srv.URL+"/ca.crl") {
		t.Fatal("no clean revocation row")
	}
	// The next day's CRL lists the leaf.
	revoked = true
	if _, err := hs.srv.Core.DB.W.Exec("UPDATE crls SET attempted_at = attempted_at - 86400"); err != nil {
		t.Fatal(err)
	}
	page = check()
	if !strings.Contains(page, `<span class="st sm crit">revoked `) || !strings.Contains(page, "key compromise") {
		t.Fatal("revoked leaf not shown")
	}
}
