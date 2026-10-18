package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// The chain view names the distrust event on the root it concerns, with
// its announcement, and the Certificates page offers the distrusted chip.
func TestDistrustOnPages(t *testing.T) {
	hs := newHarness(t)
	now := time.Now()
	mk := func(tpl *x509.Certificate, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if parent == nil {
			parent, parentKey = tpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, key.Public(), parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, key
	}
	root, rootKey := mk(&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Old Root CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour)}, nil, nil)
	leaf, _ := mk(&x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "example.org"}, DNSNames: []string{"example.org"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}, root, rootKey)
	spki := sha256.Sum256(root.RawSubjectPublicKeyInfo)
	saved := check.Distrusts
	check.Distrusts = []check.DistrustEvent{{CA: "Old CA", Program: "Mozilla", Effective: now.Add(60 * 24 * time.Hour), Link: "https://example.org/news",
		Anchors: []check.Anchor{{Name: "Old Root CA", SPKI: hex.EncodeToString(spki[:]), SKI: hex.EncodeToString(root.SubjectKeyId)}}}}
	t.Cleanup(func() { check.Distrusts = saved })

	ctx := context.Background()
	tg, err := hs.srv.Core.Target(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hs.srv.Core.Apply(ctx, tg, probe.Result{Host: tg.Host, Port: 443, Protocol: probe.TLS, StartedAt: now,
		Addresses: []probe.Address{{IP: "192.0.2.1", OK: true, Chain: []*x509.Certificate{leaf, root}, Verified: true, HostnameChecked: true, HostnameOK: true}}}); err != nil {
		t.Fatal(err)
	}
	page := hs.do(authz.Viewer, "GET", "/targets/1", nil, false).Body.String()
	if !strings.Contains(page, `href="https://example.org/news"`) || !strings.Contains(page, "Mozilla stops trusting it on ") {
		t.Fatal("chain view does not name the event")
	}
	certs := hs.do(authz.Viewer, "GET", "/certificates", nil, false).Body.String()
	if !strings.Contains(certs, `data-chip-value="distrusted"`) || !strings.Contains(certs, `<span class="pill warn ml">distrusted</span>`) {
		t.Fatal("no distrusted chip or pill")
	}
}
