package check

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

func TestDiff(t *testing.T) {
	le := newIssuer(t, "Let's Encrypt", "R11")
	old := leafCert(t, le, 60, "www.example.nl", "old.example.nl")
	// An RSA leaf for 47 days that drops a name and adds one.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: old.SerialNumber, Subject: pkix.Name{CommonName: "www.example.nl"}, DNSNames: []string{"www.example.nl", "api.example.nl"},
		NotBefore: now, NotAfter: now.Add(47 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, le.cert, &key.PublicKey, le.key)
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := x509.ParseCertificate(der)
	got := Diff(probe.Describe(old), probe.Describe(cur), Intermediate{}, Intermediate{})
	want := "SANs +api.example.nl −old.example.nl; key ECDSA P-256 → RSA 2048; expires " +
		old.NotAfter.UTC().Format(time.DateOnly) + " → " + cur.NotAfter.UTC().Format(time.DateOnly) + "; lifetime 90 → 47 days"
	if got != want {
		t.Fatalf("diff\n got %s\nwant %s", got, want)
	}

	// Another CA names both organisations; the same issuer name with
	// another intermediate certificate says so.
	sectigo := newIssuer(t, "Sectigo Limited", "Sectigo DV")
	other := leafCert(t, sectigo, 60, "www.example.nl", "old.example.nl")
	if got := Diff(probe.Describe(old), probe.Describe(other), Intermediate{}, Intermediate{}); !strings.HasPrefix(got, "issuer Let's Encrypt R11 → Sectigo Limited Sectigo DV") {
		t.Fatalf("issuer: %s", got)
	}
	a, b := Intermediate{FP: strings.Repeat("a", 64), CN: "R11"}, Intermediate{FP: strings.Repeat("b", 64), CN: "R11"}
	if got := Diff(probe.Describe(old), probe.Describe(old), a, b); got != "intermediate R11 replaced (aaaaaaaa → bbbbbbbb)" {
		t.Fatalf("intermediate: %s", got)
	}
	if got := Diff(probe.Describe(old), probe.Describe(old), a, a); got != "re-issued with the same fields" {
		t.Fatalf("same: %s", got)
	}
}

// A renewal carries the diff, and one that drops a name is no longer an
// expected renewal.
func TestRenewalDiffAndDroppedName(t *testing.T) {
	le := newIssuer(t, "Let's Encrypt", "R11")
	old := leafCert(t, le, 20, "portal.example.nl", "www.example.nl")
	tg := manual
	tg.ServerName = "portal.example.nl"

	cur := leafCert(t, le, 89, "portal.example.nl", "www.example.nl", "api.example.nl")
	a := okAddr("192.0.2.1", cur, le.cert)
	a.HostnameChecked, a.HostnameOK = true, true
	o := Evaluate(tg, prevOf(old), result(a), now)
	if len(o.Events) != 1 || !strings.HasPrefix(o.Events[0].Details, "renewed by Let's Encrypt: SANs +api.example.nl; expires ") {
		t.Fatalf("renewal: %+v", o.Events)
	}

	// The renewal drops the name the target is checked under.
	cur = leafCert(t, le, 89, "www.example.nl")
	a = okAddr("192.0.2.1", cur, le.cert)
	o = Evaluate(tg, prevOf(old), result(a), now)
	f, ok := find(o.Open, CertificateChanged)
	if !ok || f.Severity != Warning || len(o.Events) != 0 || !strings.Contains(f.Details, "SANs −portal.example.nl") {
		t.Fatalf("dropped name: %+v events %v", f, o.Events)
	}
}
