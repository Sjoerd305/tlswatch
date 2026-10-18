package check

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

func anchorOf(c *x509.Certificate) Anchor {
	spki := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return Anchor{Name: c.Subject.CommonName, SPKI: hex.EncodeToString(spki[:]), SKI: hex.EncodeToString(c.SubjectKeyId)}
}

// sctExtension is an embedded SCT list with one SCT logged at t.
func sctExtension(t *testing.T, at time.Time) pkix.Extension {
	sct := make([]byte, 47) // version 0, log ID, timestamp, no extensions, then a stub signature
	binary.BigEndian.PutUint64(sct[33:41], uint64(at.UnixMilli()))
	list := binary.BigEndian.AppendUint16(nil, uint16(2+len(sct)))
	list = binary.BigEndian.AppendUint16(list, uint16(len(sct)))
	list = append(list, sct...)
	v, err := asn1.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: sctOID, Value: v}
}

// withDistrusts swaps the table for one test.
func withDistrusts(t *testing.T, evs ...DistrustEvent) {
	old := Distrusts
	Distrusts = evs
	t.Cleanup(func() { Distrusts = old })
}

func day(s string) time.Time {
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return d
}

func TestDistrustedCA(t *testing.T) {
	root := newIssuer(t, "Old CA", "Old Root CA")
	inter := sign(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Old Issuing CA", Organization: []string{"Old CA"}},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotAfter: now.Add(3 * 365 * 24 * time.Hour)}, root)
	// leaf is issued on nb, with an SCT logged at sct (none when zero).
	leaf := func(nb, sct time.Time, life time.Duration) *x509.Certificate {
		tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "a.example"}, DNSNames: []string{"a.example"}, NotBefore: nb, NotAfter: nb.Add(life)}
		if !sct.IsZero() {
			tmpl.ExtraExtensions = []pkix.Extension{sctExtension(t, sct)}
		}
		return sign(t, tmpl, inter).cert
	}
	cutoff := day("2026-07-31")
	byNotBefore := DistrustEvent{CA: "Old CA", Program: "Mozilla", Anchors: []Anchor{anchorOf(root.cert)}, IssuedAfter: cutoff, Effective: day("2026-08-01")}
	bySCT := byNotBefore
	bySCT.Program, bySCT.BySCT = "Chrome", true
	ahead := byNotBefore
	ahead.Effective = day("2027-01-15")
	removal := DistrustEvent{CA: "Old CA", Program: "Mozilla", Anchors: []Anchor{anchorOf(root.cert)}, Effective: day("2027-01-15")}
	year := 365 * 24 * time.Hour

	for _, tc := range []struct {
		name    string
		ev      DistrustEvent
		leaf    *x509.Certificate
		chain   string // "full": leaf, intermediate, root; "served": the root left out
		want    Severity
		details string
	}{
		{"issued after the cutoff", byNotBefore, leaf(day("2026-08-10"), time.Time{}, year), "full", Critical,
			"chain roots in Old Root CA; Mozilla distrusts certificates from it issued after 31 Jul 2026; this one was issued 10 Aug 2026"},
		{"issued before the cutoff", byNotBefore, leaf(day("2026-07-01"), time.Time{}, year), "full", "", ""},
		{"root left out: matched through the intermediate", byNotBefore, leaf(day("2026-08-10"), time.Time{}, year), "served", Critical, "chain roots in Old Root CA"},
		{"ahead: a warning", ahead, leaf(day("2026-08-10"), time.Time{}, year), "full", Warning,
			"Mozilla will distrust certificates from it issued after 31 Jul 2026, from 15 Jan 2027"},
		{"expires before it takes effect", ahead, leaf(day("2026-08-10"), time.Time{}, 90*24*time.Hour), "full", "", ""},
		{"Chrome judges the SCT", bySCT, leaf(day("2026-08-10"), day("2026-07-30"), year), "full", "", ""},
		{"an SCT after the cutoff", bySCT, leaf(day("2026-07-30"), day("2026-08-02"), year), "full", Critical, "Chrome distrusts"},
		{"no SCT: NotBefore", bySCT, leaf(day("2026-08-10"), time.Time{}, year), "full", Critical, "Chrome distrusts"},
		{"removal ahead", removal, leaf(day("2025-01-10"), time.Time{}, 3*year), "full", Warning,
			"chain roots in Old Root CA; Mozilla stops trusting it on 15 Jan 2027"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withDistrusts(t, tc.ev)
			a := okAddr("192.0.2.1", tc.leaf, inter.cert)
			if tc.chain == "full" {
				a.VerifiedChain = []*x509.Certificate{tc.leaf, inter.cert, root.cert}
			}
			o := Evaluate(manual, Previous{Open: open()}, result(a), now)
			f, ok := find(o.Open, DistrustedCA)
			if tc.want == "" {
				if ok {
					t.Fatalf("opened: %+v", f)
				}
				return
			}
			if !ok || f.Severity != tc.want || !strings.Contains(f.Details, tc.details) {
				t.Fatalf("distrusted_ca %v: %+v", ok, f)
			}
		})
	}

	// A private PKI is in no root program.
	withDistrusts(t, byNotBefore)
	l := leaf(day("2026-08-10"), time.Time{}, year)
	bundle := manual
	bundle.Trust = probe.TrustBundle
	if f, ok := find(Evaluate(bundle, Previous{Open: open()}, result(okAddr("192.0.2.1", l, inter.cert)), now).Open, DistrustedCA); ok {
		t.Fatalf("bundle target: %+v", f)
	}
	// Another chain resolves it: nothing keeps it open.
	other := newIssuer(t, "New CA", "New Root CA")
	o := Evaluate(manual, prevOf(l, DistrustedCA), result(okAddr("192.0.2.1", leafCert(t, other, 90, "a.example"))), now)
	if _, ok := find(o.Open, DistrustedCA); ok || slices.Contains(o.Keep, DistrustedCA) {
		t.Fatal("distrusted_ca survived a new chain")
	}
}

func TestEarliestSCT(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	at := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	c := sign(t, &x509.Certificate{Subject: pkix.Name{CommonName: "a.example"}, NotAfter: now.Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{sctExtension(t, at)}}, iss).cert
	if got, ok := EarliestSCT(c); !ok || !got.Equal(at) {
		t.Fatalf("EarliestSCT = %v %v", got, ok)
	}
	if _, ok := EarliestSCT(leafCert(t, iss, 30, "a.example")); ok {
		t.Fatal("an SCT in a certificate without one")
	}
}

// Every row of the shipped table is complete: a known program, a link to
// the announcement, anchors, and a cutoff no later than the date it takes
// effect.
func TestDistrustTable(t *testing.T) {
	if len(Distrusts) == 0 {
		t.Fatal("empty table")
	}
	for _, ev := range Distrusts {
		name := ev.CA + " " + ev.Program + " " + ev.Effective.Format("2006-01-02")
		if !slices.Contains([]string{"Chrome", "Mozilla", "Apple", "Microsoft"}, ev.Program) || ev.CA == "" || ev.Description == "" {
			t.Errorf("%s: incomplete", name)
		}
		if !strings.HasPrefix(ev.Link, "https://") || len(ev.Anchors) == 0 || ev.Effective.IsZero() {
			t.Errorf("%s: no link, anchors or date", name)
		}
		if ev.IssuedAfter.After(ev.Effective) {
			t.Errorf("%s: cutoff %v is after %v", name, ev.IssuedAfter, ev.Effective)
		}
		for _, a := range ev.Anchors {
			if len(a.SPKI) != 64 || a.SKI == "" || a.Name == "" {
				t.Errorf("%s: anchor %+v", name, a)
			}
		}
	}
}

// A server that sends a newer root cross-signed by a removed one is
// anchored in the newer root by a program that trusts it, as
// www.swisssign.com is (SwissSign RSA TLS Root CA 2022 - 1 under Gold CA -
// G2); a program without a list of its roots still judges the anchor.
func TestDistrustCrossSign(t *testing.T) {
	old := newIssuer(t, "Old CA", "Old Root CA")
	newer := sign(t, &x509.Certificate{Subject: pkix.Name{CommonName: "New Root CA", Organization: []string{"Old CA"}},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotAfter: now.Add(5 * 365 * 24 * time.Hour)}, nil)
	// The cross-sign: the new root's key and subject, issued by the old root.
	cross := sign(t, &x509.Certificate{Subject: newer.cert.Subject, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotAfter: now.Add(4 * 365 * 24 * time.Hour)}, old)
	cross = &ca{cert: reissue(t, cross.cert, newer.key, old), key: newer.key}
	leaf := sign(t, &x509.Certificate{Subject: pkix.Name{CommonName: "a.example"}, DNSNames: []string{"a.example"}, NotAfter: now.Add(200 * 24 * time.Hour)}, cross).cert

	removal := func(program string) DistrustEvent {
		return DistrustEvent{CA: "Old CA", Program: program, Anchors: []Anchor{anchorOf(old.cert)}, Effective: now.Add(-24 * time.Hour)}
	}
	saved := programRoots["Chrome"]
	programRoots["Chrome"] = map[string]bool{anchorOf(newer.cert).SPKI: true}
	t.Cleanup(func() { programRoots["Chrome"] = saved })

	chain, verified := []*x509.Certificate{leaf, cross.cert, old.cert}, []*x509.Certificate{leaf, cross.cert, old.cert}
	withDistrusts(t, removal("Chrome"))
	if hits := Distrusted(chain, verified); len(hits) != 0 {
		t.Fatalf("Chrome trusts the newer root: %+v", hits)
	}
	withDistrusts(t, removal("Apple"))
	if hits := Distrusted(chain, verified); len(hits) != 1 {
		t.Fatalf("Apple: %+v", hits)
	}
}

// reissue signs a certificate for key's public key with the template of c,
// issued by parent: sign generates a fresh key, a cross-sign keeps one.
func reissue(t *testing.T, c *x509.Certificate, key *ecdsa.PrivateKey, parent *ca) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, c, parent.cert, key.Public(), parent.key)
	if err != nil {
		t.Fatal(err)
	}
	out, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
