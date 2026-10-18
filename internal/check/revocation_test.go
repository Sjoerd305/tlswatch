package check

import (
	"crypto/x509"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

func staple(t *testing.T, iss *ca, leaf *x509.Certificate, status int) []byte {
	t.Helper()
	tmpl := ocsp.Response{Status: status, SerialNumber: leaf.SerialNumber, ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(48 * time.Hour)}
	if status == ocsp.Revoked {
		tmpl.RevokedAt, tmpl.RevocationReason = day("2026-10-10"), ocsp.KeyCompromise
	}
	der, err := ocsp.CreateResponse(iss.cert, iss.cert, tmpl, iss.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// found returns the finding of kind k, nil when there is none.
func found(fs []Finding, k Kind) *Finding {
	if f, ok := find(fs, k); ok {
		return &f
	}
	return nil
}

func TestRevokedByCRL(t *testing.T) {
	iss := newIssuer(t, "Let's Encrypt", "R11")
	leaf := leafCert(t, iss, 60, "portal.example.nl")
	fp := probe.Fingerprint(leaf)
	tg := manual
	r := result(okAddr("192.0.2.1", leaf, iss.cert))

	prev := Previous{Open: map[Kind]bool{}, LeafFP: fp, CRL: map[string]CRLStatus{
		fp: {URL: "http://r11.c.lencr.org/7.crl", Revoked: true, RevokedAt: day("2026-10-10"), Reason: "key compromise"}}}
	out := Evaluate(tg, prev, r, now)
	f := found(out.Open, Revoked)
	if f == nil || f.Severity != Critical || f.Fingerprint != fp ||
		f.Details != "revoked 2026-10-10 (key compromise), listed in the CRL at http://r11.c.lencr.org/7.crl" {
		t.Fatalf("revoked: %+v", f)
	}

	// The CRL drops the entry (the leaf expired, or a CA tidied up): the
	// revocation is a fact about the leaf and stays while it is served.
	prev = Previous{Open: map[Kind]bool{Revoked: true}, LeafFP: fp, RevokedFP: fp, CRL: map[string]CRLStatus{fp: {URL: "u"}}}
	if out := Evaluate(tg, prev, r, now); !slices.Contains(out.Keep, Revoked) {
		t.Fatalf("not kept: %+v", out)
	}

	// A different leaf resolves it.
	next := leafCert(t, iss, 90, "portal.example.nl")
	out = Evaluate(tg, prev, result(okAddr("192.0.2.1", next, iss.cert)), now)
	if slices.Contains(out.Keep, Revoked) || found(out.Open, Revoked) != nil {
		t.Fatalf("still open on a new leaf: %+v", out)
	}
}

func TestRevocationUnknown(t *testing.T) {
	iss := newIssuer(t, "Example", "Example CA")
	leaf := leafCert(t, iss, 60, "portal.example.nl")
	fp := probe.Fingerprint(leaf)
	tg := manual
	r := result(okAddr("192.0.2.1", leaf, iss.cert))

	prev := Previous{Open: map[Kind]bool{}, CRL: map[string]CRLStatus{fp: {URL: "http://crl.example.nl/ca.crl", Unknown: "the server answered 404 Not Found"}}}
	f := found(Evaluate(tg, prev, r, now).Open, RevocationUnknown)
	if f == nil || f.Severity != Info || !strings.Contains(f.Details, "could not be checked for 3 days: the server answered 404") {
		t.Fatalf("unknown: %+v", f)
	}
	if !RevocationUnknown.Silent() || Revoked.Silent() {
		t.Fatal("only revocation_unknown is silent")
	}
	// No CRL at all is normal and records nothing.
	if out := Evaluate(tg, Previous{Open: map[Kind]bool{}}, r, now); found(out.Open, RevocationUnknown) != nil || found(out.Open, Revoked) != nil {
		t.Fatalf("no CRL: %+v", out.Open)
	}
}

func TestStapledOCSP(t *testing.T) {
	iss := newIssuer(t, "Example", "Example CA")
	leaf := leafCert(t, iss, 60, "portal.example.nl")
	tg := manual

	a := okAddr("192.0.2.1", leaf, iss.cert)
	a.OCSP = staple(t, iss, leaf, ocsp.Revoked)
	if s := probe.StapleOf(a); s.Status != probe.StapleRevoked {
		t.Fatalf("staple: %+v", s)
	}
	f := found(Evaluate(tg, Previous{Open: map[Kind]bool{}}, result(a), now).Open, Revoked)
	if f == nil || f.Details != "revoked 2026-10-10 (key compromise), says the OCSP response stapled on 192.0.2.1" {
		t.Fatalf("stapled revoked: %+v", f)
	}

	// A response signed by another CA is not believed.
	other := newIssuer(t, "Other", "Other CA")
	a.OCSP = staple(t, other, leaf, ocsp.Revoked)
	if s := probe.StapleOf(a); s.Status != probe.StapleInvalid {
		t.Fatalf("foreign staple: %+v", s)
	}
	if found(Evaluate(tg, Previous{Open: map[Kind]bool{}}, result(a), now).Open, Revoked) != nil {
		t.Fatal("a foreign staple opened revoked")
	}

	// A good staple is a grade reason that does not lower the grade.
	g := testedAddr("192.0.2.1", "TLS 1.3", leaf, nil)
	g.Chain = []*x509.Certificate{leaf, iss.cert}
	g.OCSP = staple(t, iss, leaf, ocsp.Good)
	ag := gradeAddress(g)
	if ag.Grade != GradeA || !slices.Equal(ag.Reasons, []string{StapledReason}) {
		t.Fatalf("grade: %+v", ag)
	}
}

func TestStapleUnreadable(t *testing.T) {
	iss := newIssuer(t, "Example", "Example CA")
	leaf := leafCert(t, iss, 60, "portal.example.nl")
	a := okAddr("192.0.2.1", leaf, iss.cert)
	if s := probe.StapleOf(a); s.Status != "" {
		t.Fatalf("nothing stapled: %+v", s)
	}
	a.OCSP = []byte("not DER")
	if s := probe.StapleOf(a); s.Status != probe.StapleInvalid {
		t.Fatalf("garbage: %+v", s)
	}
	// Without the issuer in the chain nothing can be verified.
	a = okAddr("192.0.2.1", leaf)
	a.OCSP = staple(t, iss, leaf, ocsp.Good)
	if s := probe.StapleOf(a); s.Status != probe.StapleInvalid {
		t.Fatalf("no issuer: %+v", s)
	}
}
