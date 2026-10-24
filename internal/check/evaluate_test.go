package check

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

var now = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial int64 = 100

// sign issues a certificate from tmpl, signed by parent or self-signed.
func sign(t *testing.T, tmpl *x509.Certificate, parent *ca) *ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	tmpl.SerialNumber = big.NewInt(serial)
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = now.Add(-30 * 24 * time.Hour)
	}
	signer, parentCert := key, tmpl
	if parent != nil {
		signer, parentCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &ca{c, key}
}

func newIssuer(t *testing.T, org, cn string) *ca {
	return sign(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: cn, Organization: []string{org}},
		IsCA:    true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotAfter: now.Add(5 * 365 * 24 * time.Hour),
	}, nil)
}

// leafCert issues a leaf valid for days more days (plus an hour, so DaysLeft
// is exactly days).
func leafCert(t *testing.T, iss *ca, days int, sans ...string) *x509.Certificate {
	return sign(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: sans[0]},
		DNSNames: sans,
		NotAfter: now.Add(time.Duration(days)*24*time.Hour + time.Hour),
	}, iss).cert
}

func okAddr(ip string, chain ...*x509.Certificate) probe.Address {
	return probe.Address{IP: ip, OK: true, Chain: chain, Verified: true}
}

func failAddr(ip string) probe.Address {
	return probe.Address{IP: ip, ErrorKind: probe.ErrConnect, Error: "timed out"}
}

func result(addrs ...probe.Address) probe.Result { return probe.Result{Addresses: addrs} }

func open(kinds ...Kind) map[Kind]bool {
	m := map[Kind]bool{}
	for _, k := range kinds {
		m[k] = true
	}
	return m
}

// prevOf is the state left by a check that saw leaf.
func prevOf(leaf *x509.Certificate, kinds ...Kind) Previous {
	i := probe.Describe(leaf)
	return Previous{LeafFP: i.Fingerprint, IssuerOrg: i.IssuerOrg, IssuerCN: i.IssuerCN, SANs: i.SANs, Leaf: &i, Open: open(kinds...)}
}

func find(fs []Finding, k Kind) (Finding, bool) {
	for _, f := range fs {
		if f.Kind == k {
			return f, true
		}
	}
	return Finding{}, false
}

func kindsOf(fs []Finding) []Kind {
	var ks []Kind
	for _, f := range fs {
		ks = append(ks, f.Kind)
	}
	return ks
}

var manual = Target{Debounce: 2, Manual: Thresholds{Warn: 30, Crit: 7}, Managed: Thresholds{Warn: 10, Crit: 3}}

func TestCurrentLeafIsTheMajority(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	a := leafCert(t, iss, 60, "a.example")
	b := leafCert(t, iss, 80, "a.example")
	o := Evaluate(manual, Previous{Open: open()}, result(okAddr("192.0.2.1", a), okAddr("192.0.2.2", b), okAddr("192.0.2.3", a)), now)
	if o.LeafFP != probe.Fingerprint(a) {
		t.Fatalf("current leaf %s, want the one two addresses serve", o.LeafFP[:8])
	}
	if f, ok := find(o.Open, Inconsistent); !ok || f.Severity != Warning {
		t.Fatalf("no inconsistent warning: %v", kindsOf(o.Open))
	}
	if !o.Answered || o.Addresses["192.0.2.2"].LeafFP != probe.Fingerprint(b) || o.Addresses["192.0.2.2"].Status != "ok" {
		t.Fatalf("addresses: %+v", o.Addresses)
	}
}

func TestCurrentLeafTieGoesToLatestExpiry(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	stale := leafCert(t, iss, 40, "a.example")
	fresh := leafCert(t, iss, 80, "a.example")
	o := Evaluate(manual, Previous{Open: open()}, result(okAddr("192.0.2.1", stale), okAddr("192.0.2.2", fresh)), now)
	if o.LeafFP != probe.Fingerprint(fresh) {
		t.Fatal("a stale node became current")
	}
}

func TestThresholds(t *testing.T) {
	acme := newIssuer(t, "Let's Encrypt", "R11")
	other := newIssuer(t, "Sectigo Limited", "Sectigo DV")
	five := 5
	cases := []struct {
		name    string
		tg      Target
		iss     *ca
		managed bool
		want    Thresholds
	}{
		{"ACME issuer is managed", manual, acme, true, Thresholds{Warn: 10, Crit: 3}},
		{"other issuer is manual", manual, other, false, Thresholds{Warn: 30, Crit: 7}},
		{"explicit flag wins over issuer", Target{Manual: Thresholds{Warn: 30, Crit: 7}, Managed: Thresholds{Warn: 10, Crit: 3}, RenewalSet: true}, acme, false, Thresholds{Warn: 30, Crit: 7}},
		{"explicit managed", Target{Manual: Thresholds{Warn: 30, Crit: 7}, Managed: Thresholds{Warn: 10, Crit: 3}, RenewalSet: true, RenewalManaged: true}, other, true, Thresholds{Warn: 10, Crit: 3}},
		{"per-target override", Target{Manual: Thresholds{Warn: 30, Crit: 7}, Managed: Thresholds{Warn: 10, Crit: 3}, Crit: &five}, other, false, Thresholds{Warn: 30, Crit: 5}},
	}
	for _, c := range cases {
		o := Evaluate(c.tg, Previous{Open: open()}, result(okAddr("192.0.2.1", leafCert(t, c.iss, 60, "a.example"))), now)
		if o.RenewalManaged != c.managed || o.Thresholds != c.want {
			t.Errorf("%s: managed %v thresholds %+v, want %v %+v", c.name, o.RenewalManaged, o.Thresholds, c.managed, c.want)
		}
	}
}

func TestExpiry(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	cases := []struct {
		days int
		kind Kind
		sev  Severity
	}{
		{60, "", ""},
		{30, "", ""},
		{29, Expiring, Warning},
		{7, Expiring, Warning},
		{6, Expiring, Critical},
		{-1, Expired, Critical},
	}
	for _, c := range cases {
		o := Evaluate(manual, Previous{Open: open()}, result(okAddr("192.0.2.1", leafCert(t, iss, c.days, "a.example"))), now)
		ks := kindsOf(o.Open)
		if c.kind == "" {
			if len(ks) != 0 {
				t.Errorf("%d days: %v", c.days, ks)
			}
			continue
		}
		f, ok := find(o.Open, c.kind)
		if !ok || f.Severity != c.sev || len(ks) != 1 {
			t.Errorf("%d days: %v, want only %s %s", c.days, ks, c.sev, c.kind)
		}
	}
}

func TestExpiryCountsTheWholeChain(t *testing.T) {
	root := newIssuer(t, "Test CA", "Test Root")
	inter := sign(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Test Intermediate", Organization: []string{"Test CA"}},
		IsCA:    true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotAfter: now.Add(10*24*time.Hour + time.Hour),
	}, root)
	leaf := leafCert(t, inter, 60, "a.example")
	o := Evaluate(manual, Previous{Open: open()}, result(okAddr("192.0.2.1", leaf, inter.cert)), now)
	if !o.NotAfter.Equal(inter.cert.NotAfter) {
		t.Fatalf("NotAfter %v, want the intermediate's", o.NotAfter)
	}
	if f, ok := find(o.Open, Expiring); !ok || *f.DaysLeft != 10 {
		t.Fatalf("expiring: %+v", o.Open)
	}
}

func TestFactsMergeToTheWorstAddress(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	o := Evaluate(manual, Previous{Open: open()}, result(
		okAddr("192.0.2.1", leafCert(t, iss, 20, "a.example")),
		okAddr("192.0.2.2", leafCert(t, iss, 5, "a.example")),
		okAddr("192.0.2.3", leafCert(t, iss, 25, "a.example")),
	), now)
	f, ok := find(o.Open, Expiring)
	if !ok || f.Severity != Critical || *f.DaysLeft != 5 {
		t.Fatalf("expiring: %+v", f)
	}
	if o.Addresses["192.0.2.1"].Status != "warning" || o.Addresses["192.0.2.2"].Status != "critical" {
		t.Fatalf("addresses: %+v", o.Addresses)
	}
}

func TestTrustFindings(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	self := sign(t, &x509.Certificate{Subject: pkix.Name{CommonName: "a.example"}, DNSNames: []string{"a.example"}, NotAfter: now.Add(400 * 24 * time.Hour)}, nil).cert

	untrusted := okAddr("192.0.2.1", leafCert(t, iss, 60, "a.example"))
	untrusted.Verified, untrusted.VerifyError = false, "unknown authority"
	selfAddr := okAddr("192.0.2.1", self)
	selfAddr.Verified = false
	mismatch := okAddr("192.0.2.1", leafCert(t, iss, 60, "b.example"))
	mismatch.HostnameChecked = true

	pinned := manual
	pinned.Trust = probe.TrustSelfSigned
	cases := []struct {
		name string
		tg   Target
		a    probe.Address
		want []Kind
	}{
		{"untrusted chain", manual, untrusted, []Kind{ChainUntrusted}},
		{"self-signed on system trust", manual, selfAddr, []Kind{SelfSigned}},
		{"self-signed trust mode", pinned, selfAddr, nil},
		{"hostname mismatch", manual, mismatch, []Kind{HostnameMismatch}},
	}
	for _, c := range cases {
		o := Evaluate(c.tg, Previous{Open: open()}, result(c.a), now)
		if got := kindsOf(o.Open); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestUnreachableDebounce(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	down := result(failAddr("192.0.2.1"))
	up := result(okAddr("192.0.2.1", leafCert(t, iss, 60, "a.example")))

	o := Evaluate(manual, Previous{OkStreak: 5, Open: open(Expiring)}, down, now)
	if !slices.Equal(o.Waiting, []Kind{Unreachable}) {
		t.Fatalf("waiting: %v", o.Waiting)
	}
	if len(o.Open) != 0 || o.FailStreak != 1 || o.OkStreak != 0 || o.Answered {
		t.Fatalf("first failure: open %v streaks %d/%d", kindsOf(o.Open), o.FailStreak, o.OkStreak)
	}
	if !slices.Equal(o.Keep, []Kind{Expiring}) {
		t.Fatalf("certificate findings not kept while nothing was read: %v", o.Keep)
	}
	o = Evaluate(manual, Previous{FailStreak: 1, Open: open()}, down, now)
	if !slices.Equal(kindsOf(o.Open), []Kind{Unreachable}) {
		t.Fatalf("second failure: %v", kindsOf(o.Open))
	}
	// Once open, every further failure keeps it open.
	o = Evaluate(Target{Debounce: 5}, Previous{FailStreak: 1, Open: open(Unreachable)}, down, now)
	if !slices.Equal(kindsOf(o.Open), []Kind{Unreachable}) {
		t.Fatalf("open finding not renewed: %v", kindsOf(o.Open))
	}

	o = Evaluate(manual, Previous{FailStreak: 3, Open: open(Unreachable)}, up, now)
	if !slices.Contains(o.Keep, Unreachable) || o.OkStreak != 1 || o.FailStreak != 0 {
		t.Fatalf("first success: keep %v streaks %d/%d", o.Keep, o.FailStreak, o.OkStreak)
	}
	o = Evaluate(manual, Previous{OkStreak: 1, Open: open(Unreachable)}, up, now)
	if slices.Contains(o.Keep, Unreachable) {
		t.Fatal("second success kept unreachable open")
	}
}

func TestDNSRecovery(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	up := result(okAddr("192.0.2.1", leafCert(t, iss, 60, "a.example")))

	o := Evaluate(manual, Previous{FailStreak: 2, OkStreak: 4, DNSOk: 7, Open: open()}, probe.Result{DNSError: "no such host"}, now)
	if o.DNSFail != 1 || o.DNSOk != 0 || o.FailStreak != 2 || o.OkStreak != 4 {
		t.Fatalf("DNS failure streaks: dns %d/%d net %d/%d", o.DNSFail, o.DNSOk, o.FailStreak, o.OkStreak)
	}
	o = Evaluate(manual, Previous{DNSFail: 3, Open: open(DNSFailed)}, up, now)
	if !slices.Contains(o.Keep, DNSFailed) || o.DNSOk != 1 || o.DNSFail != 0 {
		t.Fatalf("first resolution: keep %v dns %d/%d", o.Keep, o.DNSFail, o.DNSOk)
	}
	o = Evaluate(manual, Previous{DNSOk: 1, Open: open(DNSFailed)}, up, now)
	if slices.Contains(o.Keep, DNSFailed) {
		t.Fatal("second resolution kept dns_failed open")
	}
}

func TestSTARTTLSRefusalKeepsStreaks(t *testing.T) {
	r := result(probe.Address{IP: "192.0.2.1", ErrorKind: probe.ErrStartTLS}, failAddr("192.0.2.2"))
	o := Evaluate(manual, Previous{FailStreak: 1, OkStreak: 3, Open: open(Unreachable, Expiring)}, r, now)
	if !slices.Equal(kindsOf(o.Open), []Kind{TLSUnavailable}) {
		t.Fatalf("open: %v", kindsOf(o.Open))
	}
	if o.FailStreak != 1 || o.OkStreak != 3 || !slices.Contains(o.Keep, Unreachable) || !slices.Contains(o.Keep, Expiring) {
		t.Fatalf("streaks %d/%d keep %v", o.FailStreak, o.OkStreak, o.Keep)
	}
}

func TestManagedRenewalIsAnEvent(t *testing.T) {
	le := newIssuer(t, "Let's Encrypt", "R11")
	old := leafCert(t, le, 20, "a.example")
	renewed := leafCert(t, le, 89, "a.example", "www.a.example")
	o := Evaluate(manual, prevOf(old), result(okAddr("192.0.2.1", renewed)), now)
	if len(o.Open) != 0 {
		t.Fatalf("renewal opened %v", kindsOf(o.Open))
	}
	if len(o.Events) != 1 || o.Events[0].Kind != CertificateChanged || o.Events[0].Severity != Info {
		t.Fatalf("events: %+v", o.Events)
	}
}

func TestManagedRenewalLosingSANsIsAWarning(t *testing.T) {
	le := newIssuer(t, "Let's Encrypt", "R11")
	old := leafCert(t, le, 20, "a.example", "www.a.example")
	o := Evaluate(manual, prevOf(old), result(okAddr("192.0.2.1", leafCert(t, le, 89, "a.example"))), now)
	if f, ok := find(o.Open, CertificateChanged); !ok || f.Severity != Warning || len(o.Events) != 0 {
		t.Fatalf("open %v events %v", kindsOf(o.Open), kindsOf(o.Events))
	}
}

func TestManualChangeIsAWarning(t *testing.T) {
	iss := newIssuer(t, "Sectigo Limited", "Sectigo DV")
	old := leafCert(t, iss, 20, "a.example")
	o := Evaluate(manual, prevOf(old), result(okAddr("192.0.2.1", leafCert(t, iss, 365, "a.example"))), now)
	if !slices.Equal(kindsOf(o.Open), []Kind{CertificateChanged}) {
		t.Fatalf("open: %v", kindsOf(o.Open))
	}
}

func TestIssuerChange(t *testing.T) {
	old := leafCert(t, newIssuer(t, "Let's Encrypt", "R11"), 20, "a.example")
	cur := leafCert(t, newIssuer(t, "Sectigo Limited", "Sectigo DV"), 365, "a.example")
	o := Evaluate(manual, prevOf(old), result(okAddr("192.0.2.1", cur)), now)
	if !slices.Equal(kindsOf(o.Open), []Kind{CertificateChanged, IssuerChanged}) {
		t.Fatalf("open: %v", kindsOf(o.Open))
	}
}

func TestUnchangedLeafKeepsChangeFindings(t *testing.T) {
	iss := newIssuer(t, "Sectigo Limited", "Sectigo DV")
	leaf := leafCert(t, iss, 365, "a.example")
	o := Evaluate(manual, prevOf(leaf, CertificateChanged, IssuerChanged), result(okAddr("192.0.2.1", leaf)), now)
	if len(o.Open) != 0 || !slices.Contains(o.Keep, CertificateChanged) || !slices.Contains(o.Keep, IssuerChanged) {
		t.Fatalf("open %v keep %v", kindsOf(o.Open), o.Keep)
	}
}

// A routine renewal resolves an open change finding: it needs no
// acknowledgement.
func TestRenewalResolvesChange(t *testing.T) {
	le := newIssuer(t, "Let's Encrypt", "R11")
	old := leafCert(t, le, 20, "a.example")
	o := Evaluate(manual, prevOf(old, CertificateChanged, IssuerChanged), result(okAddr("192.0.2.1", leafCert(t, le, 89, "a.example"))), now)
	if len(o.Events) != 1 || len(o.Open) != 0 {
		t.Fatalf("open %v events %v", kindsOf(o.Open), kindsOf(o.Events))
	}
	if slices.Contains(o.Keep, CertificateChanged) || slices.Contains(o.Keep, IssuerChanged) {
		t.Fatalf("change findings kept after a renewal: %v", o.Keep)
	}
}

// A new leaf that is not an automatic renewal leaves an open issuer change
// open, so whoever acknowledges the new leaf still sees the issuer moved.
func TestManualChangeKeepsIssuerChange(t *testing.T) {
	iss := newIssuer(t, "Sectigo Limited", "Sectigo DV")
	old := leafCert(t, iss, 300, "a.example")
	o := Evaluate(manual, prevOf(old, CertificateChanged, IssuerChanged), result(okAddr("192.0.2.1", leafCert(t, iss, 365, "a.example"))), now)
	if !slices.Equal(kindsOf(o.Open), []Kind{CertificateChanged}) || !slices.Equal(o.Keep, []Kind{IssuerChanged}) {
		t.Fatalf("open %v keep %v", kindsOf(o.Open), o.Keep)
	}
}

// A different self-signed certificate never resolves the pin warning.
func TestSelfSignedChangeStaysOpen(t *testing.T) {
	mk := func() *x509.Certificate {
		return sign(t, &x509.Certificate{Subject: pkix.Name{CommonName: "a.example"}, DNSNames: []string{"a.example"}, NotAfter: now.Add(400 * 24 * time.Hour)}, nil).cert
	}
	pinned, other := mk(), mk()
	tg := manual
	tg.Trust, tg.PinnedFP = probe.TrustSelfSigned, probe.Fingerprint(pinned)
	o := Evaluate(tg, prevOf(pinned, CertificateChanged), result(okAddr("192.0.2.1", pinned)), now)
	if !slices.Equal(o.Keep, []Kind{CertificateChanged}) {
		t.Fatalf("pin restored: keep %v", o.Keep)
	}
	o = Evaluate(tg, prevOf(other, CertificateChanged), result(okAddr("192.0.2.1", mk())), now)
	if !slices.Equal(kindsOf(o.Open), []Kind{CertificateChanged}) {
		t.Fatalf("another replacement: open %v", kindsOf(o.Open))
	}
}

func TestExpectedIssuerIsAState(t *testing.T) {
	iss := newIssuer(t, "Sectigo Limited", "Sectigo DV")
	leaf := leafCert(t, iss, 365, "a.example")
	tg := manual
	tg.ExpectedIssuer = "digicert"
	o := Evaluate(tg, prevOf(leaf), result(okAddr("192.0.2.1", leaf)), now)
	if f, ok := find(o.Open, IssuerChanged); !ok || f.Severity != Warning {
		t.Fatalf("open: %v", kindsOf(o.Open))
	}
	// Matching again resolves it without an acknowledgement.
	tg.ExpectedIssuer = "sectigo"
	o = Evaluate(tg, prevOf(leaf, IssuerChanged), result(okAddr("192.0.2.1", leaf)), now)
	if len(o.Open) != 0 || slices.Contains(o.Keep, IssuerChanged) {
		t.Fatalf("open %v keep %v", kindsOf(o.Open), o.Keep)
	}
}

func TestSelfSignedPin(t *testing.T) {
	mk := func() *x509.Certificate {
		return sign(t, &x509.Certificate{Subject: pkix.Name{CommonName: "a.example"}, DNSNames: []string{"a.example"}, NotAfter: now.Add(400 * 24 * time.Hour)}, nil).cert
	}
	first, second := mk(), mk()
	tg := manual
	tg.Trust = probe.TrustSelfSigned

	o := Evaluate(tg, Previous{Open: open()}, result(okAddr("192.0.2.1", first)), now)
	if o.PinFP != probe.Fingerprint(first) || len(o.Open) != 0 {
		t.Fatalf("first sight: pin %q open %v", o.PinFP, kindsOf(o.Open))
	}
	tg.PinnedFP = o.PinFP
	o = Evaluate(tg, prevOf(first), result(okAddr("192.0.2.1", first)), now)
	if o.PinFP != "" || len(o.Open) != 0 {
		t.Fatalf("pinned and unchanged: pin %q open %v", o.PinFP, kindsOf(o.Open))
	}
	o = Evaluate(tg, prevOf(first), result(okAddr("192.0.2.1", second)), now)
	if !slices.Equal(kindsOf(o.Open), []Kind{CertificateChanged}) {
		t.Fatalf("pin replaced: %v", kindsOf(o.Open))
	}
}

func legacyAddr(ip string, leaf *x509.Certificate, checked bool, versions ...string) probe.Address {
	a := okAddr(ip, leaf)
	a.LegacyChecked, a.Legacy = checked, versions
	return a
}

func TestLegacyProtocol(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	leaf := leafCert(t, iss, 60, "a.example")
	skip := manual
	skip.SkipLegacy = true
	cases := []struct {
		name    string
		tg      Target
		prev    Previous
		addrs   []probe.Address
		details string // "": no legacy_protocol opened
		kept    bool
		checked bool
	}{
		{"both accepted", manual, Previous{Open: open()},
			[]probe.Address{legacyAddr("192.0.2.1", leaf, true, "TLS 1.0", "TLS 1.1")}, "TLS 1.0, TLS 1.1 accepted", false, true},
		{"SSL 3.0 named first", manual, Previous{Open: open()},
			[]probe.Address{legacyAddr("192.0.2.1", leaf, true, "TLS 1.0", "SSL 3.0")}, "SSL 3.0, TLS 1.0 accepted", false, true},
		{"one of two addresses", manual, Previous{Open: open()},
			[]probe.Address{legacyAddr("192.0.2.1", leaf, true, "TLS 1.0"), legacyAddr("192.0.2.2", leaf, true)}, "TLS 1.0 accepted on 192.0.2.1", false, true},
		{"refused resolves", manual, Previous{Open: open(LegacyProtocol)},
			[]probe.Address{legacyAddr("192.0.2.1", leaf, true)}, "", false, true},
		{"not tested this check keeps", manual, Previous{Open: open(LegacyProtocol)},
			[]probe.Address{okAddr("192.0.2.1", leaf)}, "", true, false},
		{"no verdict on one address keeps", manual, Previous{Open: open(LegacyProtocol)},
			[]probe.Address{legacyAddr("192.0.2.1", leaf, true), legacyAddr("192.0.2.2", leaf, false)}, "", true, false},
		{"switched off resolves", skip, Previous{Open: open(LegacyProtocol)},
			[]probe.Address{legacyAddr("192.0.2.1", leaf, true, "TLS 1.0")}, "", false, false},
	}
	for _, c := range cases {
		o := Evaluate(c.tg, c.prev, result(c.addrs...), now)
		f, opened := find(o.Open, LegacyProtocol)
		switch {
		case c.details != "" && (!opened || f.Severity != Warning || f.Details != c.details):
			t.Errorf("%s: %+v (opened %v), want warning %q", c.name, f, opened, c.details)
		case c.details == "" && opened:
			t.Errorf("%s: opened %q", c.name, f.Details)
		case slices.Contains(o.Keep, LegacyProtocol) != c.kept:
			t.Errorf("%s: kept %v, want %v", c.name, o.Keep, c.kept)
		case o.LegacyChecked != c.checked:
			t.Errorf("%s: checked %v, want %v", c.name, o.LegacyChecked, c.checked)
		}
	}
}

func TestLegacyKeptWhenNothingAnswered(t *testing.T) {
	o := Evaluate(manual, Previous{Open: open(LegacyProtocol)}, result(failAddr("192.0.2.1")), now)
	if !slices.Contains(o.Keep, LegacyProtocol) {
		t.Fatalf("legacy_protocol resolved by an unreachable check: keep %v", o.Keep)
	}
}
