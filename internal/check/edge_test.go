package check

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
		ok   bool
	}{
		{"info", Info, true},
		{"warning", Warning, true},
		{"critical", Critical, true},
		{"", "", false},
		{"Warning", "", false},
		{"warn", "", false},
		{"crit", "", false},
		{" critical", "", false},
		{"fatal", "", false},
	}
	for _, c := range cases {
		got, ok := ParseSeverity(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseSeverity(%q) = %q %v, want %q %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestSeverityMeets(t *testing.T) {
	cases := []struct {
		s, floor Severity
		want     bool
	}{
		{Info, Info, true},
		{Info, Warning, false},
		{Info, Critical, false},
		{Warning, Info, true},
		{Warning, Warning, true},
		{Warning, Critical, false},
		{Critical, Info, true},
		{Critical, Warning, true},
		{Critical, Critical, true},
		{"", Info, false},
		{"bogus", Info, false},
	}
	for _, c := range cases {
		if got := c.s.Meets(c.floor); got != c.want {
			t.Errorf("%q.Meets(%q) = %v, want %v", c.s, c.floor, got, c.want)
		}
	}
	if !(Critical.Rank() > Warning.Rank() && Warning.Rank() > Info.Rank() && Info.Rank() > Severity("").Rank()) {
		t.Fatal("severity ranks out of order")
	}
}

func TestWorst(t *testing.T) {
	f := func(ss ...Severity) []Finding {
		var fs []Finding
		for _, s := range ss {
			fs = append(fs, Finding{Severity: s})
		}
		return fs
	}
	cases := []struct {
		fs   []Finding
		want Severity
	}{
		{nil, ""},
		{f(Info), Info},
		{f(Info, Warning, Info), Warning},
		{f(Warning, Critical, Info), Critical},
		{f(Critical, Warning), Critical},
		{f("bogus", Info), Info},
	}
	for i, c := range cases {
		if got := Worst(c.fs); got != c.want {
			t.Errorf("case %d: Worst = %q, want %q", i, got, c.want)
		}
	}
}

// leafUntil issues a leaf from iss that expires at notAfter exactly.
func leafUntil(t *testing.T, iss *ca, notAfter time.Time) *x509.Certificate {
	return sign(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "a.example"}, DNSNames: []string{"a.example"},
		NotBefore: now.Add(-60 * 24 * time.Hour), NotAfter: notAfter,
	}, iss).cert
}

// "A threshold fires when strictly fewer than N whole days remain, so
// 'warning 30' alerts on the first check that sees 29 days or less."
func TestExpiryThresholdBoundaries(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	day := 24 * time.Hour
	cases := []struct {
		name string
		left time.Duration
		kind Kind
		sev  Severity
		days int
	}{
		{"exactly 30 days", 30 * day, "", "", 30},
		{"a second under 30 days", 30*day - time.Second, Expiring, Warning, 29},
		{"exactly 7 days", 7 * day, Expiring, Warning, 7},
		{"a second under 7 days", 7*day - time.Second, Expiring, Critical, 6},
		{"a second left", time.Second, Expiring, Critical, 0},
		{"expires right now", 0, Expiring, Critical, 0},
		{"expired a second ago", -time.Second, Expired, Critical, -1},
		{"expired a day ago", -day, Expired, Critical, -1},
		{"expired a day and a second ago", -day - time.Second, Expired, Critical, -2},
	}
	for _, c := range cases {
		o := Evaluate(manual, Previous{Open: open()}, result(okAddr("192.0.2.1", leafUntil(t, iss, now.Add(c.left)))), now)
		if c.kind == "" {
			if len(o.Open) != 0 {
				t.Errorf("%s: opened %v", c.name, kindsOf(o.Open))
			}
			continue
		}
		f, ok := find(o.Open, c.kind)
		if !ok || f.Severity != c.sev || f.DaysLeft == nil || *f.DaysLeft != c.days || len(o.Open) != 1 {
			t.Errorf("%s: %+v (all %v), want only %s %s with %d days", c.name, f, kindsOf(o.Open), c.sev, c.kind, c.days)
		}
	}
}

// Day counting is about instants, not wall clocks: a check run from a
// server in another zone sees the same number of days.
func TestExpiryIgnoresTimeZones(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	ams := time.FixedZone("CEST", 2*3600)
	nyc := time.FixedZone("EDT", -4*3600)
	leaf := leafUntil(t, iss, now.Add(29*24*time.Hour+23*time.Hour).In(nyc))
	for _, at := range []time.Time{now, now.In(ams), now.In(nyc)} {
		o := Evaluate(manual, Previous{Open: open()}, result(okAddr("192.0.2.1", leaf)), at)
		f, ok := find(o.Open, Expiring)
		if !ok || *f.DaysLeft != 29 || f.Severity != Warning {
			t.Errorf("now in %s: %+v", at.Location(), o.Open)
		}
	}
}

// Per-target thresholds at the edges of their ranges.
func TestExpiryCustomThresholds(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	one, two, year := 1, 2, 365
	cases := []struct {
		name       string
		warn, crit *int
		days       int
		sev        Severity // "" for no finding
	}{
		{"warning 2, critical 1, 1 day left", &two, &one, 1, Warning},
		{"warning 2, critical 1, 0 days left", &two, &one, 0, Critical},
		{"warning 2, critical 1, 2 days left", &two, &one, 2, ""},
		{"warning 365, 364 days left", &year, nil, 364, Warning},
		{"warning 365, 365 days left", &year, nil, 365, ""},
	}
	for _, c := range cases {
		tg := manual
		tg.Warn, tg.Crit = c.warn, c.crit
		o := Evaluate(tg, Previous{Open: open()}, result(okAddr("192.0.2.1", leafCert(t, iss, c.days, "a.example"))), now)
		f, ok := find(o.Open, Expiring)
		switch {
		case c.sev == "" && ok:
			t.Errorf("%s: opened %+v", c.name, f)
		case c.sev != "" && (!ok || f.Severity != c.sev):
			t.Errorf("%s: %+v, want %s", c.name, o.Open, c.sev)
		}
	}
}

// An expired intermediate behind a valid leaf is expired, not expiring, and
// the details name the certificate that expired.
func TestExpiredIntermediate(t *testing.T) {
	root := newIssuer(t, "Test CA", "Test Root")
	inter := sign(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Old Intermediate", Organization: []string{"Test CA"}},
		IsCA:    true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: now.Add(-400 * 24 * time.Hour), NotAfter: now.Add(-24 * time.Hour),
	}, root)
	leaf := leafCert(t, inter, 60, "a.example")
	o := Evaluate(manual, Previous{Open: open()}, result(okAddr("192.0.2.1", leaf, inter.cert)), now)
	f, ok := find(o.Open, Expired)
	if !ok || !strings.Contains(f.Details, "Old Intermediate") || strings.Contains(f.Details, "a.example") {
		t.Fatalf("expired: %+v", o.Open)
	}
	if _, ok := find(o.Open, Expiring); ok {
		t.Fatal("expired and expiring both opened")
	}
	if o.Addresses["192.0.2.1"].Status != "critical" {
		t.Fatalf("address status %q", o.Addresses["192.0.2.1"].Status)
	}
}

// A certificate whose NotBefore lies in the future is refused by every TLS
// client, so it must not pass as healthy. probe.Verify judges trust apart
// from the validity window and check has no not-yet-valid finding, so
// nothing reports it.
func TestNotYetValidCertificateIsReported(t *testing.T) {
	root := newIssuer(t, "Test CA", "Test Root")
	leaf := sign(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "a.example"}, DNSNames: []string{"a.example"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:   now.Add(3 * 24 * time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
	}, root).cert
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	a := probe.Address{IP: "192.0.2.1", OK: true, Chain: []*x509.Certificate{leaf}}
	probe.Verify(&a, probe.Request{ServerName: "a.example", Trust: probe.TrustBundle, Roots: pool, Now: func() time.Time { return now }})

	tg := manual
	tg.Trust, tg.ServerName = probe.TrustBundle, "a.example"
	o := Evaluate(tg, Previous{Open: open()}, result(a), now)
	if len(o.Open) == 0 || o.Addresses["192.0.2.1"].Status == "ok" {
		t.Fatalf("certificate valid only from %s reported as healthy (verified %v): open %v",
			leaf.NotBefore.Format(time.DateOnly), a.Verified, kindsOf(o.Open))
	}
}

// selfSignedRSA is a self-signed CA with an RSA key of bits.
func selfSignedRSA(t *testing.T, bits int, alg x509.SignatureAlgorithm) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "RSA Root", Organization: []string{"Test CA"}},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour), SignatureAlgorithm: alg}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Skipf("cannot create %d-bit %s root: %v", bits, alg, err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// leafSignedBy issues an ECDSA leaf signed by an arbitrary parent key.
func leafSignedBy(t *testing.T, parent *x509.Certificate, key crypto.Signer, alg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "a.example"}, DNSNames: []string{"a.example"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), SignatureAlgorithm: alg}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.PublicKey, key)
	if err != nil {
		t.Skipf("cannot sign with %s: %v", alg, err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The root's own signature is never checked, so a SHA-1 self-signature on
// a presented root is fine; the root's key, however, signs the next
// certificate, and the spec's weak_signature covers "a chain certificate
// [that] has an RSA key under 2048 bits". The grade counts it ("an RSA key
// under 2048 bits anywhere in the chain"); weak_signature must too.
func TestWeakSignaturePresentedRoot(t *testing.T) {
	sha1Root, sha1Key := selfSignedRSA(t, 2048, x509.SHA1WithRSA)
	weakRoot, weakKey := selfSignedRSA(t, 1024, x509.SHA256WithRSA)
	cases := []struct {
		name  string
		chain []*x509.Certificate
		weak  bool
		grade string
	}{
		{"SHA-1 self-signature on a presented root", []*x509.Certificate{leafSignedBy(t, sha1Root, sha1Key, x509.SHA256WithRSA), sha1Root}, false, GradeA},
		{"SHA-1 signature on the leaf", []*x509.Certificate{leafSignedBy(t, sha1Root, sha1Key, x509.SHA1WithRSA), sha1Root}, true, GradeC},
		{"1024-bit key on a presented root", []*x509.Certificate{leafSignedBy(t, weakRoot, weakKey, x509.SHA256WithRSA), weakRoot}, true, GradeC},
	}
	for _, c := range cases {
		a := testedAddr("192.0.2.1", "TLS 1.3", c.chain[0], nil)
		a.Chain = c.chain
		o := Evaluate(manual, Previous{Open: open()}, result(a), now)
		if _, got := find(o.Open, WeakSignature); got != c.weak {
			t.Errorf("%s: weak_signature %v, want %v (open %v)", c.name, got, c.weak, kindsOf(o.Open))
		}
		if o.Grade != c.grade {
			t.Errorf("%s: grade %s %v, want %s", c.name, o.Grade, o.GradeReasons, c.grade)
		}
	}
}

// ecLeaf issues a leaf with an ECDSA key on curve, signed by iss.
func ecLeaf(t *testing.T, iss *ca, curve elliptic.Curve) *x509.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keyLeaf(t, iss, &k.PublicKey)
}

func keyLeaf(t *testing.T, iss *ca, pub any) *x509.Certificate {
	t.Helper()
	serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "k.example"}, DNSNames: []string{"k.example"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(60 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, iss.cert, pub, iss.key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGradeBoundaries(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	leaf := leafCert(t, iss, 60, "a.example")
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		addr  probe.Address
		grade string
		// reasons that must all be present
		reasons []string
	}{
		{"RSA 2048 is fine", testedAddr("192.0.2.1", "TLS 1.3", rsaLeaf(t, iss, 2048, x509.ECDSAWithSHA256), nil), GradeA, nil},
		{"RSA 1024 is C, not F", testedAddr("192.0.2.1", "TLS 1.3", rsaLeaf(t, iss, 1024, x509.ECDSAWithSHA256), nil), GradeC, []string{"RSA key of 1024 bits"}},
		{"RSA 1023 is F", testedAddr("192.0.2.1", "TLS 1.3", rsaLeaf(t, iss, 1023, x509.ECDSAWithSHA256), nil), GradeF, []string{"RSA key of 1023 bits"}},
		{"ECDSA P-224 is C", testedAddr("192.0.2.1", "TLS 1.3", ecLeaf(t, iss, elliptic.P224()), nil), GradeC, []string{"ECDSA key of 224 bits"}},
		{"ECDSA P-384 is fine", testedAddr("192.0.2.1", "TLS 1.3", ecLeaf(t, iss, elliptic.P384()), nil), GradeA, nil},
		{"Ed25519 is fine", testedAddr("192.0.2.1", "TLS 1.3", keyLeaf(t, iss, edPub), nil), GradeA, nil},
		{"speaks TLS 1.1 at most", testedAddr("192.0.2.1", "TLS 1.1", leaf, []string{"TLS 1.0", "TLS 1.1"}), GradeF, []string{"speaks TLS 1.1 at most"}},
		{"TLS 1.2 with legacy: C and both reasons", testedAddr("192.0.2.1", "TLS 1.2", leaf, []string{"TLS 1.1"}), GradeC, []string{"accepts TLS 1.1", "no TLS 1.3"}},
		{"several rules: the lowest wins, every reason kept", testedAddr("192.0.2.1", "TLS 1.2", leaf, nil, probe.ClassCBC, probe.Class3DES, probe.ClassRC4), GradeF,
			[]string{"no TLS 1.3", "CBC with SHA-1", "3DES", "RC4"}},
	}
	for _, c := range cases {
		o := Evaluate(manual, Previous{Open: open()}, result(c.addr), now)
		if o.Grade != c.grade {
			t.Errorf("%s: grade %q %v, want %s", c.name, o.Grade, o.GradeReasons, c.grade)
			continue
		}
		if len(c.reasons) == 0 && len(o.GradeReasons) != 0 {
			t.Errorf("%s: reasons %v, want none", c.name, o.GradeReasons)
		}
		for _, want := range c.reasons {
			if !slices.ContainsFunc(o.GradeReasons, func(r string) bool { return strings.Contains(r, want) }) {
				t.Errorf("%s: reasons %v lack %q", c.name, o.GradeReasons, want)
			}
		}
	}
}

// One address refusing STARTTLS while another answers: the answering one
// is checked normally and tls_unavailable opens for the other.
func TestSTARTTLSRefusedOnOneAddress(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	r := result(okAddr("192.0.2.1", leafCert(t, iss, 5, "a.example")), probe.Address{IP: "192.0.2.2", ErrorKind: probe.ErrStartTLS})
	o := Evaluate(manual, Previous{Open: open()}, r, now)
	if !slices.Equal(kindsOf(o.Open), []Kind{TLSUnavailable, Expiring}) {
		t.Fatalf("open %v", kindsOf(o.Open))
	}
	if f, _ := find(o.Open, TLSUnavailable); !strings.Contains(f.Details, "192.0.2.2") || strings.Contains(f.Details, "192.0.2.1") {
		t.Fatalf("details %q", f.Details)
	}
	if o.Addresses["192.0.2.2"].Status != "critical" || o.Addresses["192.0.2.1"].Status != "critical" || !o.Answered {
		t.Fatalf("addresses %+v", o.Addresses)
	}
}

// A partial outage (one address down, one up) is not unreachable: that
// needs every address to fail.
func TestPartialOutageIsNotUnreachable(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	tg := manual
	tg.Debounce = 1
	o := Evaluate(tg, Previous{FailStreak: 4, Open: open()}, result(failAddr("192.0.2.1"), okAddr("192.0.2.2", leafCert(t, iss, 60, "a.example"))), now)
	if len(o.Open) != 0 || o.FailStreak != 0 || o.Addresses["192.0.2.1"].Status != "error" {
		t.Fatalf("open %v streak %d addresses %+v", kindsOf(o.Open), o.FailStreak, o.Addresses)
	}
}

func TestDebounceSetting(t *testing.T) {
	down := result(failAddr("192.0.2.1"))
	cases := []struct {
		debounce, prevStreak int
		open                 bool
	}{
		{0, 0, true}, // an unset debounce behaves as 1
		{1, 0, true},
		{3, 1, false},
		{3, 2, true},
		{5, 3, false},
		{5, 4, true},
	}
	for _, c := range cases {
		o := Evaluate(Target{Debounce: c.debounce}, Previous{FailStreak: c.prevStreak, Open: open()}, down, now)
		_, got := find(o.Open, Unreachable)
		if got != c.open || o.FailStreak != c.prevStreak+1 {
			t.Errorf("debounce %d after %d failures: open %v streak %d, want %v", c.debounce, c.prevStreak, got, o.FailStreak, c.open)
		}
	}
}

// The unreachable details stay short on a name with many addresses.
func TestUnreachableSummary(t *testing.T) {
	var addrs []probe.Address
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"} {
		addrs = append(addrs, failAddr(ip))
	}
	o := Evaluate(Target{Debounce: 1}, Previous{Open: open()}, result(addrs...), now)
	f, ok := find(o.Open, Unreachable)
	if !ok || !strings.HasSuffix(f.Details, "and 2 more") || strings.Contains(f.Details, "192.0.2.4") {
		t.Fatalf("details %+v", f)
	}
	if !strings.Contains(o.Error, "192.0.2.5") {
		t.Fatalf("error %q lacks an address", o.Error)
	}
}

func TestKindLabels(t *testing.T) {
	for _, k := range Kinds {
		if k.Label() == "" || k.Short() == "" {
			t.Errorf("%s: label %q short %q", k, k.Label(), k.Short())
		}
	}
	if Expiring.Label() != "Expiring" || Unreachable.Label() != "Unreachable" {
		t.Errorf("default labels: %q %q", Expiring.Label(), Unreachable.Label())
	}
}

// Label is a template function (kindLabel) fed with stored strings; an
// empty kind must not panic the page.
func TestKindLabelEmptyDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Kind(\"\").Label() panicked: %v", r)
		}
	}()
	_ = Kind("").Label()
}

// A server that still sends an expired root after a valid chain (the old
// Let's Encrypt DST Root X3 case) is fine for clients: the chain ends in a
// valid root from the store. Only the root a verified chain ends in counts.
func TestStaleExpiredRootIsNotJudged(t *testing.T) {
	stale := sign(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Old Root", Organization: []string{"Old CA"}},
		IsCA:    true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: now.Add(-20 * 365 * 24 * time.Hour), NotAfter: now.Add(-24 * time.Hour),
	}, nil)
	root := newIssuer(t, "Test CA", "Test Root")
	leaf := leafCert(t, root, 60, "a.example")
	verify := func(chain []*x509.Certificate, anchor *x509.Certificate) Outcome {
		pool := x509.NewCertPool()
		pool.AddCert(anchor)
		a := probe.Address{IP: "192.0.2.1", OK: true, Chain: chain}
		probe.Verify(&a, probe.Request{ServerName: "a.example", Trust: probe.TrustBundle, Roots: pool, Now: func() time.Time { return now }})
		tg := manual
		tg.Trust, tg.ServerName = probe.TrustBundle, "a.example"
		return Evaluate(tg, Previous{Open: open()}, result(a), now)
	}

	o := verify([]*x509.Certificate{leaf, stale.cert}, root.cert)
	if len(o.Open) != 0 {
		t.Fatalf("stale root sent after a valid chain: open %v", kindsOf(o.Open))
	}

	// The same expired root as the anchor of the chain is expired.
	old := leafCert(t, stale, 60, "a.example")
	o = verify([]*x509.Certificate{old, stale.cert}, stale.cert)
	if _, ok := find(o.Open, Expired); !ok {
		t.Fatalf("expired anchor: open %v", kindsOf(o.Open))
	}
}
