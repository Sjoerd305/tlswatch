package check

import (
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

// testedAddr is an address whose configuration test reached a full
// verdict: version v negotiated, legacy versions and suite classes
// accepted as given.
func testedAddr(ip, v string, leaf *x509.Certificate, legacy []string, classes ...probe.SuiteClass) probe.Address {
	a := okAddr(ip, leaf)
	a.TLSVersion = v
	a.LegacyChecked, a.Legacy = true, legacy
	a.SuitesChecked, a.Suites = true, classes
	for _, c := range classes {
		a.SuiteNames = append(a.SuiteNames, "TLS_TEST_"+strings.ToUpper(string(c)))
	}
	return a
}

// rsaLeaf issues a leaf with an RSA key of bits, signed by iss with alg.
// The issuer signs, so no private key is needed: a key too small for Go to
// generate is made up as a random modulus, which is all a parser sees.
func rsaLeaf(t *testing.T, iss *ca, bits int, alg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()
	var pub *rsa.PublicKey
	if bits >= 1024 {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		pub = &key.PublicKey
	} else {
		n, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		pub = &rsa.PublicKey{N: n, E: 65537}
	}
	serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "rsa.example"}, DNSNames: []string{"rsa.example"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), SignatureAlgorithm: alg}
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

func TestGradeRules(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	leaf := leafCert(t, iss, 60, "a.example")
	cases := []struct {
		name   string
		addr   probe.Address
		grade  string
		reason string // a substring of one reason, "" for none
	}{
		{"modern server", testedAddr("192.0.2.1", "TLS 1.3", leaf, nil), GradeA, ""},
		{"TLS 1.2 without 1.3", testedAddr("192.0.2.1", "TLS 1.2", leaf, nil), GradeB, "no TLS 1.3"},
		{"no forward secrecy", testedAddr("192.0.2.1", "TLS 1.3", leaf, nil, probe.ClassNoPFS), GradeB, "no forward secrecy (TLS_TEST_NO_PFS)"},
		{"CBC with SHA-1", testedAddr("192.0.2.1", "TLS 1.3", leaf, nil, probe.ClassCBC), GradeB, "CBC with SHA-1"},
		{"legacy version next to 1.3", testedAddr("192.0.2.1", "TLS 1.3", leaf, []string{"TLS 1.0", "TLS 1.1"}), GradeC, "accepts TLS 1.0 and TLS 1.1"},
		{"3DES", testedAddr("192.0.2.1", "TLS 1.3", leaf, nil, probe.Class3DES), GradeC, "3DES"},
		{"RSA 1536 key", testedAddr("192.0.2.1", "TLS 1.3", rsaLeaf(t, iss, 1536, x509.ECDSAWithSHA256), nil), GradeC, "RSA key of 1536 bits"},
		{"SHA-1 signature", testedAddr("192.0.2.1", "TLS 1.3", rsaLeaf(t, iss, 2048, x509.ECDSAWithSHA1), nil), GradeC, "SHA-1"},
		{"RC4", testedAddr("192.0.2.1", "TLS 1.3", leaf, nil, probe.ClassRC4), GradeF, "RC4"},
		{"RSA 512 key", testedAddr("192.0.2.1", "TLS 1.3", rsaLeaf(t, iss, 512, x509.ECDSAWithSHA256), nil), GradeF, "RSA key of 512 bits"},
		{"speaks TLS 1.0 at most", testedAddr("192.0.2.1", "TLS 1.0", leaf, []string{"TLS 1.0"}), GradeF, "speaks TLS 1.0 at most"},
		{"SSL 3.0 next to 1.3", testedAddr("192.0.2.1", "TLS 1.3", leaf, []string{"SSL 3.0"}), GradeF, "accepts SSL 3.0"},
	}
	for _, c := range cases {
		o := Evaluate(manual, Previous{Open: open()}, result(c.addr), now)
		if !o.GradeChecked || o.Grade != c.grade || o.GradeRules != GradeRules {
			t.Errorf("%s: checked %v grade %q rules %d, want %s", c.name, o.GradeChecked, o.Grade, o.GradeRules, c.grade)
			continue
		}
		if c.reason == "" && len(o.GradeReasons) > 0 {
			t.Errorf("%s: reasons %v, want none", c.name, o.GradeReasons)
		}
		if c.reason != "" && !slices.ContainsFunc(o.GradeReasons, func(r string) bool { return strings.Contains(r, c.reason) }) {
			t.Errorf("%s: reasons %v lack %q", c.name, o.GradeReasons, c.reason)
		}
	}
}

func TestGradeLowestAddressCounts(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	leaf := leafCert(t, iss, 60, "a.example")
	o := Evaluate(manual, Previous{Open: open()}, result(
		testedAddr("192.0.2.1", "TLS 1.3", leaf, nil),
		testedAddr("192.0.2.2", "TLS 1.3", leaf, nil, probe.Class3DES),
		testedAddr("192.0.2.3", "TLS 1.2", leaf, nil)), now)
	if o.Grade != GradeC || len(o.AddressGrades) != 3 || o.AddressGrades[0].Grade != GradeA || o.AddressGrades[2].Grade != GradeB {
		t.Fatalf("grade %s addresses %+v", o.Grade, o.AddressGrades)
	}
	if len(o.GradeReasons) != 1 || !strings.Contains(o.GradeReasons[0], "3DES") {
		t.Fatalf("reasons %v, want the C address's only", o.GradeReasons)
	}
}

func TestWeakConfigurationFinding(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	leaf := leafCert(t, iss, 60, "a.example")
	skip := manual
	skip.SkipLegacy = true
	unchecked := testedAddr("192.0.2.2", "TLS 1.3", leaf, nil)
	unchecked.SuitesChecked = false
	cases := []struct {
		name    string
		tg      Target
		prev    Previous
		addrs   []probe.Address
		details string // "": not opened
		kept    bool
		graded  bool
	}{
		{"weak classes open it", manual, Previous{Open: open()},
			[]probe.Address{testedAddr("192.0.2.1", "TLS 1.3", leaf, nil, probe.Class3DES, probe.ClassNoPFS, probe.ClassCBC)},
			"3DES (TLS_TEST_3DES), no forward secrecy (TLS_TEST_NO_PFS) accepted", false, true},
		{"CBC alone does not", manual, Previous{Open: open()},
			[]probe.Address{testedAddr("192.0.2.1", "TLS 1.3", leaf, nil, probe.ClassCBC)}, "", false, true},
		{"one of two addresses", manual, Previous{Open: open()},
			[]probe.Address{testedAddr("192.0.2.1", "TLS 1.3", leaf, nil, probe.ClassRC4), testedAddr("192.0.2.2", "TLS 1.3", leaf, nil)},
			"RC4 (TLS_TEST_RC4) accepted on 192.0.2.1", false, true},
		{"refused resolves", manual, Previous{Open: open(WeakConfiguration)},
			[]probe.Address{testedAddr("192.0.2.1", "TLS 1.3", leaf, nil)}, "", false, true},
		{"not tested keeps", manual, Previous{Open: open(WeakConfiguration)},
			[]probe.Address{okAddr("192.0.2.1", leaf)}, "", true, false},
		{"no verdict on one address keeps and does not grade", manual, Previous{Open: open(WeakConfiguration)},
			[]probe.Address{testedAddr("192.0.2.1", "TLS 1.3", leaf, nil), unchecked}, "", true, false},
		{"switched off resolves", skip, Previous{Open: open(WeakConfiguration)},
			[]probe.Address{testedAddr("192.0.2.1", "TLS 1.3", leaf, nil, probe.ClassRC4)}, "", false, false},
	}
	for _, c := range cases {
		o := Evaluate(c.tg, c.prev, result(c.addrs...), now)
		f, opened := find(o.Open, WeakConfiguration)
		switch {
		case c.details != "" && (!opened || f.Severity != Warning || f.Details != c.details):
			t.Errorf("%s: %+v (opened %v), want warning %q", c.name, f, opened, c.details)
		case c.details == "" && opened:
			t.Errorf("%s: opened %q", c.name, f.Details)
		case slices.Contains(o.Keep, WeakConfiguration) != c.kept:
			t.Errorf("%s: kept %v, want %v", c.name, o.Keep, c.kept)
		case o.GradeChecked != c.graded:
			t.Errorf("%s: graded %v, want %v", c.name, o.GradeChecked, c.graded)
		}
	}
}

func TestGradeChangeIsAnEvent(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	leaf := leafCert(t, iss, 60, "a.example")
	o := Evaluate(manual, Previous{Open: open(), Grade: GradeA}, result(testedAddr("192.0.2.1", "TLS 1.3", leaf, nil, probe.Class3DES)), now)
	ev, found := find(o.Events, GradeChanged)
	if !found || ev.Severity != Info || !strings.HasPrefix(ev.Details, "grade A → C: accepts 3DES") {
		t.Fatalf("events %+v", o.Events)
	}
	if _, opened := find(o.Open, GradeChanged); opened {
		t.Fatal("grade_changed opened as a finding")
	}
	o = Evaluate(manual, Previous{Open: open(), Grade: GradeC}, result(testedAddr("192.0.2.1", "TLS 1.3", leaf, nil)), now)
	if ev, found = find(o.Events, GradeChanged); !found || ev.Details != "grade C → A" {
		t.Fatalf("improvement: events %+v", o.Events)
	}
	o = Evaluate(manual, Previous{Open: open(), Grade: GradeA}, result(testedAddr("192.0.2.1", "TLS 1.3", leaf, nil)), now)
	if _, found = find(o.Events, GradeChanged); found {
		t.Fatal("unchanged grade recorded as an event")
	}
}

// Post-quantum key exchange is a reason that never moves the letter; the
// target's state is "no" when any address says no, untested when one got
// no verdict and none said no.
func TestPostQuantumReason(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	leaf := leafCert(t, iss, 60, "a.example")
	pq := func(ip string, checked, yes bool) probe.Address {
		a := testedAddr(ip, "TLS 1.3", leaf, nil)
		a.PQChecked, a.PQ = checked, yes
		return a
	}
	o := Evaluate(manual, Previous{Open: open(), Grade: GradeA}, result(pq("192.0.2.1", true, false)), now)
	if o.Grade != GradeA || !slices.Equal(o.GradeReasons, []string{PQNoReason}) || o.PQ != PQNo || len(o.Events) != 0 {
		t.Fatalf("no PQ: %s %v %q %+v", o.Grade, o.GradeReasons, o.PQ, o.Events)
	}
	for _, c := range []struct {
		addrs []probe.Address
		want  string
	}{
		{[]probe.Address{pq("192.0.2.1", true, true), pq("192.0.2.2", true, true)}, PQYes},
		{[]probe.Address{pq("192.0.2.1", true, true), pq("192.0.2.2", false, false)}, PQUntested},
		{[]probe.Address{pq("192.0.2.1", false, false), pq("192.0.2.2", true, false)}, PQNo},
	} {
		if o := Evaluate(manual, Previous{Open: open()}, result(c.addrs...), now); o.PQ != c.want {
			t.Errorf("%+v: %q, want %q", c.addrs, o.PQ, c.want)
		}
	}
	// A drop names what lowered the grade, not the post-quantum note.
	a := pq("192.0.2.1", true, false)
	a.Suites, a.SuiteNames = []probe.SuiteClass{probe.Class3DES}, []string{"TLS_RSA_WITH_3DES_EDE_CBC_SHA"}
	o = Evaluate(manual, Previous{Open: open(), Grade: GradeA}, result(a), now)
	if ev, _ := find(o.Events, GradeChanged); strings.Contains(ev.Details, "post-quantum") || !strings.HasPrefix(ev.Details, "grade A → C: accepts 3DES") {
		t.Fatalf("drop: %q", ev.Details)
	}
}
