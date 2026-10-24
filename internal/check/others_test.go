package check

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

var rsaKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

// rsaOther is an RSA leaf for name valid for days more days (negative:
// expired that long ago).
func rsaOther(t *testing.T, iss *ca, days int, name string) *x509.Certificate {
	t.Helper()
	serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: now.Add(-60 * 24 * time.Hour), NotAfter: now.Add(time.Duration(days)*24*time.Hour + time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, iss.cert, &rsaKey.PublicKey, iss.key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// withOthers is a fully tested address that also serves the given chains.
func withOthers(ip string, leaf *x509.Certificate, others ...probe.OtherChain) probe.Address {
	a := testedAddr(ip, "TLS 1.3", leaf, nil)
	a.OthersChecked, a.Others = true, others
	return a
}

func other(via string, leaf *x509.Certificate, hostnameOK bool) probe.OtherChain {
	return probe.OtherChain{Via: via, Chain: []*x509.Certificate{leaf}, Verified: true, HostnameChecked: true, HostnameOK: hostnameOK}
}

func TestOtherCertificates(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	leaf := leafCert(t, iss, 60, "a.example")
	named := manual
	named.ServerName = "a.example"
	skip := named
	skip.SkipLegacy = true
	unchecked := withOthers("192.0.2.2", leaf)
	unchecked.OthersChecked = false
	cases := []struct {
		name     string
		tg       Target
		prev     Previous
		addrs    []probe.Address
		kind     Kind
		sev      Severity // "": not opened
		details  []string
		kept     bool
		problems int // problems listed on the first address's first other certificate, -1 for none listed
	}{
		{"expired alternate is critical", named, Previous{Open: open()},
			[]probe.Address{withOthers("192.0.2.1", leaf, other(probe.ViaOtherKey, rsaOther(t, iss, -3, "a.example"), true))},
			AlternateCertificate, Critical, []string{"RSA certificate a.example (", "a.example expired"}, false, 1},
		{"alternate within the critical threshold", named, Previous{Open: open()},
			[]probe.Address{withOthers("192.0.2.1", leaf, other(probe.ViaOtherKey, rsaOther(t, iss, 5, "a.example"), true))},
			AlternateCertificate, Critical, []string{"left"}, false, 1},
		{"alternate within the warning threshold", named, Previous{Open: open()},
			[]probe.Address{withOthers("192.0.2.1", leaf, other(probe.ViaOtherKey, rsaOther(t, iss, 20, "a.example"), true))},
			AlternateCertificate, Warning, nil, false, 1},
		{"alternate for another name", named, Previous{Open: open()},
			[]probe.Address{withOthers("192.0.2.1", leaf, other(probe.ViaOtherKey, rsaOther(t, iss, 60, "b.example"), false))},
			AlternateCertificate, Critical, []string{"a.example is not covered by b.example"}, false, 1},
		{"valid alternate opens nothing and is listed", named, Previous{Open: open(AlternateCertificate)},
			[]probe.Address{withOthers("192.0.2.1", leaf, other(probe.ViaOtherKey, rsaOther(t, iss, 60, "a.example"), true))},
			AlternateCertificate, "", nil, false, 0},
		{"alternate on one of two addresses", named, Previous{Open: open()},
			[]probe.Address{withOthers("192.0.2.1", leaf, other(probe.ViaOtherKey, rsaOther(t, iss, -3, "a.example"), true)), withOthers("192.0.2.2", leaf)},
			AlternateCertificate, Critical, []string{"on 192.0.2.1"}, false, 1},
		{"expired default certificate is info", named, Previous{Open: open()},
			[]probe.Address{withOthers("192.0.2.1", leaf, other(probe.ViaNoSNI, rsaOther(t, iss, -30, "old.example"), false))},
			DefaultCertificate, Info, []string{"without SNI, old.example (", "old.example expired", "a.example is not covered by old.example"}, false, 2},
		{"default certificate expiring soon is not judged", named, Previous{Open: open()},
			[]probe.Address{withOthers("192.0.2.1", leaf, other(probe.ViaNoSNI, rsaOther(t, iss, 3, "a.example"), true))},
			DefaultCertificate, "", nil, false, 0},
		{"not tested keeps", named, Previous{Open: open(AlternateCertificate)},
			[]probe.Address{testedAddr("192.0.2.1", "TLS 1.3", leaf, nil)}, AlternateCertificate, "", nil, true, -1},
		{"no verdict on one address keeps", named, Previous{Open: open(AlternateCertificate)},
			[]probe.Address{withOthers("192.0.2.1", leaf), unchecked}, AlternateCertificate, "", nil, true, -1},
		{"switched off resolves", skip, Previous{Open: open(AlternateCertificate)},
			[]probe.Address{withOthers("192.0.2.1", leaf, other(probe.ViaOtherKey, rsaOther(t, iss, -3, "a.example"), true))},
			AlternateCertificate, "", nil, false, -1},
	}
	for _, c := range cases {
		o := Evaluate(c.tg, c.prev, result(c.addrs...), now)
		f, opened := find(o.Open, c.kind)
		switch {
		case opened != (c.sev != ""):
			t.Errorf("%s: opened %v %+v", c.name, opened, f)
		case opened && f.Severity != c.sev:
			t.Errorf("%s: severity %s, want %s (%s)", c.name, f.Severity, c.sev, f.Details)
		case slices.Contains(o.Keep, c.kind) != c.kept:
			t.Errorf("%s: kept %v, want %v", c.name, slices.Contains(o.Keep, c.kind), c.kept)
		}
		for _, want := range c.details {
			if !strings.Contains(f.Details, want) {
				t.Errorf("%s: details %q lack %q", c.name, f.Details, want)
			}
		}
		listed := -1
		if len(o.AddressGrades) > 0 && len(o.AddressGrades[0].Others) > 0 {
			listed = len(o.AddressGrades[0].Others[0].Problems)
		}
		if listed != c.problems {
			t.Errorf("%s: %d problems listed, want %d (%+v)", c.name, listed, c.problems, o.AddressGrades)
		}
	}
}

// The default certificate is never alerted, the alternate one is.
func TestOtherCertificateKindsSilence(t *testing.T) {
	if !DefaultCertificate.Silent() || AlternateCertificate.Silent() || MustStaple.Silent() {
		t.Fatal("silence of the new kinds")
	}
	for _, k := range []Kind{MustStaple, AlternateCertificate, DefaultCertificate} {
		if !slices.Contains(Kinds, k) || k.Label() == string(k) || k.Short() == string(k) {
			t.Errorf("%s: listed %v label %q short %q", k, slices.Contains(Kinds, k), k.Label(), k.Short())
		}
	}
}

func mustStapleCert(t *testing.T, iss *ca) *x509.Certificate {
	t.Helper()
	val, err := asn1.Marshal([]int{5})
	if err != nil {
		t.Fatal(err)
	}
	return sign(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "a.example"}, DNSNames: []string{"a.example"},
		NotAfter:        now.Add(60 * 24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}, Value: val}},
	}, iss).cert
}

func goodStaple(t *testing.T, iss *ca, leaf *x509.Certificate, status int, next time.Time) []byte {
	t.Helper()
	der, err := ocsp.CreateResponse(iss.cert, iss.cert, ocsp.Response{Status: status, SerialNumber: leaf.SerialNumber,
		ThisUpdate: now.Add(-48 * time.Hour), NextUpdate: next}, iss.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestMustStapleFinding(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	ms := mustStapleCert(t, iss)
	plain := leafCert(t, iss, 60, "a.example")
	addr := func(leaf *x509.Certificate, ocspDER []byte) probe.Address {
		a := okAddr("192.0.2.1", leaf, iss.cert)
		a.OCSP = ocspDER
		return a
	}
	cases := []struct {
		name string
		addr probe.Address
		want string // "": no finding
	}{
		{"no staple", addr(ms, nil), "the server sent none"},
		{"unreadable staple", addr(ms, []byte{0x30, 0x00}), "not valid for this certificate"},
		{"stale staple", addr(ms, goodStaple(t, iss, ms, ocsp.Good, now.Add(-time.Hour))), "the stapled response expired"},
		{"unknown to the responder", addr(ms, goodStaple(t, iss, ms, ocsp.Unknown, now.Add(24*time.Hour))), "unknown to the responder"},
		{"good staple", addr(ms, goodStaple(t, iss, ms, ocsp.Good, now.Add(24*time.Hour))), ""},
		{"good staple without NextUpdate", addr(ms, goodStaple(t, iss, ms, ocsp.Good, time.Time{})), ""},
		{"no must-staple, no staple", addr(plain, nil), ""},
	}
	for _, c := range cases {
		o := Evaluate(manual, Previous{Open: open()}, result(c.addr), now)
		f, opened := find(o.Open, MustStaple)
		switch {
		case opened != (c.want != ""):
			t.Errorf("%s: opened %v %q", c.name, opened, f.Details)
		case opened && (f.Severity != Critical || !strings.Contains(f.Details, c.want) || !strings.Contains(f.Details, "Firefox")):
			t.Errorf("%s: %s %q, want %q", c.name, f.Severity, f.Details, c.want)
		case opened && o.Addresses["192.0.2.1"].Status != "critical":
			t.Errorf("%s: address status %s", c.name, o.Addresses["192.0.2.1"].Status)
		}
	}
}
