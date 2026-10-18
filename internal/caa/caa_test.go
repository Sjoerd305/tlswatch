package caa

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestLookupClimbs(t *testing.T) {
	r := Static{"example.nl": {{Tag: "issue", Value: "letsencrypt.org"}}, "shop.example.nl": {{Tag: "issue", Value: "sectigo.com"}}}
	ctx := context.Background()
	for name, want := range map[string]string{"a.b.example.nl": "example.nl", "*.example.nl": "example.nl", "x.shop.example.nl": "shop.example.nl", "example.com": ""} {
		s, err := Lookup(ctx, r, name)
		if err != nil || s.Name != want {
			t.Errorf("%s: found at %q, want %q (%v)", name, s.Name, want, err)
		}
	}
}

func TestPermits(t *testing.T) {
	le := []string{"letsencrypt.org"}
	set := func(recs ...Record) Set { return Set{Name: "example.nl", Records: recs} }
	for _, c := range []struct {
		name     string
		set      Set
		wildcard bool
		ok       bool
		why      string
	}{
		{"no record", Set{}, false, true, ""},
		{"only iodef", set(Record{Tag: "iodef", Value: "mailto:x@example.nl"}), false, true, ""},
		{"allowed with parameters", set(Record{Tag: "issue", Value: "letsencrypt.org; validationmethods=dns-01"}), false, true, ""},
		{"case and trailing dot", set(Record{Tag: "ISSUE", Value: "LetsEncrypt.org."}), false, true, ""},
		{"another CA", set(Record{Tag: "issue", Value: "pki.goog"}), false, false, "allows only pki.goog"},
		{"none", set(Record{Tag: "issue", Value: ";"}), false, false, `allows no CA (issue ";")`},
		{"wildcard falls back to issue", set(Record{Tag: "issue", Value: "letsencrypt.org"}), true, true, ""},
		{"issuewild wins for a wildcard", set(Record{Tag: "issue", Value: "letsencrypt.org"}, Record{Tag: "issuewild", Value: "pki.goog"}), true, false, "allows only pki.goog"},
		{"issuewild does not matter otherwise", set(Record{Tag: "issue", Value: "letsencrypt.org"}, Record{Tag: "issuewild", Value: ";"}), false, true, ""},
		{"issuewild alone leaves names open", set(Record{Tag: "issuewild", Value: ";"}), false, true, ""},
		{"unknown critical", set(Record{Flags: 128, Tag: "tbs", Value: "x"}), false, false, "critical property"},
		{"unknown not critical", set(Record{Tag: "tbs", Value: "x"}, Record{Tag: "issue", Value: "letsencrypt.org"}), false, true, ""},
	} {
		ok, why := Permits(c.set, le, c.wildcard)
		if ok != c.ok || !strings.Contains(why, c.why) {
			t.Errorf("%s: %v %q", c.name, ok, why)
		}
	}
}

func TestIdentifiers(t *testing.T) {
	for _, c := range []struct{ org, cn, want string }{
		{"Let's Encrypt", "R11", "letsencrypt.org"},
		{"Google Trust Services", "WR1", "pki.goog"},
		{"Sectigo Limited", "Sectigo RSA DV", "sectigo.com"},
		{"ZeroSSL", "ZeroSSL RSA Domain Secure Site CA", "zerossl.com"},
		{"DigiCert Inc", "DigiCert Global G2 TLS RSA SHA256 2020 CA1", "digicert.com"},
		{"", "RapidSSL TLS RSA CA G1", "rapidssl.com"},
	} {
		if ids := Identifiers(c.org, c.cn); !slices.Contains(ids, c.want) {
			t.Errorf("%s / %s: %v", c.org, c.cn, ids)
		}
	}
	if Identifiers("Nobody", "Nobody CA") != nil {
		t.Error("an unknown CA got identifiers")
	}
}

// dnsServer answers CAA queries over UDP from answers; a name in fail gets
// SERVFAIL, any other NXDOMAIN.
func dnsServer(t *testing.T, answers map[string][]Record, fail map[string]bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			name := strings.TrimSuffix(q.Name.String(), ".")
			rh := dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true}
			recs, known := answers[name]
			switch {
			case fail[name]:
				rh.RCode = dnsmessage.RCodeServerFailure
			case !known:
				rh.RCode = dnsmessage.RCodeNameError
			}
			b := dnsmessage.NewBuilder(nil, rh)
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			// A CNAME first, as a resolver following one answers.
			_ = b.CNAMEResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60},
				dnsmessage.CNAMEResource{CNAME: q.Name})
			for _, r := range recs {
				_ = b.UnknownResource(dnsmessage.ResourceHeader{Name: q.Name, Type: TypeCAA, Class: dnsmessage.ClassINET, TTL: 60},
					dnsmessage.UnknownResource{Type: TypeCAA, Data: encode(r)})
			}
			out, _ := b.Finish()
			_, _ = pc.WriteTo(out, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestSystemResolver(t *testing.T) {
	srv := dnsServer(t, map[string][]Record{
		"example.nl": {{Tag: "issue", Value: "letsencrypt.org"}, {Flags: 128, Tag: "iodef", Value: "mailto:ops@example.nl"}},
		"empty.nl":   nil,
	}, map[string]bool{"broken.nl": true})
	r := System{Servers: []string{srv}, Timeout: 2 * time.Second}
	ctx := context.Background()
	recs, err := r.CAA(ctx, "example.nl")
	if err != nil || len(recs) != 2 || recs[0] != (Record{Tag: "issue", Value: "letsencrypt.org"}) || !recs[1].Critical() {
		t.Fatalf("records: %+v %v", recs, err)
	}
	if recs, err := r.CAA(ctx, "empty.nl"); err != nil || len(recs) != 0 {
		t.Fatalf("empty: %+v %v", recs, err)
	}
	if recs, err := r.CAA(ctx, "missing.nl"); err != nil || len(recs) != 0 {
		t.Fatalf("NXDOMAIN: %+v %v", recs, err)
	}
	if _, err := r.CAA(ctx, "broken.nl"); err == nil || !strings.Contains(err.Error(), "ServerFailure") {
		t.Fatalf("SERVFAIL: %v", err)
	}
	s, err := Lookup(ctx, r, "www.example.nl")
	if err != nil || s.Name != "example.nl" || !slices.Equal(s.Lines(), []string{`0 issue "letsencrypt.org"`, `128 iodef "mailto:ops@example.nl"`}) {
		t.Fatalf("lookup: %+v %v", s, err)
	}
}
