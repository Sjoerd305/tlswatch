package core

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// count runs a COUNT query.
func (e *env) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.svc.DB.R.QueryRowContext(e.ctx, q, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
	return n
}

// untrusted is a probe of one address whose chain did not verify.
func untrusted(ip string, chain ...*x509.Certificate) probe.Address {
	a := served(ip, chain...)
	a.Verified, a.VerifyError = false, "x509: certificate signed by unknown authority"
	return a
}

// An acknowledgement suppresses reminders, never the escalation or the
// recovery notice (Alerting, 2, 4 and 5).
func TestAckDoesNotSuppressEscalationOrRecovery(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	c := ca.leaf(t, now.Add(-days(300)), now.Add(days(20)+time.Hour), "portal.example.nl")
	e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	e.flush()
	if m := e.take("mail"); len(m) != 1 {
		t.Fatalf("open alert: %+v", m)
	}
	f := e.open(tg.ID)[check.Expiring]
	if _, err := e.svc.Acknowledge(e.ctx, f.ID, "Alex", time.Time{}, "renewal ordered"); err != nil {
		t.Fatal(err)
	}
	if f, _ = e.svc.Finding(e.ctx, f.ID); !f.Open() || !f.Acked(e.clock.Now()) {
		t.Fatalf("acknowledging expiring resolved it or did not record it: %+v", f)
	}

	// Into the critical window: the escalation goes out despite the ack.
	e.clock.Add(days(14))
	e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	if got := e.open(tg.ID)[check.Expiring]; got.ID != f.ID || got.Severity != check.Critical {
		t.Fatalf("escalated finding: %+v (was %d)", got, f.ID)
	}
	e.flush()
	if m := e.take("mail"); len(m) != 1 || !strings.Contains(m[0].Subject, "escalated") {
		t.Fatalf("escalation on mail: %+v", m)
	}
	if m := e.take("telegram"); len(m) != 1 || !strings.HasPrefix(m[0].Subject, "[critical]") {
		t.Fatalf("escalation on telegram: %+v", m)
	}
	// The acknowledgement was for the warning: the critical is reminded.
	if got, _ := e.svc.Finding(e.ctx, f.ID); got.Acked(e.clock.Now()) {
		t.Fatalf("still acknowledged after escalating: %+v", got)
	}

	// Renewed: the recovery notice reaches both channels.
	c2 := ca.leaf(t, e.clock.Now(), e.clock.Now().Add(days(365)), "portal.example.nl")
	e.apply(tg.ID, result(served("192.0.2.1", c2, ca.cert)))
	e.flush()
	if m := e.take("telegram"); len(m) != 1 || !strings.Contains(m[0].Subject+m[0].Body, "resolved") {
		t.Fatalf("recovery on telegram: %+v", m)
	}
	if m := e.take("mail"); len(m) != 1 || !strings.Contains(m[0].Body, "expiring resolved") {
		t.Fatalf("recovery on mail: %+v", m)
	}
}

// A snooze ends on its date and the reminders resume; Unacknowledge ends it
// at once. An until date in the past is refused.
func TestSnoozeAndUnacknowledge(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	c := ca.leaf(t, now.Add(-days(300)), now.Add(days(25)), "portal.example.nl")
	e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	e.flush()
	e.take("mail")
	f := e.open(tg.ID)[check.Expiring]

	if _, err := e.svc.Acknowledge(e.ctx, f.ID, "Alex", e.clock.Now().Add(-time.Minute), ""); err == nil {
		t.Fatal("an until date in the past was accepted")
	}
	if _, err := e.svc.Acknowledge(e.ctx, f.ID, "Alex", e.clock.Now().Add(days(9)), "snooze"); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(days(8)) // past the 7-day warning reminder, inside the snooze
	if n, _ := e.svc.Remind(e.ctx); n != 0 {
		t.Fatalf("snoozed finding reminded: %d", n)
	}
	e.clock.Add(days(1) + time.Hour) // the snooze has passed
	if n, _ := e.svc.Remind(e.ctx); n != 1 {
		t.Fatalf("reminders after the snooze: %d, want 1 (mail)", n)
	}
	e.flush()
	if m := e.take("mail"); len(m) != 1 || !strings.Contains(m[0].Subject, "still open since") {
		t.Fatalf("reminder: %+v", m)
	}

	// Acknowledge again, then take it back: reminders resume on schedule.
	if _, err := e.svc.Acknowledge(e.ctx, f.ID, "Alex", time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Unacknowledge(e.ctx, f.ID); err != nil {
		t.Fatal(err)
	}
	if f, _ = e.svc.Finding(e.ctx, f.ID); f.Acked(e.clock.Now()) || f.AckBy != "" {
		t.Fatalf("unacknowledged finding: %+v", f)
	}
	e.clock.Add(days(7) + time.Hour)
	if n, _ := e.svc.Remind(e.ctx); n != 1 {
		t.Fatalf("reminders after unacknowledge: %d", n)
	}
	if err := e.svc.Unacknowledge(e.ctx, 99999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unacknowledge of an unknown finding: %v", err)
	}
}

// A problem that comes back after it resolved opens a new finding with a
// new alert; the old one stays resolved.
func TestResolvedFindingReopensAsNew(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	c := ca.leaf(t, now.Add(-days(10)), now.Add(days(300)), "portal.example.nl")
	e.apply(tg.ID, result(untrusted("192.0.2.1", c)))
	first := e.open(tg.ID)[check.ChainUntrusted]
	if first.ID == 0 || first.Severity != check.Critical {
		t.Fatalf("chain_untrusted: %+v", e.open(tg.ID))
	}
	e.flush()
	e.take("mail")
	e.take("telegram")
	e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	if len(e.open(tg.ID)) != 0 {
		t.Fatalf("not resolved: %v", e.open(tg.ID))
	}
	e.flush()
	if m := e.take("telegram"); len(m) != 1 || !strings.HasPrefix(m[0].Subject, "[resolved]") {
		t.Fatalf("recovery: %+v", m)
	}
	e.apply(tg.ID, result(untrusted("192.0.2.1", c)))
	again := e.open(tg.ID)[check.ChainUntrusted]
	if again.ID == 0 || again.ID == first.ID {
		t.Fatalf("reopened as %d, first was %d", again.ID, first.ID)
	}
	if old, _ := e.svc.Finding(e.ctx, first.ID); old.Open() {
		t.Fatal("the old finding was reopened")
	}
	e.flush()
	if m := e.take("telegram"); len(m) != 1 || strings.Contains(m[0].Subject, "resolved") {
		t.Fatalf("second open alert: %+v", m)
	}
}

// On an ACME target an issuer change stays open until an automatic renewal
// by the new issuer confirms the certificate is back on its cycle; that
// renewal resolves both change findings without an acknowledgement.
func TestIssuerChangeResolvedByNextRenewal(t *testing.T) {
	e := newEnv(t)
	le, gts := newCA(t, "Let's Encrypt"), newCA(t, "Google Trust Services")
	now := e.clock.Now()
	tg := e.target(func(t *Target) { t.RenewalSet = false })
	e.apply(tg.ID, result(served("192.0.2.1", le.leaf(t, now.Add(-days(30)), now.Add(days(60)), "portal.example.nl"), le.cert)))
	e.apply(tg.ID, result(served("192.0.2.1", gts.leaf(t, now, now.Add(days(90)), "portal.example.nl"), gts.cert)))
	open := e.open(tg.ID)
	if open[check.IssuerChanged].ID == 0 || open[check.CertificateChanged].Severity != check.Warning {
		t.Fatalf("after the CA change: %v", open)
	}
	// Still the same next check: they stay open.
	tgt, _ := e.svc.Target(e.ctx, tg.ID)
	if tgt.Status != StatusChanged {
		t.Fatalf("status %s", tgt.Status)
	}
	e.clock.Add(days(60))
	e.apply(tg.ID, result(served("192.0.2.1", gts.leaf(t, e.clock.Now(), e.clock.Now().Add(days(90)), "portal.example.nl"), gts.cert)))
	if open := e.open(tg.ID); len(open) != 0 {
		t.Fatalf("the renewal by the new issuer left findings open: %v", open)
	}
}

// A second unexpected leaf while certificate_changed is open replaces its
// details and fingerprint (so an acknowledgement confirms the latest), and
// opens no second finding.
func TestSecondChangeReplacesDetails(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	e.apply(tg.ID, result(served("192.0.2.1", ca.leaf(t, now.Add(-days(30)), now.Add(days(300)), "portal.example.nl"), ca.cert)))
	b := ca.leaf(t, now, now.Add(days(365)), "portal.example.nl")
	e.apply(tg.ID, result(served("192.0.2.1", b, ca.cert)))
	first := e.open(tg.ID)[check.CertificateChanged]
	c := ca.leaf(t, now, now.Add(days(366)), "portal.example.nl")
	e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	second := e.open(tg.ID)[check.CertificateChanged]
	if second.ID != first.ID || second.Fingerprint != probe.Fingerprint(c) || second.Details == first.Details {
		t.Fatalf("first %+v, second %+v", first, second)
	}
	if n := e.count("SELECT COUNT(*) FROM findings WHERE target_id = ? AND kind = 'certificate_changed'", tg.ID); n != 1 {
		t.Fatalf("%d certificate_changed findings", n)
	}
}

// A new intermediate under the same leaf is not a certificate change; the
// chain of the last check resolves to its links with the roles and the
// link that expires first.
func TestChainChangeUnderSameLeaf(t *testing.T) {
	e := newEnv(t)
	root := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	leaf := root.leaf(t, now.Add(-days(10)), now.Add(days(300)), "portal.example.nl")
	e.apply(tg.ID, result(served("192.0.2.1", leaf)))
	other := newCA(t, "Cross")
	e.apply(tg.ID, result(served("192.0.2.1", leaf, root.cert, other.cert)))
	if open := e.open(tg.ID); len(open) != 0 {
		t.Fatalf("a chain change under the same leaf opened %v", open)
	}
	obs, _ := e.svc.LastCheck(e.ctx, tg.ID)
	if len(obs) != 1 {
		t.Fatalf("observations: %d", len(obs))
	}
	links := e.svc.Chain(e.ctx, obs[0])
	if len(links) != 3 || links[0].Role != "leaf" || links[1].Role != "root" {
		t.Fatalf("links: %+v", links)
	}
	worst := 0
	for _, l := range links {
		if l.Worst {
			worst++
			if l.Fingerprint != probe.Fingerprint(leaf) {
				t.Fatalf("worst link is %s, the leaf expires first", l.SubjectCN)
			}
		}
	}
	if worst != 1 {
		t.Fatalf("%d links marked worst", worst)
	}
}

func TestIsWeak(t *testing.T) {
	for _, c := range []struct {
		cert Certificate
		weak bool
	}{
		{Certificate{SigAlg: "SHA1-RSA", KeyType: "RSA", KeyBits: 2048}, true},
		{Certificate{SigAlg: "MD5-RSA", KeyType: "RSA", KeyBits: 2048}, true},
		{Certificate{SigAlg: "ECDSA-SHA1", KeyType: "ECDSA", KeyBits: 256}, true},
		{Certificate{SigAlg: "SHA256-RSA", KeyType: "RSA", KeyBits: 1024}, true},
		{Certificate{SigAlg: "SHA256-RSA", KeyType: "RSA", KeyBits: 2048}, false},
		{Certificate{SigAlg: "ECDSA-SHA256", KeyType: "ECDSA", KeyBits: 256}, false},
	} {
		if got := isWeak(c.cert); got != c.weak {
			t.Errorf("%s %s %d: weak %v", c.cert.SigAlg, c.cert.KeyType, c.cert.KeyBits, got)
		}
	}
}

// One certificate served on several targets is one inventory record with
// every place it is served.
func TestSameCertificateOnSeveralTargets(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	c := ca.leaf(t, now.Add(-days(10)), now.Add(days(300)), "portal.example.nl", "www.example.nl")
	a := e.target(nil)
	b := e.target(func(t *Target) { t.Name, t.Host, t.ServerName = "WWW", "www.example.nl", "www.example.nl" })
	e.apply(a.ID, result(served("192.0.2.1", c, ca.cert)))
	e.apply(b.ID, result(served("192.0.2.2", c, ca.cert), served("2001:db8::2", c, ca.cert)))
	inv, err := e.svc.Inventory(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv) != 1 || inv[0].Targets != 2 || len(inv[0].Served) != 3 || inv[0].Stale {
		t.Fatalf("inventory: %+v", inv)
	}
	if n := e.count("SELECT COUNT(*) FROM certificates WHERE fingerprint = ?", probe.Fingerprint(c)); n != 1 {
		t.Fatalf("certificate stored %d times", n)
	}
	on, _ := e.svc.ServedOn(e.ctx, probe.Fingerprint(c))
	if len(on) != 3 {
		t.Fatalf("served on %d places", len(on))
	}
}

// The status of a target is the worst of its addresses (Targets and
// probing, Multiple addresses): one address of two that cannot be reached
// is not a healthy target.
func TestOneAddressDownIsNotHealthy(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	c := ca.leaf(t, now.Add(-days(10)), now.Add(days(300)), "portal.example.nl")
	tg = e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert), failed("192.0.2.2")))
	if tg.Status == StatusHealthy {
		t.Errorf("status %q with one of two addresses refusing connections", tg.Status)
	}
	obs, _ := e.svc.LastCheck(e.ctx, tg.ID)
	if len(obs) != 2 {
		t.Fatalf("observations: %+v", obs)
	}
	for _, o := range obs {
		if o.Address == "192.0.2.2" && (o.Status != "error" || o.Error == "") {
			t.Errorf("failed address observation: %+v", o)
		}
	}
}

// Behind a balancer two addresses serve different certificates. When the
// address serving the current one is briefly unreachable, the other
// address's (already known) certificate becomes current, and a change
// warning opens although nothing was replaced.
func TestOneAddressDownDoesNotFlipCertificate(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	fresh := ca.leaf(t, now, now.Add(days(300)), "portal.example.nl")
	stale := ca.leaf(t, now.Add(-days(300)), now.Add(days(60)), "portal.example.nl")
	tg = e.apply(tg.ID, result(served("192.0.2.1", fresh, ca.cert), served("192.0.2.2", stale, ca.cert)))
	if tg.CurrentFP != probe.Fingerprint(fresh) {
		t.Fatal("current is not the fresh certificate")
	}
	e.apply(tg.ID, result(failed("192.0.2.1"), served("192.0.2.2", stale, ca.cert)))
	e.apply(tg.ID, result(served("192.0.2.1", fresh, ca.cert), served("192.0.2.2", stale, ca.cert)))
	if f, ok := e.open(tg.ID)[check.CertificateChanged]; ok {
		t.Errorf("certificate_changed opened by an address outage, no certificate was replaced: %s", f.Details)
	}
}

// AAAA records skipped for want of an IPv6 route are noted, not reported
// as unreachable.
func TestSkippedIPv6IsNoted(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	r := result(served("192.0.2.1", ca.leaf(t, now.Add(-days(10)), now.Add(days(300)), "portal.example.nl"), ca.cert))
	r.SkippedIPv6 = []string{"2001:db8::1"}
	tg = e.apply(tg.ID, r)
	if tg.Status != StatusHealthy || len(e.open(tg.ID)) != 0 {
		t.Fatalf("status %s, open %v", tg.Status, e.open(tg.ID))
	}
	obs, _ := e.svc.LastCheck(e.ctx, tg.ID)
	var note string
	for _, o := range obs {
		if o.Address == "2001:db8::1" {
			note = o.Status + ": " + o.Error
		}
	}
	if note != "skipped: no IPv6 route from this host" {
		t.Fatalf("skipped address: %q", note)
	}
	if noIPv6Route(7) != "no IPv6 route from the node" {
		t.Fatal("node note")
	}
}

func TestTargetValidation(t *testing.T) {
	e := newEnv(t)
	st := e.svc.CurrentSettings(e.ctx)
	base := func() Target {
		return Target{Host: "portal.example.nl", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem}
	}
	for _, c := range []struct {
		name  string
		mut   func(*Target)
		field string // "" for valid
	}{
		{"port 0", func(t *Target) { t.Port = 0 }, "port"},
		{"port 65536", func(t *Target) { t.Port = 65536 }, "port"},
		{"port 1", func(t *Target) { t.Port = 1 }, ""},
		{"port 65535", func(t *Target) { t.Port = 65535 }, ""},
		{"empty host", func(t *Target) { t.Host = " " }, "host"},
		{"host with port", func(t *Target) { t.Host = "portal.example.nl:443" }, "host"},
		{"host with scheme", func(t *Target) { t.Host = "https://portal.example.nl" }, "host"},
		{"loopback", func(t *Target) { t.Host = "127.0.0.1" }, "host"},
		{"mapped loopback", func(t *Target) { t.Host = "::ffff:127.0.0.1" }, "host"},
		{"link-local v6", func(t *Target) { t.Host = "[fe80::1]" }, "host"},
		{"unspecified", func(t *Target) { t.Host = "0.0.0.0" }, "host"},
		{"private ok", func(t *Target) { t.Host = "10.0.0.5" }, ""},
		{"ip servername", func(t *Target) { t.ServerName = "192.0.2.1" }, "servername"},
		{"bad servername", func(t *Target) { t.ServerName = "a_b.example.nl" }, "servername"},
		{"unknown protocol", func(t *Target) { t.Protocol = "http" }, "protocol"},
		{"bundle without id", func(t *Target) { t.Trust = probe.TrustBundle }, "bundle_id"},
		{"critical not below warning", func(t *Target) { t.WarnDays, t.CritDays = intp(10), intp(10) }, "crit_days"},
		{"interval under an hour", func(t *Target) { t.IntervalS = intp(1800) }, "interval_s"},
		{"tags fine", func(t *Target) { t.Tags = []string{"a"} }, ""},
	} {
		tg := base()
		c.mut(&tg)
		errs := tg.Validate(st)
		if c.field == "" && len(errs) != 0 || c.field != "" && errs[c.field] == "" {
			t.Errorf("%s: %v", c.name, errs)
		}
	}

	// Normalisation: case, trailing dot, brackets.
	tg := Target{Host: " Portal.Example.NL. ", ServerName: "Portal.Example.NL.", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem}
	if errs := tg.Validate(st); len(errs) != 0 || tg.Host != "portal.example.nl" || tg.ServerName != "portal.example.nl" || tg.Name != "portal.example.nl" {
		t.Fatalf("normalised %q %q %q: %v", tg.Host, tg.ServerName, tg.Name, errs)
	}
	v6 := Target{Host: "[2001:DB8::1]", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem}
	if errs := v6.Validate(st); len(errs) != 0 || v6.Host != "2001:db8::1" || v6.HostPort() != "[2001:db8::1]:443" {
		t.Fatalf("IPv6 literal %q: %v", v6.Host, errs)
	}
	// An internationalised name is entered in its A-label form.
	idn := Target{Host: "xn--bcher-kva.example", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem}
	if errs := idn.Validate(st); len(errs) != 0 {
		t.Fatalf("punycode name: %v", errs)
	}

	// The same endpoint typed in another case is a duplicate.
	a := Target{Host: "portal.example.nl", ServerName: "portal.example.nl", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem, Enabled: true, AllChannels: true}
	a.Validate(st)
	if _, err := e.svc.SaveTarget(e.ctx, a, "test"); err != nil {
		t.Fatal(err)
	}
	b := Target{Host: "PORTAL.example.nl.", ServerName: "Portal.Example.nl", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem, Enabled: true, AllChannels: true}
	b.Validate(st)
	if _, err := e.svc.SaveTarget(e.ctx, b, "test"); !errors.Is(err, ErrTargetExists) {
		t.Fatalf("duplicate differing in case: %v", err)
	}
}

// Two spellings of one IPv6 address are one endpoint.
func TestIPv6SpellingsAreOneEndpoint(t *testing.T) {
	e := newEnv(t)
	st := e.svc.CurrentSettings(e.ctx)
	a := Target{Host: "2001:db8::1", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem, Enabled: true, AllChannels: true}
	a.Validate(st)
	if _, err := e.svc.SaveTarget(e.ctx, a, "test"); err != nil {
		t.Fatal(err)
	}
	b := Target{Host: "2001:0db8:0:0::1", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem, Enabled: true, AllChannels: true}
	b.Validate(st)
	if _, err := e.svc.SaveTarget(e.ctx, b, "test"); !errors.Is(err, ErrTargetExists) {
		t.Errorf("2001:0db8:0:0::1 saved next to 2001:db8::1 (host stored as %q): %v", b.Host, err)
	}
}

// Changing the port of a self-signed target points it at another
// certificate: the pin starts over, as for a new host.
func TestPortChangeRepinsSelfSigned(t *testing.T) {
	e := newEnv(t)
	tg := e.target(func(t *Target) { t.Trust = probe.TrustSelfSigned; t.ServerName = ""; t.Host = "192.0.2.9" })
	a := newCA(t, "appliance").cert
	r := result(probe.Address{IP: "192.0.2.9", OK: true, Chain: []*x509.Certificate{a}})
	e.apply(tg.ID, r)
	tg, _ = e.svc.Target(e.ctx, tg.ID)
	tg.Port = 8443
	if _, err := e.svc.SaveTarget(e.ctx, tg, "test"); err != nil {
		t.Fatal(err)
	}
	b := newCA(t, "appliance").cert
	r = result(probe.Address{IP: "192.0.2.9", OK: true, Chain: []*x509.Certificate{b}})
	r.Port = 8443
	e.apply(tg.ID, r)
	if f, ok := e.open(tg.ID)[check.CertificateChanged]; ok {
		t.Errorf("new port compared against the old port's pin: %s", f.Details)
	}
}

func TestTargetDaysLeftAndTagCounts(t *testing.T) {
	now := time.Now()
	if (Target{}).DaysLeft(now) != nil {
		t.Fatal("days left without a certificate")
	}
	if d := (Target{NotAfter: now.Add(days(29) + 23*time.Hour).Unix()}).DaysLeft(now); d == nil || *d != 29 {
		t.Fatalf("29 d 23 h: %v", d)
	}
	if d := (Target{NotAfter: now.Add(-time.Hour).Unix()}).DaysLeft(now); d == nil || *d != -1 {
		t.Fatalf("expired an hour ago: %v", *d)
	}
	tc := TagCounts([]Target{{Tags: []string{"b", "a"}}, {Tags: []string{"a"}}, {Tags: []string{"c"}}})
	if len(tc) != 3 || tc[0] != (TagCount{"a", 2}) || tc[1] != (TagCount{"b", 1}) || tc[2] != (TagCount{"c", 1}) {
		t.Fatalf("tag counts: %+v", tc)
	}
}

// Pointing a target at another host is a new baseline (targets.go: "A new
// endpoint or trust mode starts a new pin and history baseline"): the new
// host's certificate is not a replacement of the old host's.
func TestHostChangeIsNewBaseline(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	e.apply(tg.ID, result(served("192.0.2.1", ca.leaf(t, now.Add(-days(10)), now.Add(days(300)), "portal.example.nl"), ca.cert)))
	tg, _ = e.svc.Target(e.ctx, tg.ID)
	tg.Host, tg.ServerName = "shop.example.nl", "shop.example.nl"
	if _, err := e.svc.SaveTarget(e.ctx, tg, "op"); err != nil {
		t.Fatal(err)
	}
	r := result(served("192.0.2.5", ca.leaf(t, now.Add(-days(10)), now.Add(days(300)), "shop.example.nl"), ca.cert))
	r.Host = "shop.example.nl"
	e.apply(tg.ID, r)
	if f, ok := e.open(tg.ID)[check.CertificateChanged]; ok {
		t.Errorf("changing the host opened certificate_changed: %s", f.Details)
	}
}
