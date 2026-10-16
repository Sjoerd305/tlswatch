package core

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
)

// ctStub is a crt.sh-shaped source whose entries the test sets.
type ctStub struct {
	mu      sync.Mutex
	entries []map[string]any
	fail    bool
	calls   int
}

func (s *ctStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.fail {
		http.Error(w, "down", http.StatusBadGateway)
		return
	}
	q := r.URL.Query().Get("q")
	var out []map[string]any
	for _, e := range s.entries {
		name := e["common_name"].(string)
		if q == name || strings.HasPrefix(q, "%.") && strings.HasSuffix(name, strings.TrimPrefix(q, "%")) {
			out = append(out, e)
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (s *ctStub) add(id int, cn, issuer string, serial string, notBefore time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, map[string]any{"id": id, "issuer_name": issuer, "common_name": cn, "name_value": cn,
		"not_before": notBefore.UTC().Format("2006-01-02T15:04:05"), "not_after": notBefore.Add(90 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05"), "serial_number": serial})
}

func ctEnv(t *testing.T) (*env, *ctStub) {
	e := newEnv(t)
	stub := &ctStub{}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	e.svc.CTClient, e.svc.CTBase = srv.Client(), srv.URL
	if err := e.svc.Settings.SaveCT(e.ctx, config.CT{Source: "crtsh", IntervalS: 3600}, false); err != nil {
		t.Fatal(err)
	}
	return e, stub
}

func (e *env) watch(name string) Domain {
	e.t.Helper()
	id, err := e.svc.SaveDomain(e.ctx, Domain{Name: name, Subdomains: true, AllChannels: true, Enabled: true}, "test")
	if err != nil {
		e.t.Fatal(err)
	}
	d, err := e.svc.Domain(e.ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

func (e *env) domainFindings(id int64) map[check.Kind]Finding {
	e.t.Helper()
	fs, err := e.svc.Findings(e.ctx, FindingFilter{DomainID: id})
	if err != nil {
		e.t.Fatal(err)
	}
	m := map[check.Kind]Finding{}
	for _, f := range fs {
		m[f.Kind] = f
	}
	return m
}

func serialOf(c *x509.Certificate) string { return fmt.Sprintf("%X", c.SerialNumber) }

func TestDomainWatchStates(t *testing.T) {
	e, stub := ctEnv(t)
	now := e.clock.Now()
	ca := newCA(t, "Sectigo")
	leaf := ca.leaf(t, now.Add(-24*time.Hour), now.Add(days(60)), "portal.example.nl")
	tg := e.target(nil)
	tg = e.apply(tg.ID, result(served("192.0.2.1", leaf, ca.cert)))
	if tg.Cert == nil {
		t.Fatal("no certificate stored")
	}
	issuerDN := "C=NL, O=" + tg.Cert.IssuerOrg + ", CN=" + tg.Cert.IssuerCN

	// Backlog: an old issuance for a name no target serves is known, with
	// no finding; the served certificate is matched.
	stub.add(1, "old.example.nl", issuerDN, "AAAA", now.Add(-30*24*time.Hour))
	stub.add(2, "portal.example.nl", issuerDN, serialOf(leaf), now.Add(-24*time.Hour))
	stub.add(3, "ancient.example.nl", issuerDN, "BBBB", now.Add(-200*24*time.Hour))
	d := e.watch("example.nl")
	if !e.svc.DomainDue(d, e.svc.CurrentSettings(e.ctx), now) {
		t.Fatal("a new watch is not due")
	}
	if err := e.svc.PollDomains(e.ctx); err != nil {
		t.Fatal(err)
	}
	iss, _ := e.svc.Issuances(e.ctx, d.ID, 0)
	if len(iss) != 2 {
		t.Fatalf("backlog: %d issuances, want 2 (the 200-day-old one skipped): %+v", len(iss), iss)
	}
	for _, i := range iss {
		if i.State != IssuanceKnown {
			t.Errorf("backlog %v in state %s", i.Names, i.State)
		}
		if i.Names[0] == "portal.example.nl" && (i.MatchedFP != tg.CurrentFP || i.TargetID != tg.ID) {
			t.Errorf("served certificate not matched: %+v", i)
		}
	}
	if len(e.domainFindings(d.ID)) != 0 {
		t.Fatal("the backlog opened a finding")
	}
	d, _ = e.svc.Domain(e.ctx, d.ID)
	if d.Cursor != "3" || d.PolledOK == 0 {
		t.Fatalf("cursor %q polled %d", d.Cursor, d.PolledOK)
	}

	// A name no target covers: unexpected at once, alerted on the mail
	// channel (warning floor) but not on telegram (critical floor).
	e.clock.Add(time.Hour + 10*time.Minute)
	stub.add(4, "admin.example.nl", "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV", "CCCC", e.clock.Now().Add(-time.Hour))
	if err := e.svc.PollDomains(e.ctx); err != nil {
		t.Fatal(err)
	}
	f, ok := e.domainFindings(d.ID)[check.UnexpectedCertificate]
	if !ok || f.Severity != check.Warning || !strings.Contains(f.Details, "admin.example.nl was issued by Sectigo Limited") || !strings.Contains(f.Details, "no target serves it") {
		t.Fatalf("unexpected_certificate: %+v", f)
	}
	if f.TargetName != "example.nl" || f.HostPort() != "example.nl" || f.DomainID != d.ID {
		t.Fatalf("finding subject: %+v", f)
	}
	e.flush()
	if m := e.take("mail"); len(m) != 1 || !strings.Contains(m[0].Subject, "domain example.nl unexpected certificate issued") || !strings.Contains(m[0].Body, "Domain:      example.nl") || !strings.Contains(m[0].Body, "admin.example.nl") {
		t.Fatalf("mail: %+v", m)
	}
	if m := e.take("telegram"); len(m) != 0 {
		t.Fatalf("telegram got a warning: %+v", m)
	}
	// Acknowledging the finding marks the issuance.
	if _, err := e.svc.Acknowledge(e.ctx, f.ID, "Alex", time.Time{}, "staging"); err != nil {
		t.Fatal(err)
	}
	iss, _ = e.svc.Issuances(e.ctx, d.ID, 0)
	if iss[0].State != IssuanceAcknowledged || iss[0].AckBy != "Alex" || iss[0].AckComment != "staging" {
		t.Fatalf("acknowledged issuance: %+v", iss[0])
	}
	if len(e.domainFindings(d.ID)) != 0 {
		t.Fatal("acknowledging did not resolve the finding")
	}

	// A renewal: same name as the target, same issuer: pending, then known
	// once the target serves it, recorded as a quiet change.
	e.clock.Add(time.Hour + 10*time.Minute)
	renewed := ca.leaf(t, e.clock.Now().Add(-time.Hour), e.clock.Now().Add(days(90)), "portal.example.nl")
	stub.add(5, "portal.example.nl", issuerDN, serialOf(renewed), e.clock.Now().Add(-time.Hour))
	if err := e.svc.PollDomains(e.ctx); err != nil {
		t.Fatal(err)
	}
	iss, _ = e.svc.Issuances(e.ctx, d.ID, 0)
	if iss[0].State != IssuancePending {
		t.Fatalf("renewal: %+v", iss[0])
	}
	if len(e.domainFindings(d.ID)) != 0 {
		t.Fatal("a pending issuance opened a finding")
	}
	e.apply(tg.ID, result(served("192.0.2.1", renewed, ca.cert)))
	iss, _ = e.svc.Issuances(e.ctx, d.ID, 0)
	if iss[0].State != IssuanceKnown || iss[0].TargetID != tg.ID {
		t.Fatalf("served renewal: %+v", iss[0])
	}
	changes, _ := e.svc.RecentChanges(e.ctx, 0, 20)
	found := false
	for _, c := range changes {
		if c.Kind == check.CertificateIssued && c.DomainID == d.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("the served renewal is not a recent change: %+v", changes)
	}

	// A renewal nobody deploys: unexpected after the hold.
	e.clock.Add(time.Hour + 10*time.Minute)
	later := ca.leaf(t, e.clock.Now().Add(-time.Hour), e.clock.Now().Add(days(90)), "portal.example.nl")
	stub.add(6, "portal.example.nl", issuerDN, serialOf(later), e.clock.Now().Add(-time.Hour))
	if err := e.svc.PollDomains(e.ctx); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(PendingHold + time.Minute)
	if err := e.svc.SweepIssuances(e.ctx); err != nil {
		t.Fatal(err)
	}
	iss, _ = e.svc.Issuances(e.ctx, d.ID, 0)
	if iss[0].State != IssuanceUnexpected {
		t.Fatalf("after the hold: %+v", iss[0])
	}
	f, ok = e.domainFindings(d.ID)[check.UnexpectedCertificate]
	if !ok || !strings.Contains(f.Details, "within two days") {
		t.Fatalf("after the hold: %+v", f)
	}
	// Served after all: the finding resolves with a recovery notice.
	e.take("mail")
	e.apply(tg.ID, result(served("192.0.2.1", later, ca.cert)))
	if len(e.domainFindings(d.ID)) != 0 {
		t.Fatal("serving the certificate did not resolve the finding")
	}
	e.flush()
	// The notice may be batched with the target's own alerts about its new
	// certificate; the body names the domain and says it is resolved.
	var text string
	for _, m := range e.take("mail") {
		text += m.Subject + "\n" + m.Body + "\n"
	}
	if !strings.Contains(text, "domain example.nl") || !strings.Contains(strings.ToLower(text), "resolved") {
		t.Fatalf("recovery: %q", text)
	}
}

func TestDomainSourceFailure(t *testing.T) {
	e, stub := ctEnv(t)
	d := e.watch("example.nl")
	stub.fail = true
	if err := e.svc.PollDomains(e.ctx); err != nil {
		t.Fatal(err)
	}
	d, _ = e.svc.Domain(e.ctx, d.ID)
	if d.FailSince == 0 || !strings.Contains(d.PollError, "502") || d.Status() != StatusUnreachable {
		t.Fatalf("after a failed poll: %+v", d)
	}
	st := e.svc.CurrentSettings(e.ctx)
	if e.svc.DomainDue(d, st, e.clock.Now().Add(10*time.Minute)) || !e.svc.DomainDue(d, st, e.clock.Now().Add(16*time.Minute)) {
		t.Fatal("a failed poll is not retried after 15 minutes")
	}
	if len(e.domainFindings(d.ID)) != 0 {
		t.Fatal("ct_source_failed opened within the day")
	}
	e.clock.Add(25 * time.Hour)
	_ = e.svc.PollDomains(e.ctx)
	if _, ok := e.domainFindings(d.ID)[check.CTSourceFailed]; !ok {
		t.Fatal("ct_source_failed not opened after a day")
	}
	stub.fail = false
	e.clock.Add(2 * time.Hour)
	if err := e.svc.PollDomains(e.ctx); err != nil {
		t.Fatal(err)
	}
	d, _ = e.svc.Domain(e.ctx, d.ID)
	if len(e.domainFindings(d.ID)) != 0 || d.FailSince != 0 || d.PollError != "" {
		t.Fatalf("recovery: %+v findings %v", d, e.domainFindings(d.ID))
	}
	if err := e.svc.SetDomainEnabled(e.ctx, d.ID, false); err != nil {
		t.Fatal(err)
	}
	d, _ = e.svc.Domain(e.ctx, d.ID)
	if e.svc.DomainDue(d, e.svc.CurrentSettings(e.ctx), e.clock.Now().Add(48*time.Hour)) {
		t.Fatal("a disabled watch is due")
	}
}

func TestDomainValidationAndDelete(t *testing.T) {
	e, _ := ctEnv(t)
	if _, err := e.svc.SaveDomain(e.ctx, Domain{Name: "*.example.nl"}, "test"); err == nil {
		t.Fatal("wildcard accepted")
	}
	d := e.watch("Example.NL")
	if d.Name != "example.nl" {
		t.Fatalf("name %q", d.Name)
	}
	if _, err := e.svc.SaveDomain(e.ctx, Domain{Name: "example.nl"}, "test"); err != ErrDomainExists {
		t.Fatalf("duplicate: %v", err)
	}
	if err := e.svc.DeleteDomain(e.ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Domain(e.ctx, d.ID); err != ErrNotFound {
		t.Fatalf("after delete: %v", err)
	}
}
