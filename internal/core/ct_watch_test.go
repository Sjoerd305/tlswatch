package core

import (
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
)

// entry adds a crt.sh entry with every field chosen by the test.
func (s *ctStub) entry(id int, cn string, names []string, issuer, serial string, nb, na time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, map[string]any{"id": id, "issuer_name": issuer, "common_name": cn, "name_value": strings.Join(names, "\n"),
		"not_before": nb.UTC().Format("2006-01-02T15:04:05"), "not_after": na.UTC().Format("2006-01-02T15:04:05"), "serial_number": serial})
}

// ctServed sets up a watch on example.nl past its first poll and a target
// portal.example.nl serving a certificate of ca; it returns the issuer DN
// as crt.sh writes it.
func ctServed(t *testing.T) (*env, *ctStub, Domain, Target, ca) {
	e, stub := ctEnv(t)
	sectigo := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	tg = e.apply(tg.ID, result(served("192.0.2.1", sectigo.leaf(t, now.Add(-days(10)), now.Add(days(80)), "portal.example.nl"), sectigo.cert)))
	d := e.watch("example.nl")
	if err := e.svc.PollDomains(e.ctx); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(2 * time.Hour)
	return e, stub, d, tg, sectigo
}

func dnOf(c ca) string {
	return "C=NL, O=" + c.cert.Subject.Organization[0] + ", CN=" + c.cert.Subject.CommonName
}

func (e *env) poll() {
	e.t.Helper()
	e.clock.Add(2 * time.Hour)
	if err := e.svc.PollDomains(e.ctx); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) issuanceStates(id int64) map[string]string {
	e.t.Helper()
	iss, err := e.svc.Issuances(e.ctx, id, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	m := map[string]string{}
	for _, i := range iss {
		m[strings.Join(i.Names, ",")] = i.State
	}
	return m
}

// A precertificate and its certificate share issuer and serial: one
// issuance, one finding, one alert.
func TestCTPrecertAndCertAreOneIssuance(t *testing.T) {
	e, stub, d, _, _ := ctServed(t)
	nb := e.clock.Now().Add(-time.Hour)
	stub.entry(40, "admin.example.nl", []string{"admin.example.nl"}, "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV", "0ab1", nb, nb.Add(days(90)))
	stub.entry(41, "admin.example.nl", []string{"admin.example.nl"}, "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV", "AB1", nb, nb.Add(days(90)))
	e.poll()
	if iss, _ := e.svc.Issuances(e.ctx, d.ID, 0); len(iss) != 1 || iss[0].Serial != "AB1" {
		t.Fatalf("issuances: %+v", iss)
	}
	if n := e.count("SELECT COUNT(*) FROM findings WHERE domain_id = ?", d.ID); n != 1 {
		t.Fatalf("%d findings", n)
	}
	e.flush()
	if m := e.take("mail"); len(m) != 1 {
		t.Fatalf("%d mails", len(m))
	}
	// Polled again (crt.sh may hand the same entries back): nothing new.
	e.poll()
	if n := e.count("SELECT COUNT(*) FROM issuances"); n != 1 {
		t.Fatalf("issuances after a repeat poll: %d", n)
	}
}

// Matching: a name a target covers with the issuer it serves is pending; a
// covered name from another CA, a name nobody covers, or a wildcard whose
// base no target is directly under is unexpected; a wildcard covers the
// names one level under it; names outside the watched domain are not
// judged.
func TestCTMatchingRules(t *testing.T) {
	e, stub, d, _, sectigo := ctServed(t)
	nb := e.clock.Now().Add(-time.Hour)
	na := nb.Add(days(90))
	other := "C=US, O=Google Trust Services, CN=WR1"
	stub.entry(50, "portal.example.nl", []string{"portal.example.nl"}, dnOf(sectigo), "5001", nb, na)
	stub.entry(51, "portal.example.nl", []string{"portal.example.nl", "www.portal.example.nl"}, dnOf(sectigo), "5002", nb, na)
	stub.entry(52, "portal.example.nl", []string{"portal.example.nl"}, other, "5003", nb, na)
	stub.entry(53, "*.example.nl", []string{"*.example.nl"}, dnOf(sectigo), "5004", nb, na)
	stub.entry(54, "*.sub.example.nl", []string{"*.sub.example.nl"}, dnOf(sectigo), "5005", nb, na)
	stub.entry(55, "portal.example.nl", []string{"portal.example.nl", "portal.example.com"}, dnOf(sectigo), "5006", nb, na)
	e.poll()
	want := map[string]string{
		"portal.example.nl":                       IssuancePending,
		"portal.example.nl,www.portal.example.nl": IssuanceUnexpected,
		"*.example.nl":                            IssuancePending,
		"*.sub.example.nl":                        IssuanceUnexpected,
		"portal.example.nl,portal.example.com":    IssuancePending,
	}
	got := map[string]string{}
	iss, _ := e.svc.Issuances(e.ctx, d.ID, 0)
	for _, i := range iss {
		key := strings.Join(i.Names, ",")
		if i.Serial == "5003" {
			if i.State != IssuanceUnexpected {
				t.Errorf("covered name from another CA: %s", i.State)
			}
			continue
		}
		got[key] = i.State
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: %s, want %s", k, got[k], w)
		}
	}
	f := e.domainFindings(d.ID)
	if _, ok := f[check.UnexpectedCertificate]; !ok {
		t.Fatal("no unexpected finding")
	}
	if n := e.count("SELECT COUNT(*) FROM findings WHERE domain_id = ? AND resolved_at = 0", d.ID); n != 3 {
		t.Fatalf("%d open findings, want one per unexpected issuance (3)", n)
	}
}

// A served certificate is matched however the source writes the serial.
func TestCTSerialSpellingsMatch(t *testing.T) {
	e, stub, d, tg, sectigo := ctServed(t)
	nb := e.clock.Now().Add(-time.Hour)
	leaf := sectigo.leaf(t, nb, nb.Add(days(90)), "portal.example.nl")
	stub.entry(60, "portal.example.nl", []string{"portal.example.nl"}, dnOf(sectigo), "00:"+strings.ToLower(serialOf(leaf)), nb, nb.Add(days(90)))
	e.poll()
	e.apply(tg.ID, result(served("192.0.2.1", leaf, sectigo.cert)))
	if s := e.issuanceStates(d.ID)["portal.example.nl"]; s != IssuanceKnown {
		t.Fatalf("state %s", s)
	}
}

// An issuance whose certificate has expired is closed silently, whatever
// its state: a pending one that expires within the hold does not become an
// unexpected finding and an alert.
func TestCTExpiredPendingClosesSilently(t *testing.T) {
	e, stub, d, _, sectigo := ctServed(t)
	nb := e.clock.Now().Add(-time.Hour)
	stub.entry(70, "portal.example.nl", []string{"portal.example.nl"}, dnOf(sectigo), "7001", nb, nb.Add(days(1)))
	e.poll()
	if s := e.issuanceStates(d.ID)["portal.example.nl"]; s != IssuancePending {
		t.Fatalf("state %s", s)
	}
	e.flush()
	e.take("mail")
	e.clock.Add(PendingHold + time.Hour)
	if err := e.svc.SweepIssuances(e.ctx); err != nil {
		t.Fatal(err)
	}
	if f, ok := e.domainFindings(d.ID)[check.UnexpectedCertificate]; ok {
		t.Errorf("an expired pending issuance opened %q", f.Details)
	}
	e.flush()
	if m := e.take("mail"); len(m) != 0 {
		t.Errorf("alert for an issuance that already expired: %s", m[0].Subject)
	}
}

// An unexpected issuance that expires closes its finding without a
// recovery notice.
func TestCTExpiredUnexpectedClosesSilently(t *testing.T) {
	e, stub, d, _, _ := ctServed(t)
	nb := e.clock.Now().Add(-time.Hour)
	stub.entry(80, "admin.example.nl", []string{"admin.example.nl"}, "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV", "8001", nb, nb.Add(days(2)))
	e.poll()
	if _, ok := e.domainFindings(d.ID)[check.UnexpectedCertificate]; !ok {
		t.Fatal("no finding")
	}
	e.flush()
	e.take("mail")
	e.clock.Add(days(3))
	if err := e.svc.SweepIssuances(e.ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.domainFindings(d.ID)) != 0 {
		t.Fatal("finding of an expired issuance still open")
	}
	e.flush()
	if m := e.take("mail"); len(m) != 0 {
		t.Fatalf("recovery for an expired issuance: %+v", m)
	}
}

// Mark unexpected on a backlog issuance opens its finding; acknowledging
// the issuance resolves it and keeps who and why; marking again starts
// over.
func TestCTMarkUnexpectedAndAcknowledge(t *testing.T) {
	e, stub := ctEnv(t)
	now := e.clock.Now()
	stub.entry(90, "old.example.nl", []string{"old.example.nl"}, "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV", "9001", now.Add(-days(20)), now.Add(days(70)))
	d := e.watch("example.nl")
	_ = e.svc.PollDomains(e.ctx)
	iss, _ := e.svc.Issuances(e.ctx, d.ID, 0)
	if len(iss) != 1 || iss[0].State != IssuanceKnown {
		t.Fatalf("backlog: %+v", iss)
	}
	i, err := e.svc.MarkUnexpected(e.ctx, iss[0].ID)
	if err != nil || i.State != IssuanceUnexpected {
		t.Fatalf("marked: %+v %v", i, err)
	}
	if _, err := e.svc.MarkUnexpected(e.ctx, i.ID); err != nil {
		t.Fatal(err)
	}
	if n := e.count("SELECT COUNT(*) FROM findings WHERE domain_id = ? AND resolved_at = 0", d.ID); n != 1 {
		t.Fatalf("open findings: %d", n)
	}
	if f := e.domainFindings(d.ID)[check.UnexpectedCertificate]; !strings.Contains(f.Details, "was marked unexpected") {
		t.Fatalf("details: %q", f.Details)
	}
	i, err = e.svc.AcknowledgeIssuance(e.ctx, i.ID, "Alex", " staging ")
	if err != nil || i.State != IssuanceAcknowledged || i.AckBy != "Alex" || i.AckComment != "staging" {
		t.Fatalf("acknowledged: %+v %v", i, err)
	}
	if len(e.domainFindings(d.ID)) != 0 {
		t.Fatal("acknowledging the issuance left its finding open")
	}
	i, _ = e.svc.MarkUnexpected(e.ctx, i.ID)
	if i.State != IssuanceUnexpected || i.AckBy != "" || len(e.domainFindings(d.ID)) != 1 {
		t.Fatalf("marked again: %+v", i)
	}
	if _, err := e.svc.Issuance(e.ctx, 9999); err != ErrNotFound {
		t.Fatalf("unknown issuance: %v", err)
	}
}

// An operator marks a served (known) issuance unexpected by hand: the
// hourly sweep must not undo that on its own.
func TestCTMarkUnexpectedOnServedStays(t *testing.T) {
	e, stub, d, tg, sectigo := ctServed(t)
	nb := e.clock.Now().Add(-time.Hour)
	leaf := sectigo.leaf(t, nb, nb.Add(days(90)), "portal.example.nl")
	e.apply(tg.ID, result(served("192.0.2.1", leaf, sectigo.cert)))
	stub.entry(95, "portal.example.nl", []string{"portal.example.nl"}, dnOf(sectigo), serialOf(leaf), nb, nb.Add(days(90)))
	e.poll()
	iss, _ := e.svc.Issuances(e.ctx, d.ID, 0)
	if len(iss) != 1 || iss[0].State != IssuanceKnown {
		t.Fatalf("issuances: %+v", iss)
	}
	if _, err := e.svc.MarkUnexpected(e.ctx, iss[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SweepIssuances(e.ctx); err != nil {
		t.Fatal(err)
	}
	if i, _ := e.svc.Issuance(e.ctx, iss[0].ID); i.State != IssuanceUnexpected {
		t.Errorf("the sweep reverted a manual mark: state %s, findings %v", i.State, e.domainFindings(d.ID))
	}
}

// A watch alerts only to its chosen channels; its open findings are
// reminded at the default warning interval.
func TestCTRecipientsAndReminders(t *testing.T) {
	e, stub := ctEnv(t)
	id, err := e.svc.SaveDomain(e.ctx, Domain{Name: "example.nl", Subdomains: true, ChannelIDs: []int64{e.chC}, Enabled: true}, "test")
	if err != nil {
		t.Fatal(err)
	}
	_ = e.svc.PollDomains(e.ctx)
	stub.entry(100, "admin.example.nl", []string{"admin.example.nl"}, "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV", "A001", e.clock.Now(), e.clock.Now().Add(days(90)))
	e.poll()
	if _, ok := e.domainFindings(id)[check.UnexpectedCertificate]; !ok {
		t.Fatal("no finding")
	}
	e.flush()
	if m, m2 := e.take("mail"), e.take("telegram"); len(m)+len(m2) != 0 {
		t.Fatalf("a watch on the critical-only channel alerted a warning: %v %v", m, m2)
	}
	d, _ := e.svc.Domain(e.ctx, id)
	d.ChannelIDs = []int64{e.chW}
	if _, err := e.svc.SaveDomain(e.ctx, d, "test"); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(days(7) + time.Hour)
	if n, err := e.svc.Remind(e.ctx); err != nil || n != 1 {
		t.Fatalf("domain reminders: %d %v", n, err)
	}
	e.flush()
	if m := e.take("mail"); len(m) != 1 || !strings.Contains(m[0].Subject, "still open since") {
		t.Fatalf("reminder: %+v", m)
	}
	if err := e.svc.SetDomainEnabled(e.ctx, id, false); err != nil {
		t.Fatal(err)
	}
	if len(e.domainFindings(id)) != 0 {
		t.Fatal("disabling left findings open")
	}
	e.clock.Add(days(8))
	if n, _ := e.svc.Remind(e.ctx); n != 0 {
		t.Fatalf("disabled watch reminded: %d", n)
	}
}

// Renaming a watch starts it over.
func TestCTRenameStartsOver(t *testing.T) {
	e, stub := ctEnv(t)
	stub.entry(110, "a.example.nl", []string{"a.example.nl"}, "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV", "B001", e.clock.Now().Add(-days(3)), e.clock.Now().Add(days(80)))
	d := e.watch("example.nl")
	_ = e.svc.PollDomains(e.ctx)
	d, _ = e.svc.Domain(e.ctx, d.ID)
	if d.Cursor == "" {
		t.Fatal("no cursor")
	}
	d.Name = "example.com"
	if _, err := e.svc.SaveDomain(e.ctx, d, "test"); err != nil {
		t.Fatal(err)
	}
	d, _ = e.svc.Domain(e.ctx, d.ID)
	if d.Cursor != "" || d.PolledOK != 0 || e.count("SELECT COUNT(*) FROM issuances") != 0 {
		t.Fatalf("after rename: %+v", d)
	}
}

// The settings page's Test polls one domain without storing anything and
// shows at most the ten newest issuances.
func TestTestCTSource(t *testing.T) {
	e, stub := ctEnv(t)
	now := e.clock.Now()
	for i := 0; i < 12; i++ {
		stub.entry(200+i, "h.example.nl", []string{"h.example.nl"}, "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV", "C0"+string(rune('A'+i)), now.Add(-days(float64(i))), now.Add(days(80)))
	}
	st := e.svc.CurrentSettings(e.ctx)
	found, err := e.svc.TestCTSource(e.ctx, st, "Example.NL")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 10 || !found[0].NotBefore.After(found[9].NotBefore) {
		t.Fatalf("found %d, first %v last %v", len(found), found[0].NotBefore, found[len(found)-1].NotBefore)
	}
	if e.count("SELECT COUNT(*) FROM issuances") != 0 || e.count("SELECT COUNT(*) FROM domains") != 0 {
		t.Fatal("the test stored something")
	}
	if _, err := e.svc.TestCTSource(e.ctx, st, "*.example.nl"); err == nil {
		t.Fatal("wildcard accepted")
	}
	st.CT = config.CT{Source: "nope"}
	if _, err := e.svc.TestCTSource(e.ctx, st, "example.nl"); err == nil {
		t.Fatal("unknown source accepted")
	}
}

// Disabling a watch closes its findings; enabling it again opens those of
// its still unexpected issuances, which did not change meanwhile.
func TestCTReenableReopensUnexpected(t *testing.T) {
	e, stub, d, _, _ := ctServed(t)
	nb := e.clock.Now().Add(-time.Hour)
	stub.entry(85, "admin.example.nl", []string{"admin.example.nl"}, "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV", "8501", nb, nb.Add(days(90)))
	e.poll()
	if _, ok := e.domainFindings(d.ID)[check.UnexpectedCertificate]; !ok {
		t.Fatal("no finding")
	}
	if err := e.svc.SetDomainEnabled(e.ctx, d.ID, false); err != nil {
		t.Fatal(err)
	}
	if len(e.domainFindings(d.ID)) != 0 {
		t.Fatal("findings open on a disabled watch")
	}
	if err := e.svc.SetDomainEnabled(e.ctx, d.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.domainFindings(d.ID)[check.UnexpectedCertificate]; !ok {
		t.Fatal("the unexpected issuance has no open finding after enabling the watch again")
	}
}
