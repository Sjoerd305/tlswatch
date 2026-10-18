package core

import (
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
)

// renewal_overdue speaks for a warning-level expiring: one alert, no
// reminder for the expiring, and the escalation to critical still goes out
// (Checks, renewal_overdue).
func TestRenewalOverdueAlertsOnce(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Let's Encrypt")
	now := e.clock.Now()
	tg := e.target(func(t *Target) { t.RenewalManaged, t.WarnPct, t.CritPct = true, nil, nil })
	// A 90-day certificate with 12 days left: 87 % used, 13 % left.
	c := ca.leaf(t, now.Add(-days(78)), now.Add(days(12)+time.Hour), "portal.example.nl")
	tg = e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	open := e.open(tg.ID)
	if open[check.RenewalOverdue].Severity != check.Warning || open[check.Expiring].Severity != check.Warning {
		t.Fatalf("findings: %+v", open)
	}
	if d := open[check.RenewalOverdue].Details; d != "renewal was due 10 days ago; the certificate expires in 12 days" {
		t.Fatalf("details: %q", d)
	}
	e.flush()
	mail := e.take("mail")
	if len(mail) != 1 || !strings.HasPrefix(mail[0].Subject, "[warning] portal.example.nl:443 renewal overdue") {
		t.Fatalf("mail: %+v", mail)
	}

	// A week on: renewal_overdue is reminded, the expiring warning is not.
	e.clock.Add(days(7) + time.Hour)
	if _, err := e.svc.Remind(e.ctx); err != nil {
		t.Fatal(err)
	}
	e.flush()
	if mail = e.take("mail"); len(mail) != 1 || !strings.Contains(mail[0].Subject, "renewal overdue, still open") {
		t.Fatalf("reminders: %+v", mail)
	}

	// Under the critical share (7 %, about 6 days): the escalation goes out,
	// in hours.
	tg = e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	if f := e.open(tg.ID)[check.Expiring]; f.Severity != check.Critical {
		t.Fatalf("expiring: %+v", f)
	}
	e.flush()
	if mail = e.take("mail"); len(mail) != 1 || !strings.Contains(mail[0].Subject, "expires in 119 h, escalated") {
		t.Fatalf("escalation: %+v", mail)
	}

	// Renewed: both resolve; only the channels told hear of it.
	c2 := ca.leaf(t, e.clock.Now(), e.clock.Now().Add(days(90)), "portal.example.nl")
	tg = e.apply(tg.ID, result(served("192.0.2.1", c2, ca.cert)))
	if open := e.open(tg.ID); len(open) != 0 {
		t.Fatalf("open after renewal: %+v", open)
	}
}

// "Expiring next" ranks by the share of the lifetime left once the
// lifetimes differ by more than a factor of four, so short-lived
// certificates do not crowd out one that is late.
func TestSortExpiring(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	d := int64(86400)
	mk := func(name string, lifetime, left int64) Target {
		na := now.Unix() + left*d
		return Target{Name: name, NotAfter: na, Cert: &Certificate{NotBefore: na - lifetime*d, NotAfter: na}}
	}
	// The 1-year certificate has 5 % left, past any normal renewal; the
	// 6-day one has 33 %, as usual for it.
	ts := []Target{mk("6-day", 6, 2), mk("1-year", 365, 20)}
	SortExpiring(ts, now)
	if ts[0].Name != "1-year" {
		t.Fatalf("order %s, %s", ts[0].Name, ts[1].Name)
	}
	// Similar lifetimes: by expiry.
	ts = []Target{mk("90 a", 90, 20), mk("200", 200, 10)}
	SortExpiring(ts, now)
	if ts[0].Name != "200" {
		t.Fatalf("order %s, %s", ts[0].Name, ts[1].Name)
	}
}
