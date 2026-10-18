package check

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"slices"
	"strings"
	"testing"
	"time"
)

// lifeCert issues a leaf of lifetime days that has left days left (plus an
// hour, so DaysLeft is exactly left).
func lifeCert(t *testing.T, iss *ca, lifetime, left int) *x509.Certificate {
	na := now.Add(time.Duration(left)*24*time.Hour + time.Hour)
	return sign(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "a.example"}, DNSNames: []string{"a.example"},
		NotBefore: na.Add(-time.Duration(lifetime) * 24 * time.Hour), NotAfter: na,
	}, iss).cert
}

// managed is a renewal-managed target on the default lifetime thresholds,
// manualPct a manually managed one.
var managed = Target{Debounce: 2, RenewalSet: true, RenewalManaged: true,
	Manual:  Thresholds{Warn: 30, Crit: 7, WarnPct: 33, CritPct: 10},
	Managed: Thresholds{Warn: 10, Crit: 3, WarnPct: 20, CritPct: 7}}

var manualPct = func() Target { m := managed; m.RenewalManaged = false; return m }()

func TestLifetimeThresholds(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	daysOnly := managed
	zero := 0
	daysOnly.WarnPct, daysOnly.CritPct = &zero, &zero
	for _, tc := range []struct {
		name           string
		tg             Target
		lifetime, left int
		want           Severity
		details        string
	}{
		{"90-day managed: the days are later", managed, 90, 9, Warning, "9 days left ·"},
		{"90-day managed: critical in hours", managed, 90, 2, Critical, "49 h left ·"},
		{"47-day manual: the share is later", manualPct, 47, 20, "", ""},
		{"47-day manual: warning by share", manualPct, 47, 15, Warning, "15 days left, 32 % of its lifetime"},
		{"1-year manual: no warning months ahead", manualPct, 365, 100, "", ""},
		{"1-year manual: warning by days", manualPct, 365, 20, Warning, "20 days left ·"},
		{"6-day managed: nothing at issuance", managed, 6, 5, "", ""},
		{"6-day managed: warning by share", managed, 6, 1, Warning, "25 h left, 17 % of its lifetime"},
		{"6-day managed: critical by share", managed, 6, 0, Critical, "1 h left, 0 % of its lifetime"},
		{"0 means days only", daysOnly, 6, 5, Warning, "121 h left ·"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := Evaluate(tc.tg, Previous{Open: open()}, result(okAddr("192.0.2.1", lifeCert(t, iss, tc.lifetime, tc.left))), now)
			f, ok := find(o.Open, Expiring)
			if tc.want == "" {
				if ok {
					t.Fatalf("expiring opened: %+v", f)
				}
				return
			}
			if !ok || f.Severity != tc.want || !strings.HasPrefix(f.Details, tc.details) {
				t.Fatalf("expiring %v: %+v", ok, f)
			}
		})
	}
}

func TestRenewalOverdue(t *testing.T) {
	iss := newIssuer(t, "Test CA", "Test CA R1")
	late := lifeCert(t, iss, 90, 12) // 78 days used of 90: 86 %
	o := Evaluate(managed, Previous{Open: open()}, result(okAddr("192.0.2.1", late)), now)
	f, ok := find(o.Open, RenewalOverdue)
	// Due at 67.5 days in, 10.5 days ago, truncated to 10.
	if !ok || f.Severity != Warning || f.Details != "renewal was due 10 days ago; the certificate expires in 12 days" {
		t.Fatalf("renewal_overdue %v: %+v", ok, f)
	}
	// Long before expiring (10 days and 20 %) opens.
	if f, ok := find(o.Open, Expiring); ok {
		t.Fatalf("expiring opened: %+v", f)
	}

	for _, tc := range []struct {
		name string
		tg   Target
		cert *x509.Certificate
	}{
		{"not yet due", managed, lifeCert(t, iss, 90, 30)},
		{"manual renewal", manualPct, late},
		{"later renewal point", func() Target { m := managed; m.RenewalPoint = 90; return m }(), late},
		{"expired", managed, lifeCert(t, iss, 90, -3)},
	} {
		o := Evaluate(tc.tg, Previous{Open: open()}, result(okAddr("192.0.2.1", tc.cert)), now)
		if f, ok := find(o.Open, RenewalOverdue); ok {
			t.Errorf("%s: renewal_overdue opened: %+v", tc.name, f)
		}
	}

	// A renewed leaf resolves it: nothing keeps it open.
	o = Evaluate(managed, prevOf(late, RenewalOverdue), result(okAddr("192.0.2.1", lifeCert(t, iss, 90, 89))), now)
	if _, ok := find(o.Open, RenewalOverdue); ok || slices.Contains(o.Keep, RenewalOverdue) {
		t.Fatal("renewal_overdue survived a new leaf")
	}
}

func TestSpan(t *testing.T) {
	for d, want := range map[time.Duration]string{
		31 * time.Hour:                 "31 h",
		7*24*time.Hour - time.Minute:   "167 h",
		7 * 24 * time.Hour:             "7 days",
		-(12*24*time.Hour + time.Hour): "12 days",
		29*24*time.Hour + 23*time.Hour: "29 days",
	} {
		if got := Span(d); got != want {
			t.Errorf("Span(%v) = %q, want %q", d, got, want)
		}
	}
}
