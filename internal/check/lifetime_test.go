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

// managed is a renewal-managed target on the default lifetime thresholds.
var managed = Target{Debounce: 2, RenewalSet: true, RenewalManaged: true,
	Manual:  Thresholds{Warn: 30, Crit: 7, WarnPct: 33, CritPct: 10},
	Managed: Thresholds{Warn: 10, Crit: 3, WarnPct: 20, CritPct: 7}}

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
		{"share fires before the days", managed, 90, 15, Warning, "15 days left, 16 % of its lifetime"},
		{"days fire before the share", managed, 30, 9, Warning, "9 days left ·"},
		{"a 1-year certificate is critical at 7 %", managed, 365, 20, Critical, "20 days left, 5 % of its lifetime"},
		{"critical by share, in hours under a week", managed, 90, 5, Critical, "121 h left, 5 % of its lifetime"},
		{"healthy share", managed, 90, 30, "", ""},
		{"0 means days only", daysOnly, 90, 15, "", ""},
		{"a 6-day certificate", managed, 6, 1, Critical, "25 h left ·"},
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
	// It sits next to expiring, which 13 % left (warning 20 %) opens too.
	if f, ok := find(o.Open, Expiring); !ok || f.Severity != Warning {
		t.Fatalf("expiring %v: %+v", ok, f)
	}

	for _, tc := range []struct {
		name string
		tg   Target
		cert *x509.Certificate
	}{
		{"not yet due", managed, lifeCert(t, iss, 90, 30)},
		{"manual renewal", func() Target { m := managed; m.RenewalManaged = false; return m }(), late},
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
