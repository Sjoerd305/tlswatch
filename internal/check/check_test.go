package check

import (
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

func TestDaysLeftTruncates(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		d    time.Duration
		want int
	}{
		{30 * 24 * time.Hour, 30},
		{30*24*time.Hour - time.Second, 29},
		{12 * time.Hour, 0},
		{0, 0},
		{-time.Second, -1},
		{-25 * time.Hour, -2},
	}
	for _, c := range cases {
		if got := DaysLeft(now.Add(c.d), now); got != c.want {
			t.Errorf("DaysLeft(%v) = %d, want %d", c.d, got, c.want)
		}
	}
}

func TestDNSDebounce(t *testing.T) {
	r := probe.Result{DNSError: "no such host"}
	tg := Target{Debounce: 2, Manual: Thresholds{Warn: 30, Crit: 7}, Managed: Thresholds{Warn: 10, Crit: 3}}
	o := Evaluate(tg, Previous{Open: map[Kind]bool{}}, r, time.Now())
	if len(o.Open) != 0 || o.DNSFail != 1 {
		t.Fatalf("first failure opened: %+v", o.Open)
	}
	o = Evaluate(tg, Previous{DNSFail: 1, Open: map[Kind]bool{Expiring: true}}, r, time.Now())
	if len(o.Open) != 1 || o.Open[0].Kind != DNSFailed {
		t.Fatalf("second failure: %+v", o.Open)
	}
	// Certificate findings are kept while nothing can be read.
	if len(o.Keep) != 1 || o.Keep[0] != Expiring {
		t.Fatalf("keep: %v", o.Keep)
	}
}

func TestSTARTTLSUnavailable(t *testing.T) {
	r := probe.Result{Addresses: []probe.Address{{IP: "192.0.2.1", ErrorKind: probe.ErrStartTLS, Error: "no STARTTLS"}}}
	o := Evaluate(Target{Debounce: 2}, Previous{Open: map[Kind]bool{}}, r, time.Now())
	if len(o.Open) != 1 || o.Open[0].Kind != TLSUnavailable || o.Open[0].Severity != Critical {
		t.Fatalf("%+v", o.Open)
	}
}

func TestACMEIssuer(t *testing.T) {
	for _, org := range []string{"Let's Encrypt", "ZeroSSL", "Google Trust Services LLC", "Google Trust Services"} {
		if !IsACMEIssuer(org, "") {
			t.Errorf("%s not ACME", org)
		}
	}
	if IsACMEIssuer("Sectigo Limited", "Sectigo RSA Domain Validation Secure Server CA") {
		t.Error("Sectigo detected as ACME")
	}
}

func TestPortHint(t *testing.T) {
	if PortHint(probe.SMTP, 465) == "" || PortHint(probe.TLS, 587) == "" || PortHint(probe.IMAP, 993) == "" {
		t.Fatal("missing hint for a mismatched port")
	}
	if PortHint(probe.SMTP, 587) != "" || PortHint(probe.TLS, 465) != "" || PortHint(probe.TLS, 443) != "" || PortHint(probe.SMTP, 2525) != "" {
		t.Fatal("hint for a fitting port")
	}
	r := probe.Result{Port: 465, Protocol: probe.SMTP, Addresses: []probe.Address{{IP: "192.0.2.1", ErrorKind: probe.ErrConnect, Error: "timed out after 10s"}}}
	o := Evaluate(Target{Debounce: 1}, Previous{Open: map[Kind]bool{}}, r, time.Now())
	if len(o.Open) != 1 || !strings.Contains(o.Open[0].Details, "implicit TLS") || !strings.Contains(o.Error, "choose protocol tls") {
		t.Fatalf("hint not in the finding: %+v %q", o.Open, o.Error)
	}
}
