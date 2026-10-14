package web

import (
	"net/url"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
)

func TestCertRowAndFilter(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	it := core.InventoryItem{Certificate: core.Certificate{Fingerprint: "ab12", SubjectCN: "portal.example.nl", IssuerOrg: "Sectigo",
		KeyType: "ECDSA", NotAfter: now.Add(20*24*time.Hour + time.Hour).Unix(), SANs: []string{"www.example.nl"}}}
	row := newCertRow(it, config.Thresholds{WarnDays: 30, CritDays: 7}, now)
	if row.Days != 20 || row.Window != "30 90" || row.Status != "warn" {
		t.Fatalf("row: days %d window %q status %s", row.Days, row.Window, row.Status)
	}
	cases := []struct {
		query string
		want  bool
	}{
		{"", true},
		{"window=30", true},
		{"issuer=Sectigo&key=ECDSA", true},
		{"issuer=ZeroSSL", false},
		{"q=WWW.example", true},
		{"q=other", false},
	}
	for _, c := range cases {
		q, _ := url.ParseQuery(c.query)
		if got := certFilterFrom(q).matches(row); got != c.want {
			t.Errorf("%q: %v", c.query, got)
		}
	}
}

func TestFilterFindings(t *testing.T) {
	list := []core.Finding{
		{ID: 1, Kind: check.Expiring, Severity: check.Warning, TargetName: "portal"},
		{ID: 2, Kind: check.Expired, Severity: check.Critical, TargetName: "mail"},
		{ID: 3, Kind: check.Expiring, Severity: check.Critical, TargetName: "vpn"},
	}
	rows, shown, sevCount, kindCount := filterFindings(list, "critical", "", "vpn")
	if len(rows) != 2 || shown != 1 || !rows[0].Hidden || rows[1].Hidden {
		t.Fatalf("rows %+v shown %d", rows, shown)
	}
	if sevCount["critical"] != 2 || kindCount["expiring"] != 2 {
		t.Fatalf("counts %v %v", sevCount, kindCount)
	}
	state, sevs, kinds := findingChips(3, 10, false, "info", "", sevCount, kindCount)
	if len(state) != 2 || !state[0].On || len(sevs) != 3 || !sevs[2].On || len(kinds) != 2 {
		t.Fatalf("chips: %+v %+v %+v", state, sevs, kinds)
	}
}

func TestSlotLabel(t *testing.T) {
	if slotLabel(1, 3600) != "" {
		t.Fatal("hourly target has a daily slot")
	}
	if l := slotLabel(1, 86400); len(l) != len("00:00 UTC") {
		t.Fatalf("slot %q", l)
	}
}
