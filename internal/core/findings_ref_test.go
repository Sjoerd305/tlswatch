package core

import (
	"strconv"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
)

// FindingRef describes a target's finding for the webhook: its kind, days
// left, the target it is on and, with a public URL set, a link to it; a
// finding that is gone has none.
func TestFindingRef(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	leaf := ca.leaf(t, now.Add(-days(300)), now.Add(days(20)+time.Hour), "portal.example.nl")
	e.apply(tg.ID, result(served("192.0.2.1", leaf, ca.cert)))
	f, ok := e.open(tg.ID)[check.Expiring]
	if !ok {
		t.Fatal("no expiring finding")
	}
	ref := e.svc.FindingRef(e.ctx, f.ID)
	if ref == nil || ref.Kind != "expiring" || ref.Severity != "warning" || ref.DaysLeft == nil || *ref.DaysLeft != 20 || ref.URL != "" || ref.ResolvedAt != "" {
		t.Fatalf("ref: %+v", ref)
	}
	if r := ref.Resource; r.Type != "target" || r.ID != tg.ID || r.Name != "Portal" || r.Host != "portal.example.nl" || r.Port != 443 || r.Protocol != "tls" {
		t.Fatalf("resource: %+v", r)
	}
	if _, err := time.Parse(time.RFC3339, ref.OpenedAt); err != nil {
		t.Fatalf("opened_at %q: %v", ref.OpenedAt, err)
	}
	if err := e.svc.Settings.SaveGeneral(e.ctx, config.General{BaseURL: "https://tlswatch.example.nl", ServerDiscovery: true}); err != nil {
		t.Fatal(err)
	}
	if ref = e.svc.FindingRef(e.ctx, f.ID); ref.URL != "https://tlswatch.example.nl/findings?sel="+strconv.FormatInt(f.ID, 10) {
		t.Fatalf("url %q", ref.URL)
	}
	if e.svc.FindingRef(e.ctx, f.ID+1000) != nil {
		t.Fatal("a finding that does not exist is described")
	}
}
