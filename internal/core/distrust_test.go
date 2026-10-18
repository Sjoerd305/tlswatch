package core

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sjoerd305/tlswatch/internal/check"
)

// A distrust event ahead opens distrusted_ca as a warning, marks the
// certificate in the inventory, is listed in the digest with the target,
// and turns critical on the day it takes effect.
func TestDistrustedCALifecycle(t *testing.T) {
	e := newEnv(t)
	old := newCA(t, "Old CA")
	now := e.clock.Now()
	spki := sha256.Sum256(old.cert.RawSubjectPublicKeyInfo)
	ev := check.DistrustEvent{CA: "Old CA", Program: "Chrome", BySCT: true, IssuedAfter: now.Add(-days(30)), Effective: now.Add(days(30)),
		Link:    "https://example.org/announcement",
		Anchors: []check.Anchor{{Name: "Old CA", SPKI: hex.EncodeToString(spki[:]), SKI: hex.EncodeToString(old.cert.SubjectKeyId)}}}
	saved := check.Distrusts
	check.Distrusts = []check.DistrustEvent{ev}
	t.Cleanup(func() { check.Distrusts = saved })

	tg := e.target(nil)
	c := old.leaf(t, now.Add(-days(2)), now.Add(days(365)), "portal.example.nl")
	tg = e.apply(tg.ID, result(served("192.0.2.1", c, old.cert)))
	f, ok := e.open(tg.ID)[check.DistrustedCA]
	if !ok || f.Severity != check.Warning || !strings.Contains(f.Details, "chain roots in Old CA; Chrome will distrust certificates from it issued after") {
		t.Fatalf("finding %v: %+v", ok, f)
	}
	e.flush()
	if mail := e.take("mail"); len(mail) != 1 || !strings.Contains(mail[0].Subject, "chain roots in a distrusted CA") {
		t.Fatalf("mail: %+v", mail)
	}
	inv, err := e.svc.Inventory(e.ctx)
	if err != nil || len(inv) != 1 || !inv[0].Distrusted {
		t.Fatalf("inventory: %v %+v", err, inv)
	}
	d, err := e.svc.Digest(e.ctx)
	if err != nil || !strings.Contains(d.Body, "Distrust taking effect in the next 90 days (1)") || !strings.Contains(d.Body, "affects Portal (portal.example.nl:443)") {
		t.Fatalf("digest: %v\n%s", err, d.Body)
	}

	// In effect: critical, and escalated.
	e.clock.Add(days(31))
	tg = e.apply(tg.ID, result(served("192.0.2.1", c, old.cert)))
	if f := e.open(tg.ID)[check.DistrustedCA]; f.Severity != check.Critical || !strings.Contains(f.Details, "Chrome distrusts certificates from it") {
		t.Fatalf("finding: %+v", f)
	}
	e.flush()
	if mail := e.take("mail"); len(mail) != 1 || !strings.Contains(mail[0].Subject, "escalated") {
		t.Fatalf("escalation: %+v", mail)
	}
	if d, _ := e.svc.Digest(e.ctx); strings.Contains(d.Body, "Distrust taking effect") {
		t.Fatal("a past event is listed as ahead")
	}

	// Moved to another CA: resolved.
	other := newCA(t, "New CA")
	tg = e.apply(tg.ID, result(served("192.0.2.1", other.leaf(t, e.clock.Now(), e.clock.Now().Add(days(90)), "portal.example.nl"), other.cert)))
	if _, ok := e.open(tg.ID)[check.DistrustedCA]; ok {
		t.Fatal("still open on another CA")
	}
}
