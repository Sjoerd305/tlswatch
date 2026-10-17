package core

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// Deleting a target removes its observations, findings, alerts and channel
// choices; the impact page counts exactly those, and nothing else goes.
func TestDeleteTargetCascades(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	keep := e.target(func(t *Target) { t.Port = 8443 })
	tg := e.target(func(t *Target) { t.AllChannels = false; t.ChannelIDs = []int64{e.chW, e.chC} })
	c := ca.leaf(t, now.Add(-days(300)), now.Add(days(3)), "portal.example.nl")
	e.apply(keep.ID, result(served("192.0.2.1", c, ca.cert)))
	e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert), served("192.0.2.2", c, ca.cert)))
	e.apply(tg.ID, result(untrusted("192.0.2.1", c), untrusted("192.0.2.2", c)))
	e.flush()
	imp, err := e.svc.TargetDeleteImpact(e.ctx, tg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if imp.Observations != 4 || imp.Findings != 2 || imp.OpenFindings != 2 || imp.Alerts != 4 {
		t.Fatalf("impact: %+v", imp)
	}
	before := map[string]int{}
	for _, tb := range []string{"observations", "findings", "alerts"} {
		before[tb] = e.count("SELECT COUNT(*) FROM " + tb)
	}
	if err := e.svc.DeleteTarget(e.ctx, tg.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteTarget(e.ctx, tg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	for tb, n := range map[string]int{"observations": imp.Observations, "findings": imp.Findings, "alerts": imp.Alerts} {
		if got := e.count("SELECT COUNT(*) FROM " + tb); got != before[tb]-n {
			t.Errorf("%s: %d left, want %d", tb, got, before[tb]-n)
		}
	}
	for _, q := range []string{
		"SELECT COUNT(*) FROM observations WHERE target_id = ?", "SELECT COUNT(*) FROM findings WHERE target_id = ?",
		"SELECT COUNT(*) FROM target_channels WHERE target_id = ?",
	} {
		if n := e.count(q, tg.ID); n != 0 {
			t.Errorf("%s: %d", q, n)
		}
	}
	if n := e.count("SELECT COUNT(*) FROM alerts WHERE finding_id IS NOT NULL AND finding_id NOT IN (SELECT id FROM findings)"); n != 0 {
		t.Errorf("%d orphaned alerts", n)
	}
	// The other target still serves the certificate.
	if _, err := e.svc.Certificate(e.ctx, probe.Fingerprint(c)); err != nil {
		t.Fatal("shared certificate removed with the target")
	}
	if len(e.open(keep.ID)) == 0 {
		t.Fatal("the other target's findings went too")
	}
}

// Deleting a channel removes its alerts and the targets' and watches'
// choices of it.
func TestDeleteChannelCascades(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(func(t *Target) { t.AllChannels = false; t.ChannelIDs = []int64{e.chW, e.chC} })
	if _, err := e.svc.SaveDomain(e.ctx, Domain{Name: "example.nl", Subdomains: true, ChannelIDs: []int64{e.chC}, Enabled: true}, "test"); err != nil {
		t.Fatal(err)
	}
	e.apply(tg.ID, result(served("192.0.2.1", ca.leaf(t, now.Add(-days(300)), now.Add(days(3)), "portal.example.nl"), ca.cert)))
	if err := e.svc.Channels.Delete(e.ctx, e.chC); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"SELECT COUNT(*) FROM alerts WHERE channel_id = ?", "SELECT COUNT(*) FROM target_channels WHERE channel_id = ?",
		"SELECT COUNT(*) FROM domain_channels WHERE channel_id = ?"} {
		if n := e.count(q, e.chC); n != 0 {
			t.Errorf("%s: %d", q, n)
		}
	}
	if got, _ := e.svc.Target(e.ctx, tg.ID); len(got.ChannelIDs) != 1 || got.ChannelIDs[0] != e.chW {
		t.Fatalf("target channels: %v", got.ChannelIDs)
	}
	// The finding resolves: the recovery goes to the remaining channel only.
	e.apply(tg.ID, result(served("192.0.2.1", ca.leaf(t, now, now.Add(days(300)), "portal.example.nl"), ca.cert)))
	e.flush()
	if m := e.take("telegram"); len(m) != 0 {
		t.Fatalf("deleted channel got mail: %+v", m)
	}
}

// Deleting a watch removes its issuances, findings and their alerts, and
// the impact counts them first.
func TestDeleteDomainCascades(t *testing.T) {
	e, stub := ctEnv(t)
	d := e.watch("example.nl")
	if err := e.svc.PollDomains(e.ctx); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(2 * time.Hour)
	stub.add(10, "admin.example.nl", "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV", "AB01", e.clock.Now().Add(-time.Hour))
	stub.add(11, "vpn.example.nl", "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV", "AB02", e.clock.Now().Add(-time.Hour))
	if err := e.svc.PollDomains(e.ctx); err != nil {
		t.Fatal(err)
	}
	imp, err := e.svc.DomainDeleteImpact(e.ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if imp.Observations != 2 || imp.Findings != 2 || imp.OpenFindings != 2 || imp.Alerts != 2 {
		t.Fatalf("impact (Observations counts issuances): %+v", imp)
	}
	if err := e.svc.DeleteDomain(e.ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"SELECT COUNT(*) FROM issuances", "SELECT COUNT(*) FROM findings", "SELECT COUNT(*) FROM alerts"} {
		if n := e.count(q); n != 0 {
			t.Errorf("%s after deleting the only watch: %d", q, n)
		}
	}
}

// A finding that stays open longer than the history retention (an
// appliance's legacy versions, a long-acknowledged expiry) still gets its
// recovery notice when it resolves: pruning the alert log must not forget
// which channels had the open alert.
func TestRecoveryAfterRetentionOfOpenAlert(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(func(t *Target) { t.RemindCritS = intp(0) })
	c := ca.leaf(t, now.Add(-days(10)), now.Add(days(900)), "portal.example.nl")
	e.apply(tg.ID, result(untrusted("192.0.2.1", c)))
	e.flush()
	if m := e.take("telegram"); len(m) != 1 {
		t.Fatalf("open alert: %+v", m)
	}
	e.take("mail")
	e.clock.Add(days(200))
	if err := e.svc.Prune(e.ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.open(tg.ID)[check.ChainUntrusted]; !ok {
		t.Fatal("the open finding was pruned")
	}
	e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	e.flush()
	if m := e.take("telegram"); len(m) != 1 || !strings.HasPrefix(m[0].Subject, "[resolved]") {
		t.Errorf("no recovery notice for a finding open longer than the retention: %+v", m)
	}
}

// Retention boundaries: a resolved finding is pruned only once it resolved
// before the cut, an open one never; an issuance stays while its finding
// is open and goes once it resolved.
func TestPruneBoundaries(t *testing.T) {
	e, stub := ctEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	c := ca.leaf(t, now.Add(-days(10)), now.Add(days(900)), "portal.example.nl")
	e.apply(tg.ID, result(untrusted("192.0.2.1", c)))
	e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert))) // resolves at now
	d := e.watch("example.nl")
	_ = e.svc.PollDomains(e.ctx)
	e.clock.Add(2 * time.Hour)
	stub.add(20, "admin.example.nl", "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV", "CD01", e.clock.Now().Add(-time.Hour))
	stub.add(21, "vpn.example.nl", "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV", "CD02", e.clock.Now().Add(-time.Hour))
	_ = e.svc.PollDomains(e.ctx)
	iss, _ := e.svc.Issuances(e.ctx, d.ID, 0)
	if len(iss) != 2 {
		t.Fatalf("issuances: %+v", iss)
	}
	// Resolve one of the two unexpected findings.
	f := e.domainFindings(d.ID)[check.UnexpectedCertificate]
	if _, err := e.svc.Acknowledge(e.ctx, f.ID, "op", time.Time{}, ""); err != nil {
		t.Fatal(err)
	}

	// Exactly at the boundary nothing goes.
	resolvedAt := e.count("SELECT resolved_at FROM findings WHERE target_id = ? AND kind = 'chain_untrusted'", tg.ID)
	e.clock.Add(time.Unix(int64(resolvedAt), 0).Add(days(180)).Sub(e.clock.Now()))
	if err := e.svc.Prune(e.ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.count("SELECT COUNT(*) FROM findings WHERE target_id = ?", tg.ID); n != 1 {
		t.Fatalf("finding resolved exactly 180 days ago pruned: %d left", n)
	}
	e.clock.Add(days(1))
	if err := e.svc.Prune(e.ctx); err != nil {
		t.Fatal(err)
	}
	if n := e.count("SELECT COUNT(*) FROM findings WHERE target_id = ?", tg.ID); n != 0 {
		t.Fatalf("finding resolved 181 days ago kept: %d", n)
	}
	iss, _ = e.svc.Issuances(e.ctx, d.ID, 0)
	if len(iss) != 1 || iss[0].State != IssuanceUnexpected {
		t.Fatalf("issuances after the retention: %+v", iss)
	}
	if n := len(e.domainFindings(d.ID)); n != 1 {
		t.Fatalf("open domain findings: %d", n)
	}
}

// Deleting a node is refused while targets are probed from it; with "move"
// they go to the server as a new vantage point, the node's findings and
// alerts go with it, and history keeps its observations.
func TestDeleteNodeCascades(t *testing.T) {
	e := newEnv(t)
	n := e.confirmedNode("dc1")
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(func(t *Target) { t.NodeID = n.ID })
	e.apply(tg.ID, result(served("192.0.2.1", ca.leaf(t, now.Add(-days(10)), now.Add(days(300)), "portal.example.nl"), ca.cert)))
	node, _ := e.svc.Node(e.ctx, n.ID)
	if err := e.svc.NodeOffline(e.ctx, node, now); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteNode(e.ctx, n.ID, false); !errors.Is(err, ErrNodeInUse) {
		t.Fatalf("delete in use: %v", err)
	}
	if err := e.svc.DeleteNode(e.ctx, n.ID, true); err != nil {
		t.Fatal(err)
	}
	got, _ := e.svc.Target(e.ctx, tg.ID)
	if got.NodeID != 0 || got.NextCheck != 0 || got.CurrentFP == "" {
		t.Fatalf("moved target: node %d next %d fp %q", got.NodeID, got.NextCheck, got.CurrentFP)
	}
	if n := e.count("SELECT COUNT(*) FROM observations WHERE target_id = ?", tg.ID); n != 1 {
		t.Fatalf("observations after the node went: %d", n)
	}
	if n := e.count("SELECT COUNT(*) FROM observations WHERE node_id IS NOT NULL"); n != 0 {
		t.Fatalf("observations still pointing at the deleted node: %d", n)
	}
	if n := e.count("SELECT COUNT(*) FROM findings WHERE node_id IS NOT NULL"); n != 0 {
		t.Fatalf("node findings left: %d", n)
	}
	if n := e.count("SELECT COUNT(*) FROM alerts WHERE finding_id NOT IN (SELECT id FROM findings)"); n != 0 {
		t.Fatalf("orphaned alerts: %d", n)
	}
	if err := e.svc.DeleteNode(e.ctx, n.ID, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

// Replacing a bundle that no longer exists is an error, not a silent
// success.
func TestSaveBundleUnknownID(t *testing.T) {
	e := newEnv(t)
	pemData := pemOf(newCA(t, "Internal").cert)
	if _, err := e.svc.SaveBundle(e.ctx, 4242, "ghost", pemData); err == nil {
		t.Errorf("replacing bundle 4242 that does not exist succeeded; %d bundles stored", e.count("SELECT COUNT(*) FROM ca_bundles"))
	}
}

// A replaced bundle takes effect on the next check: the cached pool is
// dropped. Names are unique.
func TestBundleReplaceAndUniqueName(t *testing.T) {
	e := newEnv(t)
	a, b := newCA(t, "Internal A"), newCA(t, "Internal B")
	id, err := e.svc.SaveBundle(e.ctx, 0, "internal", pemOf(a.cert))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SaveBundle(e.ctx, 0, " internal ", pemOf(b.cert)); err == nil {
		t.Fatal("duplicate bundle name accepted")
	}
	p, err := e.svc.BundlePool(e.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	leaf := b.leaf(t, time.Now().Add(-time.Hour), time.Now().Add(days(30)), "portal.example.nl")
	if _, err := leaf.Verify(x509VerifyOpts(p)); err == nil {
		t.Fatal("leaf of B verified against bundle A")
	}
	if _, err := e.svc.SaveBundle(e.ctx, id, "internal", pemOf(b.cert)); err != nil {
		t.Fatal(err)
	}
	p, _ = e.svc.BundlePool(e.ctx, id)
	if _, err := leaf.Verify(x509VerifyOpts(p)); err != nil {
		t.Fatalf("replaced bundle not in effect: %v", err)
	}
	bs, _ := e.svc.Bundles(e.ctx)
	if len(bs) != 1 || len(bs[0].Certs) != 1 {
		t.Fatalf("bundles: %+v", bs)
	}
}

func pemOf(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func x509VerifyOpts(p *x509.CertPool) x509.VerifyOptions {
	return x509.VerifyOptions{Roots: p, DNSName: "portal.example.nl"}
}
