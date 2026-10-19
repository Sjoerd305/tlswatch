package core

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

// enrolledNode creates a node and enrols it with its token; it is pending.
func (e *env) enrolledNode(host string) (Node, string) {
	e.t.Helper()
	_, tok, err := e.svc.CreateNode(e.ctx, "admin@example.nl")
	if err != nil {
		e.t.Fatal(err)
	}
	n, cred, err := e.svc.EnrolNode(e.ctx, tok, Enrolment{Facts: NodeFacts{Hostname: host}, Pool: 4, Version: "v1.0.0", Address: "198.51.100.7"})
	if err != nil {
		e.t.Fatal(err)
	}
	return n, cred
}

// confirmedNode enrols and confirms a node.
func (e *env) confirmedNode(name string) Node {
	e.t.Helper()
	n, _ := e.enrolledNode(name + ".internal")
	if err := e.svc.ConfirmNode(e.ctx, n.ID, name, "admin@example.nl"); err != nil {
		e.t.Fatal(err)
	}
	n, _ = e.svc.Node(e.ctx, n.ID)
	return n
}

// Enrolment: a one-time token gives a pending node that takes no targets
// until confirmed; the token is spent by the exchange.
func TestNodeEnrolConfirm(t *testing.T) {
	e := newEnv(t)
	e.svc.Key, _ = secret.New(make([]byte, 32))
	id, tok, err := e.svc.CreateNode(e.ctx, "admin@example.nl")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := e.svc.ValidNodeToken(e.ctx, tok); !ok {
		t.Fatal("fresh token not valid")
	}
	if got, _ := e.svc.NodeToken(e.ctx, id); got != tok {
		t.Fatalf("sealed token %q", got)
	}
	n, cred, err := e.svc.EnrolNode(e.ctx, tok, Enrolment{Facts: NodeFacts{Hostname: "probe-1"}, Pool: 999})
	if err != nil {
		t.Fatal(err)
	}
	if n.State != NodePending || n.PoolSize != 4 || n.Label() != "probe-1" {
		t.Fatalf("enrolled: %+v", n)
	}
	if _, _, err := e.svc.EnrolNode(e.ctx, tok, Enrolment{}); !errors.Is(err, ErrBadToken) {
		t.Fatalf("token spent twice: %v", err)
	}
	if ok, _ := e.svc.ValidNodeToken(e.ctx, tok); ok {
		t.Fatal("spent token still serves the install script")
	}
	if got, _ := e.svc.NodeByCredential(e.ctx, cred); got.ID != n.ID {
		t.Fatal("credential does not find the node")
	}
	if _, err := e.svc.SaveTarget(e.ctx, Target{Name: "x", Host: "x.example.nl", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem, NodeID: n.ID, Enabled: true}, "op"); err == nil {
		t.Fatal("target assigned to a pending node")
	}
	if err := e.svc.ConfirmNode(e.ctx, n.ID, "  ", "admin"); err == nil {
		t.Fatal("confirmed without a name")
	}
	if err := e.svc.ConfirmNode(e.ctx, n.ID, "dc1", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ConfirmNode(e.ctx, n.ID, "dc1", "admin"); err == nil {
		t.Fatal("confirmed twice")
	}
	e.target(func(t *Target) { t.NodeID = n.ID })

	// An expired token is refused.
	_, tok2, _ := e.svc.CreateNode(e.ctx, "admin")
	e.clock.Add(NodeTokenTTL + time.Second)
	if _, _, err := e.svc.EnrolNode(e.ctx, tok2, Enrolment{}); !errors.Is(err, ErrBadToken) {
		t.Fatalf("expired token: %v", err)
	}
}

// Rotating the credential revokes the old one at once; re-enrolling with
// the new token waits for confirmation and keeps the name and targets;
// rejecting that revokes the new credential and keeps the node.
func TestNodeRotateCredential(t *testing.T) {
	e := newEnv(t)
	e.svc.Key, _ = secret.New(make([]byte, 32))
	n, cred := e.enrolledNode("probe-1")
	if err := e.svc.ConfirmNode(e.ctx, n.ID, "dc1", "admin"); err != nil {
		t.Fatal(err)
	}
	tg := e.target(func(t *Target) { t.NodeID = n.ID })

	tok, err := e.svc.RenewNodeToken(e.ctx, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.NodeByCredential(e.ctx, cred); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old credential still works: %v", err)
	}
	if got, _ := e.svc.NodeToken(e.ctx, n.ID); got != tok {
		t.Fatal("the new install command is not shown")
	}
	if _, err := e.svc.RenewNodeToken(e.ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotate unknown node: %v", err)
	}
	re, cred2, err := e.svc.EnrolNode(e.ctx, tok, Enrolment{Facts: NodeFacts{Hostname: "probe-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if re.ID != n.ID || re.State != NodePending || re.Name != "dc1" || re.Targets != 1 {
		t.Fatalf("re-enrolled: %+v", re)
	}
	if err := e.svc.RejectNode(e.ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.NodeByCredential(e.ctx, cred2); !errors.Is(err, ErrNotFound) {
		t.Fatal("rejected credential still works")
	}
	got, err := e.svc.Node(e.ctx, n.ID)
	if err != nil || got.State != NodeConfirmed || got.HasCredential || got.Targets != 1 {
		t.Fatalf("after rejecting a re-enrolment: %+v %v", got, err)
	}
	if got, _ := e.svc.Target(e.ctx, tg.ID); got.NodeID != n.ID {
		t.Fatal("rejection moved the target")
	}
	if err := e.svc.RejectNode(e.ctx, n.ID); err == nil {
		t.Fatal("rejected a confirmed node")
	}
}

// Rejecting a node that was never confirmed deletes it with its credential.
func TestNodeRejectNew(t *testing.T) {
	e := newEnv(t)
	n, cred := e.enrolledNode("stranger")
	if err := e.svc.RejectNode(e.ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Node(e.ctx, n.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected node kept: %v", err)
	}
	if _, err := e.svc.NodeByCredential(e.ctx, cred); !errors.Is(err, ErrNotFound) {
		t.Fatal("credential kept")
	}
	if err := e.svc.RejectNode(e.ctx, n.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reject twice: %v", err)
	}
}

// After an hour: an install command that never ran and a node never
// confirmed are deleted; a confirmed node's spare token is dropped, and a
// re-enrolment that was not confirmed is revoked.
func TestExpireNodes(t *testing.T) {
	e := newEnv(t)
	idle, _, _ := e.svc.CreateNode(e.ctx, "admin")
	pending, _ := e.enrolledNode("pending")
	conf := e.confirmedNode("dc1")
	spare, _ := e.svc.RenewNodeToken(e.ctx, conf.ID)
	reen := e.confirmedNode("dc2")
	e.target(func(t *Target) { t.NodeID = reen.ID })
	tok, _ := e.svc.RenewNodeToken(e.ctx, reen.ID)
	if _, _, err := e.svc.EnrolNode(e.ctx, tok, Enrolment{}); err != nil {
		t.Fatal(err)
	}

	e.clock.Add(NodeTokenTTL - time.Minute)
	if err := e.svc.ExpireNodes(e.ctx); err != nil {
		t.Fatal(err)
	}
	if ns, _ := e.svc.Nodes(e.ctx); len(ns) != 4 {
		t.Fatalf("expired early: %d nodes", len(ns))
	}
	e.clock.Add(2 * time.Minute)
	if err := e.svc.ExpireNodes(e.ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{idle, pending.ID} {
		if _, err := e.svc.Node(e.ctx, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("node %d kept: %v", id, err)
		}
	}
	if ok, _ := e.svc.ValidNodeToken(e.ctx, spare); ok {
		t.Error("spare token of a confirmed node kept")
	}
	if c, err := e.svc.Node(e.ctx, conf.ID); err != nil || c.State != NodeConfirmed {
		t.Errorf("confirmed node: %+v %v", c, err)
	}
	r, err := e.svc.Node(e.ctx, reen.ID)
	if err != nil || r.State != NodeConfirmed || r.HasCredential || r.Targets != 1 {
		t.Errorf("unconfirmed re-enrolment: %+v %v", r, err)
	}
}

func TestSaveNode(t *testing.T) {
	e := newEnv(t)
	n := e.confirmedNode("dc1")
	for _, c := range []struct{ name, notes string }{{"", ""}, {strings.Repeat("x", 81), ""}, {"ok", strings.Repeat("n", 4001)}} {
		if err := e.svc.SaveNode(e.ctx, n.ID, c.name, c.notes); err == nil {
			t.Errorf("saved name %d chars, notes %d chars", len(c.name), len(c.notes))
		}
	}
	if err := e.svc.SaveNode(e.ctx, n.ID, " dc-one ", "rack 4\r\nrow 2 "); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.Node(e.ctx, n.ID); got.Name != "dc-one" || got.Notes != "rack 4\nrow 2" {
		t.Fatalf("saved: %q %q", got.Name, got.Notes)
	}
	if err := e.svc.SaveNode(e.ctx, 9999, "x", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown node: %v", err)
	}
}

// node_offline: a warning on every enabled channel whose floor allows it,
// critical (with an escalation) once a target under the node is overdue by
// more than its interval, reminded, and resolved with a recovery notice
// when the node polls again.
func TestNodeOfflineLifecycle(t *testing.T) {
	e := newEnv(t)
	n := e.confirmedNode("dc1")
	tg := e.target(func(t *Target) { t.NodeID = n.ID; t.AllChannels = false; t.ChannelIDs = nil })
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	e.apply(tg.ID, result(served("192.0.2.1", ca.leaf(t, now.Add(-days(10)), now.Add(days(300)), "portal.example.nl"), ca.cert)))
	n, _ = e.svc.Node(e.ctx, n.ID)
	seen := e.clock.Now()
	e.clock.Add(10 * time.Minute)
	if err := e.svc.NodeOffline(e.ctx, n, seen); err != nil {
		t.Fatal(err)
	}
	fs, _ := e.svc.Findings(e.ctx, FindingFilter{})
	if len(fs) != 1 || fs[0].Kind != check.NodeOffline || fs[0].Severity != check.Warning || fs[0].TargetName != "dc1" || fs[0].NodeID != n.ID {
		t.Fatalf("findings: %+v", fs)
	}
	if !strings.Contains(fs[0].Details, "1 target waits") {
		t.Fatalf("details: %q", fs[0].Details)
	}
	// Repeated while offline: no new alert.
	if err := e.svc.NodeOffline(e.ctx, n, seen); err != nil {
		t.Fatal(err)
	}
	e.flush()
	if m := e.take("mail"); len(m) != 1 || !strings.Contains(m[0].Subject, "node dc1") {
		t.Fatalf("mail: %+v", m)
	}
	if m := e.take("telegram"); len(m) != 0 {
		t.Fatalf("telegram (critical floor) got the warning: %+v", m)
	}

	// The target is overdue by more than its interval: critical.
	e.clock.Add(days(3))
	if err := e.svc.NodeOffline(e.ctx, n, seen); err != nil {
		t.Fatal(err)
	}
	fs, _ = e.svc.Findings(e.ctx, FindingFilter{})
	if fs[0].Severity != check.Critical {
		t.Fatalf("not escalated: %+v", fs[0])
	}
	e.flush()
	if m := e.take("telegram"); len(m) != 1 || !strings.HasPrefix(m[0].Subject, "[critical]") {
		t.Fatalf("telegram escalation: %+v", m)
	}
	e.take("mail")

	// Reminded at the critical interval of the defaults.
	e.clock.Add(25 * time.Hour)
	if q, err := e.svc.Remind(e.ctx); err != nil || q != 2 {
		t.Fatalf("node reminders: %d %v", q, err)
	}
	e.flush()
	e.take("mail")
	e.take("telegram")

	if err := e.svc.NodeOnline(e.ctx, n); err != nil {
		t.Fatal(err)
	}
	if fs, _ = e.svc.Findings(e.ctx, FindingFilter{}); len(fs) != 0 {
		t.Fatalf("still open: %+v", fs)
	}
	e.flush()
	if m := e.take("telegram"); len(m) != 1 || !strings.HasPrefix(m[0].Subject, "[resolved]") {
		t.Fatalf("telegram recovery: %+v", m)
	}
	if m := e.take("mail"); len(m) != 1 || !strings.HasPrefix(m[0].Subject, "[resolved]") {
		t.Fatalf("mail recovery: %+v", m)
	}
	if err := e.svc.NodeOnline(e.ctx, n); err != nil {
		t.Fatal("online twice:", err)
	}
}

// Disabling a node that owns targets is allowed at any time, keeps the
// targets on it, and closes node_offline without a recovery notice.
func TestDisableNodeWithTargets(t *testing.T) {
	e := newEnv(t)
	n := e.confirmedNode("dc1")
	tg := e.target(func(t *Target) { t.NodeID = n.ID })
	n, _ = e.svc.Node(e.ctx, n.ID)
	if err := e.svc.NodeOffline(e.ctx, n, time.Time{}); err != nil {
		t.Fatal(err)
	}
	e.flush()
	e.take("mail")
	if err := e.svc.SetNodeEnabled(e.ctx, n.ID, false); err != nil {
		t.Fatal(err)
	}
	if fs, _ := e.svc.Findings(e.ctx, FindingFilter{}); len(fs) != 0 {
		t.Fatalf("node_offline left open on a disabled node: %+v", fs)
	}
	e.flush()
	if m := e.take("mail"); len(m) != 0 {
		t.Fatalf("disabling sent a recovery: %+v", m)
	}
	if got, _ := e.svc.Target(e.ctx, tg.ID); got.NodeID != n.ID || !got.Enabled {
		t.Fatalf("target after disabling its node: %+v", got)
	}
	if err := e.svc.SetNodeEnabled(e.ctx, 9999, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown node: %v", err)
	}
}

// A target already assigned to a node can still be edited while that node
// re-enrols after a credential rotation; only a new assignment needs a
// confirmed node.
func TestEditTargetOfReenrollingNode(t *testing.T) {
	e := newEnv(t)
	n := e.confirmedNode("dc1")
	tg := e.target(func(t *Target) { t.NodeID = n.ID })
	tok, _ := e.svc.RenewNodeToken(e.ctx, n.ID)
	if _, _, err := e.svc.EnrolNode(e.ctx, tok, Enrolment{}); err != nil {
		t.Fatal(err)
	}
	tg.Notes = "owner: ops"
	if _, err := e.svc.SaveTarget(e.ctx, tg, "op"); err != nil {
		t.Errorf("editing the notes of a target on a re-enrolling node: %v", err)
	}
}

// A failed update stays on the node until it runs another version than the
// one it failed from: reinstalled by hand, it is no longer "update failed".
func TestFailedUpdateClearsOnAnotherVersion(t *testing.T) {
	e := newEnv(t)
	n := e.confirmedNode("edge")
	if err := e.svc.TouchNode(e.ctx, n.ID, e.clock.Now(), "v0.0.3", 1, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	n, _ = e.svc.Node(e.ctx, n.ID)
	if err := e.svc.StartNodeUpdate(e.ctx, n, "v0.0.5"); err != nil {
		t.Fatal(err)
	}
	n, _ = e.svc.Node(e.ctx, n.ID)
	if err := e.svc.EndNodeUpdate(e.ctx, n, "the download needs a node credential"); err != nil {
		t.Fatal(err)
	}
	_ = e.svc.TouchNode(e.ctx, n.ID, e.clock.Now(), "v0.0.3", 1, "192.0.2.1")
	if n, _ = e.svc.Node(e.ctx, n.ID); n.UpdateFailed == "" {
		t.Fatal("failure forgotten while the node still runs the old version")
	}
	_ = e.svc.TouchNode(e.ctx, n.ID, e.clock.Now(), "v0.0.5", 1, "192.0.2.1")
	if n, _ = e.svc.Node(e.ctx, n.ID); n.UpdateFailed != "" {
		t.Fatalf("still update failed on v0.0.5: %q", n.UpdateFailed)
	}
}

// A link-local address that comes and goes is not a move worth an audit
// entry every hour; a changed routable address is.
func TestNodeFactsAuditIgnoresLinkLocal(t *testing.T) {
	e := newEnv(t)
	n := e.confirmedNode("edge")
	facts := func(addrs ...string) NodeFacts {
		return NodeFacts{Hostname: "edge", Interfaces: []NodeInterface{{Name: "eth0", Addrs: addrs}}}
	}
	report := func(f NodeFacts) {
		n, _ = e.svc.Node(e.ctx, n.ID)
		if err := e.svc.SaveNodeFacts(e.ctx, n, f); err != nil {
			t.Fatal(err)
		}
	}
	report(facts("192.168.1.157/24", "fe80::1/64"))
	before := e.count("SELECT COUNT(*) FROM audit WHERE action = 'node.facts'")
	report(facts("192.168.1.157/24", "fe80::1/64", "fe80::2/64"))
	report(facts("192.168.1.157/24", "fe80::1/64"))
	if n := e.count("SELECT COUNT(*) FROM audit WHERE action = 'node.facts'"); n != before {
		t.Fatalf("%d audit entries for link-local addresses coming and going", n-before)
	}
	report(facts("192.168.1.158/24", "fe80::1/64"))
	if n := e.count("SELECT COUNT(*) FROM audit WHERE action = 'node.facts'"); n != before+1 {
		t.Fatalf("a changed routable address: %d entries", n-before)
	}
}

// A node that starts probing more, or less, shows in the audit log; its
// first report of the limits, after an update, is not a change.
func TestNodeFactsAuditAllowlist(t *testing.T) {
	e := newEnv(t)
	n := e.confirmedNode("edge")
	report := func(l *NodeLimits) {
		n, _ = e.svc.Node(e.ctx, n.ID)
		if err := e.svc.SaveNodeFacts(e.ctx, n, NodeFacts{Hostname: "edge", Limits: l}); err != nil {
			t.Fatal(err)
		}
	}
	report(nil)
	before := e.count("SELECT COUNT(*) FROM audit WHERE action = 'node.facts'")
	report(&NodeLimits{Allow: []string{"10.0.0.0/8"}, From: NodeLimitsEnv})
	report(&NodeLimits{Allow: []string{"10.0.0.0/8"}, From: NodeLimitsEnv, EnvFile: "/etc/tlswatch-node.env"})
	if got := e.count("SELECT COUNT(*) FROM audit WHERE action = 'node.facts'"); got != before {
		t.Fatalf("%d audit entries without a change of the allowlist", got-before)
	}
	report(&NodeLimits{From: NodeLimitsEnv, AllowLocal: true})
	if got := e.count("SELECT COUNT(*) FROM audit WHERE action = 'node.facts' AND details LIKE '%allowlist 10.0.0.0/8 → any%' AND details LIKE '%local addresses false → true%'"); got != 1 {
		t.Fatalf("a widened allowlist: %d entries", got)
	}
	if n, _ = e.svc.Node(e.ctx, n.ID); n.Facts.Limits == nil || !n.Facts.Limits.AllowLocal {
		t.Fatalf("limits not stored: %+v", n.Facts.Limits)
	}
}

// "N targets wait" counts the enabled targets only.
func TestNodeOfflineCountsEnabledTargets(t *testing.T) {
	e := newEnv(t)
	n := e.confirmedNode("dc1")
	e.target(func(t *Target) { t.NodeID = n.ID })
	e.target(func(t *Target) {
		t.NodeID = n.ID
		t.Name, t.Host, t.ServerName, t.Enabled = "Off", "off.example.nl", "off.example.nl", false
	})
	n, _ = e.svc.Node(e.ctx, n.ID)
	e.clock.Add(10 * time.Minute)
	if err := e.svc.NodeOffline(e.ctx, n, e.clock.Now().Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	fs, _ := e.svc.Findings(e.ctx, FindingFilter{})
	if len(fs) != 1 || !strings.Contains(fs[0].Details, "1 target waits") {
		t.Fatalf("findings: %+v", fs)
	}
}

// Confirm and Reject pressed at once on a pending node: never both. A node
// that was confirmed is not deleted or revoked by the Reject that lost.
func TestConfirmRejectRace(t *testing.T) {
	e := newEnv(t)
	for i := range 40 {
		n, _ := e.enrolledNode(fmt.Sprintf("race%d.internal", i))
		var wg sync.WaitGroup
		var confirmErr, rejectErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			confirmErr = e.svc.ConfirmNode(e.ctx, n.ID, fmt.Sprintf("race%d", i), "admin@example.nl")
		}()
		go func() { defer wg.Done(); rejectErr = e.svc.RejectNode(e.ctx, n.ID) }()
		wg.Wait()
		if (confirmErr == nil) == (rejectErr == nil) {
			t.Fatalf("round %d: confirm %v, reject %v", i, confirmErr, rejectErr)
		}
		got, err := e.svc.Node(e.ctx, n.ID)
		if confirmErr == nil && (err != nil || got.State != NodeConfirmed || !got.HasCredential) {
			t.Fatalf("round %d: confirmed node after the losing reject: %+v, %v", i, got, err)
		}
	}
}
