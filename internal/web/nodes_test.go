package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// The Add node flow: refused without a public URL, then the command screen,
// the arrival screen with the reported facts, confirmation, and the node
// under "Probe from" and in the targets list.
func TestAddNodeFlow(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	c := hs.srv.Core
	rec := hs.do(authz.Admin, http.MethodPost, "/settings/nodes", nil, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/settings/nodes" {
		t.Fatalf("Add node without a public URL: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if n, _ := c.Nodes(ctx); len(n) != 0 {
		t.Fatal("a node was created without a public URL")
	}
	if err := hs.srv.Settings.SaveGeneral(ctx, config.General{BaseURL: "https://tlswatch.example.nl"}); err != nil {
		t.Fatal(err)
	}
	rec = hs.do(authz.Admin, http.MethodPost, "/settings/nodes", nil, true)
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/settings/nodes/") {
		t.Fatalf("Add node: %d %s", rec.Code, loc)
	}
	var id int64
	fmt.Sscanf(loc, "/settings/nodes/%d", &id)
	tok, err := c.NodeToken(ctx, id)
	if err != nil || tok == "" {
		t.Fatalf("token: %q %v", tok, err)
	}
	page := hs.do(authz.Admin, http.MethodGet, loc, nil, false).Body.String()
	for _, want := range []string{"curl -fsSL https://tlswatch.example.nl/agent/v1/install/" + tok + " | sudo sh", "Waiting for the node to connect", "docker run"} {
		if !strings.Contains(page, want) {
			t.Errorf("command screen lacks %q", want)
		}
	}
	// The machine enrols: the page shows what it reported.
	if _, _, err := c.EnrolNode(ctx, tok, core.Enrolment{Address: "198.51.100.7", Version: "test",
		Facts: core.NodeFacts{Hostname: "probe-ams1", OS: "Ubuntu 24.04 LTS", Arch: "linux/amd64",
			Interfaces: []core.NodeInterface{{Name: "eth0", Addrs: []string{"10.0.3.2/24"}}}}}); err != nil {
		t.Fatal(err)
	}
	page = hs.do(authz.Admin, http.MethodGet, loc, nil, false).Body.String()
	for _, want := range []string{"probe-ams1", "Ubuntu 24.04 LTS", "10.0.3.2/24", "198.51.100.7", "Confirm node", `value="probe-ams1"`} {
		if !strings.Contains(page, want) {
			t.Errorf("arrival screen lacks %q", want)
		}
	}
	if strings.Contains(page, tok) {
		t.Error("the spent token is still shown")
	}
	rec = hs.do(authz.Admin, http.MethodPost, loc+"/confirm", url.Values{"name": {"Amsterdam DC"}}, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body.String())
	}
	form := hs.do(authz.Operator, http.MethodGet, "/targets/new", nil, false).Body.String()
	if !strings.Contains(form, "Probe from") || !strings.Contains(form, "Node Amsterdam DC") {
		t.Error("target form has no Probe from with the node")
	}
	rec = hs.do(authz.Operator, http.MethodPost, "/targets/new", url.Values{"host": {"intranet.example"}, "protocol": {"tls"},
		"trust_mode": {"system"}, "node_id": {fmt.Sprint(id)}, "all_channels": {"1"}, "action": {"save"}}, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save target on node: %d %s", rec.Code, rec.Body.String())
	}
	list := hs.do(authz.Viewer, http.MethodGet, "/targets", nil, false).Body.String()
	if !strings.Contains(list, `data-chip-key="node" data-chip-value="`+fmt.Sprint(id)+`"`) || !strings.Contains(list, ">Amsterdam DC<") {
		t.Error("targets list has no node chip or column")
	}
	nodes := hs.do(authz.Admin, http.MethodGet, "/settings/nodes", nil, false).Body.String()
	if !strings.Contains(nodes, "Amsterdam DC") || !strings.Contains(nodes, "probe-ams1") {
		t.Error("nodes list lacks the node")
	}
	// Deleting it moves its target to this server.
	if page := hs.do(authz.Admin, http.MethodGet, loc+"/delete", nil, false).Body.String(); !strings.Contains(page, "Move 1 to this server") {
		t.Error("delete page does not offer to move the target")
	}
	rec = hs.do(authz.Admin, http.MethodPost, loc+"/delete", url.Values{"confirm": {"yes"}, "move": {"yes"}}, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d", rec.Code)
	}
	ts, _ := c.Targets(ctx)
	for _, tg := range ts {
		if tg.NodeID != 0 {
			t.Errorf("target %s still on a node", tg.Name)
		}
	}
}

// A target on an offline node shows "Waiting for node", and Check now says
// why it cannot run.
func TestWaitingForNode(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	c := hs.srv.Core
	id, tok, _ := c.CreateNode(ctx, "admin")
	if _, _, err := c.EnrolNode(ctx, tok, core.Enrolment{Facts: core.NodeFacts{Hostname: "p"}}); err != nil {
		t.Fatal(err)
	}
	_ = c.ConfirmNode(ctx, id, "dc1", "admin")
	_ = c.SetNodeEnabled(ctx, id, false)
	tid, err := c.SaveTarget(ctx, core.Target{Name: "inside", Host: "intranet.example", Port: 443, Protocol: probe.TLS,
		Trust: probe.TrustSystem, AllChannels: true, Enabled: true, NodeID: id}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	page := hs.do(authz.Viewer, http.MethodGet, fmt.Sprintf("/targets/%d", tid), nil, false).Body.String()
	if !strings.Contains(page, "Waiting for node") {
		t.Error("target page does not say it waits for the node")
	}
	rec := hs.do(authz.Operator, http.MethodPost, fmt.Sprintf("/api/v1/targets/%d/check", tid), nil, true)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "offline") {
		t.Errorf("check now on an offline node: %d %s", rec.Code, rec.Body.String())
	}
}

// While a node enrols, live pages poll quickly, and its arrival changes
// the stamp, so the Add node screen swaps in the machine's facts.
func TestStampFollowsEnrolment(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	c := hs.srv.Core
	stamp := func() (string, bool) {
		var r struct {
			Stamp string `json:"stamp"`
			Busy  bool   `json:"busy"`
		}
		rec := hs.do(authz.Admin, http.MethodGet, "/api/v1/stamp", nil, false)
		if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return r.Stamp, r.Busy
	}
	// The harness target counts as never checked, which is busy too.
	if _, err := c.DB.W.Exec("UPDATE targets SET last_check = 1"); err != nil {
		t.Fatal(err)
	}
	before, busy := stamp()
	if busy {
		t.Fatal("busy before any enrolment")
	}
	id, tok, _ := c.CreateNode(ctx, "admin")
	afterCreate, busy := stamp()
	if !busy {
		t.Error("not busy while an install token is out")
	}
	if _, _, err := c.EnrolNode(ctx, tok, core.Enrolment{Facts: core.NodeFacts{Hostname: "p"}}); err != nil {
		t.Fatal(err)
	}
	afterEnrol, busy := stamp()
	if afterEnrol == afterCreate || afterCreate == before {
		t.Errorf("stamp did not change: %s %s %s", before, afterCreate, afterEnrol)
	}
	if !busy {
		t.Error("not busy while a node waits for confirmation")
	}
	_ = c.ConfirmNode(ctx, id, "dc1", "admin")
	if _, busy := stamp(); busy {
		t.Error("still busy after the node was confirmed")
	}
	// A running update is followed quickly too, and its end changes the
	// stamp.
	n, _ := c.Node(ctx, id)
	if err := c.StartNodeUpdate(ctx, n, "v9.9.9"); err != nil {
		t.Fatal(err)
	}
	afterStart, busy := stamp()
	if !busy {
		t.Error("not busy while a node updates")
	}
	n, _ = c.Node(ctx, id)
	if err := c.EndNodeUpdate(ctx, n, "404 Not Found"); err != nil {
		t.Fatal(err)
	}
	if afterEnd, busy := stamp(); busy || afterEnd == afterStart {
		t.Errorf("after the update ended: busy %v, stamp %s then %s", busy, afterStart, afterEnd)
	}
}
