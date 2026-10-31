package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"html"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// Discover: a scan of a private range runs, lists what answered, and hands
// the ticked endpoints to Add many with the protocol of their port and the
// certificate's name as server name where it resolves to the address.
func TestDiscoverFlow(t *testing.T) {
	hs := newHarness(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "intranet.example.nl"},
		DNSNames: []string{"*.example.nl", "intranet.example.nl"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	cert, _ := x509.ParseCertificate(der)
	hs.srv.Sched.Scan = func(_ context.Context, req probe.ScanRequest) (probe.ScanResult, error) {
		return probe.ScanResult{Probed: len(req.Addresses) * len(req.Ports), Hits: []probe.ScanHit{
			{IP: "10.0.0.1", Port: 443, Protocol: probe.TLS, TLSVersion: "TLS 1.3", Chain: []*x509.Certificate{cert}},
			{IP: "10.0.0.2", Port: 587, Protocol: probe.SMTP, TLSVersion: "TLS 1.2", Chain: []*x509.Certificate{cert}},
		}}, nil
	}
	hs.srv.LookupHost = func(_ context.Context, name string) ([]string, error) {
		if name == "intranet.example.nl" {
			return []string{"10.0.0.1"}, nil
		}
		return nil, &url.Error{Op: "lookup", URL: name}
	}

	if rec := hs.do(authz.Operator, "POST", "/targets/discover", url.Values{"ranges": {"8.8.8.0/24"}}, true); rec.Code != http.StatusBadRequest ||
		!strings.Contains(html.UnescapeString(rec.Body.String()), "is not a private range") {
		t.Fatalf("public range: %d", rec.Code)
	}
	rec := hs.do(authz.Operator, "POST", "/targets/discover", url.Values{"ranges": {"10.0.0.0/30"}, "ports": {"443, 587"}, "rate": {"100"}}, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/scans/1" {
		t.Fatalf("start: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	ctx := context.Background()
	deadline := time.Now().Add(5 * time.Second)
	for sc, _ := hs.srv.Core.Scan(ctx, 1); sc.State == core.ScanRunning; sc, _ = hs.srv.Core.Scan(ctx, 1) {
		if time.Now().After(deadline) {
			t.Fatal("scan did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	page := hs.do(authz.Operator, "GET", "/scans/1", nil, false).Body.String()
	if !strings.Contains(page, "10.0.0.1:443") || !strings.Contains(page, `<span class="tag">smtp</span>`) || !strings.Contains(page, "2 without a target") {
		t.Fatal("scan page does not list the endpoints")
	}
	list := hs.do(authz.Operator, "GET", "/targets/discover", nil, false).Body.String()
	if !strings.Contains(list, `href="/scans/1"`) || !strings.Contains(list, "10.0.0.0/30") {
		t.Fatal("recent scans do not list the scan")
	}
	add := hs.do(authz.Operator, "POST", "/scans/1/add", url.Values{"id": {"1", "2"}}, true).Body.String()
	if !strings.Contains(add, "10.0.0.1:443 sni=intranet.example.nl intranet.example.nl\n10.0.0.2:587 protocol=smtp</textarea>") {
		t.Fatalf("Add many is not pre-filled:\n%s", add[strings.Index(add, `name="hosts"`):][:400])
	}
	if a, _ := hs.srv.Core.AuditLog(ctx, "scan.start", 5); len(a) != 1 || !strings.Contains(a[0].Details, "ranges=10.0.0.0/30 ports=443,587 rate=100 from=this server") {
		t.Fatalf("audit: %+v", a)
	}
}

// The domain page lists names of known certificates without a target and
// hands the ticked ones to Add many; an unexpected issuance offers "Add as
// target" beside Acknowledge, on the domain page and in the finding panel.
func TestDiscoverFromCT(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	id, err := hs.srv.Core.SaveDomain(ctx, core.Domain{Name: "example.nl", Subdomains: true, AllChannels: true, Enabled: true}, "test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, row := range []struct {
		serial, names, state string
	}{
		{"1", `["portal.example.nl","api.example.nl","*.dev.example.nl"]`, "known"},
		{"2", `["admin.example.nl"]`, "unexpected"},
	} {
		if _, err := hs.db.W.Exec(`INSERT INTO issuances(domain_id, issuer_cn, issuer_org, serial, names, not_before, not_after, first_seen, state)
			VALUES(?, 'R10', 'Let''s Encrypt', ?, ?, ?, ?, ?, ?)`, id, row.serial, row.names, now.Add(-time.Hour).Unix(), now.Add(80*24*time.Hour).Unix(), now.Unix(), row.state); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := hs.db.W.Exec(`INSERT INTO findings(domain_id, kind, severity, opened_at, details, fingerprint, last_alert_at)
		VALUES(?, 'unexpected_certificate', 'warning', ?, 'admin.example.nl by Let''s Encrypt', '2', ?)`, id, now.Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	page := hs.do(authz.Operator, "GET", fmt.Sprintf("/domains/%d", id), nil, false).Body.String()
	for _, want := range []string{"Names without a target", `name="hosts" value="api.example.nl"`, `name="hosts" value="portal.example.nl"`,
		`*.dev.example.nl <span class="tag"`, `href="/targets/bulk-add?hosts=admin.example.nl"`} {
		if !strings.Contains(page, want) {
			t.Errorf("domain page lacks %q", want)
		}
	}
	if strings.Contains(page, `value="*.dev.example.nl"`) {
		t.Error("a wildcard can be ticked")
	}
	add := hs.do(authz.Operator, "POST", "/targets/bulk-add", url.Values{"prefill": {"1"}, "hosts": {"api.example.nl", "portal.example.nl"}}, true).Body.String()
	if !strings.Contains(add, "api.example.nl\nportal.example.nl</textarea>") {
		t.Fatal("Add many is not pre-filled")
	}
	var fid int64
	_ = hs.db.R.QueryRow("SELECT id FROM findings WHERE domain_id = ?", id).Scan(&fid)
	panel := hs.do(authz.Operator, "GET", fmt.Sprintf("/findings?sel=%d", fid), nil, false).Body.String()
	if !strings.Contains(panel, `href="/targets/bulk-add?hosts=admin.example.nl" class="btn">Add as target`) {
		t.Fatal("the finding panel offers no Add as target")
	}
}

// Discover with Repeat: the scan is saved as a schedule and run as its first
// run; endpoints without a target become findings with Add as target; the
// schedule page, Run now, Pause and the REST endpoints work on it.
func TestDiscoverSchedule(t *testing.T) {
	hs := newHarness(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "intranet.example.nl"},
		DNSNames: []string{"intranet.example.nl"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	cert, _ := x509.ParseCertificate(der)
	hs.srv.Sched.Scan = func(_ context.Context, req probe.ScanRequest) (probe.ScanResult, error) {
		return probe.ScanResult{Probed: len(req.Addresses) * len(req.Ports), Hits: []probe.ScanHit{
			{IP: "10.0.0.1", Port: 443, Protocol: probe.TLS, TLSVersion: "TLS 1.3", Chain: []*x509.Certificate{cert}},
		}}, nil
	}
	hs.srv.LookupHost = func(_ context.Context, name string) ([]string, error) { return []string{"10.0.0.1"}, nil }
	ctx := context.Background()

	rec := hs.do(authz.Operator, "POST", "/targets/discover", url.Values{"ranges": {"10.0.0.0/30"}, "ports": {"443"}, "repeat": {"day"}, "hour": {"3"}, "name": {"Office"}}, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/scans/1" {
		t.Fatalf("start: %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	var open []core.Finding
	for len(open) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no finding from the first run")
		}
		time.Sleep(10 * time.Millisecond)
		open, _ = hs.srv.Core.Findings(ctx, core.FindingFilter{ScheduleID: 1})
	}
	if open[0].HostPort() != "10.0.0.1:443" || open[0].TargetName != "Office" {
		t.Fatalf("finding: %+v", open[0])
	}
	sc, err := hs.srv.Core.ScanSchedule(ctx, 1)
	if err != nil || sc.LastScanID != 1 || sc.CreatedBy != "op@example.nl" && sc.CreatedBy == "" {
		t.Fatalf("schedule: %+v %v", sc, err)
	}

	page := hs.do(authz.Operator, "GET", "/targets/discover", nil, false).Body.String()
	for _, want := range []string{`href="/targets/discover/schedules/1"`, "Office", "daily at 03:00", "Scheduled scans"} {
		if !strings.Contains(page, want) {
			t.Errorf("Discover lacks %q", want)
		}
	}
	page = hs.do(authz.Operator, "GET", "/targets/discover/schedules/1", nil, false).Body.String()
	for _, want := range []string{"10.0.0.1:443", "intranet.example.nl", "1 not in inventory", "Run now", "Pause", `href="/scans/1"`} {
		if !strings.Contains(page, want) {
			t.Errorf("schedule page lacks %q", want)
		}
	}
	page = hs.do(authz.Operator, "GET", "/scans/1", nil, false).Body.String()
	if !strings.Contains(page, `href="/targets/discover/schedules/1">its schedule</a>`) {
		t.Error("the scan page does not name its schedule")
	}
	panel := hs.do(authz.Operator, "GET", fmt.Sprintf("/findings?sel=%d", open[0].ID), nil, false).Body.String()
	if !strings.Contains(panel, `href="/targets/bulk-add?hosts=10.0.0.1%3A443&#43;sni%3Dintranet.example.nl&#43;intranet.example.nl" class="btn">Add as target`) {
		t.Fatal("the finding panel offers no Add as target with the scan line")
	}
	list := hs.do(authz.Operator, "GET", "/findings", nil, false).Body.String()
	if !strings.Contains(list, `href="/targets/discover/schedules/1" class="ink strong">Office</a>`) || !strings.Contains(list, "Endpoint not in inventory") {
		t.Error("the findings list does not link the schedule")
	}

	// Run now: a second scan; then pause: the finding resolves.
	rec = hs.do(authz.Operator, "POST", "/targets/discover/schedules/1/run", nil, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/scans/2" {
		t.Fatalf("run now: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	for sc, _ := hs.srv.Core.Scan(ctx, 2); sc.State == core.ScanRunning; sc, _ = hs.srv.Core.Scan(ctx, 2) {
		time.Sleep(10 * time.Millisecond)
	}
	if rec = hs.do(authz.Operator, "POST", "/targets/discover/schedules/1/enabled", url.Values{"enabled": {"0"}}, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("pause: %d", rec.Code)
	}
	if open, _ = hs.srv.Core.Findings(ctx, core.FindingFilter{ScheduleID: 1}); len(open) != 0 {
		t.Fatal("pausing left the finding open")
	}
	if rec = hs.do(authz.Operator, "POST", "/targets/discover/schedules/1", url.Values{"ranges": {"10.0.0.0/30"}, "ports": {"443, 8443"}, "rate": {"20"}, "repeat": {"week"}, "weekday": {"5"}, "hour": {"22"}, "name": {"Office"}}, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	if sc, _ = hs.srv.Core.ScanSchedule(ctx, 1); sc.Every != core.ScheduleWeekly || sc.Weekday != 5 || sc.Hour != 22 || sc.Rate != 20 || len(sc.Ports) != 2 || sc.Enabled {
		t.Fatalf("after save: %+v", sc)
	}
	if rec = hs.do(authz.Operator, "POST", "/targets/discover/schedules/1", url.Values{"ranges": {"8.8.8.0/24"}, "repeat": {"week"}}, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("public range saved: %d", rec.Code)
	}
	if rec = hs.do(authz.Viewer, "GET", "/targets/discover/schedules/1", nil, false); rec.Code == http.StatusOK {
		t.Fatal("a viewer sees the schedule page")
	}

	// The REST API.
	op := hs.apiToken(authz.Operator, authz.Operator)
	if rec := hs.api(op, "GET", "/api/v2/discovery/schedules", ""); rec.Code != http.StatusOK || len(decodeJSON[apiList](t, rec).Data.([]any)) != 1 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	rec = hs.api(op, "PATCH", "/api/v2/discovery/schedules/1", `{"enabled":true,"hour":5}`)
	if d := decodeJSON[map[string]any](t, rec); rec.Code != http.StatusOK || d["enabled"] != true || d["hour"] != float64(5) || d["next_run"] == nil {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body.String())
	}
	if rec := hs.api(op, "POST", "/api/v2/discovery/schedules", `{"ranges":["8.8.8.0/24"],"every":"day"}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"ranges"`) {
		t.Fatalf("public range: %d %s", rec.Code, rec.Body.String())
	}
	if rec := hs.api(op, "POST", "/api/v2/discovery/schedules", `{"ranges":["10.0.1.0/29"]}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"every"`) {
		t.Fatalf("missing every: %d %s", rec.Code, rec.Body.String())
	}
	rec = hs.api(op, "POST", "/api/v2/discovery/schedules", `{"name":"Lab","ranges":["10.0.1.0/29"],"every":"week","weekday":3,"hour":1,"ports":[443,8443]}`)
	if d := decodeJSON[map[string]any](t, rec); rec.Code != http.StatusCreated || d["name"] != "Lab" || d["every"] != "week" || rec.Header().Get("Location") != "/api/v2/discovery/schedules/2" {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	if rec := hs.api(op, "POST", "/api/v2/discovery/schedules/2/run", ""); rec.Code != http.StatusOK {
		t.Fatalf("run: %d %s", rec.Code, rec.Body.String())
	}
	for sc, _ := hs.srv.Core.Scan(ctx, 3); sc.State == core.ScanRunning; sc, _ = hs.srv.Core.Scan(ctx, 3) {
		time.Sleep(10 * time.Millisecond)
	}
	if rec := hs.api(op, "DELETE", "/api/v2/discovery/schedules/2", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := hs.api(op, "GET", "/api/v2/discovery/schedules/2", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("after delete: %d", rec.Code)
	}
	if a, _ := hs.srv.Core.AuditLog(ctx, "scan.start", 10); len(a) != 3 || !strings.Contains(a[0].Details, "schedule=") {
		t.Fatalf("audit: %+v", a)
	}
}
