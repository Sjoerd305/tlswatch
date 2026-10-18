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
