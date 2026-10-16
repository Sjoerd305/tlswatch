package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

func TestParseEndpoints(t *testing.T) {
	eps, errs := parseEndpoints("portal.example.nl\nmail.example.nl:587 Mail server\nhttps://Shop.example.nl./shop?x=1\n\n# comment\n[2001:db8::1]:8443\n2001:db8::2\nportal.example.nl:443\nbad:port\nhost:70000", probe.TLS)
	if len(errs) != 3 || !strings.HasPrefix(errs[0], "Line 8: repeats line 1") || !strings.HasPrefix(errs[1], "Line 9: port") || !strings.HasPrefix(errs[2], "Line 10: port") {
		t.Fatalf("errors: %q", errs)
	}
	want := []endpoint{{1, "portal.example.nl", 443, ""}, {2, "mail.example.nl", 587, "Mail server"}, {3, "shop.example.nl", 443, ""}, {6, "2001:db8::1", 8443, ""}, {7, "2001:db8::2", 443, ""}}
	if len(eps) != len(want) {
		t.Fatalf("endpoints: %+v", eps)
	}
	for i := range want {
		if eps[i] != want[i] {
			t.Errorf("line %d: got %+v, want %+v", want[i].Line, eps[i], want[i])
		}
	}
	if _, errs := parseEndpoints("  \n#x\n", probe.SMTP); len(errs) != 0 {
		t.Fatalf("blank list: %q", errs)
	}
}

func TestBulkAdd(t *testing.T) {
	hs := newHarness(t)
	page := hs.do(authz.Operator, "GET", "/targets/bulk-add", nil, false)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `name="hosts"`) {
		t.Fatalf("form: %d", page.Code)
	}
	// A bad line or field saves nothing.
	f := url.Values{"hosts": {"ok.example.nl\nbad_host!\n127.0.0.1"}, "protocol": {"tls"}, "trust_mode": {"system"}, "warn_days": {"x"}, "all_channels": {"1"}}
	rec := hs.do(authz.Operator, "POST", "/targets/bulk-add", f, true)
	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest || !strings.Contains(body, "Line 2: Enter a DNS name") || !strings.Contains(body, "Line 3: Loopback") || !strings.Contains(body, "Enter a whole number") {
		t.Fatalf("validation: %d %s", rec.Code, body[:200])
	}
	if ts, _ := hs.srv.Core.Targets(context.Background()); len(ts) != 1 {
		t.Fatalf("targets saved on error: %d", len(ts))
	}
	// A valid list adds every line with the shared settings.
	f = url.Values{"hosts": {"mail.example.nl:465 Mail\nshop.example.nl"}, "protocol": {"tls"}, "trust_mode": {"system"},
		"interval_s": {"21600"}, "tags": {"Customer:X"}, "all_channels": {"1"}, "notes": {"bulk"}}
	rec = hs.do(authz.Operator, "POST", "/targets/bulk-add", f, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/targets" {
		t.Fatalf("add: %d %s", rec.Code, rec.Body.String())
	}
	ts, _ := hs.srv.Core.Targets(context.Background())
	if len(ts) != 3 {
		t.Fatalf("targets: %d", len(ts))
	}
	// An endpoint that exists already is skipped, the rest is added.
	f.Set("hosts", "shop.example.nl\nvpn.example.nl")
	if rec := hs.do(authz.Operator, "POST", "/targets/bulk-add", f, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("add again: %d", rec.Code)
	}
	if ts, _ := hs.srv.Core.Targets(context.Background()); len(ts) != 4 {
		t.Fatalf("targets after repeat: %d", len(ts))
	}
	byHost := map[string]int{}
	for i, tg := range ts {
		byHost[tg.Host] = i
	}
	mail := ts[byHost["mail.example.nl"]]
	if mail.Port != 465 || mail.Name != "Mail" || mail.ServerName != "mail.example.nl" || mail.IntervalS == nil || *mail.IntervalS != 21600 || strings.Join(mail.Tags, ",") != "customer:x" || mail.Notes != "bulk" {
		t.Fatalf("mail target: %+v", mail)
	}
	if shop := ts[byHost["shop.example.nl"]]; shop.Name != "shop.example.nl" || shop.Port != 443 {
		t.Fatalf("shop target: %+v", shop)
	}
	var audits int
	_ = hs.db.R.QueryRow("SELECT COUNT(*) FROM audit WHERE action = 'target.create' AND details LIKE '%bulk=true%'").Scan(&audits)
	if audits != 3 {
		t.Fatalf("audit entries: %d", audits)
	}
}

func TestBulkEdit(t *testing.T) {
	hs := newHarness(t)
	f := url.Values{"hosts": {"a.example.nl\nb.example.nl"}, "protocol": {"tls"}, "trust_mode": {"system"}, "tags": {"old, keep"}, "all_channels": {"1"}}
	if rec := hs.do(authz.Operator, "POST", "/targets/bulk-add", f, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("add: %d", rec.Code)
	}
	page := hs.do(authz.Operator, "GET", "/targets", nil, false).Body.String()
	if !strings.Contains(page, `form="bulk-targets"`) || !strings.Contains(page, `data-select-all="#targets"`) {
		t.Fatal("no bulk selection for an operator")
	}
	if page := hs.do(authz.Viewer, "GET", "/targets", nil, false).Body.String(); strings.Contains(page, `form="bulk-targets"`) {
		t.Fatal("bulk selection shown to a viewer")
	}
	// The bar leads to the edit page with the selection.
	rec := hs.do(authz.Operator, "POST", "/targets/bulk", url.Values{"id": {"2", "3", "2"}}, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/targets/bulk-edit?id=2&id=3" {
		t.Fatalf("select: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if rec := hs.do(authz.Operator, "POST", "/targets/bulk", nil, true); rec.Header().Get("Location") != "/targets" {
		t.Fatalf("empty selection: %s", rec.Header().Get("Location"))
	}
	edit := hs.do(authz.Operator, "GET", "/targets/bulk-edit?id=2&id=3&id=999", nil, false)
	if edit.Code != http.StatusOK || !strings.Contains(edit.Body.String(), "Edit 2 targets") || !strings.Contains(edit.Body.String(), `value="interval_s"`) {
		t.Fatalf("edit page: %d", edit.Code)
	}
	// Nothing ticked is refused; so is an invalid value of a ticked field,
	// while untouched fields are not even read.
	rec = hs.do(authz.Operator, "POST", "/targets/bulk-edit", url.Values{"id": {"2", "3"}, "warn_days": {"x"}}, true)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Tick Change") {
		t.Fatalf("no change: %d", rec.Code)
	}
	rec = hs.do(authz.Operator, "POST", "/targets/bulk-edit", url.Values{"id": {"2", "3"}, "change": {"thresholds"}, "warn_days": {"5"}, "crit_days": {"9"}}, true)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "a.example.nl: Critical must be") {
		t.Fatalf("bad thresholds: %d %s", rec.Code, rec.Body.String()[:100])
	}
	// Interval, tags and state change on both; the rest stays.
	f = url.Values{"id": {"2", "3"}, "change": {"interval_s", "notes"}, "interval_s": {"43200"}, "notes": {"shared"},
		"add_tags": {"New"}, "remove_tags": {"old"}, "enabled": {"disable"}, "warn_days": {"ignored"}}
	rec = hs.do(authz.Operator, "POST", "/targets/bulk-edit", f, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/targets" {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	for _, id := range []int64{2, 3} {
		tg, _ := hs.srv.Core.Target(context.Background(), id)
		if tg.IntervalS == nil || *tg.IntervalS != 43200 || tg.Notes != "shared" || strings.Join(tg.Tags, ",") != "keep,new" || tg.Enabled || tg.WarnDays != nil || tg.Trust != probe.TrustSystem || !tg.AllChannels {
			t.Fatalf("target %d: %+v", id, tg)
		}
	}
	if tg, _ := hs.srv.Core.Target(context.Background(), 1); tg.IntervalS != nil || !tg.Enabled {
		t.Fatalf("unselected target changed: %+v", tg)
	}
	var audits int
	_ = hs.db.R.QueryRow("SELECT COUNT(*) FROM audit WHERE action = 'target.update' AND details = 'bulk=true changed=interval_s,notes,tags,disable'").Scan(&audits)
	if audits != 2 {
		t.Fatalf("audit entries: %d", audits)
	}
	// Enabling again queues a check.
	rec = hs.do(authz.Operator, "POST", "/targets/bulk-edit", url.Values{"id": {"2"}, "enabled": {"enable"}}, true)
	if tg, _ := hs.srv.Core.Target(context.Background(), 2); rec.Code != http.StatusSeeOther || !tg.Enabled {
		t.Fatalf("enable: %d %+v", rec.Code, tg)
	}
}

// The overview's "Expiring next" shows ten targets and folds the rest
// until ?all=1.
func TestOverviewFoldsExpiring(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	now := hs.srv.now().Unix()
	if _, err := hs.db.W.Exec(`INSERT INTO certificates(fingerprint, subject, subject_cn, issuer, issuer_cn, issuer_org, serial, not_before, not_after,
		key_type, key_bits, sig_alg, is_ca, self_signed, pem, first_seen, last_seen) VALUES('fp1','CN=x','x','CN=ca','ca','CA','1',?,?,'RSA',2048,'SHA256-RSA',0,0,'',?,?)`,
		now-86400, now+40*86400, now, now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		id, err := hs.srv.Core.SaveTarget(ctx, core.Target{Name: fmt.Sprintf("t%d", i), Host: "example.org", Port: 1000 + i, Protocol: probe.TLS, Trust: probe.TrustSystem,
			AllAddresses: true, AllChannels: true, Enabled: true}, "test")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := hs.db.W.Exec("UPDATE targets SET current_fp = 'fp1', not_after = ?, status = 'healthy' WHERE id = ?", now+40*86400, id); err != nil {
			t.Fatal(err)
		}
	}
	page := hs.do(authz.Viewer, "GET", "/", nil, false).Body.String()
	if n := strings.Count(page, "data-more hidden"); n != 2 || !strings.Contains(page, "Show all 12") || !strings.Contains(page, `href="/?all=1"`) {
		t.Fatalf("folded: %d hidden rows", n)
	}
	page = hs.do(authz.Viewer, "GET", "/?all=1", nil, false).Body.String()
	if strings.Contains(page, "data-more hidden") || strings.Count(page, "data-more") != 2 || !strings.Contains(page, "Show 10") {
		t.Fatal("not unfolded with ?all=1")
	}
}
