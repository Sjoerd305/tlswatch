package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/caa"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/node"
)

// Restores that must not happen: a damaged or foreign file, a database of
// a newer tlswatch, one without an admin, a missing file, and a second
// restore while one runs. None changes the database.
func TestRestoreRefusals(t *testing.T) {
	hs := newHarness(t)
	file := hs.download()
	admin := hs.sess[authz.Admin]
	fields := func(pass string) [][2]string {
		return [][2]string{{"csrf", admin.csrf}, {"passphrase", pass}, {"confirm", "1"}}
	}
	plain := func(mutate func(d *db.DB)) []byte {
		t.Helper()
		p := filepath.Join(t.TempDir(), "copy.db")
		d, err := db.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		mutate(d)
		d.Close()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	newer := plain(func(d *db.DB) {
		_, _ = d.W.Exec("INSERT INTO users(email, role, method, created_at) VALUES('a@example.test', 'admin', 'local', 1)")
		_, _ = d.W.Exec(fmt.Sprintf("PRAGMA user_version = %d", db.SchemaVersion()+1))
	})
	noAdmin := plain(func(d *db.DB) {
		_, _ = d.W.Exec("INSERT INTO users(email, role, method, created_at) VALUES('v@example.test', 'viewer', 'local', 1)")
	})
	if _, err := hs.db.W.Exec("UPDATE targets SET name = 'after the backup'"); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		file []byte
		pass string
		want string
	}{
		"cut off":       {file[:len(file)/2], testPassphrase, "passphrase is wrong or the file is damaged"},
		"last byte cut": {file[:len(file)-1], testPassphrase, "damaged"},
		"not a backup":  {[]byte("PK\x03\x04 a zip file"), "", "not a tlswatch backup"},
		"empty":         {nil, "", "not a tlswatch backup"},
		"newer schema":  {newer, "", "newer version of tlswatch"},
		"no admin":      {noAdmin, "", "no enabled admin"},
		"no passphrase": {file, "", "Enter the passphrase"},
	} {
		rec := hs.upload("/settings/backup/restore", authz.Admin, nil, fields(c.pass), c.file)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: %d, want 400 with %q", name, rec.Code, c.want)
		}
	}
	// A form without a file part.
	body, ct := multipartForm(t, fields(testPassphrase), nil)
	raw := strings.Replace(readAll(t, body), `name="file"; filename="tlswatch.backup"`, `name="other"`, 1)
	req := httptest.NewRequest("POST", "/settings/backup/restore", strings.NewReader(raw))
	req.Header.Set("Content-Type", ct)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: admin.cookie})
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Choose a backup file") {
		t.Errorf("no file: %d", rec.Code)
	}
	// A second restore while one runs is refused, not queued.
	hs.srv.restoring.Lock()
	rec = hs.upload("/settings/backup/restore", authz.Admin, nil, fields(testPassphrase), file)
	hs.srv.restoring.Unlock()
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Another restore is running") {
		t.Errorf("concurrent restore: %d", rec.Code)
	}
	var name string
	_ = hs.db.R.QueryRow("SELECT name FROM targets WHERE id = 1").Scan(&name)
	if name != "after the backup" || hs.count("SELECT COUNT(*) FROM sessions") != 3 {
		t.Fatalf("a refused restore changed the database: %q", name)
	}
	if hs.count("SELECT COUNT(*) FROM audit WHERE action = 'backup.download'") != 1 || hs.count("SELECT COUNT(*) FROM audit WHERE action = 'backup.restore'") != 0 {
		t.Error("downloads and refused restores are not audited as such")
	}
	// The scheduler still runs after the refusals.
	if rec := hs.do(authz.Operator, "POST", "/targets/check-all", nil, true); rec.Code != http.StatusSeeOther {
		t.Errorf("check all after refused restores: %d", rec.Code)
	}
}

func readAll(t *testing.T, r interface{ Read([]byte) (int, error) }) string {
	t.Helper()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			return b.String()
		}
	}
}

// fakeCrtSh answers like crt.sh with one certificate for every query.
func fakeCrtSh(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		nb := time.Now().Add(-time.Hour).UTC().Format("2006-01-02T15:04:05")
		na := time.Now().Add(80 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05")
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 77, "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "www.watched.example",
			"name_value": "www.watched.example", "not_before": nb, "not_after": na, "serial_number": "0abc"}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The domain form, Edit, Enable and Poll now; the CT settings' Test.
func TestDomainFormEnableAndPoll(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	var hits atomic.Int32
	hs.srv.Core.CTBase = fakeCrtSh(t, &hits).URL
	if err := hs.srv.Settings.SaveCT(ctx, config.CT{Source: "crtsh", IntervalS: 3600}, false); err != nil {
		t.Fatal(err)
	}
	if rec := hs.do(authz.Operator, "GET", "/domains/new", nil, false); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="name"`) {
		t.Fatalf("new form: %d", rec.Code)
	}
	id, err := hs.srv.Core.SaveDomain(ctx, core.Domain{Name: "watched.example", Subdomains: true, Enabled: true, AllChannels: true}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if rec := hs.do(authz.Operator, "GET", fmt.Sprintf("/domains/%d/edit", id), nil, false); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `value="watched.example"`) {
		t.Fatalf("edit form: %d", rec.Code)
	}
	// Editing keeps the watch's id; the form cannot move it to another.
	f := url.Values{"name": {"watched.example"}, "subdomains": {"1"}, "tags": {"team:web"}, "all_channels": {"1"}, "id": {"999"}}
	if rec := hs.do(authz.Operator, "POST", fmt.Sprintf("/domains/%d/edit", id), f, true); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != fmt.Sprintf("/domains/%d", id) {
		t.Fatalf("save: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if d, _ := hs.srv.Core.Domain(ctx, id); len(d.Tags) != 1 || d.Tags[0] != "team:web" {
		t.Fatalf("after edit: %+v", d)
	}
	if rec := hs.do(authz.Operator, "POST", fmt.Sprintf("/domains/%d/edit", id), url.Values{"name": {"not a domain!"}}, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad name: %d", rec.Code)
	}
	// Poll now: the issuance is recorded.
	if rec := hs.do(authz.Viewer, "POST", fmt.Sprintf("/domains/%d/poll", id), nil, true); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer polls: %d", rec.Code)
	}
	hs.srv.Core.CAAResolver = caa.Static{"watched.example": {{Tag: "issue", Value: "letsencrypt.org"}}}
	before := hits.Load()
	if rec := hs.do(authz.Operator, "POST", fmt.Sprintf("/domains/%d/poll", id), nil, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("poll: %d", rec.Code)
	}
	if hits.Load() == before || hs.count(fmt.Sprintf("SELECT COUNT(*) FROM issuances WHERE domain_id = %d", id)) != 1 {
		t.Fatal("Poll now did not record the issuance")
	}
	// The poll looked up CAA; the page shows the record.
	if page := hs.do(authz.Viewer, "GET", fmt.Sprintf("/domains/%d", id), nil, false).Body.String(); !strings.Contains(page, `0 issue &#34;letsencrypt.org&#34;`) {
		t.Fatal("CAA record not on the domain page")
	}
	// Disable, then Enable through the form, with a next that stays here.
	if rec := hs.do(authz.Operator, "POST", fmt.Sprintf("/domains/%d/disable", id), nil, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("disable: %d", rec.Code)
	}
	rec := hs.do(authz.Operator, "POST", fmt.Sprintf("/domains/%d/enable", id), url.Values{"next": {"//evil.example/x"}}, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != fmt.Sprintf("/domains/%d", id) {
		t.Fatalf("enable: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if d, _ := hs.srv.Core.Domain(ctx, id); !d.Enabled {
		t.Fatal("not enabled")
	}
	if hs.count("SELECT COUNT(*) FROM audit WHERE action IN ('domain.update', 'domain.disable', 'domain.enable')") != 3 {
		t.Error("domain changes not audited")
	}
	// Settings › CT › Test polls the source for one name and shows it.
	if rec := hs.do(authz.Operator, "POST", "/settings/ct/test", url.Values{"domain": {"watched.example"}}, true); rec.Code != http.StatusForbidden {
		t.Fatalf("operator tests the CT source: %d", rec.Code)
	}
	rec = hs.do(authz.Admin, "POST", "/settings/ct/test", url.Values{"domain": {"watched.example"}}, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "www.watched.example") {
		t.Fatalf("CT test: %d", rec.Code)
	}
	if rec := hs.do(authz.Admin, "POST", "/settings/ct/test", url.Values{"domain": {"*.bad name"}}, true); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "www.watched.example") {
		t.Fatalf("CT test of a bad name: %d", rec.Code)
	}
}

// A node's page actions: reject a pending machine, save the name and
// notes, ask for an update, disable and enable.
func TestNodeActions(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	c := hs.srv.Core
	pending, tok, _ := c.CreateNode(ctx, "admin")
	if _, _, err := c.EnrolNode(ctx, tok, core.Enrolment{Facts: core.NodeFacts{Hostname: "stranger"}}); err != nil {
		t.Fatal(err)
	}
	rec := hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/nodes/%d/reject", pending), nil, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/settings/nodes" {
		t.Fatalf("reject: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if _, err := c.Node(ctx, pending); err == nil {
		t.Fatal("a rejected, never-confirmed node is kept")
	}

	id, tok, _ := c.CreateNode(ctx, "admin")
	if _, _, err := c.EnrolNode(ctx, tok, core.Enrolment{Facts: core.NodeFacts{Hostname: "probe"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.ConfirmNode(ctx, id, "dc1", "admin"); err != nil {
		t.Fatal(err)
	}
	if rec := hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/nodes/%d/reject", id), nil, true); rec.Code != http.StatusBadRequest {
		t.Errorf("reject a confirmed node: %d", rec.Code)
	}
	if rec := hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/nodes/%d", id), url.Values{"name": {"  "}, "notes": {"x"}}, true); rec.Code != http.StatusBadRequest {
		t.Errorf("empty name: %d", rec.Code)
	}
	if rec := hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/nodes/%d", id), url.Values{"name": {"Amsterdam"}, "notes": {"rack 4"}}, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d", rec.Code)
	}
	n, _ := c.Node(ctx, id)
	if n.Name != "Amsterdam" || n.Notes != "rack 4" {
		t.Fatalf("after save: %q %q", n.Name, n.Notes)
	}
	// A node on another platform than this development build: nothing to
	// update to, so no Update.
	_ = c.TouchNode(ctx, id, time.Now(), "v0.0.1", 1, "192.0.2.1")
	n, _ = c.Node(ctx, id)
	_ = c.SaveNodeFacts(ctx, n, core.NodeFacts{Hostname: "probe", Arch: "plan9/arm"})
	if rec := hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/nodes/%d/update", id), nil, true); rec.Code != http.StatusBadRequest {
		t.Errorf("update a node whose platform this build cannot serve: %d", rec.Code)
	}
	if body := hs.do(authz.Admin, "GET", fmt.Sprintf("/settings/nodes/%d", id), nil, false).Body.String(); strings.Contains(body, "Update to ") || !strings.Contains(body, "no plan9/arm binary") {
		t.Error("the node page offers Update for a platform this build cannot serve")
	}
	n, _ = c.Node(ctx, id)
	_ = c.SaveNodeFacts(ctx, n, core.NodeFacts{Hostname: "probe", Arch: node.OwnPlatform()})
	rec = hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/nodes/%d/update", id), url.Values{"next": {"https://evil.example/"}}, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("update: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if n, _ := c.Node(ctx, id); n.UpdateRequested == 0 {
		t.Error("the update was not requested")
	}
	for _, step := range []struct {
		path string
		want bool
	}{{"disable", false}, {"enable", true}} {
		if rec := hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/nodes/%d/%s", id, step.path), nil, true); rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: %d", step.path, rec.Code)
		}
		if n, _ := c.Node(ctx, id); n.Enabled != step.want {
			t.Fatalf("after %s: enabled %v", step.path, n.Enabled)
		}
	}
	if hs.count("SELECT COUNT(*) FROM audit WHERE action IN ('node.reject', 'node.update_details', 'node.update_request', 'node.disable', 'node.enable')") != 5 {
		t.Error("node actions not audited")
	}
}

// The PEM of a stored certificate is served as text, or as a download
// whose file name cannot be broken by the certificate's own subject.
func TestCertificatePEMDownloadName(t *testing.T) {
	hs := newHarness(t)
	fp := strings.Repeat("ab", 32)
	body := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	now := time.Now().Unix()
	if _, err := hs.db.W.Exec(`INSERT INTO certificates(fingerprint, subject, subject_cn, issuer, issuer_cn, issuer_org, serial, not_before, not_after,
		key_type, key_bits, sig_alg, is_ca, self_signed, pem, first_seen, last_seen) VALUES(?, 'CN=x', ?, 'CN=ca', 'ca', 'CA', '1', ?, ?, 'RSA', 2048, 'SHA256-RSA', 0, 0, ?, ?, ?)`,
		fp, `*.evil"; filename="run.exe`, now-60, now+86400, body, now, now); err != nil {
		t.Fatal(err)
	}
	rec := hs.do(authz.Viewer, "GET", "/certificates/"+strings.ToUpper(fp)+"/pem", nil, false)
	if rec.Code != http.StatusOK || rec.Body.String() != body || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("view: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("PEM served without nosniff")
	}
	rec = hs.do(authz.Viewer, "GET", "/certificates/"+fp+"/pem?download=1", nil, false)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-pem-file" {
		t.Fatalf("download: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	disp, params, err := mime.ParseMediaType(rec.Header().Get("Content-Disposition"))
	if err != nil || disp != "attachment" || !strings.HasSuffix(params["filename"], "-abababab.pem") {
		t.Errorf("Content-Disposition %q does not parse to one .pem file name: %v %v", rec.Header().Get("Content-Disposition"), params, err)
	}
	if rec := hs.signedOut("GET", "/certificates/"+fp+"/pem", nil, nil); rec.Code != http.StatusSeeOther {
		t.Errorf("signed out: %d", rec.Code)
	}
}

// The finding panel answers JSON with the acknowledge form for those who
// may acknowledge, and without it for a viewer.
func TestFindingPanelAPI(t *testing.T) {
	hs := newHarness(t)
	id := hs.addFinding("expiring", "warning", false)
	panel := func(role authz.Role) string {
		t.Helper()
		rec := hs.do(role, "GET", fmt.Sprintf("/api/v1/findings/%d/panel?next=%s", id, url.QueryEscape("/findings?severity=warning&sel=3")), nil, false)
		var r struct{ HTML string }
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &r) != nil || r.HTML == "" {
			t.Fatalf("panel as %s: %d %s", role, rec.Code, rec.Body.String())
		}
		return r.HTML
	}
	op := panel(authz.Operator)
	if !strings.Contains(op, fmt.Sprintf(`action="/findings/%d/ack"`, id)) || !strings.Contains(op, "severity=warning") || strings.Contains(op, "sel=3") {
		t.Errorf("operator panel lacks the form or keeps the selection:\n%s", op)
	}
	if v := panel(authz.Viewer); strings.Contains(v, fmt.Sprintf(`action="/findings/%d/ack"`, id)) {
		t.Error("viewer panel has the acknowledge form")
	}
	// next is only ever the findings list.
	rec := hs.do(authz.Operator, "GET", fmt.Sprintf("/api/v1/findings/%d/panel?next=%s", id, url.QueryEscape("https://evil.example/findings")), nil, false)
	if strings.Contains(rec.Body.String(), "evil.example") {
		t.Error("the panel carries an off-site next")
	}
	if rec := hs.signedOut("GET", fmt.Sprintf("/api/v1/findings/%d/panel", id), nil, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("signed out: %d", rec.Code)
	}
}

// Test without saving probes the endpoint and stores nothing; a loopback
// host is refused unless Settings › General allows local targets.
func TestTargetTestWithoutSaving(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the configuration test's refused handshakes
	srv.StartTLS()
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	f := url.Values{"host": {host}, "port": {port}, "protocol": {"tls"}, "trust_mode": {"self-signed"}, "all_channels": {"1"}}
	if rec := hs.do(authz.Operator, "POST", "/api/v1/targets/test", f, true); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Loopback") {
		t.Fatalf("loopback test while not allowed: %d %s", rec.Code, rec.Body.String())
	}
	if err := hs.srv.Settings.SaveGeneral(ctx, config.General{AllowLocal: true}); err != nil {
		t.Fatal(err)
	}
	targets, obs, certs := hs.count("SELECT COUNT(*) FROM targets"), hs.count("SELECT COUNT(*) FROM observations"), hs.count("SELECT COUNT(*) FROM certificates")
	rec := hs.do(authz.Operator, "POST", "/api/v1/targets/test", f, true)
	var r struct{ HTML string }
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &r) != nil {
		t.Fatalf("test: %d %s", rec.Code, rec.Body.String())
	}
	leaf := srv.Certificate()
	if !strings.Contains(r.HTML, "pinned") && !strings.Contains(r.HTML, leaf.Subject.Organization[0]) {
		t.Errorf("the result does not describe the served certificate:\n%s", r.HTML)
	}
	if hs.count("SELECT COUNT(*) FROM targets") != targets || hs.count("SELECT COUNT(*) FROM observations") != obs || hs.count("SELECT COUNT(*) FROM certificates") != certs {
		t.Error("Test without saving stored something")
	}
	// The same through the plain form (action=test) renders the result.
	f.Set("action", "test")
	page := hs.do(authz.Operator, "POST", "/targets/new", f, true)
	if page.Code != http.StatusOK || hs.count("SELECT COUNT(*) FROM targets") != targets {
		t.Errorf("form test: %d, targets %d", page.Code, hs.count("SELECT COUNT(*) FROM targets"))
	}
}

// A bulk edit with one bad value saves nothing, not even the valid parts or
// the state change; ids that are not numbers or not targets are ignored.
func TestBulkEditAllOrNothing(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	f := url.Values{"hosts": {"a.example.nl\nb.example.nl"}, "protocol": {"tls"}, "trust_mode": {"system"}, "all_channels": {"1"}}
	if rec := hs.do(authz.Operator, "POST", "/targets/bulk-add", f, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("add: %d", rec.Code)
	}
	ids := []string{"1", "2", "abc", "-4", "3", "999999", "2"}
	for name, bad := range map[string]url.Values{
		"long tag":     {"id": ids, "change": {"interval_s"}, "interval_s": {"43200"}, "add_tags": {strings.Repeat("x", 41)}, "enabled": {"disable"}},
		"bad interval": {"id": ids, "change": {"interval_s", "notes"}, "interval_s": {"60"}, "notes": {"n"}, "enabled": {"disable"}},
		"unknown node": {"id": ids, "change": {"node_id"}, "node_id": {"12345"}, "enabled": {"disable"}},
	} {
		if rec := hs.do(authz.Operator, "POST", "/targets/bulk-edit", bad, true); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, rec.Code)
		}
	}
	for _, id := range []int64{1, 2, 3} {
		tg, _ := hs.srv.Core.Target(ctx, id)
		if !tg.Enabled || tg.IntervalS != nil || tg.Notes != "" || tg.NodeID != 0 || tg.Trust != "system" || len(tg.Tags) != 0 {
			t.Errorf("target %d changed by a refused bulk edit: %+v", id, tg)
		}
	}
	if n := hs.count("SELECT COUNT(*) FROM audit WHERE action = 'target.update'"); n != 0 {
		t.Errorf("%d audit entries for refused bulk edits", n)
	}
	rec := hs.do(authz.Operator, "POST", "/targets/bulk-edit", url.Values{"id": ids, "add_tags": {"ok"}}, true)
	if rec.Code != http.StatusSeeOther || hs.count("SELECT COUNT(*) FROM audit WHERE action = 'target.update'") != 3 {
		t.Fatalf("valid bulk edit: %d, audit %d", rec.Code, hs.count("SELECT COUNT(*) FROM audit WHERE action = 'target.update'"))
	}
}

// A CA bundle id that does not exist (deleted while the form was open, or a
// crafted form) is a form error on every target form, not a server error.
func TestUnknownBundleIsAFormError(t *testing.T) {
	hs := newHarness(t)
	bundle := url.Values{"protocol": {"tls"}, "trust_mode": {"bundle"}, "bundle_id": {"777"}, "all_channels": {"1"}, "action": {"save"}}
	with := func(extra url.Values) url.Values {
		f := url.Values{}
		for k, v := range bundle {
			f[k] = v
		}
		for k, v := range extra {
			f[k] = v
		}
		return f
	}
	for path, f := range map[string]url.Values{
		"/targets/new":       with(url.Values{"host": {"x.example"}}),
		"/targets/1/edit":    with(url.Values{"host": {"example.org"}}),
		"/targets/bulk-add":  with(url.Values{"hosts": {"y.example"}}),
		"/targets/bulk-edit": with(url.Values{"id": {"1"}, "change": {"trust"}}),
	} {
		if rec := hs.do(authz.Operator, "POST", path, f, true); rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s with bundle 777: %d, want 400", path, rec.Code)
		}
	}
	if hs.count("SELECT COUNT(*) FROM targets") != 1 {
		t.Error("a target with an unknown bundle was saved")
	}
}
