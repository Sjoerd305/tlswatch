package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/sched"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

type harness struct {
	t    *testing.T
	srv  *Server
	h    http.Handler
	db   *db.DB
	sess map[authz.Role]session
}

type session struct {
	cookie string
	csrf   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessUsers(t, true)
}

func newHarnessUsers(t *testing.T, withUsers bool) *harness {
	t.Helper()
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	key, _ := secret.New([]byte("0123456789abcdef0123456789abcdef"))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := config.NewStore(d, key)
	chans := &notify.Channels{DB: d, Key: key}
	disp := &notify.Dispatcher{DB: d, Channels: chans, Log: log}
	c := &core.Service{DB: d, Settings: st, Channels: chans, Dispatcher: disp, Log: log}
	sc := &sched.Scheduler{Core: c, Log: log, Probe: func(context.Context, probe.Request) probe.Result {
		return probe.Result{DNSError: "no such host"}
	}}
	a := auth.New(d, key)
	srv := &Server{Core: c, Sched: sc, Auth: a, Settings: st, Dispatch: disp, Log: log, Version: "test", Listen: "test"}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	hs := &harness{t: t, srv: srv, h: h, db: d, sess: map[authz.Role]session{}}
	ctx := context.Background()
	if !withUsers {
		return hs
	}
	for _, r := range authz.Roles {
		u, err := a.CreateUser(ctx, string(r)+"@example.test", string(r), r, auth.MethodLocal)
		if err != nil {
			t.Fatal(err)
		}
		raw, csrf, err := a.NewSession(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		hs.sess[r] = session{raw, csrf}
	}
	if _, err := c.SaveTarget(ctx, core.Target{Name: "t", Host: "example.org", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem,
		AllAddresses: true, AllChannels: true, Enabled: true}, "test"); err != nil {
		t.Fatal(err)
	}
	return hs
}

func (hs *harness) do(role authz.Role, method, path string, form url.Values, withCSRF bool) *httptest.ResponseRecorder {
	var body io.Reader
	if form == nil {
		form = url.Values{}
	}
	s, signedIn := hs.sess[role]
	if method == http.MethodPost && withCSRF && signedIn {
		form.Set("csrf", s.csrf)
	}
	if method == http.MethodPost {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if signedIn {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.cookie})
	}
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, req)
	return rec
}

type route struct {
	method, path string
	action       authz.Action
}

var protected = []route{
	{"GET", "/", authz.ViewData},
	{"GET", "/targets", authz.ViewData},
	{"GET", "/targets/1", authz.ViewData},
	{"GET", "/certificates", authz.ViewData},
	{"GET", "/certificates.csv", authz.ViewData},
	{"GET", "/findings", authz.ViewData},
	{"GET", "/targets/new", authz.EditTargets},
	{"POST", "/targets/new", authz.EditTargets},
	{"GET", "/targets/1/edit", authz.EditTargets},
	{"POST", "/targets/1/edit", authz.EditTargets},
	{"POST", "/targets/1/check", authz.EditTargets},
	{"POST", "/targets/1/disable", authz.EditTargets},
	{"POST", "/targets/1/enable", authz.EditTargets},
	{"GET", "/targets/1/delete", authz.EditTargets},
	{"POST", "/targets/1/delete", authz.EditTargets},
	{"POST", "/targets/check-all", authz.EditTargets},
	{"POST", "/api/v1/targets/1/check", authz.EditTargets},
	{"POST", "/api/v1/targets/check-all", authz.EditTargets},
	{"POST", "/api/v1/targets/test", authz.EditTargets},
	{"POST", "/findings/1/ack", authz.Acknowledge},
	{"POST", "/findings/1/unack", authz.Acknowledge},
	{"GET", "/settings/general", authz.ManageSettings},
	{"POST", "/settings/general", authz.ManageSettings},
	{"GET", "/settings/signin", authz.ManageSettings},
	{"POST", "/settings/signin", authz.ManageSettings},
	{"GET", "/settings/channels", authz.ManageSettings},
	{"POST", "/settings/channels", authz.ManageSettings},
	{"POST", "/settings/channels/1/test", authz.ManageSettings},
	{"POST", "/settings/channels/1/delete", authz.ManageSettings},
	{"GET", "/settings/bundles", authz.ManageSettings},
	{"POST", "/settings/bundles", authz.ManageSettings},
	{"POST", "/settings/bundles/1/delete", authz.ManageSettings},
	{"GET", "/settings/defaults", authz.ManageSettings},
	{"POST", "/settings/defaults", authz.ManageSettings},
	{"POST", "/settings/digest/send", authz.ManageSettings},
	{"GET", "/settings/about", authz.ManageSettings},
	{"GET", "/settings/users", authz.ManageUsers},
	{"POST", "/settings/users", authz.ManageUsers},
	{"POST", "/settings/users/1", authz.ManageUsers},
	{"POST", "/settings/users/1/link", authz.ManageUsers},
	{"GET", "/settings/audit", authz.ViewAudit},
	{"GET", "/settings/audit.csv", authz.ViewAudit},
	{"GET", "/account", authz.ManageOwnAccount},
}

// TestRoleNegativeSuite tries every role against every route it must not
// reach, and checks that allowed roles get past the authorisation check.
func TestRoleNegativeSuite(t *testing.T) {
	hs := newHarness(t)
	for _, r := range protected {
		for _, role := range authz.Roles {
			rec := hs.do(role, r.method, r.path, nil, true)
			allowed := authz.Allowed(role, r.action)
			if !allowed && rec.Code != http.StatusForbidden {
				t.Errorf("%s %s as %s: got %d, want 403", r.method, r.path, role, rec.Code)
			}
			if allowed && rec.Code == http.StatusForbidden {
				t.Errorf("%s %s as %s: forbidden but allowed by policy", r.method, r.path, role)
			}
		}
		// Signed out: redirect to sign in, or 401 for the API.
		rec := hs.do("", r.method, r.path, nil, false)
		if r.method == "POST" {
			if rec.Code != http.StatusForbidden { // CSRF fails first without a session
				t.Errorf("%s %s signed out: got %d", r.method, r.path, rec.Code)
			}
		} else if rec.Code != http.StatusSeeOther {
			t.Errorf("%s %s signed out: got %d, want redirect", r.method, r.path, rec.Code)
		}
	}
	// Every route the mux knows is in the table above (or public).
	for _, p := range []string{"/settings/users", "/settings/channels", "/targets/new"} {
		found := false
		for _, r := range protected {
			if r.path == p {
				found = true
			}
		}
		if !found {
			t.Errorf("route %s missing from the negative suite", p)
		}
	}
}

func TestCSRFRequired(t *testing.T) {
	hs := newHarness(t)
	rec := hs.do(authz.Admin, "POST", "/targets/check-all", nil, false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF: %d", rec.Code)
	}
	rec = hs.do(authz.Admin, "POST", "/targets/check-all", nil, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST with CSRF: %d", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	hs := newHarness(t)
	rec := hs.do(authz.Viewer, "GET", "/", nil, false)
	h := rec.Header()
	if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'self'") || !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("CSP: %q", h.Get("Content-Security-Policy"))
	}
	if h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers: %v", h)
	}
	if strings.Contains(rec.Body.String(), "style=\"") {
		t.Fatal("inline style in page")
	}
}

func TestLoginFlow(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	u, _ := hs.srv.Auth.UserByEmail(ctx, "operator@example.test")
	if err := hs.srv.Auth.SetPassword(ctx, u.ID, "correct horse battery staple 42"); err != nil {
		t.Fatal(err)
	}
	// Fetch the sign-in page for the double-submit CSRF cookie.
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	var csrfC *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookie {
			csrfC = c
		}
	}
	if csrfC == nil {
		t.Fatal("no csrf cookie on the sign-in page")
	}
	post := func(pw string) *httptest.ResponseRecorder {
		f := url.Values{"email": {"operator@example.test"}, "password": {pw}, "csrf": {csrfC.Value}, "next": {"/targets"}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(csrfC)
		rec := httptest.NewRecorder()
		hs.h.ServeHTTP(rec, req)
		return rec
	}
	bad := post("wrong password here")
	if bad.Code != http.StatusUnauthorized || !strings.Contains(bad.Body.String(), "e-mail address or password is incorrect") {
		t.Fatalf("bad login: %d", bad.Code)
	}
	good := post("correct horse battery staple 42")
	if good.Code != http.StatusSeeOther || good.Header().Get("Location") != "/targets" {
		t.Fatalf("good login: %d %s", good.Code, good.Header().Get("Location"))
	}
	var sess *http.Cookie
	for _, c := range good.Result().Cookies() {
		if c.Name == sessionCookie {
			sess = c
		}
	}
	if sess == nil || !sess.HttpOnly || sess.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie: %+v", sess)
	}
}

func TestChannelCredentialsEncrypted(t *testing.T) {
	hs := newHarness(t)
	f := url.Values{"kind": {"smtp"}, "name": {"Ops mailbox"}, "min_severity": {"warning"}, "host": {"smtp.example.nl"}, "port": {"587"},
		"encryption": {"starttls"}, "username": {"tlswatch@example.nl"}, "password": {"s3cret-relay-password"},
		"from": {"tlswatch <tlswatch@example.nl>"}, "recipients": {"ops@example.nl, noc@example.nl"}, "enabled": {"1"}}
	rec := hs.do(authz.Admin, "POST", "/settings/channels", f, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save channel: %d %s", rec.Code, rec.Body.String())
	}
	var blob []byte
	var dest string
	if err := hs.db.R.QueryRow("SELECT settings, destination FROM channels").Scan(&blob, &dest); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "s3cret") || strings.Contains(string(blob), "smtp.example.nl") {
		t.Fatal("channel settings stored in clear text")
	}
	if dest != "ops@example.nl, noc@example.nl" {
		t.Fatalf("destination %q", dest)
	}
	// The edit form never shows the password back; an empty password keeps it.
	page := hs.do(authz.Admin, "GET", "/settings/channels?edit=1", nil, false).Body.String()
	if strings.Contains(page, "s3cret") {
		t.Fatal("password rendered in the edit form")
	}
	f.Set("id", "1")
	f.Set("password", "")
	f.Set("min_severity", "critical")
	if rec := hs.do(authz.Admin, "POST", "/settings/channels", f, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("update: %d", rec.Code)
	}
	c, err := hs.srv.Core.Channels.Get(context.Background(), 1)
	if err != nil || c.SMTP.Password != "s3cret-relay-password" || c.MinSeverity != "critical" {
		t.Fatalf("after update: %+v %v", c.SMTP, err)
	}
	// Audit entry without the secret.
	var details string
	_ = hs.db.R.QueryRow("SELECT details FROM audit WHERE action = 'channel.update'").Scan(&details)
	if details == "" || strings.Contains(details, "s3cret") {
		t.Fatalf("audit details: %q", details)
	}
}

func TestSettingsSavedFromUI(t *testing.T) {
	hs := newHarness(t)
	f := url.Values{"base_url": {"https://tlswatch.example.nl/"}, "behind_proxy": {"1"}, "time_zone": {"Europe/Amsterdam"}}
	if rec := hs.do(authz.Admin, "POST", "/settings/general", f, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("general: %d", rec.Code)
	}
	g := url.Values{"google_client_id": {"123.apps.googleusercontent.com"}, "google_client_secret": {"gsecret"}, "google_domain": {"Example.nl"}}
	if rec := hs.do(authz.Admin, "POST", "/settings/signin", g, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("signin: %d", rec.Code)
	}
	st, _ := hs.srv.Settings.Get(context.Background())
	if st.General.BaseURL != "https://tlswatch.example.nl" || !st.General.BehindProxy || st.General.TimeZone != "Europe/Amsterdam" {
		t.Fatalf("general: %+v", st.General)
	}
	if !st.GoogleEnabled() || st.SignIn.GoogleDomain != "example.nl" {
		t.Fatalf("signin: %+v", st.SignIn)
	}
	var raw string
	_ = hs.db.R.QueryRow("SELECT value FROM settings WHERE key = 'signin.google_client_secret'").Scan(&raw)
	if raw == "" || strings.Contains(raw, "gsecret") {
		t.Fatalf("google secret stored as %q", raw)
	}
	// The sign-in page now offers Google.
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	if !strings.Contains(rec.Body.String(), "Sign in with Google") {
		t.Fatal("Google button missing")
	}
	// Invalid defaults are refused with a message.
	d := url.Values{"manual_warn": {"10"}, "manual_crit": {"20"}, "managed_warn": {"10"}, "managed_crit": {"3"}, "interval_s": {"86400"},
		"timeout_s": {"10"}, "retries": {"2"}, "debounce": {"2"}, "remind_warn_s": {"604800"}, "remind_crit_s": {"86400"}, "workers": {"8"}, "retention_days": {"180"}}
	rec2 := hs.do(authz.Admin, "POST", "/settings/defaults", d, true)
	if rec2.Code != http.StatusBadRequest || !strings.Contains(rec2.Body.String(), "critical must be 1 to warning minus 1") {
		t.Fatalf("bad defaults: %d", rec2.Code)
	}
}

func TestTargetFormValidation(t *testing.T) {
	hs := newHarness(t)
	f := url.Values{"host": {"not a host!"}, "port": {"70000"}, "protocol": {"tls"}, "trust_mode": {"system"}, "action": {"save"}}
	rec := hs.do(authz.Operator, "POST", "/targets/new", f, true)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Enter a DNS name or an IP address") || !strings.Contains(rec.Body.String(), "Port must be 1 to 65535") {
		t.Fatalf("validation: %d", rec.Code)
	}
	f = url.Values{"host": {"127.0.0.1"}, "protocol": {"tls"}, "trust_mode": {"system"}, "action": {"save"}}
	rec = hs.do(authz.Operator, "POST", "/targets/new", f, true)
	if !strings.Contains(rec.Body.String(), "Loopback and link-local addresses are not allowed") {
		t.Fatal("loopback target accepted")
	}
	f = url.Values{"host": {"mail.example.nl"}, "protocol": {"smtp"}, "trust_mode": {"system"}, "tags": {"Customer:X, sip"}, "all_channels": {"1"}, "action": {"save"}}
	rec = hs.do(authz.Operator, "POST", "/targets/new", f, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	id := regexp.MustCompile(`/targets/(\d+)`).FindStringSubmatch(rec.Header().Get("Location"))
	if id == nil {
		t.Fatalf("redirect %q", rec.Header().Get("Location"))
	}
	tg, _ := hs.srv.Core.Target(context.Background(), 2)
	if tg.Port != 587 || tg.ServerName != "mail.example.nl" || strings.Join(tg.Tags, ",") != "customer:x,sip" {
		t.Fatalf("saved target: %+v", tg)
	}
}

// get fetches a page signed out, carrying the CSRF cookie along.
func (hs *harness) signedOut(method, path string, form url.Values, c *http.Cookie) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, req)
	return rec
}

func TestFirstRunSetupScreen(t *testing.T) {
	hs := newHarnessUsers(t, false)
	for _, p := range []string{"/", "/targets", "/login"} {
		if rec := hs.signedOut("GET", p, nil, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/setup" {
			t.Fatalf("GET %s without accounts: %d %s", p, rec.Code, rec.Header().Get("Location"))
		}
	}
	page := hs.signedOut("GET", "/setup", nil, nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Create administrator and sign in") {
		t.Fatalf("setup page: %d", page.Code)
	}
	var csrfC *http.Cookie
	for _, c := range page.Result().Cookies() {
		if c.Name == csrfCookie {
			csrfC = c
		}
	}
	form := func(email, pw, pw2 string) url.Values {
		return url.Values{"csrf": {csrfC.Value}, "email": {email}, "name": {"Sjoerd"}, "password": {pw}, "password2": {pw2}}
	}
	// Without the CSRF token the form is refused.
	if rec := hs.signedOut("POST", "/setup", url.Values{"email": {"a@example.nl"}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("setup without CSRF: %d", rec.Code)
	}
	if rec := hs.signedOut("POST", "/setup", form("admin@example.nl", "correct horse battery 9", "different horse battery 9"), csrfC); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "do not match") {
		t.Fatalf("mismatch: %d", rec.Code)
	}
	if rec := hs.signedOut("POST", "/setup", form("admin@example.nl", "short", "short"), csrfC); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "at least 12") {
		t.Fatalf("short password: %d %s", rec.Code, rec.Body.String())
	}
	rec := hs.signedOut("POST", "/setup", form("Admin@Example.nl", "correct horse battery 9", "correct horse battery 9"), csrfC)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("create admin: %d %s", rec.Code, rec.Body.String())
	}
	var sess *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			sess = c
		}
	}
	if sess == nil {
		t.Fatal("not signed in after setup")
	}
	if home := hs.signedOut("GET", "/settings/users", nil, sess); home.Code != http.StatusOK || !strings.Contains(home.Body.String(), "admin@example.nl") {
		t.Fatalf("new admin cannot manage users: %d", home.Code)
	}
	// The screen is gone once an account exists.
	if again := hs.signedOut("GET", "/setup", nil, nil); again.Code != http.StatusSeeOther || again.Header().Get("Location") != "/login" {
		t.Fatalf("setup after first admin: %d %s", again.Code, again.Header().Get("Location"))
	}
	second := hs.signedOut("POST", "/setup", form("intruder@example.nl", "correct horse battery 9", "correct horse battery 9"), csrfC)
	if second.Code != http.StatusSeeOther || second.Header().Get("Location") != "/login" {
		t.Fatalf("second setup: %d", second.Code)
	}
	if n, _ := hs.srv.Auth.CountUsers(context.Background()); n != 1 {
		t.Fatalf("users: %d", n)
	}
}

func TestDeleteTarget(t *testing.T) {
	hs := newHarness(t)
	page := hs.do(authz.Operator, "GET", "/targets/1", nil, false).Body.String()
	if !strings.Contains(page, `href="/targets/1/delete"`) {
		t.Fatal("no Delete button on the target page")
	}
	confirm := hs.do(authz.Operator, "GET", "/targets/1/delete", nil, false)
	if confirm.Code != http.StatusOK || !strings.Contains(confirm.Body.String(), "Delete permanently") {
		t.Fatalf("confirm page: %d", confirm.Code)
	}
	// A POST without the confirmation goes back to the confirmation page.
	if rec := hs.do(authz.Operator, "POST", "/targets/1/delete", nil, true); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/targets/1/delete" {
		t.Fatalf("unconfirmed delete: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if _, err := hs.srv.Core.Target(context.Background(), 1); err != nil {
		t.Fatal("deleted without confirmation")
	}
	rec := hs.do(authz.Operator, "POST", "/targets/1/delete", url.Values{"confirm": {"yes"}}, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/targets" {
		t.Fatalf("delete: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if _, err := hs.srv.Core.Target(context.Background(), 1); err == nil {
		t.Fatal("target still exists")
	}
	var n int
	_ = hs.db.R.QueryRow("SELECT COUNT(*) FROM audit WHERE action = 'target.delete'").Scan(&n)
	if n != 1 {
		t.Fatalf("audit entries: %d", n)
	}
}
