package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/sjoerd305/tlswatch/internal/authz"
)

// demoMode switches the harness to demo mode; the routes are built anew,
// as serve builds them with the flag set.
func (hs *harness) demoMode() {
	hs.t.Helper()
	hs.srv.Demo = true
	h, err := hs.srv.Handler()
	if err != nil {
		hs.t.Fatal(err)
	}
	hs.h = h
}

func TestDemoViewsWithoutSignIn(t *testing.T) {
	hs := newHarness(t)
	hs.demoMode()
	for _, p := range []string{"/", "/targets", "/targets/1", "/domains", "/certificates", "/certificates.csv", "/findings"} {
		rec := hs.do(authz.Demo, "GET", p, nil, false)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", p, rec.Code)
		}
	}
	body := hs.do(authz.Demo, "GET", "/", nil, false).Body.String()
	for _, want := range []string{"read-only demo", "Demo visitor"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	for _, unwanted := range []string{"Sign out", `href="/account"`, `href="/settings"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("overview shows %q to a demo visitor", unwanted)
		}
	}
}

func TestDemoClosesAccountPages(t *testing.T) {
	hs := newHarness(t)
	hs.demoMode()
	for _, p := range []string{"/login", "/setup", "/invite?token=x", "/auth/google", "/account", "/settings", "/settings/users", "/settings/backup"} {
		rec := hs.do(authz.Demo, "GET", p, nil, false)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
			t.Errorf("GET %s = %d to %q, want 303 to /", p, rec.Code, rec.Header().Get("Location"))
		}
	}
	// A real session cookie counts for nothing in demo mode.
	if rec := hs.do(authz.Admin, "GET", "/settings", nil, true); rec.Code != http.StatusSeeOther {
		t.Errorf("admin cookie reached /settings in demo mode: %d", rec.Code)
	}
}

func TestDemoRefusesWrites(t *testing.T) {
	hs := newHarness(t)
	hs.demoMode()
	ctx := context.Background()
	before, _ := hs.srv.Core.Targets(ctx)
	for _, p := range []string{"/targets/new", "/targets/bulk-add", "/targets/1/check", "/targets/1/delete", "/targets/check-all", "/findings/ack", "/login", "/logout", "/setup", "/settings/general"} {
		rec := hs.do(authz.Demo, "POST", p, url.Values{"hosts": {"example.net"}, "confirm": {"1"}}, false)
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST %s = %d, want 403", p, rec.Code)
		}
	}
	after, _ := hs.srv.Core.Targets(ctx)
	if len(after) != len(before) {
		t.Errorf("targets went from %d to %d", len(before), len(after))
	}
	if rec := hs.do(authz.Demo, "GET", "/targets/new", nil, false); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "This is a demo") {
		t.Errorf("GET /targets/new = %d, want 403 with the demo message", rec.Code)
	}
}

// A new instance in demo mode has no accounts, and its setup screen must
// not hand the first visitor an admin.
func TestDemoHasNoSetup(t *testing.T) {
	hs := newHarnessUsers(t, false)
	hs.demoMode()
	if rec := hs.do(authz.Demo, "GET", "/", nil, false); rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want the overview", rec.Code)
	}
	form := url.Values{"email": {"x@example.test"}, "name": {"x"}, "password": {"long enough password"}, "password2": {"long enough password"}}
	if rec := hs.do(authz.Demo, "POST", "/setup", form, false); rec.Code != http.StatusForbidden {
		t.Errorf("POST /setup = %d, want 403", rec.Code)
	}
	if n, _ := hs.srv.Auth.CountUsers(context.Background()); n != 0 {
		t.Errorf("%d users after a demo setup attempt", n)
	}
}

func TestDemoTheme(t *testing.T) {
	hs := newHarness(t)
	hs.demoMode()
	page := httptest.NewRecorder()
	hs.h.ServeHTTP(page, httptest.NewRequest("GET", "/", nil))
	m := regexp.MustCompile(`name="csrf-token" content="([^"]+)"`).FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatal("no CSRF token on the demo overview")
	}
	var csrf *http.Cookie
	for _, c := range page.Result().Cookies() {
		if c.Name == csrfCookie {
			csrf = c
		}
	}
	if csrf == nil || csrf.Value != m[1] {
		t.Fatal("the page token is not the double-submit cookie")
	}
	post := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/account/theme", strings.NewReader(url.Values{"csrf": {token}, "theme": {"dark"}, "next": {"/findings"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(csrf)
		rec := httptest.NewRecorder()
		hs.h.ServeHTTP(rec, req)
		return rec
	}
	if rec := post("wrong"); rec.Code != http.StatusForbidden {
		t.Errorf("theme with a wrong token = %d, want 403", rec.Code)
	}
	rec := post(m[1])
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/findings" {
		t.Fatalf("theme = %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), themeCookie+"=dark") {
		t.Errorf("no theme cookie: %q", rec.Header().Get("Set-Cookie"))
	}
}

// No instance is indexed; a public demo also keeps crawlers out, while a
// real instance, behind its sign-in, has no robots.txt.
func TestNoIndex(t *testing.T) {
	hs := newHarness(t)
	if rec := hs.do(authz.Viewer, "GET", "/robots.txt", nil, false); rec.Code != http.StatusNotFound {
		t.Errorf("robots.txt outside demo mode = %d, want 404", rec.Code)
	}
	for _, p := range []string{"/login", "/setup", "/", "/static/app.css"} {
		if got := hs.do(authz.Viewer, "GET", p, nil, false).Header().Get("X-Robots-Tag"); got != "noindex, nofollow" {
			t.Errorf("GET %s X-Robots-Tag = %q", p, got)
		}
	}
	hs.demoMode()
	rec := hs.do(authz.Demo, "GET", "/robots.txt", nil, false)
	if rec.Code != http.StatusOK || rec.Body.String() != "User-agent: *\nDisallow: /\n" {
		t.Errorf("robots.txt = %d %q", rec.Code, rec.Body.String())
	}
	for _, p := range []string{"/", "/targets", "/robots.txt"} {
		if got := hs.do(authz.Demo, "GET", p, nil, false).Header().Get("X-Robots-Tag"); got != "noindex, nofollow" {
			t.Errorf("GET %s X-Robots-Tag = %q", p, got)
		}
	}
}
