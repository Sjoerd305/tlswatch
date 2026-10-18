package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
)

// muxRoute is one route as routes.go registers it.
type muxRoute struct {
	method, pattern string
	wrapper         string // view, edit, …; empty for a public route
}

// registeredRoutes reads the routes from routes.go itself, so a route added
// there is covered by the suites below without anyone listing it.
func registeredRoutes(t *testing.T) []muxRoute {
	t.Helper()
	src, err := os.ReadFile("routes.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`mux\.HandleFunc\("([A-Z]+) ([^"]+)", (?:(\w+)\()?`)
	var out []muxRoute
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		out = append(out, muxRoute{method: m[1], pattern: m[2], wrapper: m[3]})
	}
	if len(out) < 100 {
		t.Fatalf("read only %d routes from routes.go", len(out))
	}
	return out
}

var wrapperAction = map[string]authz.Action{
	"view": authz.ViewData, "edit": authz.EditTargets, "ack": authz.Acknowledge, "admin": authz.ManageSettings,
	"users": authz.ManageUsers, "audit": authz.ViewAudit, "own": authz.ManageOwnAccount,
}

// publicRoutes are the only routes reachable without the role check.
var publicRoutes = map[string]bool{
	"GET /healthz": true, "GET /metrics": true, "GET /favicon.ico": true,
	"GET /login": true, "POST /login": true, "POST /logout": true,
	"GET /login/code": true, "POST /login/code": true, // after the password, before the session
	"GET /auth/google": true, "GET /auth/google/callback": true,
	"GET /auth/oidc": true, "GET /auth/oidc/callback": true,
	"GET /setup": true, "POST /setup": true, "POST /setup/restore": true,
	"GET /invite": true, "POST /invite": true,
	// The feed's secret token is its credential, as a calendar client
	// cannot sign in.
	"GET /calendar/{file}": true,
}

// concrete fills a pattern's wildcards with IDs that exist nowhere, so an
// allowed request that gets through does no harm.
func concrete(pattern string) string {
	p := strings.ReplaceAll(pattern, "{$}", "")
	p = strings.ReplaceAll(p, "{id}", "999999")
	p = strings.ReplaceAll(p, "{iid}", "999999")
	p = strings.ReplaceAll(p, "{fp}", "00")
	return p
}

// Every route in routes.go is either on the short public list or behind the
// role check, and every role is refused what the policy does not give it.
func TestEveryRegisteredRouteIsGuarded(t *testing.T) {
	hs := newHarness(t)
	for _, r := range registeredRoutes(t) {
		key := r.method + " " + r.pattern
		if r.wrapper == "" {
			if !publicRoutes[key] {
				t.Errorf("%s is reachable without the role check", key)
			}
			continue
		}
		action, ok := wrapperAction[r.wrapper]
		if !ok {
			t.Errorf("%s: unknown wrapper %q", key, r.wrapper)
			continue
		}
		path := concrete(r.pattern)
		for _, role := range authz.Roles {
			rec := hs.do(role, r.method, path, nil, true)
			allowed := authz.Allowed(role, action)
			if !allowed && rec.Code != http.StatusForbidden {
				t.Errorf("%s %s as %s: %d, want 403", r.method, path, role, rec.Code)
			}
			if allowed && rec.Code == http.StatusForbidden {
				t.Errorf("%s %s as %s: forbidden, but the policy allows it: %s", r.method, path, role, rec.Body.String())
			}
		}
	}
}

// Every state-changing route refuses a request without the CSRF token, with
// a wrong one in the form, and with a wrong one in the X-CSRF-Token header,
// even from an admin, who may do everything else.
func TestEveryPostNeedsTheCSRFToken(t *testing.T) {
	hs := newHarness(t)
	admin := hs.sess[authz.Admin]
	n := 0
	for _, r := range registeredRoutes(t) {
		if r.method != http.MethodPost {
			continue
		}
		n++
		path := concrete(r.pattern)
		if streamedUpload(path) {
			if r.wrapper == "" {
				continue // the setup screen; covered by TestSetupRestore
			}
			for _, tok := range []string{"", "wrong"} {
				var fields [][2]string
				if tok != "" {
					fields = [][2]string{{"csrf", tok}}
				}
				if rec := hs.upload(path, authz.Admin, nil, append(fields, [2]string{"confirm", "1"}), []byte("x")); rec.Code != http.StatusForbidden {
					t.Errorf("%s with CSRF %q: %d, want 403", path, tok, rec.Code)
				}
			}
			continue
		}
		if rec := hs.do(authz.Admin, "POST", path, nil, false); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s without a CSRF token: %d, want 403", path, rec.Code)
		}
		if rec := hs.do(authz.Admin, "POST", path, url.Values{"csrf": {admin.csrf + "x"}}, false); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s with a wrong CSRF token: %d, want 403", path, rec.Code)
		}
		// A wrong header wins over a right form value.
		req := httptest.NewRequest("POST", path, strings.NewReader(url.Values{"csrf": {admin.csrf}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-CSRF-Token", "wrong")
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: admin.cookie})
		rec := httptest.NewRecorder()
		hs.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST %s with a wrong X-CSRF-Token: %d, want 403", path, rec.Code)
		}
		// Another user's token does not pass for this session.
		if rec := hs.do(authz.Admin, "POST", path, url.Values{"csrf": {hs.sess[authz.Viewer].csrf}}, false); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s with another session's token: %d, want 403", path, rec.Code)
		}
	}
	if n < 50 {
		t.Fatalf("only %d POST routes", n)
	}
	// Signed out, the public forms need the double-submit cookie. Sign out
	// itself, signed out, has nothing to protect and lands on /login.
	for _, p := range []string{"/login", "/setup", "/invite"} {
		if rec := hs.signedOut("POST", p, url.Values{"csrf": {"made-up-token-123456789"}}, nil); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s signed out without the CSRF cookie: %d, want 403", p, rec.Code)
		}
		c := &http.Cookie{Name: csrfCookie, Value: "made-up-token-123456789"}
		if rec := hs.signedOut("POST", p, url.Values{"csrf": {"another-token-123456789"}}, c); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s signed out with a token that is not the cookie's: %d, want 403", p, rec.Code)
		}
	}
}

func sessionRows(hs *harness, role authz.Role) int {
	hs.t.Helper()
	return hs.count(fmt.Sprintf("SELECT COUNT(*) FROM sessions WHERE user_id = %d", hs.userID(role)))
}

// Signing out deletes the session on the server, so a copied cookie does
// not work afterwards; without the CSRF token nothing happens.
func TestLogoutEndsSessionOnServer(t *testing.T) {
	hs := newHarness(t)
	if rec := hs.do(authz.Viewer, "POST", "/logout", nil, false); rec.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF: %d", rec.Code)
	}
	if sessionRows(hs, authz.Viewer) != 1 {
		t.Fatal("a logout without the CSRF token ended the session")
	}
	rec := hs.do(authz.Viewer, "POST", "/logout", nil, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("logout: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the session cookie is not cleared")
	}
	if sessionRows(hs, authz.Viewer) != 0 {
		t.Fatal("the session row survived the logout")
	}
	if rec := hs.do(authz.Viewer, "GET", "/", nil, false); rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login") {
		t.Fatalf("old cookie after logout: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	// Other users stay signed in.
	if rec := hs.do(authz.Operator, "GET", "/", nil, false); rec.Code != http.StatusOK {
		t.Fatalf("another user's session after a logout: %d", rec.Code)
	}
	// Sign out pressed again, the session long gone: the sign-in page, not
	// "the form has expired".
	if rec := hs.do(authz.Viewer, "POST", "/logout", nil, true); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("logout after the session ended: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

// An idle session and one past its maximum age end on the next request,
// which redirects to sign in and clears the cookie; the API answers 401.
func TestSessionIdleAndMaxAgeOverHTTP(t *testing.T) {
	hs := newHarness(t)
	now := time.Now().Unix()
	if _, err := hs.db.W.Exec("UPDATE sessions SET last_seen = ? WHERE user_id = ?", now-int64((8*time.Hour+time.Minute)/time.Second), hs.userID(authz.Viewer)); err != nil {
		t.Fatal(err)
	}
	if _, err := hs.db.W.Exec("UPDATE sessions SET created_at = ? WHERE user_id = ?", now-int64((7*24*time.Hour+time.Minute)/time.Second), hs.userID(authz.Operator)); err != nil {
		t.Fatal(err)
	}
	rec := hs.do(authz.Viewer, "GET", "/targets", nil, false)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login?next=%2Ftargets") {
		t.Fatalf("idle session: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if sessionRows(hs, authz.Viewer) != 0 {
		t.Error("the idle session was not deleted")
	}
	if rec := hs.do(authz.Operator, "GET", "/api/v1/stamp", nil, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session past its maximum age on the API: %d", rec.Code)
	}
	// A live session just inside the idle timeout still works.
	if _, err := hs.db.W.Exec("UPDATE sessions SET last_seen = ? WHERE user_id = ?", now-int64((8*time.Hour-time.Minute)/time.Second), hs.userID(authz.Admin)); err != nil {
		t.Fatal(err)
	}
	if rec := hs.do(authz.Admin, "GET", "/", nil, false); rec.Code != http.StatusOK {
		t.Fatalf("session inside the idle timeout: %d", rec.Code)
	}
}

// A role change applies to the user's open sessions at once, and disabling
// a user signs them out.
func TestRoleChangeAppliesToOpenSessions(t *testing.T) {
	hs := newHarness(t)
	op := hs.userID(authz.Operator)
	if rec := hs.do(authz.Operator, "POST", "/targets/1/disable", nil, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("operator disables a target: %d", rec.Code)
	}
	f := url.Values{"name": {"Op"}, "role": {"viewer"}, "method": {"local"}, "enabled": {"1"}}
	if rec := hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/users/%d", op), f, true); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/settings/users" {
		t.Fatalf("demote: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if rec := hs.do(authz.Operator, "POST", "/targets/1/enable", nil, true); rec.Code != http.StatusForbidden {
		t.Fatalf("demoted user's open session still edits targets: %d", rec.Code)
	}
	f.Set("enabled", "0")
	if rec := hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/users/%d", op), f, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("disable: %d", rec.Code)
	}
	if rec := hs.do(authz.Operator, "GET", "/", nil, false); rec.Code != http.StatusSeeOther {
		t.Fatalf("disabled user's session: %d", rec.Code)
	}
}

// The last enabled admin cannot demote or disable themselves through the
// users page, and deleting oneself is refused even with another admin.
func TestLastAdminProtectedOverHTTP(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	admin := hs.userID(authz.Admin)
	for _, f := range []url.Values{
		{"name": {"A"}, "role": {"operator"}, "method": {"local"}, "enabled": {"1"}},
		{"name": {"A"}, "role": {"admin"}, "method": {"local"}, "enabled": {"0"}},
		{"name": {"A"}, "role": {"viewer"}, "method": {"google"}, "enabled": {"0"}},
	} {
		rec := hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/users/%d", admin), f, true)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != fmt.Sprintf("/settings/users?edit=%d", admin) {
			t.Fatalf("change the last admin %v: %d %s", f, rec.Code, rec.Header().Get("Location"))
		}
		u, _ := hs.srv.Auth.UserByID(ctx, admin)
		if u.Role != authz.Admin || !u.Enabled || u.Method != "local" {
			t.Fatalf("the last admin was changed: %+v", u)
		}
	}
	if rec := hs.do(authz.Admin, "GET", "/", nil, false); rec.Code != http.StatusOK {
		t.Fatalf("the last admin was signed out: %d", rec.Code)
	}
	// With a second admin, demoting is fine but deleting oneself is not.
	other, err := hs.srv.Auth.CreateUser(ctx, "admin2@example.test", "B", authz.Admin, "local")
	if err != nil {
		t.Fatal(err)
	}
	if rec := hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/users/%d/delete", admin), nil, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete self: %d", rec.Code)
	}
	if _, err := hs.srv.Auth.UserByID(ctx, admin); err != nil {
		t.Fatal("an admin deleted their own account")
	}
	if rec := hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/users/%d/delete", other.ID), nil, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete the other admin: %d", rec.Code)
	}
	if _, err := hs.srv.Auth.UserByID(ctx, other.ID); err == nil {
		t.Fatal("the other admin was not deleted")
	}
}

// Malformed IDs, unknown users and odd query values answer 404 or a normal
// page, never a server error.
func TestMalformedInputIsNotAServerError(t *testing.T) {
	hs := newHarness(t)
	gets := []string{
		"/targets/abc", "/targets/-1", "/targets/0", "/targets/99999999999999999999", "/targets/1.5/edit",
		"/domains/abc", "/domains/0/edit", "/domains/-3/delete", "/settings/nodes/abc", "/settings/nodes/0/delete",
		"/api/v1/findings/abc/panel", "/api/v1/findings/999/panel", "/certificates/zz/pem", "/certificates/" + strings.Repeat("a", 64) + "/pem",
	}
	for _, p := range gets {
		rec := hs.do(authz.Admin, "GET", p, nil, false)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", p, rec.Code)
		}
	}
	posts := []string{
		"/targets/abc/check", "/targets/0/enable", "/targets/x/delete", "/domains/x/poll", "/domains/1/issuances/x/ack",
		"/findings/abc/ack", "/findings/0/unack", "/settings/users/abc", "/settings/users/0/delete", "/settings/users/999/unlock",
		"/settings/users/999/link", "/settings/channels/x/test", "/settings/channels/999/delete", "/settings/bundles/x/delete",
		"/settings/nodes/abc/reject", "/settings/nodes/999/update", "/settings/nodes/999/enable", "/api/v1/targets/abc/check",
	}
	for _, p := range posts {
		rec := hs.do(authz.Admin, "POST", p, nil, true)
		if rec.Code != http.StatusNotFound {
			t.Errorf("POST %s: %d, want 404", p, rec.Code)
		}
	}
	// Unknown sort keys, directions, chips and flags fall back to defaults.
	for _, p := range []string{
		"/targets?sort=evil&dir=sideways", "/targets?sort=name&dir=desc&status=%00&tag=%ff", "/certificates?sort=;drop&window=-1&all=maybe",
		"/findings?sort=x&dir=y&state=z&severity=w&group=q&target=abc", "/domains?status=nope", "/?all=yes", "/settings/users?edit=abc",
		"/settings/audit?q=%25%27", "/settings/channels?edit=-1", "/settings/bundles?edit=x",
	} {
		if rec := hs.do(authz.Admin, "GET", p, nil, false); rec.Code != http.StatusOK {
			t.Errorf("GET %s: %d, want 200", p, rec.Code)
		}
	}
}

// /healthz needs no sign-in, works before setup, and says nothing about the
// version.
func TestHealthWithoutSignIn(t *testing.T) {
	for _, withUsers := range []bool{true, false} {
		hs := newHarnessUsers(t, withUsers)
		rec := hs.signedOut("GET", "/healthz", nil, nil)
		if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("healthz (users %v): %d %s", withUsers, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		for _, want := range []string{`"ok":true`, `"database":true`, `"backlog":`, `"overdue_s":`} {
			if !strings.Contains(body, want) {
				t.Errorf("healthz lacks %s: %s", want, body)
			}
		}
		if strings.Contains(body, `"version"`) || strings.Contains(body, "test") {
			t.Errorf("healthz names the version: %s", body)
		}
	}
	// A closed database is reported, not hidden.
	hs := newHarness(t)
	hs.db.Close()
	if rec := hs.signedOut("GET", "/healthz", nil, nil); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"database":false`) {
		t.Fatalf("healthz with the database gone: %d %s", rec.Code, rec.Body.String())
	}
}

// Without proxy trust the client address used for the per-address sign-in
// limit is the peer's, whatever X-Forwarded-For says; with it, the last hop.
func TestClientAddressIgnoresForwardedForUntilTrusted(t *testing.T) {
	req := httptest.NewRequest("POST", "/login", nil)
	req.RemoteAddr = "198.51.100.4:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	if ip, _ := clientInfo(req, false); ip != "198.51.100.4" {
		t.Fatalf("untrusted X-Forwarded-For used: %s", ip)
	}
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 192.0.2.77")
	if ip, _ := clientInfo(req, true); ip != "192.0.2.77" {
		t.Fatalf("behind a proxy: %s, want the last hop", ip)
	}
	req.Header.Set("X-Forwarded-For", "not-an-ip")
	if ip, _ := clientInfo(req, true); ip != "198.51.100.4" {
		t.Fatalf("garbage X-Forwarded-For: %s", ip)
	}
	// A public peer is not believed about https either.
	req.Header.Set("X-Forwarded-Proto", "https")
	if _, https := clientInfo(req, false); https {
		t.Fatal("a public peer's X-Forwarded-Proto was believed")
	}
}

// signedOutForm fetches page for its CSRF cookie and returns a function that
// posts forms with it.
func (hs *harness) signedOutForm(page string) (*http.Cookie, func(path string, f url.Values, extra ...*http.Cookie) *httptest.ResponseRecorder) {
	hs.t.Helper()
	rec := hs.signedOut("GET", page, nil, nil)
	var c *http.Cookie
	for _, k := range rec.Result().Cookies() {
		if k.Name == csrfCookie {
			c = k
		}
	}
	if c == nil {
		hs.t.Fatalf("no CSRF cookie on %s (%d)", page, rec.Code)
	}
	return c, func(path string, f url.Values, extra ...*http.Cookie) *httptest.ResponseRecorder {
		f.Set("csrf", c.Value)
		req := httptest.NewRequest("POST", path, strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(c)
		for _, e := range extra {
			req.AddCookie(e)
		}
		rec := httptest.NewRecorder()
		hs.h.ServeHTTP(rec, req)
		return rec
	}
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Five failed sign-ins lock the account with a message that is the same
// for an address without an account.
func TestLoginLockoutOverHTTP(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	u, _ := hs.srv.Auth.UserByEmail(ctx, "operator@example.test")
	pw := "correct horse battery staple 42"
	if err := hs.srv.Auth.SetPassword(ctx, u.ID, pw); err != nil {
		t.Fatal(err)
	}
	_, post := hs.signedOutForm("/login")
	var last, ghost *httptest.ResponseRecorder
	for i := 0; i < 5; i++ {
		last = post("/login", url.Values{"email": {"operator@example.test"}, "password": {"wrong password " + fmt.Sprint(i)}})
		ghost = post("/login", url.Values{"email": {"nobody@example.test"}, "password": {"wrong password " + fmt.Sprint(i)}})
	}
	for name, rec := range map[string]*httptest.ResponseRecorder{"account": last, "no account": ghost} {
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Too many failed attempts") {
			t.Errorf("fifth failure (%s): %d", name, rec.Code)
		}
	}
	if rec := post("/login", url.Values{"email": {"operator@example.test"}, "password": {pw}}); rec.Code != http.StatusUnauthorized || cookieNamed(rec, sessionCookie) != nil {
		t.Fatalf("the right password while locked: %d", rec.Code)
	}
	page := hs.do(authz.Admin, "GET", "/settings/users", nil, false).Body.String()
	if !strings.Contains(page, fmt.Sprintf(`action="/settings/users/%d/unlock"`, u.ID)) {
		t.Fatal("the locked account has no Unlock button")
	}
	if rec := hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/users/%d/unlock", u.ID), nil, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("unlock: %d", rec.Code)
	}
	if rec := post("/login", url.Values{"email": {"OPERATOR@example.test"}, "password": {pw}}); rec.Code != http.StatusSeeOther || cookieNamed(rec, sessionCookie) == nil {
		t.Fatalf("sign in after the unlock: %d %s", rec.Code, rec.Body.String())
	}
}
