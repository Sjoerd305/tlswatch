package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/config"
)

// withCookie runs a request with a raw session cookie.
func (hs *harness) withCookie(method, path, raw string, form url.Values) *httptest.ResponseRecorder {
	return hs.signedOut(method, path, form, &http.Cookie{Name: sessionCookie, Value: raw})
}

// Changing one's own password checks the current one, ends every other
// session of the user and keeps this browser signed in with a new session.
func TestAccountPasswordEndsOtherSessions(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	id := hs.userID(authz.Viewer)
	old := "correct horse battery staple 42"
	if err := hs.srv.Auth.SetPassword(ctx, id, old); err != nil {
		t.Fatal(err)
	}
	other, _, err := hs.srv.Auth.NewSession(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	newPW := "another horse battery staple 43"
	for name, f := range map[string]url.Values{
		"wrong current": {"current": {"not my password at all"}, "password": {newPW}, "password2": {newPW}},
		"mismatch":      {"current": {old}, "password": {newPW}, "password2": {newPW + "x"}},
		"short":         {"current": {old}, "password": {"short"}, "password2": {"short"}},
		"same as email": {"current": {old}, "password": {"viewer@example.test"}, "password2": {"viewer@example.test"}},
	} {
		rec := hs.do(authz.Viewer, "POST", "/account/password", f, true)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, rec.Code)
		}
	}
	if _, err := hs.srv.Auth.Session(ctx, other); err != nil {
		t.Fatal("a refused password change ended the other session")
	}
	rec := hs.do(authz.Viewer, "POST", "/account/password", url.Values{"current": {old}, "password": {newPW}, "password2": {newPW}}, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/account" {
		t.Fatalf("change: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := hs.srv.Auth.Session(ctx, other); err == nil {
		t.Error("another session survived the password change")
	}
	if r := hs.do(authz.Viewer, "GET", "/account", nil, false); r.Code != http.StatusSeeOther {
		t.Errorf("the old cookie of this browser still works: %d", r.Code)
	}
	fresh := cookieNamed(rec, sessionCookie)
	if fresh == nil || fresh.Value == "" || !fresh.HttpOnly {
		t.Fatalf("no new session cookie: %+v", fresh)
	}
	if r := hs.withCookie("GET", "/account", fresh.Value, nil); r.Code != http.StatusOK {
		t.Fatalf("the new session: %d", r.Code)
	}
	if _, err := hs.srv.Auth.Login(ctx, "viewer@example.test", old, "192.0.2.9"); err == nil {
		t.Error("the old password still signs in")
	}
	if _, err := hs.srv.Auth.Login(ctx, "viewer@example.test", newPW, "192.0.2.9"); err != nil {
		t.Errorf("the new password: %v", err)
	}
	if hs.count("SELECT COUNT(*) FROM audit WHERE action = 'user.password'") != 1 {
		t.Error("the change is not audited once")
	}

	// A Google account has no password to change.
	g, err := hs.srv.Auth.CreateUser(ctx, "g@example.test", "G", authz.Viewer, auth.MethodGoogle)
	if err != nil {
		t.Fatal(err)
	}
	raw, csrf, _ := hs.srv.Auth.NewSession(ctx, g.ID)
	hs.sess["google"] = session{raw, csrf}
	if r := hs.do("google", "POST", "/account/password", url.Values{"current": {""}, "password": {newPW}, "password2": {newPW}}, true); r.Code != http.StatusBadRequest {
		t.Fatalf("Google user changes a password: %d", r.Code)
	}
}

// The account form changes only the signed-in user's name and theme,
// whatever the form says about another user.
func TestAccountSaveAndTheme(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	admin := hs.userID(authz.Admin)
	f := url.Values{"name": {"Vera Viewer"}, "theme": {"dark"}, "id": {fmt.Sprint(admin)}, "user_id": {fmt.Sprint(admin)}, "role": {"admin"}}
	rec := hs.do(authz.Viewer, "POST", "/account", f, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/account" {
		t.Fatalf("save: %d", rec.Code)
	}
	if c := cookieNamed(rec, themeCookie); c == nil || c.Value != "dark" {
		t.Errorf("theme cookie: %+v", c)
	}
	v, _ := hs.srv.Auth.UserByID(ctx, hs.userID(authz.Viewer))
	a, _ := hs.srv.Auth.UserByID(ctx, admin)
	if v.Name != "Vera Viewer" || v.Theme != "dark" || v.Role != authz.Viewer {
		t.Errorf("viewer after save: %+v", v)
	}
	if a.Name != "admin" || a.Theme == "dark" {
		t.Errorf("the admin was changed through another user's form: %+v", a)
	}
	// An unknown theme is refused and changes nothing.
	rec = hs.do(authz.Viewer, "POST", "/account", url.Values{"name": {"X"}, "theme": {"purple"}}, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("bad theme: %d", rec.Code)
	}
	v, _ = hs.srv.Auth.UserByID(ctx, v.ID)
	if v.Theme != "dark" || v.Name != "Vera Viewer" {
		t.Errorf("a refused save changed the account: %+v", v)
	}
	// The account menu's switch returns to the page, never off-site.
	for next, want := range map[string]string{"/targets?sort=name": "/targets?sort=name", "//evil.example/": "/", "https://evil.example": "/", "": "/"} {
		rec := hs.do(authz.Viewer, "POST", "/account/theme", url.Values{"theme": {"light"}, "next": {next}}, true)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
			t.Errorf("theme switch next=%q: %d %q, want %q", next, rec.Code, rec.Header().Get("Location"), want)
		}
	}
	if rec := hs.do(authz.Viewer, "POST", "/account/theme", url.Values{"theme": {"<script>"}, "next": {"/targets"}}, true); cookieNamed(rec, themeCookie) != nil {
		t.Error("an unknown theme was set as a cookie")
	}
	v, _ = hs.srv.Auth.UserByID(ctx, v.ID)
	if v.Theme != "light" {
		t.Errorf("theme after the switch: %q", v.Theme)
	}
	// The stored theme is applied on the next page without a cookie.
	if body := hs.do(authz.Viewer, "GET", "/", nil, false).Body.String(); !strings.Contains(body, `data-theme="light"`) {
		t.Error("the stored theme is not rendered")
	}
}

var inviteRe = regexp.MustCompile(`/invite\?token=([A-Za-z0-9_-]+)`)

// inviteUser adds a local user without SMTP, which shows the one-time link,
// and returns the user and the token.
func (hs *harness) inviteUser(email string) (auth.User, string) {
	hs.t.Helper()
	rec := hs.do(authz.Admin, "POST", "/settings/users", url.Values{"email": {email}, "name": {"New"}, "role": {"operator"}, "method": {"local"}}, true)
	m := inviteRe.FindStringSubmatch(rec.Body.String())
	if rec.Code != http.StatusOK || m == nil {
		hs.t.Fatalf("invite %s: %d, no link", email, rec.Code)
	}
	u, err := hs.srv.Auth.UserByEmail(context.Background(), email)
	if err != nil {
		hs.t.Fatal(err)
	}
	return u, m[1]
}

// The one-time link: a refused password leaves it usable, a good one signs
// the user in, ends their other sessions and clears a lockout, and the
// link works once.
func TestInviteLink(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	u, tok := hs.inviteUser("new@example.test")
	if rec := hs.do(authz.Admin, "POST", "/settings/users", url.Values{"email": {"NEW@example.test"}, "role": {"viewer"}, "method": {"local"}}, true); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "already exists") {
		t.Fatalf("invite an existing address: %d", rec.Code)
	}
	if page := hs.signedOut("GET", "/invite?token=bogus", nil, nil).Body.String(); !strings.Contains(page, "Link not valid") {
		t.Fatal("a made-up token shows the password form")
	}
	if page := hs.signedOut("GET", "/invite?token="+tok, nil, nil).Body.String(); !strings.Contains(page, "Set your password") || !strings.Contains(page, "new@example.test") {
		t.Fatal("the invite page does not show the form")
	}
	_, post := hs.signedOutForm("/invite?token=" + tok)
	pw := "correct horse battery staple 51"
	if rec := post("/invite", url.Values{"token": {tok}, "password": {pw}, "password2": {pw + "!"}}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "do not match") {
		t.Fatalf("mismatch: %d", rec.Code)
	}
	if rec := post("/invite", url.Values{"token": {tok}, "password": {"password1234"}, "password2": {"password1234"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("leaked password: %d", rec.Code)
	}
	if _, err := hs.srv.Auth.PeekToken(ctx, auth.TokenInvite, tok); err != nil {
		t.Fatal("a refused password spent the link")
	}
	stale, _, _ := hs.srv.Auth.NewSession(ctx, u.ID)
	if _, err := hs.db.W.Exec("UPDATE users SET locked_until = ?, failed_count = 5 WHERE id = ?", time.Now().Unix()+600, u.ID); err != nil {
		t.Fatal(err)
	}
	rec := post("/invite", url.Values{"token": {tok}, "password": {pw}, "password2": {pw}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" || cookieNamed(rec, sessionCookie) == nil {
		t.Fatalf("set password: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := hs.srv.Auth.Session(ctx, stale); err == nil {
		t.Error("an older session survived the password link")
	}
	if _, err := hs.srv.Auth.Login(ctx, "new@example.test", pw, "192.0.2.50"); err != nil {
		t.Errorf("sign in after the link (lock cleared?): %v", err)
	}
	if rec := post("/invite", url.Values{"token": {tok}, "password": {pw}, "password2": {pw}}); rec.Code != http.StatusBadRequest || cookieNamed(rec, sessionCookie) != nil {
		t.Fatalf("link used twice: %d", rec.Code)
	}

	// A new link replaces the old; an expired one does nothing.
	rec = hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/users/%d/link", u.ID), nil, true)
	m := inviteRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("new link: %d", rec.Code)
	}
	hs.srv.Auth.Now = func() time.Time { return time.Now().Add(auth.InviteTTL + time.Minute) }
	if rec := post("/invite", url.Values{"token": {m[1]}, "password": {pw + "x"}, "password2": {pw + "x"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("expired link: %d", rec.Code)
	}
	hs.srv.Auth.Now = time.Now

	// A disabled user's link does not work.
	v, tok2 := hs.inviteUser("later@example.test")
	if err := hs.srv.Auth.UpdateUser(ctx, v.ID, "", authz.Viewer, auth.MethodLocal, false); err != nil {
		t.Fatal(err)
	}
	if page := hs.signedOut("GET", "/invite?token="+tok2, nil, nil).Body.String(); !strings.Contains(page, "Link not valid") {
		t.Error("a disabled user's link shows the form")
	}
	if rec := post("/invite", url.Values{"token": {tok2}, "password": {pw}, "password2": {pw}}); rec.Code != http.StatusBadRequest {
		t.Errorf("a disabled user's link: %d", rec.Code)
	}
	// A deleted user's link is gone with the account.
	w, tok3 := hs.inviteUser("gone@example.test")
	if err := hs.srv.Auth.DeleteUser(ctx, w.ID); err != nil {
		t.Fatal(err)
	}
	if rec := post("/invite", url.Values{"token": {tok3}, "password": {pw}, "password2": {pw}}); rec.Code != http.StatusBadRequest {
		t.Errorf("a deleted user's link: %d", rec.Code)
	}
}

// A link issued while the account had a password stops working once an
// admin switches the account to Google sign-in: a Google user has no
// password, and the link must not answer with a server error.
func TestInviteLinkAfterSwitchToGoogle(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	u, tok := hs.inviteUser("switch@example.test")
	f := url.Values{"name": {"S"}, "role": {"operator"}, "method": {"google"}, "enabled": {"1"}}
	if rec := hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/users/%d", u.ID), f, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("switch to Google: %d", rec.Code)
	}
	if page := hs.signedOut("GET", "/invite?token="+tok, nil, nil).Body.String(); !strings.Contains(page, "Link not valid") {
		t.Error("the invite page offers a password form to a Google account")
	}
	_, post := hs.signedOutForm("/invite?token=" + tok)
	pw := "correct horse battery staple 52"
	rec := post("/invite", url.Values{"token": {tok}, "password": {pw}, "password2": {pw}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("password link of a Google account: %d, want 400", rec.Code)
	}
	if got, _ := hs.srv.Auth.UserByID(ctx, u.ID); got.HasPassword {
		t.Error("a Google account got a password")
	}
}

// Google sign-in: the start sets a sealed, HttpOnly state cookie and sends
// the browser to Google with PKCE; a callback without that cookie, with a
// tampered or expired one, with an error or another state never signs in.
func TestGoogleSignInHandlers(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	if rec := hs.signedOut("GET", "/auth/google", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("start while not configured: %d", rec.Code)
	}
	if err := hs.srv.Settings.SaveSignIn(ctx, config.SignIn{GoogleClientID: "cid.apps.googleusercontent.com", GoogleClientSecret: "gsecret", GoogleDomain: "example.test"}, false); err != nil {
		t.Fatal(err)
	}
	rec := hs.signedOut("GET", "/auth/google", nil, nil)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc == nil || loc.Host != "accounts.google.com" {
		t.Fatalf("start: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("hd") != "example.test" ||
		q.Get("redirect_uri") != "http://example.com/auth/google/callback" || strings.Contains(loc.String(), "gsecret") {
		t.Fatalf("auth URL: %s", loc)
	}
	st := cookieNamed(rec, oidcCookie)
	if st == nil || !st.HttpOnly || st.Path != "/auth/google" || st.MaxAge <= 0 || st.MaxAge > 600 {
		t.Fatalf("state cookie: %+v", st)
	}
	callback := func(query string, c *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		rec := hs.signedOut("GET", "/auth/google/callback"+query, nil, c)
		if cookieNamed(rec, sessionCookie) != nil && cookieNamed(rec, sessionCookie).MaxAge >= 0 {
			t.Errorf("callback %s signed in", query)
		}
		if c := cookieNamed(rec, oidcCookie); c == nil || c.MaxAge >= 0 {
			t.Errorf("callback %s does not clear the state cookie", query)
		}
		return rec
	}
	good := "?state=" + url.QueryEscape(q.Get("state")) + "&code=abc"
	if rec := callback(good, nil); rec.Header().Get("Location") != "/login?error=expired" {
		t.Errorf("no state cookie: %s", rec.Header().Get("Location"))
	}
	tampered := *st
	tampered.Value = st.Value[:len(st.Value)-4] + "AAAA"
	if rec := callback(good, &tampered); rec.Header().Get("Location") != "/login?error=expired" {
		t.Errorf("tampered state cookie: %s", rec.Header().Get("Location"))
	}
	if rec := callback("?state=someone-elses&code=abc", st); rec.Header().Get("Location") != "/login?error=google" {
		t.Errorf("other state: %s", rec.Header().Get("Location"))
	}
	if rec := callback("?error=access_denied&state="+url.QueryEscape(q.Get("state")), st); rec.Header().Get("Location") != "/login?error=google" {
		t.Errorf("error from Google: %s", rec.Header().Get("Location"))
	}
	hs.srv.Auth.Now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if rec := callback(good, st); rec.Header().Get("Location") != "/login?error=expired" {
		t.Errorf("expired state: %s", rec.Header().Get("Location"))
	}
	hs.srv.Auth.Now = time.Now
	// The sign-in page explains both outcomes neutrally.
	for q, want := range map[string]string{"google": "Ask an administrator", "expired": "expired"} {
		if body := hs.signedOut("GET", "/login?error="+q, nil, nil).Body.String(); !strings.Contains(body, want) {
			t.Errorf("/login?error=%s lacks %q", q, want)
		}
	}
}
