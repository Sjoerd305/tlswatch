package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/authz"
)

// totpNow is the code of a base32 secret at t, as an authenticator app
// computes it (RFC 6238).
func totpNow(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha1.New, key)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1000000)
}

// req runs a request carrying cookies.
func (hs *harness) req(method, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, path, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, r)
	return rec
}

func (hs *harness) audited(action string) bool {
	es, _ := hs.srv.Core.AuditLog(context.Background(), action, 50)
	for _, e := range es {
		if e.Action == action {
			return true
		}
	}
	return false
}

// The sign-in of an account with TOTP takes the password, then the code:
// the password alone gives no session.
func TestTOTPSignIn(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	u, _ := hs.srv.Auth.UserByEmail(ctx, "operator@example.test")
	pw := "correct horse battery staple 42"
	if err := hs.srv.Auth.SetPassword(ctx, u.ID, pw); err != nil {
		t.Fatal(err)
	}
	setup, _ := hs.srv.Auth.BeginTOTP(u, "tlswatch")
	codes, err := hs.srv.Auth.ConfirmTOTP(ctx, u, setup.Sealed, totpNow(t, setup.Secret, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	csrfC := cookieNamed(hs.req("GET", "/login", nil), csrfCookie)
	rec := hs.req("POST", "/login", url.Values{"email": {u.Email}, "password": {pw}, "csrf": {csrfC.Value}, "next": {"/targets"}}, csrfC)
	mfa := cookieNamed(rec, mfaCookie)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login/code" || mfa == nil || !mfa.HttpOnly || cookieNamed(rec, sessionCookie) != nil {
		t.Fatalf("password: %d %s %+v", rec.Code, rec.Header().Get("Location"), mfa)
	}
	if body := hs.req("GET", "/login/code", nil, mfa, csrfC).Body.String(); !strings.Contains(body, "authenticator app") {
		t.Fatal("code page")
	}
	post := func(code string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		return hs.req("POST", "/login/code", url.Values{"code": {code}, "csrf": {csrfC.Value}}, append(cookies, csrfC)...)
	}
	if rec := post("000000", mfa); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "code is incorrect") {
		t.Fatalf("wrong code: %d", rec.Code)
	}
	if rec := post(codes[0]); rec.Header().Get("Location") != "/login?error=expired" {
		t.Fatalf("no sign-in state: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	rec = post(codes[0], mfa)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/targets" || cookieNamed(rec, sessionCookie) == nil {
		t.Fatalf("recovery code: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if c := cookieNamed(rec, mfaCookie); c == nil || c.MaxAge >= 0 {
		t.Error("sign-in state not cleared")
	}
	if !hs.audited("user.totp.recovery_used") {
		t.Error("recovery code use not audited")
	}
}

// A role an admin requires TOTP for sets it up before anything else; the
// setup page shows a QR code, and confirming shows the recovery codes once.
func TestTOTPRequiredAndSetup(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	if rec := hs.do(authz.Admin, "POST", "/settings/signin", url.Values{"section": {"totp"}, "totp_roles": {"operator", "bogus"}}, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d", rec.Code)
	}
	if st, _ := hs.srv.Settings.Get(ctx); strings.Join(st.SignIn.TOTPRoles, ",") != "operator" {
		t.Fatalf("roles: %v", st.SignIn.TOTPRoles)
	}
	if rec := hs.do(authz.Operator, "GET", "/targets", nil, false); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/account/totp" {
		t.Fatalf("operator without TOTP: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if rec := hs.do(authz.Operator, "GET", "/api/v1/stamp", nil, false); rec.Code != http.StatusForbidden {
		t.Fatalf("API without TOTP: %d", rec.Code)
	}
	if rec := hs.do(authz.Viewer, "GET", "/targets", nil, false); rec.Code != http.StatusOK {
		t.Fatalf("viewer: %d", rec.Code)
	}
	page := hs.do(authz.Operator, "GET", "/account/totp", nil, false).Body.String()
	if !strings.Contains(page, "<svg") || !strings.Contains(page, "requires two-factor sign-in") {
		t.Fatal("setup page without QR code")
	}
	sealed := regexp.MustCompile(`name="setup" value="([^"]+)"`).FindStringSubmatch(page)
	key := regexp.MustCompile(`<span class="mono wrap-any">([A-Z2-7]+)</span>`).FindStringSubmatch(page)
	if sealed == nil || key == nil {
		t.Fatal("setup form incomplete")
	}
	f := url.Values{"setup": {html.UnescapeString(sealed[1])}, "code": {"123456"}}
	if rec := hs.do(authz.Operator, "POST", "/account/totp", f, true); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), key[1]) {
		t.Fatalf("wrong code keeps the same secret: %d", rec.Code)
	}
	f.Set("code", totpNow(t, key[1], time.Now()))
	rec := hs.do(authz.Operator, "POST", "/account/totp", f, true)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "recovery codes") || len(regexp.MustCompile(`<li>[a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4}</li>`).FindAllString(body, -1)) != 10 {
		t.Fatalf("confirm: %d", rec.Code)
	}
	// The old session ended; the new one opens the rest again.
	if rec := hs.do(authz.Operator, "GET", "/targets", nil, false); rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login") {
		t.Fatalf("old session: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	sess := cookieNamed(rec, sessionCookie)
	if sess == nil || hs.withCookie("GET", "/targets", sess.Value, nil).Code != http.StatusOK {
		t.Fatal("new session")
	}
	if !hs.audited("user.totp.enable") {
		t.Error("not audited")
	}
	// Required, it cannot be turned off by the user; an admin resets it.
	id := hs.userID(authz.Operator)
	raw, csrf, _ := hs.srv.Auth.NewSession(ctx, id)
	hs.sess[authz.Operator] = session{raw, csrf}
	if rec := hs.do(authz.Operator, "POST", "/account/totp/disable", url.Values{"code": {"000000"}}, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("disable: %d", rec.Code)
	}
	if got, _ := hs.srv.Auth.UserByID(ctx, id); !got.HasTOTP() {
		t.Fatal("required TOTP turned off by the user")
	}
	if rec := hs.do(authz.Operator, "POST", fmt.Sprintf("/settings/users/%d/totp/reset", id), nil, true); rec.Code != http.StatusForbidden {
		t.Fatalf("reset by an operator: %d", rec.Code)
	}
	if rec := hs.do(authz.Admin, "POST", fmt.Sprintf("/settings/users/%d/totp/reset", id), nil, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("reset: %d", rec.Code)
	}
	if got, _ := hs.srv.Auth.UserByID(ctx, id); got.HasTOTP() || !hs.audited("user.totp.reset") {
		t.Fatalf("after reset: %+v", got)
	}
	if hs.withCookie("GET", "/targets", raw, nil).Code != http.StatusSeeOther {
		t.Error("reset kept the user's sessions")
	}
}

// Turning one's own TOTP off and making new recovery codes take a code
// from the app.
func TestTOTPAccountActions(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	id := hs.userID(authz.Viewer)
	u, _ := hs.srv.Auth.UserByID(ctx, id)
	setup, _ := hs.srv.Auth.BeginTOTP(u, "tlswatch")
	if _, err := hs.srv.Auth.ConfirmTOTP(ctx, u, setup.Sealed, totpNow(t, setup.Secret, time.Now())); err != nil {
		t.Fatal(err)
	}
	if body := hs.do(authz.Viewer, "GET", "/account", nil, false).Body.String(); !strings.Contains(body, "10 of 10 recovery codes left") {
		t.Fatal("account page")
	}
	if rec := hs.do(authz.Viewer, "POST", "/account/totp/recovery", url.Values{"code": {"000000"}}, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("wrong code: %d", rec.Code)
	}
	later := time.Now().Add(30 * time.Second)
	hs.srv.Auth.Now = func() time.Time { return later }
	rec := hs.do(authz.Viewer, "POST", "/account/totp/recovery", url.Values{"code": {totpNow(t, setup.Secret, later)}}, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "not shown again") || !hs.audited("user.totp.recovery") {
		t.Fatalf("new codes: %d", rec.Code)
	}
	later = later.Add(30 * time.Second)
	if rec := hs.do(authz.Viewer, "POST", "/account/totp/disable", url.Values{"code": {totpNow(t, setup.Secret, later)}}, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("disable: %d", rec.Code)
	}
	if got, _ := hs.srv.Auth.UserByID(ctx, id); got.HasTOTP() || !hs.audited("user.totp.disable") {
		t.Fatal("not turned off")
	}
}

// The generic provider through the web: discovery over TLS, the redirect
// with PKCE, and a callback that creates the user from the role claim.
func TestOIDCSignInWeb(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	var claims map[string]any
	var idp *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": idp.URL, "authorization_endpoint": idp.URL + "/auth", "token_endpoint": idp.URL + "/token"})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(claims)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer",
			"id_token": "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"})
	})
	idp = httptest.NewTLSServer(mux)
	defer idp.Close()
	hs.srv.Auth.HTTPClient = idp.Client()

	bad := url.Values{"section": {"oidc"}, "oidc_issuer": {idp.URL}, "oidc_client_id": {"cid"}, "oidc_role_claim": {"groups"}}
	if rec := hs.do(authz.Admin, "POST", "/settings/signin", bad, true); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "groups of at least one role") {
		t.Fatalf("role claim without groups: %d", rec.Code)
	}
	f := url.Values{"section": {"oidc"}, "oidc_name": {"Keycloak"}, "oidc_issuer": {idp.URL}, "oidc_client_id": {"cid"}, "oidc_client_secret": {"cs"},
		"oidc_role_claim": {"groups"}, "oidc_operator_groups": {"ops, sre"}, "oidc_create_users": {"1"}}
	if rec := hs.do(authz.Admin, "POST", "/settings/signin", f, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	st, _ := hs.srv.Settings.Get(ctx)
	if !st.OIDCEnabled() || st.SignIn.OIDCOperatorGroups != "ops, sre" || st.GoogleEnabled() {
		t.Fatalf("settings: %+v", st.SignIn)
	}
	var raw string
	_ = hs.db.R.QueryRow("SELECT value FROM settings WHERE key = 'signin.oidc_client_secret'").Scan(&raw)
	if raw == "" || strings.Contains(raw, `"cs"`) {
		t.Fatalf("secret stored as %q", raw)
	}
	if body := hs.req("GET", "/login", nil).Body.String(); !strings.Contains(body, "Sign in with Keycloak") {
		t.Fatal("no button")
	}
	rec := hs.req("GET", "/auth/oidc", nil)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	state := cookieNamed(rec, oidcCookie)
	if rec.Code != http.StatusFound || loc == nil || !strings.HasPrefix(loc.String(), idp.URL+"/auth?") || state == nil || state.Path != "/auth/oidc" ||
		loc.Query().Get("redirect_uri") != "http://example.com/auth/oidc/callback" {
		t.Fatalf("start: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	sealed, _ := hs.srv.Auth.OpenState(state.Value)
	claims = map[string]any{"iss": idp.URL, "sub": "1", "aud": "cid", "exp": time.Now().Add(time.Hour).Unix(), "nonce": sealed.Nonce,
		"email": "new@example.test", "groups": []string{"sre"}}
	// The Google callback does not take the generic provider's state.
	if rec := hs.req("GET", "/auth/google/callback?code=c&state="+url.QueryEscape(sealed.State), nil, state); cookieNamed(rec, sessionCookie) != nil {
		t.Fatal("signed in through the other provider's callback")
	}
	rec = hs.req("GET", "/auth/oidc/callback?code=c&state="+url.QueryEscape(sealed.State), nil, state)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" || cookieNamed(rec, sessionCookie) == nil {
		t.Fatalf("callback: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	u, err := hs.srv.Auth.UserByEmail(ctx, "new@example.test")
	if err != nil || u.Role != authz.Operator || u.Method != auth.MethodOIDC || !hs.audited("user.create") {
		t.Fatalf("created: %+v %v", u, err)
	}
	if body := hs.do(authz.Admin, "GET", "/settings/users", nil, false).Body.String(); !strings.Contains(body, "Keycloak") {
		t.Fatal("users list does not name the provider")
	}
}
