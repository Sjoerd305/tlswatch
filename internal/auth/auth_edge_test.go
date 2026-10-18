package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
)

func TestSetTheme(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	u := mkLocal(t, s, "a@example.nl", authz.Viewer)
	for _, th := range []string{"system", "light", "dark"} {
		if err := s.SetTheme(ctx, u.ID, th); err != nil {
			t.Fatalf("%s: %v", th, err)
		}
		if got, _ := s.UserByID(ctx, u.ID); got.Theme != th {
			t.Fatalf("stored %q, want %q", got.Theme, th)
		}
	}
	for _, th := range []string{"", "Dark", "solarized", `dark" onload="x`} {
		if err := s.SetTheme(ctx, u.ID, th); err == nil {
			t.Errorf("theme %q accepted", th)
		}
	}
	if got, _ := s.UserByID(ctx, u.ID); got.Theme != "dark" {
		t.Fatalf("a refused theme changed the stored one: %q", got.Theme)
	}
}

// oidcServer is a token endpoint that answers with the claims set last.
func oidcServer(t *testing.T, claims *map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(*claims)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": jwt})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The ID token's claims are checked one by one: a configured Workspace
// domain needs the hd claim (a personal Google account has none), the
// e-mail must be verified, and only an enabled Google user may sign in.
func TestOIDCClaimEdgeCases(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	g, err := s.CreateUser(ctx, "g@example.nl", "Kept Name", authz.Operator, MethodGoogle)
	if err != nil {
		t.Fatal(err)
	}
	mkLocal(t, s, "admin@example.nl", authz.Admin)
	off, _ := s.CreateUser(ctx, "off@example.nl", "", authz.Viewer, MethodGoogle)
	if err := s.UpdateUser(ctx, off.ID, "", authz.Viewer, MethodGoogle, false); err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	srv := oidcServer(t, &claims)
	cfg := OIDCConfig{ClientID: "cid", ClientSecret: "cs", Domain: "example.nl", TokenURL: srv.URL, AuthURL: srv.URL, RedirectURL: "https://w.example/cb"}
	_, st, _ := s.OIDCStart(cfg)
	base := func() map[string]any {
		return map[string]any{"iss": "accounts.google.com", "aud": "cid", "exp": s.Now().Add(time.Hour).Unix(), "nonce": st.Nonce,
			"email": "g@example.nl", "email_verified": "true", "hd": "Example.NL", "name": "From Google"}
	}
	claims = base()
	u, _, err := s.OIDCFinish(ctx, cfg, st, st.State, "c")
	if err != nil || u.ID != g.ID || u.Name != "Kept Name" {
		t.Fatalf("string email_verified, short issuer, hd in another case: %+v %v", u, err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"no hd with a domain set": func(m map[string]any) { delete(m, "hd") },
		"no email_verified":       func(m map[string]any) { delete(m, "email_verified") },
		"email_verified string":   func(m map[string]any) { m["email_verified"] = "false" },
		"no email":                func(m map[string]any) { delete(m, "email") },
		"no nonce":                func(m map[string]any) { delete(m, "nonce") },
		"no exp":                  func(m map[string]any) { delete(m, "exp") },
		"disabled user":           func(m map[string]any) { m["email"] = "off@example.nl" },
		"empty aud array":         func(m map[string]any) { m["aud"] = []string{} },
	} {
		claims = base()
		mutate(claims)
		if _, _, err := s.OIDCFinish(ctx, cfg, st, st.State, "c"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A state without a value never matches, even an empty one from the
	// callback.
	claims = base()
	if _, _, err := s.OIDCFinish(ctx, cfg, OIDCState{Nonce: st.Nonce, Expires: st.Expires}, "", "c"); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("empty state: %v", err)
	}
	// Without a domain, any verified account an admin added signs in.
	cfg.Domain = ""
	claims = base()
	delete(claims, "hd")
	if _, _, err := s.OIDCFinish(ctx, cfg, st, st.State, "c"); err != nil {
		t.Errorf("no domain configured, no hd: %v", err)
	}
}

// Switching a password account to Google removes the password and with it
// any one-time password link still out, which would otherwise offer a
// password to an account that has none.
func TestSwitchToGoogleRevokesPasswordLinks(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	mkLocal(t, s, "admin@example.nl", authz.Admin)
	u := mkLocal(t, s, "u@example.nl", authz.Viewer)
	raw, err := s.CreateToken(ctx, TokenInvite, u.ID, InviteTTL)
	if err != nil {
		t.Fatal(err)
	}
	sess, _, err := s.NewSession(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUser(ctx, u.ID, "U", authz.Viewer, MethodGoogle, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.UserByID(ctx, u.ID); got.HasPassword || got.Method != MethodGoogle {
		t.Fatalf("after the switch: %+v", got)
	}
	if _, err := s.Login(ctx, "u@example.nl", goodPW, "192.0.2.1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("the old password after the switch: %v", err)
	}
	if _, err := s.PeekToken(ctx, TokenInvite, raw); err == nil {
		t.Error("a password link stays valid for an account switched to Google")
	}
	if _, err := s.Session(ctx, sess); err == nil {
		t.Error("a session signed in with the password survives the switch to Google")
	}
}

// Pruning drops spent and long-expired links but keeps live ones.
func TestPruneTokens(t *testing.T) {
	s, c := newService(t)
	ctx := context.Background()
	u := mkLocal(t, s, "a@example.nl", authz.Viewer)
	v := mkLocal(t, s, "b@example.nl", authz.Viewer)
	spent, _ := s.CreateToken(ctx, TokenInvite, u.ID, InviteTTL)
	if _, err := s.UseToken(ctx, TokenInvite, spent); err != nil {
		t.Fatal(err)
	}
	live, _ := s.CreateToken(ctx, TokenInvite, v.ID, InviteTTL)
	c.add(2 * 24 * time.Hour)
	if err := s.PruneSessions(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.DB.R.QueryRow("SELECT COUNT(*) FROM tokens").Scan(&n)
	if n != 1 {
		t.Fatalf("%d tokens after pruning, want the live one", n)
	}
	if _, err := s.PeekToken(ctx, TokenInvite, live); err != nil {
		t.Fatalf("live token pruned: %v", err)
	}
}

// A login from an address over its limit is refused before the password
// is looked at, also for a right password, and Forget keeps that limit.
func TestIPLimitSurvivesForget(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	mkLocal(t, s, "a@example.nl", authz.Viewer)
	for i := 0; i < ipMaxFailures; i++ {
		_, _ = s.Login(ctx, "spray"+string(rune('a'+i))+"@example.nl", "x", "198.51.100.1")
	}
	s.Forget()
	if _, err := s.Login(ctx, "a@example.nl", goodPW, "198.51.100.1"); !errors.Is(err, ErrLocked) {
		t.Fatalf("after Forget: %v", err)
	}
}
