package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
)

// fakeIdP is a generic OpenID Connect provider: discovery, a token
// endpoint answering with claims, and a userinfo endpoint.
type fakeIdP struct {
	srv      *httptest.Server
	issuer   string // what discovery states
	claims   map[string]any
	userinfo map[string]any
	auth     string // how the client authenticated at the token endpoint
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	p := &fakeIdP{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /realms/main/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": p.issuer, "authorization_endpoint": p.srv.URL + "/auth", "token_endpoint": p.srv.URL + "/token",
			"userinfo_endpoint": p.srv.URL + "/userinfo",
		})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code_verifier") == "" || r.Form.Get("code") != "the-code" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if id, _, ok := r.BasicAuth(); ok && id == "cid" {
			p.auth = "basic"
		} else if r.Form.Get("client_secret") == "cs" {
			p.auth = "params"
		}
		b, _ := json.Marshal(p.claims)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": jwt})
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at" {
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(p.userinfo)
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	p.issuer = p.srv.URL + "/realms/main"
	return p
}

func genericConfig(t *testing.T, s *Service, p *fakeIdP) OIDCConfig {
	t.Helper()
	d, err := s.Discover(context.Background(), p.srv.URL+"/realms/main/")
	if err != nil {
		t.Fatal(err)
	}
	return OIDCConfig{Provider: ProviderOIDC, ClientID: "cid", ClientSecret: "cs", RedirectURL: "https://w.example/auth/oidc/callback",
		Issuer: d.Issuer, AuthURL: d.AuthURL, TokenURL: d.TokenURL, UserinfoURL: d.UserinfoURL}
}

func TestDiscovery(t *testing.T) {
	s, c := newService(t)
	ctx := context.Background()
	p := newFakeIdP(t)
	if _, err := s.Discover(ctx, p.issuer); err == nil {
		t.Fatal("plain HTTP endpoints accepted")
	}
	s.AllowHTTP = true
	d, err := s.Discover(ctx, p.issuer)
	if err != nil || d.TokenURL != p.srv.URL+"/token" {
		t.Fatalf("discover: %+v %v", d, err)
	}
	// Kept for an hour, then read again; a provider naming another
	// issuer is refused.
	p.issuer = "https://evil.example"
	if _, err := s.Discover(ctx, p.srv.URL+"/realms/main"); err != nil {
		t.Fatalf("cached: %v", err)
	}
	c.add(61 * time.Minute)
	if _, err := s.Discover(ctx, p.srv.URL+"/realms/main"); err == nil {
		t.Fatal("issuer mismatch accepted")
	}
}

func TestGenericOIDC(t *testing.T) {
	s, _ := newService(t)
	s.AllowHTTP = true
	ctx := context.Background()
	p := newFakeIdP(t)
	cfg := genericConfig(t, s, p)
	u0, _ := s.CreateUser(ctx, "kc@example.nl", "", authz.Operator, MethodOIDC)
	if _, err := s.CreateUser(ctx, "g@example.nl", "", authz.Operator, MethodGoogle); err != nil {
		t.Fatal(err)
	}
	redirect, st, err := s.OIDCStart(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if q := mustQuery(t, redirect); q.Get("prompt") != "" || q.Get("scope") != "openid email profile" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("auth URL: %s", redirect)
	}
	base := func() map[string]any {
		return map[string]any{"iss": p.issuer, "sub": "s-1", "aud": "cid", "exp": s.Now().Add(time.Hour).Unix(), "nonce": st.Nonce,
			"email": "KC@example.nl", "name": "Kay"}
	}
	finish := func() (User, OIDCOutcome, error) { return s.OIDCFinish(ctx, cfg, st, st.State, "the-code") }

	// No email_verified claim is accepted (Entra ID sends none); a
	// verified false is not.
	p.claims = base()
	u, out, err := finish()
	if err != nil || u.ID != u0.ID || u.Name != "Kay" || out.Created || out.OldRole != "" {
		t.Fatalf("good: %+v %+v %v", u, out, err)
	}
	bad := map[string]func(m map[string]any){
		"unverified": func(m map[string]any) { m["email_verified"] = false },
		"google":     func(m map[string]any) { m["email"] = "g@example.nl" },
		"unknown":    func(m map[string]any) { m["email"] = "new@example.nl" },
		"azp":        func(m map[string]any) { m["aud"] = []string{"cid", "other"}; m["azp"] = "other" },
		"iss":        func(m map[string]any) { m["iss"] = "https://accounts.google.com" },
	}
	for name, mutate := range bad {
		p.claims = base()
		mutate(p.claims)
		if _, _, err := finish(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A Google state does not complete a generic sign-in.
	gst := st
	gst.Provider = ProviderGoogle
	p.claims = base()
	if _, _, err := s.OIDCFinish(ctx, cfg, gst, gst.State, "the-code"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("provider mismatch: %v", err)
	}

	// The e-mail domain.
	cfg.Domain = "corp.example"
	if _, _, err := finish(); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("other domain: %v", err)
	}
	cfg.Domain = "Example.NL"
	if _, _, err := finish(); err != nil {
		t.Fatalf("domain: %v", err)
	}
	cfg.Domain = ""

	// Missing from the ID token, the e-mail address comes from userinfo,
	// for the same subject only.
	p.claims = base()
	delete(p.claims, "email")
	p.userinfo = map[string]any{"sub": "s-1", "email": "kc@example.nl", "email_verified": true}
	if u, _, err := finish(); err != nil || u.ID != u0.ID {
		t.Fatalf("userinfo: %v", err)
	}
	p.userinfo["sub"] = "s-2"
	if _, _, err := finish(); err == nil {
		t.Fatal("userinfo of another subject accepted")
	}
	if p.auth == "" {
		t.Fatal("client did not authenticate at the token endpoint")
	}
}

func TestRoleClaim(t *testing.T) {
	s, _ := newService(t)
	s.AllowHTTP = true
	ctx := context.Background()
	p := newFakeIdP(t)
	cfg := genericConfig(t, s, p)
	cfg.RoleClaim = "realm_access.roles"
	cfg.RoleGroups = map[authz.Role][]string{authz.Admin: {"tls-admins"}, authz.Operator: {"tls-ops"}, authz.Viewer: {"staff"}}
	_, st, _ := s.OIDCStart(cfg)
	claims := func(email string, groups ...string) map[string]any {
		return map[string]any{"iss": p.issuer, "sub": email, "aud": "cid", "exp": s.Now().Add(time.Hour).Unix(), "nonce": st.Nonce,
			"email": email, "realm_access": map[string]any{"roles": groups}}
	}
	finish := func() (User, OIDCOutcome, error) { return s.OIDCFinish(ctx, cfg, st, st.State, "the-code") }

	// Without "create users", someone not added cannot sign in.
	p.claims = claims("new@example.nl", "staff")
	if _, _, err := finish(); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("not added: %v", err)
	}
	cfg.CreateUsers = true
	u, out, err := finish()
	if err != nil || !out.Created || u.Role != authz.Viewer || u.Method != MethodOIDC {
		t.Fatalf("created: %+v %+v %v", u, out, err)
	}
	// The highest role wins, at every sign-in.
	p.claims = claims("new@example.nl", "staff", "tls-ops")
	if u, out, err = finish(); err != nil || u.Role != authz.Operator || out.OldRole != authz.Viewer || out.Created {
		t.Fatalf("promoted: %+v %+v %v", u, out, err)
	}
	// In none of the groups, no sign-in, created or not.
	p.claims = claims("new@example.nl", "other")
	if _, _, err := finish(); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("no group: %v", err)
	}
	p.claims = claims("stranger@example.nl")
	if _, _, err := finish(); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("no claim: %v", err)
	}
	// A top-level claim of that name, or a plain string, counts too.
	cfg.RoleClaim = "groups"
	p.claims = claims("new@example.nl")
	p.claims["groups"] = "tls-admins"
	if u, _, err = finish(); err != nil || u.Role != authz.Admin {
		t.Fatalf("string claim: %+v %v", u, err)
	}
	// The last enabled admin keeps the role whatever the provider says.
	p.claims["groups"] = []string{"staff"}
	if u, out, err = finish(); err != nil || u.Role != authz.Admin || out.OldRole != "" {
		t.Fatalf("last admin demoted: %+v %+v %v", u, out, err)
	}
	// Missing from the ID token, the claim comes from userinfo.
	mkLocal(t, s, "local-admin@example.nl", authz.Admin)
	delete(p.claims, "groups")
	p.userinfo = map[string]any{"sub": "new@example.nl", "groups": []string{"staff"}}
	if u, _, err = finish(); err != nil || u.Role != authz.Viewer {
		t.Fatalf("claim from userinfo: %+v %v", u, err)
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}
