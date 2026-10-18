package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/sjoerd305/tlswatch/internal/authz"
)

// Google's OpenID Connect endpoints: the Google provider is the generic
// one with these preset.
const (
	GoogleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	GoogleTokenURL = "https://oauth2.googleapis.com/token" // #nosec G101 -- a public endpoint URL, not a credential
	GoogleIssuer   = "https://accounts.google.com"

	oidcStateTTL = 10 * time.Minute
	discoveryTTL = time.Hour
)

// Providers, which are also the login methods of their users.
const (
	ProviderGoogle = MethodGoogle
	ProviderOIDC   = MethodOIDC
)

// OIDCConfig configures one OpenID Connect provider. An empty Provider is
// Google, whose endpoints default to Google's.
type OIDCConfig struct {
	Provider     string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// Domain is, for Google, the Workspace domain (hd claim); for the
	// generic provider, the domain every e-mail address must be in.
	Domain      string
	AuthURL     string
	TokenURL    string
	UserinfoURL string
	Issuer      string
	Scopes      []string
	// RoleClaim names the claim with the user's groups or roles; when set,
	// RoleGroups decides the role at every sign-in, and a user whose
	// claim maps to no role is refused.
	RoleClaim  string
	RoleGroups map[authz.Role][]string
	// CreateUsers creates a user who does not exist yet, with the role
	// from the claim.
	CreateUsers bool
}

// Enabled reports whether the provider is configured.
func (c OIDCConfig) Enabled() bool {
	return c.ClientID != "" && c.ClientSecret != "" && (c.google() || c.Issuer != "")
}

func (c OIDCConfig) google() bool { return c.Provider == "" || c.Provider == ProviderGoogle }

// Method is the login method of the provider's users.
func (c OIDCConfig) Method() string {
	if c.google() {
		return MethodGoogle
	}
	return MethodOIDC
}

func (c OIDCConfig) oauth2() *oauth2.Config {
	auth, tok, style := c.AuthURL, c.TokenURL, oauth2.AuthStyleAutoDetect
	if c.google() {
		if auth == "" {
			auth = GoogleAuthURL
		}
		if tok == "" {
			tok = GoogleTokenURL
		}
		style = oauth2.AuthStyleInParams
	}
	scopes := c.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	} else if !slices.Contains(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
		Endpoint:     oauth2.Endpoint{AuthURL: auth, TokenURL: tok, AuthStyle: style},
		Scopes:       scopes,
	}
}

func (c OIDCConfig) issuers() []string {
	if c.Issuer != "" {
		return []string{c.Issuer}
	}
	return []string{GoogleIssuer, "accounts.google.com"}
}

// role is the highest role whose groups include one of values.
func (c OIDCConfig) role(values []string) (authz.Role, bool) {
	for _, r := range slices.Backward(authz.Roles) {
		for _, g := range c.RoleGroups[r] {
			if slices.Contains(values, g) {
				return r, true
			}
		}
	}
	return "", false
}

// Discovery is what a provider's .well-known/openid-configuration says.
type Discovery struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	UserinfoURL string `json:"userinfo_endpoint"`
}

type cachedDiscovery struct {
	d       Discovery
	fetched time.Time
}

func (s *Service) httpClient() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Discover reads the provider configuration of an issuer, kept for an
// hour. The issuer it states must be the one asked for (a trailing slash
// aside), and every endpoint must be HTTPS.
func (s *Service) Discover(ctx context.Context, issuer string) (Discovery, error) {
	key := strings.TrimSuffix(issuer, "/")
	s.mu.Lock()
	c, ok := s.discovery[key]
	s.mu.Unlock()
	if ok && s.Now().Sub(c.fetched) < discoveryTTL {
		return c.d, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, key+"/.well-known/openid-configuration", nil)
	if err != nil {
		return Discovery{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return Discovery{}, fmt.Errorf("discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Discovery{}, fmt.Errorf("discovery: %s", resp.Status)
	}
	var d Discovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return Discovery{}, fmt.Errorf("discovery: %w", err)
	}
	if strings.TrimSuffix(d.Issuer, "/") != key {
		return Discovery{}, fmt.Errorf("discovery: the provider names its issuer %q, not %q", d.Issuer, issuer)
	}
	endpoints := []string{d.AuthURL, d.TokenURL}
	if d.UserinfoURL != "" { // the one endpoint that is optional
		endpoints = append(endpoints, d.UserinfoURL)
	}
	for _, u := range endpoints {
		if !s.allowedURL(u) {
			return Discovery{}, fmt.Errorf("discovery: endpoint %q is not an HTTPS URL", u)
		}
	}
	s.mu.Lock()
	if s.discovery == nil {
		s.discovery = map[string]cachedDiscovery{}
	}
	s.discovery[key] = cachedDiscovery{d: d, fetched: s.Now()}
	s.mu.Unlock()
	return d, nil
}

// allowedURL accepts an absolute HTTPS URL, and plain HTTP only when tests
// allow it.
func (s *Service) allowedURL(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Host != "" && (u.Scheme == "https" || s.AllowHTTP && u.Scheme == "http")
}

// OIDCState is what the browser carries between the redirect to the
// provider and the callback, sealed in a short-lived cookie.
type OIDCState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Expires  int64  `json:"e"`
	Provider string `json:"p,omitempty"`
}

// OIDCStart returns the URL to send the browser to and the state to keep.
func (s *Service) OIDCStart(cfg OIDCConfig) (string, OIDCState, error) {
	if !cfg.Enabled() {
		return "", OIDCState{}, errors.New("single sign-on is not configured")
	}
	st := OIDCState{
		State:    randomToken(),
		Nonce:    randomToken(),
		Verifier: oauth2.GenerateVerifier(),
		Expires:  s.Now().Add(oidcStateTTL).Unix(),
		Provider: cfg.Method(),
	}
	opts := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(st.Verifier),
		oauth2.SetAuthURLParam("nonce", st.Nonce),
	}
	if cfg.google() {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "select_account"))
		if cfg.Domain != "" {
			opts = append(opts, oauth2.SetAuthURLParam("hd", cfg.Domain))
		}
	}
	return cfg.oauth2().AuthCodeURL(st.State, opts...), st, nil
}

// SealState encrypts the state for a cookie.
func (s *Service) SealState(st OIDCState) string {
	b, _ := json.Marshal(st)
	return base64.RawURLEncoding.EncodeToString(s.Key.Seal("oidc.state", b))
}

// OpenState decrypts and checks a sealed state.
func (s *Service) OpenState(v string) (OIDCState, error) {
	var st OIDCState
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return st, ErrTokenInvalid
	}
	b, err := s.Key.Open("oidc.state", raw)
	if err != nil {
		return st, ErrTokenInvalid
	}
	if err := json.Unmarshal(b, &st); err != nil || st.Expires < s.now() {
		return OIDCState{}, ErrTokenInvalid
	}
	return st, nil
}

type idClaims struct {
	Iss           string          `json:"iss"`
	Sub           string          `json:"sub"`
	Aud           json.RawMessage `json:"aud"`
	Azp           string          `json:"azp"`
	Exp           int64           `json:"exp"`
	Nonce         string          `json:"nonce"`
	Email         string          `json:"email"`
	EmailVerified json.RawMessage `json:"email_verified"`
	HD            string          `json:"hd"`
	Name          string          `json:"name"`

	all map[string]json.RawMessage // every claim, for the role claim
}

func (c idClaims) hasAudience(clientID string) bool {
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		return one == clientID
	}
	var many []string
	if json.Unmarshal(c.Aud, &many) == nil {
		return slices.Contains(many, clientID)
	}
	return false
}

// emailVerified reports the email_verified claim; absent is "unknown".
func (c idClaims) emailVerified() (verified, stated bool) {
	if len(c.EmailVerified) == 0 || string(c.EmailVerified) == "null" {
		return false, false
	}
	return strings.Trim(string(c.EmailVerified), `"`) == "true", true
}

// claimValues reads a claim as a list of strings: a string or an array of
// them. A name that is no claim of its own is followed as a path through
// nested objects ("realm_access.roles").
func (c idClaims) claimValues(name string) ([]string, bool) {
	raw, ok := c.all[name]
	if !ok {
		parts := strings.Split(name, ".")
		cur := c.all
		for i, p := range parts {
			v, found := cur[p]
			if !found {
				return nil, false
			}
			if i == len(parts)-1 {
				raw, ok = v, true
				break
			}
			cur = nil
			if json.Unmarshal(v, &cur) != nil {
				return nil, false
			}
		}
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}, true
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many, true
	}
	return nil, false
}

// OIDCOutcome says what a sign-in changed about the user, for the audit
// log.
type OIDCOutcome struct {
	Created bool
	OldRole authz.Role // set when the role claim changed the role
}

// OIDCFinish completes the callback: it checks the state, exchanges the code
// with the PKCE verifier and validates the ID token, then returns the user
// the e-mail address belongs to. Only users of the provider's login method
// sign in, and only users an admin added unless the configuration creates
// them from the role claim.
func (s *Service) OIDCFinish(ctx context.Context, cfg OIDCConfig, st OIDCState, gotState, code string) (User, OIDCOutcome, error) {
	if st.State == "" || subtle.ConstantTimeCompare([]byte(st.State), []byte(gotState)) != 1 || st.Expires < s.now() ||
		st.Provider != "" && st.Provider != cfg.Method() {
		return User{}, OIDCOutcome{}, ErrTokenInvalid
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, s.httpClient())
	tok, err := cfg.oauth2().Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return User{}, OIDCOutcome{}, fmt.Errorf("token exchange: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return User{}, OIDCOutcome{}, errors.New("token response has no id_token")
	}
	c, err := parseIDToken(raw)
	if err != nil {
		return User{}, OIDCOutcome{}, err
	}
	if err := c.validate(cfg, st.Nonce, s.now()); err != nil {
		return User{}, OIDCOutcome{}, err
	}
	_, hasRoles := c.claimValues(cfg.RoleClaim)
	if !cfg.google() && cfg.UserinfoURL != "" && (c.Email == "" || cfg.RoleClaim != "" && !hasRoles) {
		if err := s.userinfo(ctx, cfg, tok, &c); err != nil {
			return User{}, OIDCOutcome{}, err
		}
	}
	if err := c.allowed(cfg); err != nil {
		return User{}, OIDCOutcome{}, err
	}
	return s.providerUser(ctx, cfg, c)
}

// parseIDToken reads the claims of an ID token without checking its
// signature. The token was received directly from the token endpoint over
// TLS (server certificate verified by net/http), not via the browser. Per
// OpenID Connect Core 1.0 section 3.1.3.7 step 6, TLS server validation may
// then be used to validate the issuer in place of checking the token
// signature, so no JWKS fetch is needed. validate checks every claim.
func parseIDToken(raw string) (idClaims, error) {
	var c idClaims
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return c, errors.New("malformed id_token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, errors.New("malformed id_token")
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, errors.New("malformed id_token")
	}
	if err := json.Unmarshal(payload, &c.all); err != nil {
		return c, errors.New("malformed id_token")
	}
	return c, nil
}

// validate checks issuer, audience, authorised party, expiry and nonce.
func (c idClaims) validate(cfg OIDCConfig, nonce string, now int64) error {
	switch {
	case !slices.Contains(cfg.issuers(), c.Iss):
		return errors.New("id_token issuer mismatch")
	case !c.hasAudience(cfg.ClientID):
		return errors.New("id_token audience mismatch")
	case c.Azp != "" && c.Azp != cfg.ClientID:
		return errors.New("id_token authorised party mismatch")
	case c.Exp <= now:
		return errors.New("id_token expired")
	case subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1:
		return errors.New("id_token nonce mismatch")
	}
	return nil
}

// allowed checks the e-mail address: present, not stated unverified (for
// Google, stated verified), and in the configured domain.
func (c idClaims) allowed(cfg OIDCConfig) error {
	verified, stated := c.emailVerified()
	switch {
	case c.Email == "":
		return ErrNotAllowed
	case cfg.google() && !verified, stated && !verified:
		return ErrNotAllowed
	case cfg.google() && cfg.Domain != "" && !strings.EqualFold(c.HD, cfg.Domain):
		return ErrNotAllowed
	case !cfg.google() && cfg.Domain != "" && !strings.HasSuffix(strings.ToLower(c.Email), "@"+strings.ToLower(cfg.Domain)):
		return ErrNotAllowed
	}
	return nil
}

// userinfo fills in the e-mail address, the name and the role claim from
// the userinfo endpoint, for providers that leave them out of the ID token.
// Its subject must be the token's (OpenID Connect Core 1.0, 5.3.2).
func (s *Service) userinfo(ctx context.Context, cfg OIDCConfig, tok *oauth2.Token, c *idClaims) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.UserinfoURL, nil)
	if err != nil {
		return err
	}
	tok.SetAuthHeader(req)
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("userinfo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("userinfo: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("userinfo: %w", err)
	}
	var ui idClaims
	if json.Unmarshal(body, &ui) != nil || json.Unmarshal(body, &ui.all) != nil {
		return errors.New("userinfo: not a JSON object (a signed response is not supported)")
	}
	if ui.Sub == "" || ui.Sub != c.Sub {
		return errors.New("userinfo subject mismatch")
	}
	if c.Email == "" {
		c.Email, c.EmailVerified = ui.Email, ui.EmailVerified
	}
	if c.Name == "" {
		c.Name = ui.Name
	}
	if _, ok := c.claimValues(cfg.RoleClaim); !ok && cfg.RoleClaim != "" {
		if v, ok := ui.all[cfg.RoleClaim]; ok {
			c.all[cfg.RoleClaim] = v
		} else if root, _, nested := strings.Cut(cfg.RoleClaim, "."); nested {
			if v, ok := ui.all[root]; ok {
				c.all[root] = v
			}
		}
	}
	return nil
}

// providerUser returns the enabled user of the provider's login method
// with the token's e-mail address, taking the name from the token when
// none is set, the role from the role claim when one is configured, and
// creating the user when the configuration says so.
func (s *Service) providerUser(ctx context.Context, cfg OIDCConfig, c idClaims) (User, OIDCOutcome, error) {
	var out OIDCOutcome
	var role authz.Role
	mapped := false
	if cfg.RoleClaim != "" {
		values, _ := c.claimValues(cfg.RoleClaim)
		role, mapped = cfg.role(values)
		if !mapped {
			return User{}, out, ErrNotAllowed
		}
	}
	u, err := s.UserByEmail(ctx, c.Email)
	if errors.Is(err, ErrNotFound) {
		if !cfg.CreateUsers || !mapped {
			return User{}, out, ErrNotAllowed
		}
		u, err = s.CreateUser(ctx, c.Email, c.Name, role, cfg.Method())
		if errors.Is(err, ErrExists) {
			u, err = s.UserByEmail(ctx, c.Email) // created by a sign-in in parallel
		} else if err == nil {
			out.Created = true
		}
	}
	if err != nil {
		return User{}, out, err
	}
	if !u.Enabled || u.Method != cfg.Method() {
		return User{}, out, ErrNotAllowed
	}
	if mapped && role != u.Role {
		// The last enabled admin keeps the role: the provider must not
		// leave the instance without one.
		switch err := s.UpdateUser(ctx, u.ID, u.Name, role, u.Method, true); {
		case err == nil:
			out.OldRole, u.Role = u.Role, role
		case !errors.Is(err, ErrLastAdmin):
			return User{}, out, err
		}
	}
	if u.Name == "" && c.Name != "" {
		_ = s.SetName(ctx, u.ID, c.Name)
		u.Name = c.Name
	}
	return u, out, nil
}
