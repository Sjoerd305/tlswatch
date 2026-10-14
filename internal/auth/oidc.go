package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// Google's OpenID Connect endpoints.
const (
	GoogleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	GoogleTokenURL = "https://oauth2.googleapis.com/token" // #nosec G101 -- a public endpoint URL, not a credential
	GoogleIssuer   = "https://accounts.google.com"

	oidcStateTTL = 10 * time.Minute
)

// OIDCConfig configures Google sign-in. Empty endpoints default to Google.
type OIDCConfig struct {
	ClientID     string
	ClientSecret string
	Domain       string // optional Workspace domain (hd claim)
	RedirectURL  string
	AuthURL      string
	TokenURL     string
	Issuer       string
}

// Enabled reports whether Google sign-in is configured.
func (c OIDCConfig) Enabled() bool { return c.ClientID != "" && c.ClientSecret != "" }

func (c OIDCConfig) oauth2() *oauth2.Config {
	auth, tok := c.AuthURL, c.TokenURL
	if auth == "" {
		auth = GoogleAuthURL
	}
	if tok == "" {
		tok = GoogleTokenURL
	}
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
		Endpoint:     oauth2.Endpoint{AuthURL: auth, TokenURL: tok, AuthStyle: oauth2.AuthStyleInParams},
		Scopes:       []string{"openid", "email", "profile"},
	}
}

func (c OIDCConfig) issuers() []string {
	if c.Issuer != "" {
		return []string{c.Issuer}
	}
	return []string{GoogleIssuer, "accounts.google.com"}
}

// OIDCState is what the browser carries between the redirect to Google and
// the callback, sealed in a short-lived cookie.
type OIDCState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Expires  int64  `json:"e"`
}

// OIDCStart returns the URL to send the browser to and the state to keep.
func (s *Service) OIDCStart(cfg OIDCConfig) (string, OIDCState, error) {
	if !cfg.Enabled() {
		return "", OIDCState{}, errors.New("Google sign-in is not configured")
	}
	st := OIDCState{
		State:    randomToken(),
		Nonce:    randomToken(),
		Verifier: oauth2.GenerateVerifier(),
		Expires:  s.Now().Add(oidcStateTTL).Unix(),
	}
	opts := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(st.Verifier),
		oauth2.SetAuthURLParam("nonce", st.Nonce),
		oauth2.SetAuthURLParam("prompt", "select_account"),
	}
	if cfg.Domain != "" {
		opts = append(opts, oauth2.SetAuthURLParam("hd", cfg.Domain))
	}
	return cfg.oauth2().AuthCodeURL(st.State, opts...), st, nil
}

// SealState encrypts the state for a cookie.
func (s *Service) SealState(st OIDCState) string {
	b, _ := json.Marshal(st)
	return base64.RawURLEncoding.EncodeToString(s.Key.Seal(b))
}

// OpenState decrypts and checks a sealed state.
func (s *Service) OpenState(v string) (OIDCState, error) {
	var st OIDCState
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return st, ErrTokenInvalid
	}
	b, err := s.Key.Open(raw)
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
	Aud           json.RawMessage `json:"aud"`
	Exp           int64           `json:"exp"`
	Nonce         string          `json:"nonce"`
	Email         string          `json:"email"`
	EmailVerified json.RawMessage `json:"email_verified"`
	HD            string          `json:"hd"`
	Name          string          `json:"name"`
}

func (c idClaims) hasAudience(clientID string) bool {
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		return one == clientID
	}
	var many []string
	if json.Unmarshal(c.Aud, &many) == nil {
		for _, a := range many {
			if a == clientID {
				return true
			}
		}
	}
	return false
}

func (c idClaims) emailVerified() bool {
	s := strings.Trim(string(c.EmailVerified), `"`)
	return s == "true"
}

// OIDCFinish completes the callback: it checks the state, exchanges the code
// with the PKCE verifier and validates the ID token, then returns the user
// the e-mail address belongs to. Only users an admin added with the Google
// login method may sign in.
func (s *Service) OIDCFinish(ctx context.Context, cfg OIDCConfig, st OIDCState, gotState, code string) (User, error) {
	if st.State == "" || subtle.ConstantTimeCompare([]byte(st.State), []byte(gotState)) != 1 || st.Expires < s.now() {
		return User{}, ErrTokenInvalid
	}
	tok, err := cfg.oauth2().Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return User{}, fmt.Errorf("token exchange: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return User{}, errors.New("token response has no id_token")
	}
	c, err := parseIDToken(raw)
	if err != nil {
		return User{}, err
	}
	if err := c.validate(cfg, st.Nonce, s.now()); err != nil {
		return User{}, err
	}
	return s.googleUser(ctx, c)
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
	return c, nil
}

// validate checks issuer, audience, expiry and nonce, and that the e-mail
// address is verified and, when a domain is configured, in that domain.
func (c idClaims) validate(cfg OIDCConfig, nonce string, now int64) error {
	switch {
	case !slices.Contains(cfg.issuers(), c.Iss):
		return errors.New("id_token issuer mismatch")
	case !c.hasAudience(cfg.ClientID):
		return errors.New("id_token audience mismatch")
	case c.Exp <= now:
		return errors.New("id_token expired")
	case subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1:
		return errors.New("id_token nonce mismatch")
	case c.Email == "" || !c.emailVerified():
		return ErrNotAllowed
	case cfg.Domain != "" && !strings.EqualFold(c.HD, cfg.Domain):
		return ErrNotAllowed
	}
	return nil
}

// googleUser returns the enabled Google-method user with the token's
// e-mail address, taking the name from the token when none is set.
func (s *Service) googleUser(ctx context.Context, c idClaims) (User, error) {
	u, err := s.UserByEmail(ctx, c.Email)
	if errors.Is(err, ErrNotFound) {
		return User{}, ErrNotAllowed
	}
	if err != nil {
		return User{}, err
	}
	if !u.Enabled || u.Method != MethodGoogle {
		return User{}, ErrNotAllowed
	}
	if u.Name == "" && c.Name != "" {
		_ = s.SetName(ctx, u.ID, c.Name)
		u.Name = c.Name
	}
	return u, nil
}
