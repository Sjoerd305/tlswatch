package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/config"
)

type loginData struct {
	Email  string
	Next   string
	Error  string
	Google bool
	// OIDC is the generic OpenID Connect provider, under OIDCName.
	OIDC     bool
	OIDCName string
}

func (s *Server) newLoginData(r *http.Request, next string) loginData {
	st := info(r).settings
	return loginData{Next: safeNext(next), Google: st.GoogleEnabled(), OIDC: st.OIDCEnabled(), OIDCName: st.SignIn.OIDCLabel()}
}

// providerConfig is the configuration of a single sign-on provider: Google,
// or the generic one, whose endpoints come from its discovery document.
func (s *Server) providerConfig(r *http.Request, provider string) (auth.OIDCConfig, error) {
	st := info(r).settings
	si := st.SignIn
	if provider == auth.ProviderGoogle {
		return auth.OIDCConfig{
			Provider: auth.ProviderGoogle, ClientID: si.GoogleClientID, ClientSecret: si.GoogleClientSecret, Domain: si.GoogleDomain,
			RedirectURL: s.baseURL(r) + "/auth/google/callback",
		}, nil
	}
	if !st.OIDCEnabled() {
		return auth.OIDCConfig{Provider: auth.ProviderOIDC}, nil
	}
	d, err := s.Auth.Discover(r.Context(), si.OIDCIssuer)
	if err != nil {
		return auth.OIDCConfig{}, err
	}
	return auth.OIDCConfig{
		Provider: auth.ProviderOIDC, ClientID: si.OIDCClientID, ClientSecret: si.OIDCClientSecret,
		RedirectURL: s.baseURL(r) + "/auth/oidc/callback",
		Issuer:      d.Issuer, AuthURL: d.AuthURL, TokenURL: d.TokenURL, UserinfoURL: d.UserinfoURL,
		Scopes: strings.Fields(si.OIDCScopes), Domain: si.OIDCDomain, RoleClaim: si.OIDCRoleClaim,
		RoleGroups: map[authz.Role][]string{
			authz.Admin: config.SplitGroups(si.OIDCAdminGroups), authz.Operator: config.SplitGroups(si.OIDCOperatorGroups), authz.Viewer: config.SplitGroups(si.OIDCViewerGroups),
		},
		CreateUsers: si.OIDCCreateUsers,
	}, nil
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if info(r).session != nil {
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther) // #nosec G710 -- safeNext keeps only a path on this origin
		return
	}
	if s.needsSetup(r) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	d := s.newLoginData(r, r.URL.Query().Get("next"))
	switch r.URL.Query().Get("error") {
	case "google":
		d.Error = "Google sign-in failed. Ask an administrator to add your account."
	case "oidc":
		d.Error = "Sign-in with " + d.OIDCName + " failed. Ask an administrator to add your account."
	case "expired":
		d.Error = "The sign-in attempt expired. Try again."
	}
	s.render(w, r, "login", &Page{Title: "Sign in", Data: d})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.PostFormValue("email"))
	d := s.newLoginData(r, r.PostFormValue("next"))
	d.Email = email
	u, err := s.Auth.Login(r.Context(), email, r.PostFormValue("password"), info(r).ip)
	if errors.Is(err, auth.ErrSecondFactor) {
		https := info(r).https
		setCookie(w, https, cookieName(mfaCookie, https), s.Auth.SealMFA(u.ID, d.Next), "/", 300)
		http.Redirect(w, r, "/login/code", http.StatusSeeOther)
		return
	}
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrLocked):
			d.Error = "Too many failed attempts. Try again in 15 minutes."
		case errors.Is(err, auth.ErrInvalidCredentials):
			d.Error = "The e-mail address or password is incorrect."
		default:
			s.serverError(w, r, err)
			return
		}
		s.Log.Info("sign-in failed", "ip", info(r).ip)
		s.renderStatus(w, r, http.StatusUnauthorized, "login", &Page{Title: "Sign in", Data: d})
		return
	}
	s.startSession(w, r, u, d.Next)
}

type codeData struct {
	Error string
}

// mfaState returns the sign-in waiting for its code, or sends the browser
// back to the sign-in page.
func (s *Server) mfaState(w http.ResponseWriter, r *http.Request) (auth.MFAState, bool) {
	c, err := readCookie(r, mfaCookie, info(r).https)
	if err == nil {
		if st, err := s.Auth.OpenMFA(c.Value); err == nil {
			return st, true
		}
	}
	s.clearCookie(w, mfaCookie, info(r))
	http.Redirect(w, r, "/login?error=expired", http.StatusSeeOther)
	return auth.MFAState{}, false
}

// loginCodePage asks for the TOTP code after the password.
func (s *Server) loginCodePage(w http.ResponseWriter, r *http.Request) {
	if info(r).session != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if _, ok := s.mfaState(w, r); !ok {
		return
	}
	s.render(w, r, "login-code", &Page{Title: "Sign in", Data: codeData{}})
}

func (s *Server) loginCode(w http.ResponseWriter, r *http.Request) {
	st, ok := s.mfaState(w, r)
	if !ok {
		return
	}
	u, recovery, err := s.Auth.LoginCode(r.Context(), st.UserID, r.PostFormValue("code"), info(r).ip)
	if err != nil {
		var d codeData
		switch {
		case errors.Is(err, auth.ErrTokenInvalid):
			s.clearCookie(w, mfaCookie, info(r))
			http.Redirect(w, r, "/login?error=expired", http.StatusSeeOther)
			return
		case errors.Is(err, auth.ErrLocked):
			d.Error = "Too many failed attempts. Try again in 15 minutes."
		case errors.Is(err, auth.ErrInvalidCode):
			d.Error = "The code is incorrect."
		default:
			s.serverError(w, r, err)
			return
		}
		s.Log.Info("sign-in code failed", "ip", info(r).ip)
		s.renderStatus(w, r, http.StatusUnauthorized, "login-code", &Page{Title: "Sign in", Data: d})
		return
	}
	s.clearCookie(w, mfaCookie, info(r))
	if recovery {
		left, _ := s.Auth.RecoveryCodesLeft(r.Context(), u.ID)
		s.Core.Audit(r.Context(), u.Email, "user.totp.recovery_used", "user "+u.Email, fmt.Sprintf("%d recovery codes left", left))
		s.setFlash(w, r, fmt.Sprintf("You signed in with a recovery code; %d left. Make new ones under Account if you lost your phone.", left), "warn")
	}
	s.startSession(w, r, u, st.Next)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u auth.User, next string) {
	raw, _, err := s.Auth.NewSession(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setSessionCookie(w, r, raw)
	if u.Theme != "" {
		setCookie(w, info(r).https, themeCookie, u.Theme, "/", 365*86400)
	}
	s.Log.Info("signed in", "user", u.Email, "method", u.Method)
	http.Redirect(w, r, safeNext(next), http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := readCookie(r, sessionCookie, info(r).https); err == nil {
		_ = s.Auth.DeleteSession(r.Context(), c.Value)
	}
	s.clearCookie(w, sessionCookie, info(r))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ssoStart sends the browser to a single sign-on provider.
func (s *Server) ssoStart(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := s.providerConfig(r, provider)
		if err != nil {
			s.Log.Warn("single sign-on discovery failed", "provider", provider, "err", err)
			s.fail(w, r, http.StatusBadGateway, "The sign-in provider cannot be reached. Try again later, or ask an administrator to check Settings › Sign-in.")
			return
		}
		if !cfg.Enabled() {
			s.fail(w, r, http.StatusNotFound, "This sign-in method is not configured.")
			return
		}
		redirect, st, err := s.Auth.OIDCStart(cfg)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		setCookie(w, info(r).https, oidcCookie, s.Auth.SealState(st), "/auth/"+provider, 600)
		http.Redirect(w, r, redirect, http.StatusFound)
	}
}

// ssoCallback completes a single sign-on: the provider sends the browser
// back here with a code.
func (s *Server) ssoCallback(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(oidcCookie)
		setCookie(w, info(r).https, oidcCookie, "", "/auth/"+provider, -1)
		if err != nil {
			http.Redirect(w, r, "/login?error=expired", http.StatusSeeOther)
			return
		}
		st, err := s.Auth.OpenState(c.Value)
		if err != nil {
			http.Redirect(w, r, "/login?error=expired", http.StatusSeeOther)
			return
		}
		if r.URL.Query().Get("error") != "" {
			http.Redirect(w, r, "/login?error="+provider, http.StatusSeeOther)
			return
		}
		cfg, err := s.providerConfig(r, provider)
		if err == nil && !cfg.Enabled() {
			err = errors.New("not configured")
		}
		var u auth.User
		var out auth.OIDCOutcome
		if err == nil {
			u, out, err = s.Auth.OIDCFinish(r.Context(), cfg, st, r.URL.Query().Get("state"), r.URL.Query().Get("code"))
		}
		if err != nil {
			s.Log.Warn("single sign-on refused", "provider", provider, "err", err, "ip", info(r).ip)
			http.Redirect(w, r, "/login?error="+provider, http.StatusSeeOther)
			return
		}
		actor := provider + " sign-in"
		switch {
		case out.Created:
			s.Core.Audit(r.Context(), actor, "user.create", "user "+u.Email, fmt.Sprintf("role=%s method=%s from the role claim", u.Role, u.Method))
		case out.OldRole != "":
			s.Core.Audit(r.Context(), actor, "user.update", "user "+u.Email, fmt.Sprintf("role=%s (was %s) from the role claim", u.Role, out.OldRole))
		}
		s.startSession(w, r, u, "/")
	}
}

type setupData struct {
	Email        string
	Name         string
	Error        string
	RestoreError string
}

// needsSetup reports whether no account exists yet, so the first-run
// screen should be shown.
func (s *Server) needsSetup(r *http.Request) bool {
	n, err := s.Auth.CountUsers(r.Context())
	return err == nil && n == 0
}

// setupPage is the first-run screen: while no account exists, anyone who
// reaches tlswatch creates the first admin with their own password.
func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	if !s.needsSetup(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, "setup", &Page{Title: "Set up tlswatch", Data: setupData{}})
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	if !s.needsSetup(r) {
		// Answered before the password is hashed: once set up, this form
		// costs nothing to post at.
		s.back(w, r, "/login", "tlswatch is already set up. Sign in.", "info")
		return
	}
	d := setupData{Email: strings.TrimSpace(r.PostFormValue("email")), Name: strings.TrimSpace(r.PostFormValue("name"))}
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("password2") {
		d.Error = "The passwords do not match."
	} else {
		u, err := s.Auth.CreateFirstAdmin(r.Context(), d.Email, d.Name, pw)
		switch {
		case err == nil:
			s.Core.Audit(r.Context(), u.Email, "user.setup", "user "+u.Email, "first admin created on the setup screen")
			s.Log.Info("first admin created", "user", u.Email, "ip", info(r).ip)
			s.startSession(w, r, u, "/")
			return
		case errors.Is(err, auth.ErrSetupDone):
			s.back(w, r, "/login", "tlswatch is already set up. Sign in.", "info")
			return
		default:
			d.Error = s.userError(r, err)
		}
	}
	s.renderStatus(w, r, http.StatusBadRequest, "setup", &Page{Title: "Set up tlswatch", Data: d})
}

type inviteData struct {
	Token string
	User  auth.User
	Error string
	Valid bool
}

func (s *Server) invitePage(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	d := inviteData{Token: tok}
	if id, err := s.Auth.PeekToken(r.Context(), auth.TokenInvite, tok); err == nil {
		if u, err := s.Auth.UserByID(r.Context(), id); err == nil && u.Enabled && u.Method == auth.MethodLocal {
			d.User, d.Valid = u, true
		}
	}
	s.render(w, r, "invite", &Page{Title: "Set your password", Data: d})
}

func (s *Server) invite(w http.ResponseWriter, r *http.Request) {
	tok := r.PostFormValue("token")
	d := inviteData{Token: tok}
	id, err := s.Auth.PeekToken(r.Context(), auth.TokenInvite, tok)
	if err == nil {
		d.User, err = s.Auth.UserByID(r.Context(), id)
	}
	// A single sign-on account has no password to set.
	if err != nil || !d.User.Enabled || d.User.Method != auth.MethodLocal {
		s.renderStatus(w, r, http.StatusBadRequest, "invite", &Page{Title: "Set your password", Data: d})
		return
	}
	d.Valid = true
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("password2") {
		d.Error = "The passwords do not match."
	} else if err := s.Auth.CheckPasswordPolicy(pw, d.User.Email); err != nil {
		d.Error = err.Error()
	}
	if d.Error != "" {
		s.renderStatus(w, r, http.StatusBadRequest, "invite", &Page{Title: "Set your password", Data: d})
		return
	}
	if _, err := s.Auth.UseToken(r.Context(), auth.TokenInvite, tok); err != nil {
		d.Valid, d.Error = false, ""
		s.renderStatus(w, r, http.StatusBadRequest, "invite", &Page{Title: "Set your password", Data: d})
		return
	}
	if err := s.Auth.SetPassword(r.Context(), d.User.ID, pw); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), d.User.Email, "user.password", "user "+d.User.Email, "password set via one-time link")
	_ = s.Auth.DeleteUserSessions(r.Context(), d.User.ID)
	s.startSession(w, r, d.User, "/")
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	st := s.Sched.Status()
	ok := s.Core.DB.Ping(r.Context()) == nil
	stalled := !st.LastLoop.IsZero() && s.now().Sub(st.LastLoop) > 2*time.Minute
	// The scheduler runs but cannot keep up: workers are stuck or too few.
	behind := st.Overdue > maxOverdue
	status := http.StatusOK
	if !ok || stalled || behind {
		status = http.StatusServiceUnavailable
	}
	last := ""
	if !st.LastCheck.IsZero() {
		last = st.LastCheck.UTC().Format(time.RFC3339)
	}
	writeJSON(w, status, map[string]any{
		"ok": ok && !stalled && !behind, "database": ok, "scheduler_running": !stalled && !st.LastLoop.IsZero(),
		"last_check": last, "backlog": st.Backlog, "overdue_s": int64(st.Overdue / time.Second), "running": st.Running,
		"checks": st.Checks, // the version is not here: this route needs no sign-in
	})
}

// maxOverdue is how long a due check may wait before /healthz reports the
// scheduler as behind.
const maxOverdue = time.Hour

const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#2f6fd1" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5 4 5.5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10v-6z"/><path d="m8.5 12 2.5 2.5 4.5-5"/></svg>`

func (s *Server) favicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte(faviconSVG))
}
