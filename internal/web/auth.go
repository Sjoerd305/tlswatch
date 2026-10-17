package web

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/auth"
)

type loginData struct {
	Email  string
	Next   string
	Error  string
	Google bool
}

func (s *Server) googleConfig(r *http.Request) auth.OIDCConfig {
	st := info(r).settings
	return auth.OIDCConfig{
		ClientID: st.SignIn.GoogleClientID, ClientSecret: st.SignIn.GoogleClientSecret, Domain: st.SignIn.GoogleDomain,
		RedirectURL: s.baseURL(r) + "/auth/google/callback",
	}
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if info(r).session != nil {
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}
	if s.needsSetup(r) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	d := loginData{Next: safeNext(r.URL.Query().Get("next")), Google: s.googleConfig(r).Enabled()}
	switch r.URL.Query().Get("error") {
	case "google":
		d.Error = "Google sign-in failed. Ask an administrator to add your account."
	case "expired":
		d.Error = "The sign-in attempt expired. Try again."
	}
	s.render(w, r, "login", &Page{Title: "Sign in", Data: d})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.PostFormValue("email"))
	d := loginData{Email: email, Next: safeNext(r.PostFormValue("next")), Google: s.googleConfig(r).Enabled()}
	u, err := s.Auth.Login(r.Context(), email, r.PostFormValue("password"), info(r).ip)
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

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u auth.User, next string) {
	raw, _, err := s.Auth.NewSession(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setSessionCookie(w, r, raw)
	if u.Theme != "" {
		http.SetCookie(w, &http.Cookie{Name: themeCookie, Value: u.Theme, Path: "/", Secure: info(r).https, SameSite: http.SameSiteLaxMode, MaxAge: 365 * 86400})
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

func (s *Server) googleStart(w http.ResponseWriter, r *http.Request) {
	cfg := s.googleConfig(r)
	if !cfg.Enabled() {
		s.fail(w, r, http.StatusNotFound, "Google sign-in is not configured.")
		return
	}
	redirect, st, err := s.Auth.OIDCStart(cfg)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: s.Auth.SealState(st), Path: "/auth/google", HttpOnly: true,
		Secure: info(r).https, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (s *Server) googleCallback(w http.ResponseWriter, r *http.Request) {
	cfg := s.googleConfig(r)
	c, err := r.Cookie(oidcCookie)
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/auth/google", MaxAge: -1, HttpOnly: true, Secure: info(r).https})
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
		http.Redirect(w, r, "/login?error=google", http.StatusSeeOther)
		return
	}
	u, err := s.Auth.OIDCFinish(r.Context(), cfg, st, r.URL.Query().Get("state"), r.URL.Query().Get("code"))
	if err != nil {
		s.Log.Warn("google sign-in refused", "err", err, "ip", info(r).ip)
		http.Redirect(w, r, "/login?error=google", http.StatusSeeOther)
		return
	}
	s.startSession(w, r, u, "/")
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
	// A Google account has no password to set.
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
