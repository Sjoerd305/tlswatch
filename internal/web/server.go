// Package web serves the UI: server-rendered pages, real forms that work
// without JavaScript, and a small internal JSON API under /api/v1 used by the
// TypeScript modules.
package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/sched"
	assets "github.com/sjoerd305/tlswatch/web"
)

// Server holds the dependencies of the HTTP handlers.
type Server struct {
	Core     *core.Service
	Sched    *sched.Scheduler
	Auth     *auth.Service
	Settings *config.Store
	Dispatch *notify.Dispatcher
	Log      *slog.Logger
	Version  string
	Listen   string
	Now      func() time.Time

	pages  map[string]*template.Template
	static http.Handler
}

const (
	sessionCookie = "tlswatch_session"
	csrfCookie    = "tlswatch_csrf"
	themeCookie   = "tlswatch_theme"
	oidcCookie    = "tlswatch_oidc"
	flashCookie   = "tlswatch_flash"
)

type ctxKey int

const (
	keyReq ctxKey = iota
)

// reqInfo is per-request state set by the middleware.
type reqInfo struct {
	session  *auth.Session
	settings config.Settings
	ip       string
	https    bool
	csrf     string // pre-session CSRF token for the sign-in forms
}

func info(r *http.Request) *reqInfo {
	if v, ok := r.Context().Value(keyReq).(*reqInfo); ok {
		return v
	}
	return &reqInfo{}
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler builds the HTTP handler.
func (s *Server) Handler() (http.Handler, error) {
	if err := s.loadTemplates(); err != nil {
		return nil, err
	}
	static, err := fs.Sub(assets.FS, "static")
	if err != nil {
		return nil, err
	}
	s.static = http.StripPrefix("/static/", cacheStatic(http.FileServer(http.FS(static)), s.Version == "dev"))
	mux := http.NewServeMux()
	s.routes(mux)
	return s.middleware(mux), nil
}

func cacheStatic(h http.Handler, dev bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dev {
			w.Header().Set("Cache-Control", "no-cache")
		} else if strings.HasSuffix(r.URL.Path, ".woff2") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=300")
		}
		h.ServeHTTP(w, r)
	})
}

// middleware sets security headers, resolves the client address and scheme,
// loads the session and enforces CSRF on every state-changing request.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.now()
		defer func() {
			if v := recover(); v != nil {
				s.Log.Error("panic", "path", r.URL.Path, "err", v)
				http.Error(w, "Internal error", http.StatusInternalServerError)
			}
		}()
		st, err := s.Settings.Get(r.Context())
		if err != nil {
			s.Log.Error("settings", "err", err)
		}
		ri := &reqInfo{settings: st}
		ri.ip, ri.https = clientInfo(r, st.General.BehindProxy)
		if strings.HasPrefix(st.General.BaseURL, "https://") {
			ri.https = true
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://accounts.google.com")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		if ri.https {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}

		if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
			if sess, err := s.Auth.Session(r.Context(), c.Value); err == nil {
				ri.session = sess
			} else {
				s.clearCookie(w, sessionCookie, ri)
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), keyReq, ri))

		if strings.HasPrefix(r.URL.Path, "/static/") {
			s.static.ServeHTTP(w, r)
			return
		}
		h.Set("Cache-Control", "no-store")

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !s.csrfOK(r, ri) {
				s.fail(w, r, http.StatusForbidden, "The form has expired. Reload the page and try again.")
				return
			}
		}
		lw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(lw, r)
		if r.URL.Path != "/healthz" {
			s.Log.Debug("http", "method", r.Method, "path", r.URL.Path, "status", lw.status, "ms", s.now().Sub(start).Milliseconds(), "ip", ri.ip)
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// clientInfo returns the client IP and whether the request arrived over
// HTTPS, trusting forwarded headers from one proxy hop only when configured.
func clientInfo(r *http.Request, behindProxy bool) (string, bool) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	https := r.TLS != nil
	if behindProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if last := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(last) != nil {
				ip = last
			}
		}
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			https = strings.EqualFold(strings.TrimSpace(p), "https")
		}
	}
	return ip, https
}

func (s *Server) csrfOK(r *http.Request, ri *reqInfo) bool {
	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		got = r.PostFormValue("csrf")
	}
	if got == "" {
		return false
	}
	if ri.session != nil {
		return constEq(got, ri.session.CSRF)
	}
	// Signed-out forms (sign in, setup, set password) use a double-submit
	// cookie.
	c, err := r.Cookie(csrfCookie)
	return err == nil && c.Value != "" && constEq(got, c.Value)
}

func constEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// preCSRF returns (and sets) the double-submit token for signed-out forms.
func (s *Server) preCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) >= 20 {
		return c.Value
	}
	v := randomString(24)
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: v, Path: "/", HttpOnly: true, Secure: info(r).https, SameSite: http.SameSiteLaxMode, MaxAge: 86400})
	return v
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, raw string) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: raw, Path: "/", HttpOnly: true, Secure: info(r).https, SameSite: http.SameSiteLaxMode})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string, ri *reqInfo) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: ri.https, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// baseURL is the configured public URL, or one derived from the request.
func (s *Server) baseURL(r *http.Request) string {
	ri := info(r)
	if ri.settings.General.BaseURL != "" {
		return ri.settings.General.BaseURL
	}
	scheme := "http"
	if ri.https {
		scheme = "https"
	}
	host := r.Host
	if ri.settings.General.BehindProxy {
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			host = h
		}
	}
	return scheme + "://" + host
}

// wantsJSON reports whether the client asked for JSON (the TypeScript API).
func wantsJSON(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api/") || strings.Contains(r.Header.Get("Accept"), "application/json")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// fail answers an error as JSON for the API and as a page otherwise.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if wantsJSON(r) {
		writeJSON(w, status, map[string]string{"error": msg})
		return
	}
	s.renderStatus(w, r, status, "error", &Page{Title: http.StatusText(status), Data: errorPage{Status: status, Message: msg}})
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.Log.Error("request failed", "path", r.URL.Path, "err", err)
	s.fail(w, r, http.StatusInternalServerError, "Something went wrong. The error has been logged.")
}

type errorPage struct {
	Status  int
	Message string
}

// require wraps a handler with the authentication and authorisation check:
// every handler is reached only through the role × action decision.
func (s *Server) require(a authz.Action, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ri := info(r)
		if ri.session == nil {
			if wantsJSON(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Your session has ended. Sign in again."})
				return
			}
			if s.needsSetup(r) {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			next := r.URL.RequestURI()
			if r.Method != http.MethodGet {
				next = "/"
			}
			http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
			return
		}
		if !authz.Allowed(ri.session.User.Role, a) {
			s.fail(w, r, http.StatusForbidden, "Your role does not allow this.")
			return
		}
		h(w, r)
	}
}

// user returns the signed-in user (only valid behind require).
func user(r *http.Request) auth.User {
	if s := info(r).session; s != nil {
		return s.User
	}
	return auth.User{}
}

// back redirects to a local path, carrying an optional notice in a
// short-lived flash cookie.
func (s *Server) back(w http.ResponseWriter, r *http.Request, path, notice, kind string) {
	if notice != "" {
		if kind == "" {
			kind = "ok"
		}
		v := base64.RawURLEncoding.EncodeToString([]byte(kind + "|" + notice))
		http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: v, Path: "/", HttpOnly: true, Secure: info(r).https, SameSite: http.SameSiteLaxMode, MaxAge: 60})
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// flash reads and clears the notice set by back.
func (s *Server) flash(w http.ResponseWriter, r *http.Request) *Notice {
	c, err := r.Cookie(flashCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	s.clearCookie(w, flashCookie, info(r))
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	kind, msg, ok := strings.Cut(string(b), "|")
	if !ok {
		return nil
	}
	switch kind {
	case "ok", "warn", "crit", "info":
	default:
		kind = "info"
	}
	return &Notice{Kind: kind, Text: msg}
}

// safeNext keeps redirects on this site.
func safeNext(v string) string {
	if v == "" || !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") || strings.HasPrefix(v, "/\\") {
		return "/"
	}
	return v
}

var errBadID = errors.New("bad id")
