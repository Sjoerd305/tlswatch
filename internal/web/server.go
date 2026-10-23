// Package web serves the UI: server-rendered pages, real forms that work
// without JavaScript, a small internal JSON API under /api/v1 used by the
// TypeScript modules, and the public REST API under /api/v2 (api.go).
package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/node"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/sched"
	"github.com/sjoerd305/tlswatch/internal/secret"
	"github.com/sjoerd305/tlswatch/internal/usererr"
	assets "github.com/sjoerd305/tlswatch/web"
)

// Server holds the dependencies of the HTTP handlers.
type Server struct {
	Core     *core.Service
	Sched    *sched.Scheduler
	Nodes    *node.Dispatcher // the nodes' queues and the /agent/v1 protocol
	Auth     *auth.Service
	Settings *config.Store
	Dispatch *notify.Dispatcher
	Key      *secret.Key // seals the stored credentials; a restore re-seals under it
	Log      *slog.Logger
	Version  string
	// DevAssets serves the static files uncached: a development build can
	// change them without changing Version.
	DevAssets bool
	Listen    string
	Now       func() time.Time
	// Demo is demo mode (TLSWATCH_DEMO): nobody signs in, every visitor
	// is the demo role, which views the data and changes nothing.
	Demo bool
	// LookupHost resolves names for Discover's server name guess; nil is
	// the system resolver. Tests replace it.
	LookupHost func(ctx context.Context, name string) ([]string, error)

	pages     map[string]*template.Template
	static    http.Handler
	restoring sync.Mutex // one restore at a time
	// apiLimits rate-limits each API token; apiFails the addresses that
	// present invalid ones.
	apiLimits limiter
	apiFails  limiter
}

const (
	sessionCookie = "tlswatch_session"
	csrfCookie    = "tlswatch_csrf"
	themeCookie   = "tlswatch_theme"
	oidcCookie    = "tlswatch_oidc"
	mfaCookie     = "tlswatch_mfa" // a sign-in waiting for its TOTP code
	flashCookie   = "tlswatch_flash"
)

type ctxKey int

const (
	keyReq ctxKey = iota
)

// reqInfo is per-request state set by the middleware.
type reqInfo struct {
	id       string // request ID, in the X-Request-ID header and the logs
	session  *auth.Session
	api      *auth.APISession // the API token of a /api/v2 request
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
	s.static = staticHandler(http.FileServer(http.FS(static)), assetVersion(s.Version), s.DevAssets)
	s.Nodes.ClientIP = func(r *http.Request) string { return info(r).ip }
	mux := http.NewServeMux()
	s.routes(mux)
	return s.middleware(mux), nil
}

// assetVersion is the version as a path segment.
func assetVersion(v string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, v)
}

// staticHandler serves the assets under /static/<version>/, so every file
// of a release, including the modules app.js imports relatively, has its
// own URL and can be cached for good. Unversioned /static/ paths are still
// served, with a short cache.
func staticHandler(files http.Handler, version string, dev bool) http.Handler {
	prefix := "/static/" + version + "/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, versioned := strings.CutPrefix(r.URL.Path, prefix)
		if !versioned {
			rest = strings.TrimPrefix(r.URL.Path, "/static/")
		}
		switch {
		case dev:
			w.Header().Set("Cache-Control", "no-cache")
		case versioned || strings.HasSuffix(rest, ".woff2"):
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		default:
			w.Header().Set("Cache-Control", "public, max-age=300")
		}
		// The assets are files; the file server would list a directory.
		if rest == "" || strings.HasSuffix(rest, "/") {
			http.NotFound(w, r)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/" + rest
		r2.URL.RawPath = ""
		files.ServeHTTP(w, r2)
	})
}

// middleware sets security headers, resolves the client address and scheme,
// loads the session and enforces CSRF on every state-changing request.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.now()
		ri := &reqInfo{id: randomString(6)}
		lw := &statusWriter{ResponseWriter: w, status: 200}
		w = lw
		w.Header().Set("X-Request-ID", ri.id)
		defer func() {
			if v := recover(); v != nil {
				s.Log.Error("panic", "request_id", ri.id, "method", r.Method, "path", r.URL.Path, "err", v, "stack", string(debug.Stack()))
				http.Error(w, "Internal error", http.StatusInternalServerError)
			}
			s.logRequest(r, ri, lw.status, s.now().Sub(start))
		}()
		st, err := s.Settings.Get(r.Context())
		if err != nil {
			s.Log.Error("settings", "request_id", ri.id, "err", err)
		}
		ri.settings = st
		ri.ip, ri.https = clientInfo(r, st.General.BehindProxy)
		if strings.HasPrefix(st.General.BaseURL, "https://") {
			ri.https = true
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://accounts.google.com")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if ri.https {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		// No instance belongs in search results, not even its sign-in page.
		h.Set("X-Robots-Tag", "noindex, nofollow")

		if strings.HasPrefix(r.URL.Path, "/static/") {
			s.static.ServeHTTP(w, r)
			return
		}
		// The agent protocol authenticates nodes by their credential,
		// never a session cookie, so it sits outside sessions and CSRF.
		if strings.HasPrefix(r.URL.Path, "/agent/") {
			s.Nodes.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyReq, ri)))
			return
		}

		// The public API authenticates API tokens, never the session
		// cookie, so CSRF does not apply to it; apiGuard checks the token.
		if strings.HasPrefix(r.URL.Path, apiPrefix) {
			h.Set("Cache-Control", "no-store")
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyReq, ri)))
			return
		}

		if s.Demo {
			if !s.demoOpen(w, r, ri) {
				return
			}
		} else if c, err := readCookie(r, sessionCookie, ri.https); err == nil && c.Value != "" {
			lookup := s.Auth.Session
			if passiveRequest(r) {
				lookup = s.Auth.SessionPassive
			}
			sess, err := lookup(r.Context(), c.Value)
			switch {
			case err == nil:
				ri.session = sess
			case errors.Is(err, auth.ErrNoSession):
				s.clearCookie(w, sessionCookie, ri)
			default:
				// A database hiccup is not a sign-out: keep the cookie.
				s.Log.Error("session lookup", "request_id", ri.id, "path", r.URL.Path, "err", err)
				http.Error(w, "tlswatch is temporarily unavailable; try again shortly.", http.StatusServiceUnavailable)
				return
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), keyReq, ri))
		h.Set("Cache-Control", "no-store")

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// A browser says where a request came from; one from another
			// site is refused before anything is read, whatever token it
			// carries.
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				s.fail(w, r, http.StatusForbidden, "Cross-site requests are not accepted.")
				return
			}
			// Cap the body before anything reads it, signed in or not.
			limit := bodyLimit(r.URL.Path)
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			if streamedUpload(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			if r.Header.Get("X-CSRF-Token") == "" {
				if err := parseForm(r, limit); err != nil {
					if mbe := (*http.MaxBytesError)(nil); errors.As(err, &mbe) {
						s.fail(w, r, http.StatusRequestEntityTooLarge, fmt.Sprintf("The request is too large (%d MB at most).", limit>>20))
					} else {
						s.fail(w, r, http.StatusBadRequest, "The form could not be read.")
					}
					return
				}
			}
			// Sign out after the session already ended has nothing to
			// protect: it clears the cookie and lands on the sign-in page.
			if r.URL.Path == "/logout" && ri.session == nil {
				next.ServeHTTP(w, r)
				return
			}
			if !s.csrfOK(r, ri) {
				s.fail(w, r, http.StatusForbidden, "The form has expired. Reload the page and try again.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// slowRequest is the duration from which a request is logged at info level.
const slowRequest = 2 * time.Second

// logRequest logs every request at debug level, and failed or slow ones at
// info level, so they show up in production logs.
func (s *Server) logRequest(r *http.Request, ri *reqInfo, status int, d time.Duration) {
	if r.URL.Path == "/healthz" || strings.HasPrefix(r.URL.Path, "/static/") && status < 400 {
		return
	}
	level := slog.LevelDebug
	// A node's poll is held for up to node.PollCeiling by design; it is not slow.
	held := strings.HasPrefix(r.URL.Path, "/agent/")
	if status >= 400 || d >= slowRequest && !held {
		level = slog.LevelInfo
	}
	user := ""
	if ri.session != nil {
		user = ri.session.User.Email
	}
	if ri.api != nil {
		user = ri.api.User.Email + " (token " + ri.api.Token.Name + ")"
	}
	s.Log.Log(r.Context(), level, "http", "request_id", ri.id, "method", r.Method, "path", r.URL.Path, "status", status,
		"ms", d.Milliseconds(), "ip", ri.ip, "user", user)
}

// streamedUpload reports a path whose handler reads the multipart body
// itself, as a stream, and checks its CSRF token: backups are too large to
// buffer, and the container has no /tmp to spill them to.
func streamedUpload(path string) bool {
	return path == "/settings/backup/restore" || path == "/setup/restore"
}

// bodyLimit is the largest request body accepted on path: CA bundles and
// backups are uploaded as files, everything else is a small form or JSON
// call.
func bodyLimit(path string) int64 {
	if streamedUpload(path) {
		return maxBackup
	}
	if strings.HasPrefix(path, "/settings/bundles") {
		return 3 << 20 // a 2 MB file plus the form around it
	}
	return 1 << 20
}

// parseForm reads a form body, keeping multipart uploads in memory up to
// limit.
func parseForm(r *http.Request, limit int64) error {
	// ParseMultipartForm on another content type swallows ParseForm's
	// error, so pick the parser by type.
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		return r.ParseMultipartForm(limit)
	}
	return r.ParseForm()
}

// refreshHeader marks the live-page refresh of the TypeScript.
const refreshHeader = "X-Tlswatch-Refresh"

// passiveRequest reports a background request that must not count as user
// activity for the session idle timeout.
func passiveRequest(r *http.Request) bool {
	return r.Method == http.MethodGet && (r.Header.Get(refreshHeader) == "1" || r.URL.Path == "/api/v1/stamp")
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
// Before that is configured, a peer on a loopback or private address that
// says X-Forwarded-Proto: https is believed about the scheme alone, so the
// cookies of a fresh install behind a TLS proxy are Secure from the first
// sign-in; the address is never taken from a header until then.
func clientInfo(r *http.Request, behindProxy bool) (string, bool) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	https := r.TLS != nil
	if !behindProxy && !https && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		if peer := net.ParseIP(ip); peer != nil && (peer.IsLoopback() || peer.IsPrivate()) {
			https = true
		}
	}
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
	return csrfMatch(r, ri, got)
}

// csrfMatch checks a CSRF token taken from the request.
func csrfMatch(r *http.Request, ri *reqInfo, got string) bool {
	if got == "" {
		return false
	}
	if ri.session != nil {
		return constEq(got, ri.session.CSRF)
	}
	// Signed-out forms (sign in, setup, set password) use a double-submit
	// cookie.
	c, err := readCookie(r, csrfCookie, ri.https)
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

// cookieName is the name a cookie is set and read under: over HTTPS it
// carries the __Host- prefix, so the browser accepts it only from this host,
// over TLS, for the whole site, and a cookie planted from a sibling
// subdomain or over plain HTTP is never read.
func cookieName(base string, https bool) string {
	if https {
		return "__Host-" + base
	}
	return base
}

// readCookie reads a cookie under the name cookieName gives it.
func readCookie(r *http.Request, base string, https bool) (*http.Cookie, error) {
	return r.Cookie(cookieName(base, https))
}

// setCookie sets a cookie the way every cookie of the UI is set: HttpOnly,
// SameSite=Lax and Secure over HTTPS. Secure follows the request's scheme
// rather than being always on, because an instance on plain HTTP (a fresh
// install before its base URL is set, a loopback listener) would never get
// a Secure cookie back and nobody could sign in. maxAge 0 is a session
// cookie, -1 deletes.
func setCookie(w http.ResponseWriter, https bool, name, value, path string, maxAge int) {
	// #nosec G124 -- Secure follows the scheme, see above
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: path, HttpOnly: true, Secure: https, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

// preCSRF returns (and sets) the double-submit token for signed-out forms.
func (s *Server) preCSRF(w http.ResponseWriter, r *http.Request) string {
	https := info(r).https
	if c, err := readCookie(r, csrfCookie, https); err == nil && len(c.Value) >= 20 {
		return c.Value
	}
	v := randomString(24)
	setCookie(w, https, cookieName(csrfCookie, https), v, "/", 86400)
	return v
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, raw string) {
	https := info(r).https
	setCookie(w, https, cookieName(sessionCookie, https), raw, "/", 0)
}

func (s *Server) clearCookie(w http.ResponseWriter, name string, ri *reqInfo) {
	setCookie(w, ri.https, cookieName(name, ri.https), "", "/", -1)
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
	s.Log.Error("request failed", "request_id", info(r).id, "method", r.Method, "path", r.URL.Path, "err", err)
	s.fail(w, r, http.StatusInternalServerError, "Something went wrong. The error has been logged.")
}

// failErr answers an error from core: 404 with notFound for ErrNotFound,
// 400 with the message for an error meant for the user (usererr), and a
// logged 500 otherwise.
func (s *Server) failErr(w http.ResponseWriter, r *http.Request, err error, notFound string) {
	msg, isUser := usererr.Message(err)
	switch {
	case errors.Is(err, core.ErrNotFound):
		s.fail(w, r, http.StatusNotFound, notFound)
	case isUser:
		s.fail(w, r, http.StatusBadRequest, msg)
	default:
		s.serverError(w, r, err)
	}
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
		// A local account whose role must use TOTP and has none yet sets
		// it up before anything else.
		if s.totpDue(ri) && r.URL.Path != "/account/totp" {
			if wantsJSON(r) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "Set up two-factor sign-in first."})
				return
			}
			http.Redirect(w, r, "/account/totp", http.StatusSeeOther)
			return
		}
		if !authz.Allowed(ri.session.User.Role, a) {
			if ri.session.User.Role == authz.Demo {
				s.fail(w, r, http.StatusForbidden, demoRefusal)
				return
			}
			s.fail(w, r, http.StatusForbidden, "Your role does not allow this.")
			return
		}
		h(w, r)
	}
}

// totpDue reports whether the signed-in user must set up TOTP: a local
// account of a role an admin requires it for, without it.
func (s *Server) totpDue(ri *reqInfo) bool {
	u := ri.session.User
	return !s.Demo && u.Method == auth.MethodLocal && !u.HasTOTP() && ri.settings.SignIn.TOTPRequired(string(u.Role))
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
		s.setFlash(w, r, notice, kind)
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// setFlash sets the notice the next page shows.
func (s *Server) setFlash(w http.ResponseWriter, r *http.Request, notice, kind string) {
	if kind == "" {
		kind = "ok"
	}
	v := base64.RawURLEncoding.EncodeToString([]byte(kind + "|" + notice))
	setCookie(w, info(r).https, flashCookie, v, "/", 60)
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

// safeNext keeps redirects on this site: a path on this origin, parsed and
// normalised, so a control character or a backslash cannot turn it into a
// scheme-relative URL for the browser.
func safeNext(v string) string {
	if v == "" || !strings.HasPrefix(v, "/") {
		return "/"
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f || v[i] == '\\' {
			return "/"
		}
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	for i := 0; i < len(u.Path); i++ {
		if u.Path[i] < 0x20 || u.Path[i] == 0x7f || u.Path[i] == '\\' {
			return "/" // an encoded control character; a path has none
		}
	}
	u.Fragment = ""
	return u.RequestURI()
}

var errBadID = errors.New("bad id")

// demoRefusal is the answer to anything a demo visitor may not do.
const demoRefusal = "This is a demo: it shows the data, and nothing can be changed."

// demoClosed lists the pages a demo has no use for: signing in and out,
// setup, invitations, the account and the settings. A visit lands on the
// overview.
var demoClosed = []string{"/login", "/logout", "/setup", "/invite", "/auth/", "/account", "/settings"}

// demoRobots is the demo's robots.txt: no crawling at all, as a public
// demo's crawlers would otherwise walk every filter and sort of every page.
// A real instance has none: a crawler only reaches its sign-in page, and it
// must be let in to read the noindex there.
const demoRobots = "User-agent: *\nDisallow: /\n"

func (s *Server) robots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte(demoRobots))
}

// demoOpen makes the request a demo visitor's, or answers it: a closed
// page redirects to the overview, and any write but the theme is refused.
// It reports whether the request goes on.
func (s *Server) demoOpen(w http.ResponseWriter, r *http.Request, ri *reqInfo) bool {
	path := r.URL.Path
	write := r.Method != http.MethodGet && r.Method != http.MethodHead
	if write && path != "/account/theme" {
		s.fail(w, r.WithContext(context.WithValue(r.Context(), keyReq, ri)), http.StatusForbidden, demoRefusal)
		return false
	}
	if !write {
		for _, p := range demoClosed {
			if path == p || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return false
			}
		}
	}
	// The double-submit cookie stands in for the session's CSRF token,
	// so the theme form works as it does for a signed-in user.
	u := auth.User{Name: "Demo visitor", Role: authz.Demo, Enabled: true}
	if c, err := r.Cookie(themeCookie); err == nil && (c.Value == "light" || c.Value == "dark") {
		u.Theme = c.Value
	}
	ri.session = &auth.Session{User: u, CSRF: s.preCSRF(w, r)}
	return true
}
