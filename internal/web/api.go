package web

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/sched"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// The public REST API under /api/v2 (see the specification, "REST API").
// It authenticates API tokens only, as "Authorization: Bearer"; it never
// reads the session cookie, so CSRF does not apply to it, and a token
// never opens a page of the UI. Every endpoint is a row of apiRoutes,
// guarded by the role × action decision of the UI; the same rows generate
// the OpenAPI document. The internal /api/v1 of the TypeScript stays
// private.

const apiPrefix = "/api/v2/"

// apiRoute is one endpoint of the public API: what routes.go registers and
// what the OpenAPI document describes.
type apiRoute struct {
	Method, Path string
	Action       authz.Action
	Summary      string
	Query        []apiParam
	Body         any // a value of the request body's type; nil for none
	Resp         any // a value of the response's type; nil for none
	List         bool
	Status       int // on success; 200 when 0
	Handler      http.HandlerFunc
}

// apiParam is a documented query parameter.
type apiParam struct {
	Name, Doc string
}

var pageParams = []apiParam{
	{"limit", "Items per page, 1 to 500; 100 when left out."},
	{"cursor", "The next_cursor of the previous page."},
}

func withPage(ps ...apiParam) []apiParam { return append(ps, pageParams...) }

func (s *Server) apiRoutes() []apiRoute {
	return []apiRoute{
		{Method: "GET", Path: "/api/v2/targets", Action: authz.ViewData, Summary: "List targets, with the filters of the targets page.", List: true, Resp: apiTarget{},
			Query: withPage(apiParam{"status", "critical, warning, healthy, unreachable, pending or disabled."}, apiParam{"tag", "A tag."},
				apiParam{"q", "Text in the name, endpoint, server name, protocol, tags, node, issuer or subject."},
				apiParam{"node", `"server", or a node's id.`}, apiParam{"grade", `A, B, C, F, or "none".`}, apiParam{"pq", "yes, no or untested."}),
			Handler: s.apiTargets},
		{Method: "POST", Path: "/api/v2/targets", Action: authz.EditTargets, Summary: "Add a target; its first check is queued.", Body: apiTargetInput{}, Resp: apiTarget{}, Status: http.StatusCreated, Handler: s.apiTargetCreate},
		{Method: "GET", Path: "/api/v2/targets/{id}", Action: authz.ViewData, Summary: "Get a target.", Resp: apiTarget{}, Handler: s.apiTargetGet},
		{Method: "PATCH", Path: "/api/v2/targets/{id}", Action: authz.EditTargets, Summary: "Change a target: the fields sent change; null returns an override to its default.", Body: apiTargetInput{}, Resp: apiTarget{}, Handler: s.apiTargetUpdate},
		{Method: "DELETE", Path: "/api/v2/targets/{id}", Action: authz.EditTargets, Summary: "Delete a target with its history.", Status: http.StatusNoContent, Handler: s.apiTargetDelete},
		{Method: "POST", Path: "/api/v2/targets/{id}/check", Action: authz.EditTargets, Summary: "Check a target now and return its new state.", Resp: apiTarget{}, Handler: s.apiTargetCheckNow},
		{Method: "GET", Path: "/api/v2/certificates", Action: authz.ViewData, Summary: "List leaf certificates, served now unless all=1.", List: true, Resp: apiCertificate{},
			Query: withPage(apiParam{"window", "30 or 90 (days left), or distrusted."}, apiParam{"issuer", "The issuer as listed."}, apiParam{"key", "RSA, ECDSA or Ed25519."},
				apiParam{"q", "Text in the subject, names, issuer, fingerprint or serial."}, apiParam{"all", "1 includes certificates no longer served."}),
			Handler: s.apiCertificates},
		{Method: "GET", Path: "/api/v2/certificates/{fp}", Action: authz.ViewData, Summary: "Get a certificate by its SHA-256 fingerprint, with its PEM.", Resp: apiCertificate{}, Handler: s.apiCertificateGet},
		{Method: "GET", Path: "/api/v2/findings", Action: authz.ViewData, Summary: "List findings: open, or resolved within the retention period.", List: true, Resp: apiFinding{},
			Query: withPage(apiParam{"state", "open (the default) or resolved."}, apiParam{"severity", "critical, warning or info."}, apiParam{"kind", "A finding kind, such as expiring."},
				apiParam{"target_id", "Only this target's."}, apiParam{"domain_id", "Only this domain watch's."}),
			Handler: s.apiFindings},
		{Method: "GET", Path: "/api/v2/findings/{id}", Action: authz.ViewData, Summary: "Get a finding.", Resp: apiFinding{}, Handler: s.apiFindingGet},
		{Method: "POST", Path: "/api/v2/findings/{id}/ack", Action: authz.Acknowledge, Summary: "Acknowledge an open finding: reminders stop; a change finding is confirmed and resolved.", Body: apiAckInput{}, Resp: apiFinding{}, Handler: s.apiFindingAck},
		{Method: "GET", Path: "/api/v2/domains", Action: authz.ViewData, Summary: "List domain watches.", List: true, Resp: apiDomain{},
			Query:   withPage(apiParam{"status", "warning (unexpected), unreachable (source failing), healthy, pending or disabled."}, apiParam{"tag", "A tag."}, apiParam{"q", "Text in the name or tags."}),
			Handler: s.apiDomains},
		{Method: "POST", Path: "/api/v2/domains", Action: authz.EditTargets, Summary: "Add a domain watch; its first poll runs in the background.", Body: apiDomainInput{}, Resp: apiDomain{}, Status: http.StatusCreated, Handler: s.apiDomainCreate},
		{Method: "GET", Path: "/api/v2/domains/{id}", Action: authz.ViewData, Summary: "Get a domain watch.", Resp: apiDomain{}, Handler: s.apiDomainGet},
		{Method: "PATCH", Path: "/api/v2/domains/{id}", Action: authz.EditTargets, Summary: "Change a domain watch: the fields sent change.", Body: apiDomainInput{}, Resp: apiDomain{}, Handler: s.apiDomainUpdate},
		{Method: "DELETE", Path: "/api/v2/domains/{id}", Action: authz.EditTargets, Summary: "Delete a domain watch with its issuances and findings.", Status: http.StatusNoContent, Handler: s.apiDomainDelete},
		{Method: "POST", Path: "/api/v2/domains/{id}/poll", Action: authz.EditTargets, Summary: "Poll a domain watch now and return its new state.", Resp: apiDomain{}, Handler: s.apiDomainPoll},
		{Method: "GET", Path: "/api/v2/issuances", Action: authz.ViewData, Summary: "List issuances found in Certificate Transparency, newest first by id.", List: true, Resp: apiIssuance{},
			Query:   withPage(apiParam{"domain_id", "Only this watch's."}, apiParam{"state", "known, unexpected, pending or acknowledged."}),
			Handler: s.apiIssuances},
		{Method: "GET", Path: "/api/v2/channels", Action: authz.ManageSettings, Summary: "List alert channels, without their credentials.", List: true, Resp: apiChannel{}, Query: pageParams, Handler: s.apiChannels},
		{Method: "POST", Path: "/api/v2/channels/{id}/test", Action: authz.ManageSettings, Summary: "Send a test message through a channel.", Resp: apiSent{}, Handler: s.apiChannelTest},
		{Method: "GET", Path: "/api/v2/export", Action: authz.ViewData, Summary: "Export targets and domain watches as YAML, for Targets › Add many to import.", Resp: "", Handler: s.apiExport},
	}
}

// ---------- Errors ----------

type apiErrorBody struct {
	Error apiErrorDetail `json:"error"`
}

type apiErrorDetail struct {
	Code    string            `json:"code" doc:"Stable: unauthorized, forbidden, not_found, invalid, conflict, rate_limited, unsupported_media_type, too_large, node_offline, timeout, delivery_failed, poll_failed, unavailable, internal."`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty" doc:"What is wrong with each field, for invalid."`
}

func apiFail(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiErrorBody{apiErrorDetail{Code: code, Message: msg}})
}

func apiInvalid(w http.ResponseWriter, fields map[string]string) {
	msgs := make([]string, 0, len(fields))
	for _, k := range sortedKeys(fields) {
		msgs = append(msgs, k+": "+fields[k])
	}
	writeJSON(w, http.StatusBadRequest, apiErrorBody{apiErrorDetail{Code: "invalid", Message: strings.Join(msgs, "; "), Fields: fields}})
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// apiFailErr answers an error from core as failErr does for the UI.
func (s *Server) apiFailErr(w http.ResponseWriter, r *http.Request, err error, notFound string) {
	msg, isUser := usererr.Message(err)
	switch {
	case errors.Is(err, core.ErrNotFound), errors.Is(err, sql.ErrNoRows):
		apiFail(w, http.StatusNotFound, "not_found", notFound)
	case isUser:
		apiFail(w, http.StatusBadRequest, "invalid", msg)
	case errors.Is(err, sched.ErrPaused):
		apiFail(w, http.StatusServiceUnavailable, "unavailable", "A restore is running; try again shortly.")
	default:
		s.Log.Error("api request failed", "request_id", info(r).id, "method", r.Method, "path", r.URL.Path, "err", err)
		apiFail(w, http.StatusInternalServerError, "internal", "Something went wrong. The error has been logged.")
	}
}

func (s *Server) apiNotFound(w http.ResponseWriter, r *http.Request) {
	apiFail(w, http.StatusNotFound, "not_found", "There is no such endpoint; GET /api/v2/openapi.json lists them.")
}

// ---------- Authentication and rate limits ----------

// API rate limits: a token gets apiRate requests a second with bursts of
// apiBurst; an address that presents apiFailBurst bad tokens is refused
// for a while, regaining one attempt every apiFailEvery.
const (
	apiRate      = 10
	apiBurst     = 100
	apiFailBurst = 20
	apiFailEvery = 30 * time.Second
)

// limiter is a set of token buckets.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

// take spends one token from key's bucket (rate per second, burst at most)
// and reports whether there was one, else how long until there is.
func (l *limiter) take(key string, rate, burst float64, now time.Time, spend bool) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[string]*bucket{}
	}
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) > 10000 {
			for k, o := range l.buckets {
				if o.tokens+now.Sub(o.at).Seconds()*rate >= burst {
					delete(l.buckets, k)
				}
			}
		}
		b = &bucket{tokens: burst, at: now}
		l.buckets[key] = b
	}
	b.tokens = min(burst, b.tokens+now.Sub(b.at).Seconds()*rate)
	b.at = now
	if b.tokens < 1 {
		return false, time.Duration((1 - b.tokens) / rate * float64(time.Second))
	}
	if spend {
		b.tokens--
	}
	return true, 0
}

func retryAfter(w http.ResponseWriter, d time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(d/time.Second)+1))
}

// apiGuard authenticates the token, applies the rate limits and the role ×
// action decision, then runs h.
func (s *Server) apiGuard(a authz.Action, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ri := info(r)
		now := s.now()
		if ok, wait := s.apiFails.take(ri.ip, 1/apiFailEvery.Seconds(), apiFailBurst, now, false); !ok {
			retryAfter(w, wait)
			apiFail(w, http.StatusTooManyRequests, "rate_limited", "Too many requests with an invalid token from this address; try again later.")
			return
		}
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || strings.TrimSpace(raw) == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="tlswatch"`)
			apiFail(w, http.StatusUnauthorized, "unauthorized", "Send an API token as Authorization: Bearer. Create one under Account.")
			return
		}
		sess, err := s.Auth.APIAuth(r.Context(), strings.TrimSpace(raw), ri.ip)
		if errors.Is(err, auth.ErrNoAPIToken) {
			s.apiFails.take(ri.ip, 1/apiFailEvery.Seconds(), apiFailBurst, now, true)
			w.Header().Set("WWW-Authenticate", `Bearer realm="tlswatch", error="invalid_token"`)
			apiFail(w, http.StatusUnauthorized, "unauthorized", "The API token is invalid, expired or revoked.")
			return
		}
		if err != nil {
			s.Log.Error("api token lookup", "request_id", ri.id, "err", err)
			apiFail(w, http.StatusServiceUnavailable, "unavailable", "tlswatch is temporarily unavailable; try again shortly.")
			return
		}
		ri.api = sess
		if ok, wait := s.apiLimits.take(strconv.FormatInt(sess.Token.ID, 10), apiRate, apiBurst, now, true); !ok {
			retryAfter(w, wait)
			apiFail(w, http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("This token is limited to %d requests a second.", apiRate))
			return
		}
		if !authz.Allowed(sess.Role, a) {
			apiFail(w, http.StatusForbidden, "forbidden", fmt.Sprintf("The token's role (%s) does not allow this.", sess.Role))
			return
		}
		h(w, r)
	}
}

// apiSession is the token of the request (only valid behind apiGuard).
func apiSession(r *http.Request) *auth.APISession {
	if s := info(r).api; s != nil {
		return s
	}
	return &auth.APISession{}
}

// apiAudit records a write made through a token, naming the token.
func (s *Server) apiAudit(r *http.Request, action, object, details string) {
	sess := apiSession(r)
	via := "token=" + strconv.Quote(sess.Token.Name)
	if details != "" {
		via = details + " " + via
	}
	s.Core.Audit(r.Context(), sess.User.Email, action, object, via)
}

// actor is the name an acknowledgement through a token carries.
func actor(r *http.Request) string {
	sess := apiSession(r)
	return sess.User.DisplayName() + " (token " + sess.Token.Name + ")"
}

// ---------- Request bodies and pages ----------

// readBody decodes a JSON object into dst, refusing unknown fields, and
// returns its raw fields, so an update can tell a field sent as null
// from one left out.
func readBody(w http.ResponseWriter, r *http.Request, dst any) (map[string]json.RawMessage, bool) {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		apiFail(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Send the body as application/json.")
		return nil, false
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		if mbe := (*http.MaxBytesError)(nil); errors.As(err, &mbe) {
			apiFail(w, http.StatusRequestEntityTooLarge, "too_large", "The body is limited to 1 MB.")
		} else {
			apiFail(w, http.StatusBadRequest, "invalid", "The body could not be read.")
		}
		return nil, false
	}
	if len(bytes.TrimSpace(data)) == 0 {
		data = []byte("{}")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		apiFail(w, http.StatusBadRequest, "invalid", "The body is not a JSON object.")
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		apiFail(w, http.StatusBadRequest, "invalid", "The body does not match the schema: "+strings.TrimPrefix(err.Error(), "json: "))
		return nil, false
	}
	return raw, true
}

func isNull(m json.RawMessage) bool { return string(bytes.TrimSpace(m)) == "null" }

// apiList is a page of a list.
type apiList struct {
	Data       any     `json:"data"`
	NextCursor *string `json:"next_cursor" doc:"Pass as cursor for the next page; null on the last."`
}

// Validate target pagination before touching the database. Existing cursors
// encode the zero-padded decimal ID; keep that representation on the wire.
func targetPageParams(w http.ResponseWriter, r *http.Request) (int, int64, bool) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 500 {
			apiFail(w, http.StatusBadRequest, "invalid", "limit is 1 to 500")
			return 0, 0, false
		}
		limit = n
	}
	var after int64
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		value, err := base64.RawURLEncoding.DecodeString(raw)
		if err == nil {
			after, err = strconv.ParseInt(string(value), 10, 64)
		}
		if err != nil || after < 1 || string(value) != idKey(after) {
			apiFail(w, http.StatusBadRequest, "invalid", "The cursor is not one this API gave out")
			return 0, 0, false
		}
	}
	return limit, after, true
}

// writePage answers one page of items, ordered by key: the items after the
// cursor, up to the limit.
func writePage[T any](w http.ResponseWriter, r *http.Request, items []T, key func(T) string, conv func(T) any) {
	q := r.URL.Query()
	limit := 100
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			apiFail(w, http.StatusBadRequest, "invalid", "limit is 1 to 500")
			return
		}
		limit = n
	}
	after := ""
	if c := q.Get("cursor"); c != "" {
		b, err := base64.RawURLEncoding.DecodeString(c)
		if err != nil || len(b) == 0 {
			apiFail(w, http.StatusBadRequest, "invalid", "The cursor is not one this API gave out")
			return
		}
		after = string(b)
	}
	sort.SliceStable(items, func(i, j int) bool { return key(items[i]) < key(items[j]) })
	out := []any{}
	var next *string
	last := ""
	for _, it := range items {
		k := key(it)
		if after != "" && k <= after {
			continue
		}
		if len(out) == limit {
			c := base64.RawURLEncoding.EncodeToString([]byte(last))
			next = &c
			break
		}
		out = append(out, conv(it))
		last = k
	}
	writeJSON(w, http.StatusOK, apiList{Data: out, NextCursor: next})
}
