package node

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sjoerd305/tlswatch/internal/core"
)

// ServeHTTP answers the agent protocol under /agent/. These routes sit
// outside session authentication and CSRF: the node authenticates with its
// bearer credential, never a cookie. Only the install script and the
// binary download are served without it.
func (d *Dispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.init()
	w.Header().Set("Cache-Control", "no-store")
	rest, ok := strings.CutPrefix(r.URL.Path, Prefix+"/")
	if !ok {
		// Another protocol version: the fixed reply every node version
		// understands, which makes it update itself to the server's.
		if parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/agent/"), "/"); len(parts) == 2 && parts[1] == "jobs" {
			writeJSON(w, http.StatusOK, PollResponse{ServerVersion: d.Version, Update: true})
			return
		}
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(rest, "/")
	switch {
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "install":
		d.install(w, r, parts[1])
	case r.Method == http.MethodGet && rest == "uninstall":
		d.uninstall(w, r)
	case r.Method == http.MethodGet && len(parts) == 3 && parts[0] == "download":
		d.download(w, r, parts[1], parts[2])
	case r.Method == http.MethodPost && rest == "enrol":
		d.enrol(w, r)
	case r.Method == http.MethodGet && rest == "jobs":
		d.withNode(w, r, d.poll)
	case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "jobs" && parts[2] == "result":
		d.withNode(w, r, func(w http.ResponseWriter, r *http.Request, n core.Node) { d.result(w, r, n, parts[1]) })
	case r.Method == http.MethodPost && rest == "facts":
		d.withNode(w, r, d.facts)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown call"})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (d *Dispatcher) clientIP(r *http.Request) string {
	if d.ClientIP != nil {
		return d.ClientIP(r)
	}
	return r.RemoteAddr
}

// maxBody caps a node's request: a result holds up to eight chains.
const maxBody = 4 << 20

// readJSON decodes a request body, gzipped or not. The cap applies to the
// body as sent and again to what it inflates to.
func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	body := http.MaxBytesReader(w, r.Body, maxBody)
	switch r.Header.Get("Content-Encoding") {
	case "":
	case "gzip":
		gz, err := gzip.NewReader(body)
		if err != nil {
			return err
		}
		defer gz.Close()
		body = http.MaxBytesReader(w, gz, maxBody)
	default:
		return errors.New("unsupported content encoding")
	}
	return json.NewDecoder(body).Decode(v)
}

// withNode authenticates a node by its bearer credential and records the
// request: every call updates last seen, the version and the address.
func (d *Dispatcher) withNode(w http.ResponseWriter, r *http.Request, h func(http.ResponseWriter, *http.Request, core.Node)) {
	ip := d.clientIP(r)
	if d.auth.blocked(ip, d.now()) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed attempts from this address; wait 15 minutes"})
		return
	}
	cred, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	n, err := d.Core.NodeByCredential(r.Context(), strings.TrimSpace(cred))
	if !ok || err != nil {
		if err != nil && !errors.Is(err, core.ErrNotFound) {
			d.Log.Error("node credential", "err", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "the server cannot check the credential now"})
			return
		}
		d.auth.fail(ip, d.now())
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "credential not accepted; enrol the node again with a new install command"})
		return
	}
	now := d.now()
	version := r.Header.Get(HeaderVersion)
	if version == "" {
		version = n.Version
	}
	if err := d.Core.TouchNode(r.Context(), n.ID, now, version, Protocol, ip); err != nil {
		d.Log.Error("node seen", "node_id", n.ID, "err", err)
	}
	n.LastSeen, n.Version, n.Protocol, n.Address = now.Unix(), version, Protocol, ip
	d.mu.Lock()
	ns := d.state(n.ID)
	ns.lastSeen, ns.meta, ns.known = now, n, true
	d.mu.Unlock()
	d.judge(r.Context())
	h(w, r, n)
}

// poll is the long-poll: it is held until a job exists for the node or
// the ceiling passes, then answered with zero or more jobs.
func (d *Dispatcher) poll(w http.ResponseWriter, r *http.Request, n core.Node) {
	// RFC 7694: the node may gzip what it sends; an older server does not
	// say so and gets plain bodies.
	w.Header().Set("Accept-Encoding", "gzip")
	resp := PollResponse{ServerVersion: d.Version}
	if d.wantUpdate(r.Context(), n, r.Header.Get(HeaderUpdateError)) {
		resp.Jobs = []Job{{ID: newID(), Kind: KindUpdate, Update: &UpdateJob{Version: d.Version}}}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	wait := PollCeiling
	if v, err := time.ParseDuration(r.URL.Query().Get("wait")); err == nil && v >= 0 && v < wait {
		wait = v
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	// A pending or disabled node receives no jobs of any kind; its poll
	// is held all the same, so it does not spin.
	active := n.State == core.NodeConfirmed && n.Enabled
	d.mu.Lock()
	wake := d.state(n.ID).wake
	d.mu.Unlock()
	for {
		if active {
			if resp.Jobs = d.lease(n.ID, max(n.PoolSize, 1)); len(resp.Jobs) > 0 {
				break
			}
		}
		select {
		case <-wake:
			continue
		case <-timer.C:
		case <-r.Context().Done():
		case <-d.stop:
		}
		break
	}
	writeJSON(w, http.StatusOK, resp)
}

// result takes the answer to one job; an unknown or expired job id is
// acknowledged and discarded.
func (d *Dispatcher) result(w http.ResponseWriter, r *http.Request, n core.Node, id string) {
	var res Result
	if err := readJSON(w, r, &res); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the result could not be read"})
		return
	}
	d.complete(n.ID, id, res)
	w.WriteHeader(http.StatusNoContent)
}

// facts stores the system facts a node reports once an hour.
func (d *Dispatcher) facts(w http.ResponseWriter, r *http.Request, n core.Node) {
	var f Facts
	if err := readJSON(w, r, &f); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the facts could not be read"})
		return
	}
	if err := d.Core.SaveNodeFacts(r.Context(), n, d.stamp(f)); err != nil {
		d.Log.Error("node facts", "node_id", n.ID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the facts could not be stored"})
		return
	}
	d.load(r.Context(), n.ID)
	w.WriteHeader(http.StatusNoContent)
}

// stamp computes the clock offset of reported facts.
func (d *Dispatcher) stamp(f Facts) core.NodeFacts {
	nf := f.NodeFacts
	if !f.Time.IsZero() {
		nf.ClockOffsetMS = f.Time.Sub(d.now()).Milliseconds()
	}
	return nf
}

// enrol exchanges a one-time install token for the node's credential.
func (d *Dispatcher) enrol(w http.ResponseWriter, r *http.Request) {
	ip := d.clientIP(r)
	if d.auth.blocked(ip, d.now()) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed attempts from this address; wait 15 minutes"})
		return
	}
	var req EnrolRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the enrolment could not be read"})
		return
	}
	version := r.Header.Get(HeaderVersion)
	if version == "" {
		version = req.Facts.Version
	}
	n, cred, err := d.Core.EnrolNode(r.Context(), req.Token, core.Enrolment{Facts: d.stamp(req.Facts), Pool: req.Pool, Version: version, Protocol: Protocol, Address: ip})
	switch {
	case errors.Is(err, core.ErrBadToken):
		d.auth.fail(ip, d.now())
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "the install token is unknown, spent or expired; create a new one under Settings › Nodes"})
		return
	case err != nil:
		d.Log.Error("node enrol", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the enrolment could not be stored"})
		return
	}
	d.Log.Info("node enrolled", "node_id", n.ID, "hostname", req.Facts.Hostname, "address", ip, "version", version)
	d.mu.Lock()
	ns := d.state(n.ID)
	ns.meta, ns.known, ns.lastSeen = n, true, d.now()
	d.mu.Unlock()
	writeJSON(w, http.StatusOK, EnrolResponse{NodeID: n.ID, Credential: cred, ServerVersion: d.Version})
}

// install serves the install script for an unspent install token.
func (d *Dispatcher) install(w http.ResponseWriter, r *http.Request, token string) {
	ok, err := d.Core.ValidNodeToken(r.Context(), token)
	base := d.Core.CurrentSettings(r.Context()).General.BaseURL
	if err != nil || !ok || base == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, InstallScript(base, token))
}

// uninstall serves the uninstall script; it is the same for every node.
func (d *Dispatcher) uninstall(w http.ResponseWriter, r *http.Request) {
	base := d.Core.CurrentSettings(r.Context()).General.BaseURL
	if base == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, UninstallScript(base))
}

// limiter counts failed attempts per address: 20 in 15 minutes block it,
// as for sign-in.
type limiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

const (
	limitFails  = 20
	limitWindow = 15 * time.Minute
)

func (l *limiter) recent(ip string, now time.Time) []time.Time {
	var keep []time.Time
	for _, t := range l.fails[ip] {
		if now.Sub(t) < limitWindow {
			keep = append(keep, t)
		}
	}
	return keep
}

func (l *limiter) blocked(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(ip, now)) >= limitFails
}

func (l *limiter) fail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fails == nil {
		l.fails = map[string][]time.Time{}
	}
	if len(l.fails) > 10000 {
		l.fails = map[string][]time.Time{} // a flood of addresses: start over rather than grow
	}
	l.fails[ip] = append(l.recent(ip, now), now)
}

// pollURL is the long-poll with its ceiling.
func pollURL(server string) string {
	return server + Prefix + "/jobs?wait=" + strconv.Itoa(int(PollCeiling/time.Second)) + "s"
}
