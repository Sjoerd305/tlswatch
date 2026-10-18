package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// ---------- Discover: network scans ----------

// discoverData is the Discover page: the scan form and the recent scans.
type discoverData struct {
	In     core.ScanInput
	Rate   string
	Nodes  []core.Node // confirmed nodes, for "Probe from"
	Scans  []core.Scan
	Error  string
	Public bool // public ranges may be scanned
}

func (s *Server) discoverPage(w http.ResponseWriter, r *http.Request) {
	s.renderDiscover(w, r, http.StatusOK, discoverData{Rate: strconv.Itoa(probe.DefaultScanRate)})
}

func (s *Server) renderDiscover(w http.ResponseWriter, r *http.Request, status int, d discoverData) {
	ctx := r.Context()
	nodes, err := s.Core.Nodes(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, n := range nodes {
		if n.Assignable() {
			d.Nodes = append(d.Nodes, n)
		}
	}
	if d.Scans, err = s.Core.Scans(ctx); err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Public = info(r).settings.General.PublicDiscovery
	running := false
	for _, sc := range d.Scans {
		running = running || sc.State == core.ScanRunning
	}
	s.renderStatus(w, r, status, "targets-discover", &Page{Title: "Discover", Nav: "targets", Data: d, Live: running})
}

// discoverStart records a scan and starts it.
func (s *Server) discoverStart(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	d := discoverData{In: core.ScanInput{Ranges: r.PostFormValue("ranges"), Ports: r.PostFormValue("ports")}, Rate: r.PostFormValue("rate")}
	d.In.NodeID, _ = strconv.ParseInt(r.PostFormValue("node_id"), 10, 64)
	if strings.TrimSpace(d.Rate) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(d.Rate))
		if err != nil {
			d.Error = "Enter the rate as a whole number of connects per second"
			s.renderDiscover(w, r, http.StatusBadRequest, d)
			return
		}
		d.In.Rate = n
	}
	sc, addrs, err := s.Core.CreateScan(r.Context(), d.In, user(r).Email)
	if err != nil {
		if msg, ok := s.formError(w, r, err); ok {
			d.Error = msg
			s.renderDiscover(w, r, http.StatusBadRequest, d)
		}
		return
	}
	s.Sched.StartScan(sc, addrs)
	http.Redirect(w, r, fmt.Sprintf("/scans/%d", sc.ID), http.StatusSeeOther)
}

// scanData is one scan's page: its progress and what it found.
type scanData struct {
	S       core.Scan
	Results []core.ScanResult
	New     int // results no target covers
}

func (s *Server) scanPage(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such scan.")
		return
	}
	sc, err := s.Core.Scan(r.Context(), id)
	if err != nil {
		s.failErr(w, r, err, "No such scan; scans are kept for 7 days.")
		return
	}
	d := scanData{S: sc}
	if d.Results, err = s.Core.ScanResults(r.Context(), id); err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, res := range d.Results {
		if res.TargetID == 0 {
			d.New++
		}
	}
	s.render(w, r, "targets-scan", &Page{Title: "Scan", Nav: "targets", Data: d, Live: sc.State == core.ScanRunning})
}

// scanAdd hands the ticked results to Add many: one line per endpoint,
// with the protocol of its port and, when the first name in the
// certificate resolves to the address, that name as the server name.
func (s *Server) scanAdd(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such scan.")
		return
	}
	_ = r.ParseForm()
	sc, err := s.Core.Scan(r.Context(), id)
	if err != nil {
		s.failErr(w, r, err, "No such scan; scans are kept for 7 days.")
		return
	}
	results, err := s.Core.ScanResults(r.Context(), id)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	want := map[string]bool{}
	for _, v := range r.PostForm["id"] {
		want[v] = true
	}
	var picked []core.ScanResult
	for _, res := range results {
		if want[strconv.FormatInt(res.ID, 10)] {
			picked = append(picked, res)
		}
	}
	if len(picked) == 0 {
		s.back(w, r, fmt.Sprintf("/scans/%d", id), "Tick the endpoints to add first.", "warn")
		return
	}
	lines := scanLines(r.Context(), picked, s.lookupHost)
	v := url.Values{"hosts": {strings.Join(lines, "\n")}, "node_id": {strconv.FormatInt(sc.NodeID, 10)}}
	r.PostForm = v
	r.Method = http.MethodPost
	s.bulkAddPage(w, r)
}

// lookupHost resolves a name, for the server name guess; replaceable in
// tests.
func (s *Server) lookupHost(ctx context.Context, name string) ([]string, error) {
	if s.LookupHost != nil {
		return s.LookupHost(ctx, name)
	}
	return net.DefaultResolver.LookupHost(ctx, name)
}

// scanLines writes an Add many line per result. The first DNS name the
// certificate carries (no wildcard) becomes the server name when it
// resolves to the address, here on the server; the names are looked up at
// once, each for at most two seconds.
func scanLines(ctx context.Context, results []core.ScanResult, lookup func(context.Context, string) ([]string, error)) []string {
	sni := make([]string, len(results))
	var wg sync.WaitGroup
	for i, res := range results {
		name := firstName(res)
		if name == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			addrs, err := lookup(lctx, name)
			if err != nil {
				return
			}
			for _, a := range addrs {
				if net.ParseIP(a).Equal(net.ParseIP(res.Address)) {
					sni[i] = name
					return
				}
			}
		}()
	}
	wg.Wait()
	lines := make([]string, 0, len(results))
	for i, res := range results {
		line := net.JoinHostPort(res.Address, strconv.Itoa(res.Port))
		if res.Protocol != probe.TLS && res.Protocol != "" {
			line += " protocol=" + string(res.Protocol)
		}
		if sni[i] != "" {
			line += " sni=" + sni[i] + " " + sni[i]
		}
		lines = append(lines, line)
	}
	return lines
}

// firstName is the first DNS name of a result's certificate: its first
// SAN that is not a wildcard or an address, else its subject CN when that
// looks like a name.
func firstName(res core.ScanResult) string {
	for _, n := range append(append([]string{}, res.SANs...), res.SubjectCN) {
		if n == "" || strings.Contains(n, "*") || net.ParseIP(n) != nil || !strings.Contains(n, ".") || probe.ValidateHost(n) != nil {
			continue
		}
		return strings.ToLower(n)
	}
	return ""
}
