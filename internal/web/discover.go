package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// ---------- Discover: network scans ----------

// discoverData is the Discover page: the scan form, the schedules and the
// recent scans.
type discoverData struct {
	In     core.ScanInput
	Rate   string
	Nodes  []core.Node // confirmed nodes, for "Probe from"
	Scans  []core.Scan
	Error  string
	Public bool // public ranges may be scanned
	// Repeat is the form's repeat choice: "", day or week; Weekday, Hour
	// and Name go with it.
	Repeat    string
	Weekday   int
	Hour      int
	Name      string
	Schedules []scheduleRow
}

// scheduleRow is a schedule as the Discover page lists it.
type scheduleRow struct {
	core.ScanSchedule
	Next time.Time
}

func (s *Server) discoverPage(w http.ResponseWriter, r *http.Request) {
	s.renderDiscover(w, r, http.StatusOK, discoverData{Rate: strconv.Itoa(probe.DefaultScanRate), Weekday: int(time.Monday), Hour: 3})
}

// scheduleRows lists the schedules with their next run in the instance's
// time zone.
func (s *Server) scheduleRows(r *http.Request) ([]scheduleRow, error) {
	scs, err := s.Core.ScanSchedules(r.Context())
	if err != nil {
		return nil, err
	}
	now := s.now().In(info(r).settings.Location())
	rows := make([]scheduleRow, 0, len(scs))
	for _, sc := range scs {
		rows = append(rows, scheduleRow{ScanSchedule: sc, Next: sc.NextRun(now)})
	}
	return rows, nil
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
	if d.Schedules, err = s.scheduleRows(r); err != nil {
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

// scheduleInput reads the repeat fields of the scan form into a schedule.
func scheduleInput(r *http.Request, in core.ScanInput) core.ScanScheduleInput {
	weekday, _ := strconv.Atoi(r.PostFormValue("weekday"))
	hour, _ := strconv.Atoi(r.PostFormValue("hour"))
	return core.ScanScheduleInput{Name: r.PostFormValue("name"), Ranges: in.Ranges, Ports: in.Ports, Rate: in.Rate, NodeID: in.NodeID,
		Every: r.PostFormValue("repeat"), Weekday: weekday, Hour: hour, Enabled: r.PostFormValue("enabled") != "0"}
}

// discoverStart records a scan and starts it. With Repeat set it saves the
// scan as a schedule first and runs it as the schedule's first run.
func (s *Server) discoverStart(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	d := discoverData{In: core.ScanInput{Ranges: r.PostFormValue("ranges"), Ports: r.PostFormValue("ports")}, Rate: r.PostFormValue("rate"),
		Repeat: r.PostFormValue("repeat"), Name: r.PostFormValue("name")}
	d.In.NodeID, _ = strconv.ParseInt(r.PostFormValue("node_id"), 10, 64)
	d.Weekday, _ = strconv.Atoi(r.PostFormValue("weekday"))
	d.Hour, _ = strconv.Atoi(r.PostFormValue("hour"))
	if strings.TrimSpace(d.Rate) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(d.Rate))
		if err != nil {
			d.Error = "Enter the rate as a whole number of connects per second"
			s.renderDiscover(w, r, http.StatusBadRequest, d)
			return
		}
		d.In.Rate = n
	}
	email := user(r).Email
	var sc core.Scan
	var addrs []netip.Addr
	var err error
	if d.Repeat != "" {
		var id int64
		if id, err = s.Core.SaveScanSchedule(r.Context(), 0, scheduleInput(r, d.In), email); err == nil {
			var sch core.ScanSchedule
			if sch, err = s.Core.ScanSchedule(r.Context(), id); err == nil {
				sc, addrs, err = s.Core.StartScheduledScan(r.Context(), sch, email)
				if errors.Is(err, core.ErrScanBusy) {
					// The schedule is saved; its first run waits for the slot.
					s.back(w, r, fmt.Sprintf("/targets/discover/schedules/%d", id), "Schedule saved. A scan is already running from there, so the first run is the next scheduled one.", "info")
					return
				}
			}
		}
	} else {
		sc, addrs, err = s.Core.CreateScan(r.Context(), d.In, email)
	}
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

// ---------- Scan schedules ----------

// scheduleData is a schedule's page: its settings to edit, its findings
// and its runs.
type scheduleData struct {
	S        core.ScanSchedule
	Next     time.Time
	Rate     string
	Nodes    []core.Node
	Error    string
	Public   bool
	Findings []core.Finding
	Scans    []core.Scan // this schedule's runs of the last 7 days
}

func (s *Server) renderSchedule(w http.ResponseWriter, r *http.Request, status int, d scheduleData) {
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
	if d.Findings, err = s.Core.Findings(ctx, core.FindingFilter{ScheduleID: d.S.ID}); err != nil {
		s.serverError(w, r, err)
		return
	}
	scans, err := s.Core.Scans(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	running := false
	for _, sc := range scans {
		if sc.ScheduleID == d.S.ID {
			d.Scans = append(d.Scans, sc)
			running = running || sc.State == core.ScanRunning
		}
	}
	d.Next = d.S.NextRun(s.now().In(info(r).settings.Location()))
	d.Public = info(r).settings.General.PublicDiscovery
	if d.Rate == "" {
		d.Rate = strconv.Itoa(d.S.Rate)
	}
	s.renderStatus(w, r, status, "targets-discover-schedule", &Page{Title: "Scan schedule", Nav: "targets", Data: d, Live: running})
}

func (s *Server) schedule(w http.ResponseWriter, r *http.Request) (core.ScanSchedule, bool) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such scan schedule.")
		return core.ScanSchedule{}, false
	}
	sc, err := s.Core.ScanSchedule(r.Context(), id)
	if err != nil {
		s.failErr(w, r, err, "No such scan schedule.")
		return core.ScanSchedule{}, false
	}
	return sc, true
}

func (s *Server) schedulePage(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.schedule(w, r)
	if !ok {
		return
	}
	s.renderSchedule(w, r, http.StatusOK, scheduleData{S: sc})
}

// scheduleSave changes a schedule's settings.
func (s *Server) scheduleSave(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.schedule(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	in := core.ScanInput{Ranges: r.PostFormValue("ranges"), Ports: r.PostFormValue("ports")}
	in.NodeID, _ = strconv.ParseInt(r.PostFormValue("node_id"), 10, 64)
	d := scheduleData{S: sc, Rate: r.PostFormValue("rate")}
	if strings.TrimSpace(d.Rate) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(d.Rate))
		if err != nil {
			d.Error = "Enter the rate as a whole number of connects per second"
			s.renderSchedule(w, r, http.StatusBadRequest, d)
			return
		}
		in.Rate = n
	}
	si := scheduleInput(r, in)
	si.Enabled = sc.Enabled
	if _, err := s.Core.SaveScanSchedule(r.Context(), sc.ID, si, user(r).Email); err != nil {
		if msg, ok := s.formError(w, r, err); ok {
			// Show what was typed, not what is stored.
			d.S.Name, d.S.Every, d.S.Weekday, d.S.Hour, d.S.NodeID = si.Name, si.Every, si.Weekday, si.Hour, si.NodeID
			d.S.Ranges = strings.Fields(strings.NewReplacer(",", " ", "\n", " ").Replace(si.Ranges))
			d.Error = msg
			s.renderSchedule(w, r, http.StatusBadRequest, d)
		}
		return
	}
	s.back(w, r, fmt.Sprintf("/targets/discover/schedules/%d", sc.ID), "Schedule saved.", "ok")
}

// scheduleRun starts a run now, as the operator.
func (s *Server) scheduleRun(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.schedule(w, r)
	if !ok {
		return
	}
	scan, addrs, err := s.Core.StartScheduledScan(r.Context(), sc, user(r).Email)
	if err != nil {
		if msg, ok := s.formError(w, r, err); ok {
			s.back(w, r, fmt.Sprintf("/targets/discover/schedules/%d", sc.ID), msg, "warn")
		}
		return
	}
	s.Sched.StartScan(scan, addrs)
	http.Redirect(w, r, fmt.Sprintf("/scans/%d", scan.ID), http.StatusSeeOther)
}

// scheduleEnabled pauses or resumes a schedule.
func (s *Server) scheduleEnabled(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.schedule(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	enabled := r.PostFormValue("enabled") == "1"
	if err := s.Core.SetScanScheduleEnabled(r.Context(), sc.ID, enabled, user(r).Email); err != nil {
		s.serverError(w, r, err)
		return
	}
	notice := "Schedule paused; its open findings are resolved."
	if enabled {
		notice = "Schedule resumed; the next run is at its scheduled time."
	}
	s.back(w, r, fmt.Sprintf("/targets/discover/schedules/%d", sc.ID), notice, "ok")
}

// scheduleDelete removes a schedule with its findings.
func (s *Server) scheduleDelete(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.schedule(w, r)
	if !ok {
		return
	}
	if err := s.Core.DeleteScanSchedule(r.Context(), sc.ID, user(r).Email); err != nil {
		s.failErr(w, r, err, "No such scan schedule.")
		return
	}
	s.back(w, r, "/targets/discover", "Schedule deleted.", "ok")
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
