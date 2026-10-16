package web

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/node"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, errBadID
	}
	return id, nil
}

// overviewRows is how many targets "Expiring next" shows before "Show all".
const overviewRows = 10

// overviewData is the home screen: the overview plus whether the expiring
// list is unfolded (?all=1).
type overviewData struct {
	core.Overview
	All  bool
	Rows int // overviewRows, for the template
}

// More is how many targets the folded list hides.
func (d overviewData) More() int { return max(len(d.Targets)-d.Rows, 0) }

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	o, err := s.Core.Overview(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := overviewData{Overview: o, All: r.URL.Query().Get("all") == "1", Rows: overviewRows}
	s.render(w, r, "overview", &Page{Title: "Overview", Nav: "overview", Data: d, Live: true})
}

// Chip is a filter chip with its count.
type Chip struct {
	Key, Value, Label, Class string
	Count                    int
	On                       bool
	Href                     string
}

type targetsData struct {
	Groups    []targetGroup // set when grouped by tag
	GroupHref string
	Targets   []targetRow
	Shown     int
	Status    []Chip
	Tags      []Chip
	Grades    []Chip
	Nodes     []Chip // "Probe from" chips, when there are nodes
	ShowNode  bool   // the node column
	Query     string
	Group     bool
	Sort      Sort
}

// targetSortKeys are the sortable columns of the targets table; "days" is
// the list's own order (expiry, unknown and disabled last).
var targetSortKeys = []string{"status", "name", "host", "node", "days", "lifetime", "expires", "issuer", "tls", "grade", "tags", "checked"}

func (s *Server) targets(w http.ResponseWriter, r *http.Request) {
	ts, err := s.Core.Targets(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	nodes, err := s.Core.Nodes(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	q := r.URL.Query()
	status, tag, text := q.Get("status"), q.Get("tag"), strings.ToLower(strings.TrimSpace(q.Get("q")))
	nodeF, gradeF := q.Get("node"), q.Get("grade")
	d := targetsData{Query: q.Get("q"), Sort: sortFrom(r, "days", targetSortKeys...)}
	counts := map[string]int{}
	for _, t := range ts {
		counts[chipStatus(t.Status)]++
	}
	d.Status = append(d.Status, Chip{Key: "status", Value: "", Label: "All", Count: len(ts), On: status == ""})
	for _, st := range []string{"critical", "warning", "healthy", "unreachable", "pending", "disabled"} {
		if counts[st] == 0 && st != "critical" && st != "warning" && st != "healthy" {
			continue
		}
		d.Status = append(d.Status, Chip{Key: "status", Value: st, Label: core.StatusLabel(st), Class: core.StatusClass(st), Count: counts[st], On: status == st})
	}
	for _, tc := range core.TagCounts(ts) {
		d.Tags = append(d.Tags, Chip{Key: "tag", Value: tc.Tag, Label: tc.Tag, Count: tc.Count, On: tag == tc.Tag})
	}
	if tag != "" {
		d.Tags = append([]Chip{{Key: "tag", Value: "", Label: "Any tag", On: false}}, d.Tags...)
	}
	for i := range d.Status {
		d.Status[i].Href = chipHref(r, "status", d.Status[i].Value)
	}
	for i := range d.Tags {
		d.Tags[i].Href = chipHref(r, "tag", d.Tags[i].Value)
	}
	// Grade chips, once a target has a grade: one per grade in use, and
	// "no grade" for the targets not fully tested yet or with the test off.
	perGrade := map[string]int{}
	for _, t := range ts {
		perGrade[gradeToken(t)]++
	}
	if len(perGrade) > 1 || perGrade["none"] == 0 {
		d.Grades = append(d.Grades, Chip{Key: "grade", Value: "", Label: "Any grade", Count: len(ts), On: gradeF == ""})
		for _, g := range check.Grades {
			if perGrade[g] > 0 {
				d.Grades = append(d.Grades, Chip{Key: "grade", Value: g, Label: "Grade " + g, Class: check.GradeClass(g), Count: perGrade[g], On: gradeF == g})
			}
		}
		if perGrade["none"] > 0 {
			d.Grades = append(d.Grades, Chip{Key: "grade", Value: "none", Label: "No grade", Count: perGrade["none"], On: gradeF == "none"})
		}
		for i := range d.Grades {
			d.Grades[i].Href = chipHref(r, "grade", d.Grades[i].Value)
		}
	}
	d.ShowNode = len(nodes) > 0
	if d.ShowNode {
		perNode := map[string]int{}
		for _, t := range ts {
			perNode[nodeToken(t)]++
		}
		d.Nodes = append(d.Nodes, Chip{Key: "node", Value: "", Label: "Anywhere", Count: len(ts), On: nodeF == ""},
			Chip{Key: "node", Value: "server", Label: "This server", Count: perNode["server"], On: nodeF == "server"})
		for _, n := range nodes {
			if n.State != core.NodeConfirmed {
				continue
			}
			v := strconv.FormatInt(n.ID, 10)
			d.Nodes = append(d.Nodes, Chip{Key: "node", Value: v, Label: n.Label(), Count: perNode[v], On: nodeF == v})
		}
		for i := range d.Nodes {
			d.Nodes[i].Href = chipHref(r, "node", d.Nodes[i].Value)
		}
	}
	// Server-side filtering mirrors the TypeScript filter, so the page
	// works without JavaScript; rows are rendered hidden, not dropped.
	now := s.now()
	for _, t := range ts {
		row := targetRow{T: t, Now: now, ShowNode: d.ShowNode, Hidden: !targetMatches(t, status, tag, text) || nodeF != "" && nodeToken(t) != nodeF || gradeF != "" && gradeToken(t) != gradeF}
		if !row.Hidden {
			d.Shown++
		}
		d.Targets = append(d.Targets, row)
	}
	sortRows(d.Sort, d.Targets, targetRow.sortVal)
	d.Group = q.Get("group") == "tag"
	if d.Group {
		d.GroupHref = chipHref(r, "group", "")
		byTag := map[string][]targetRow{}
		var untagged []targetRow
		for _, row := range d.Targets {
			if len(row.T.Tags) == 0 {
				untagged = append(untagged, row)
			}
			for _, g := range row.T.Tags {
				byTag[g] = append(byTag[g], row)
			}
		}
		for _, tc := range core.TagCounts(ts) {
			d.Groups = append(d.Groups, targetGroup{Tag: tc.Tag, Rows: byTag[tc.Tag]})
		}
		if len(untagged) > 0 {
			d.Groups = append(d.Groups, targetGroup{Tag: "", Rows: untagged})
		}
	} else {
		d.GroupHref = chipHref(r, "group", "tag")
	}
	s.render(w, r, "targets", &Page{Title: "Targets", Nav: "targets", Data: d, Live: true})
}

// targetGroup is one tag section of the grouped targets list; a target with
// several tags appears in each.
type targetGroup struct {
	Tag  string
	Rows []targetRow
}

func chipStatus(s string) string {
	if s == core.StatusChanged {
		return core.StatusWarning
	}
	return s
}

func targetMatches(t core.Target, status, tag, text string) bool {
	if status != "" && chipStatus(t.Status) != status {
		return false
	}
	if tag != "" && !contains(t.Tags, tag) {
		return false
	}
	if text != "" && !strings.Contains(targetSearch(t), text) {
		return false
	}
	return true
}

func targetSearch(t core.Target) string {
	parts := []string{t.Name, t.HostPort(), t.ServerName, string(t.Protocol), strings.Join(t.Tags, " "), t.NodeName}
	if t.Cert != nil {
		parts = append(parts, t.Cert.IssuerName(), t.Cert.SubjectCN)
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func chipHref(r *http.Request, key, value string) string {
	q := r.URL.Query()
	if value == "" {
		q.Del(key)
	} else {
		q.Set(key, value)
	}
	if enc := q.Encode(); enc != "" {
		return "?" + enc
	}
	return r.URL.Path
}

// targetRow is a row in the targets table, also rendered alone by the API.
type targetRow struct {
	T        core.Target
	Now      time.Time
	Hidden   bool
	ShowNode bool
}

// nodeToken is the "node" chip value of a target: its node's id, or
// "server".
func nodeToken(t core.Target) string {
	if t.NodeID == 0 {
		return "server"
	}
	return strconv.FormatInt(t.NodeID, 10)
}

// NodeToken is the row's "node" chip value.
func (r targetRow) NodeToken() string { return nodeToken(r.T) }

// GradeToken is the row's "grade" chip value: the grade, or "none".
func (r targetRow) GradeToken() string { return gradeToken(r.T) }

func gradeToken(t core.Target) string {
	if t.Grade == "" {
		return "none"
	}
	return t.Grade
}

// Search is the text the live filter matches.
func (r targetRow) Search() string { return targetSearch(r.T) }

// SortAttrs are the row's data-sort-* attributes.
func (r targetRow) SortAttrs() template.HTMLAttr { return sortAttrs(targetSortKeys, r.sortVal) }

func (r targetRow) sortVal(key string) sortVal {
	t := r.T
	switch key {
	case "status":
		return num(float64(statusRank(t.Status)))
	case "name":
		return txt(t.Name)
	case "host":
		return txt(t.HostPort())
	case "node":
		return txt(t.NodeName)
	case "days", "expires":
		return numIf(t.NotAfter > 0, float64(t.NotAfter))
	case "lifetime":
		if t.Cert == nil {
			return sortVal{}
		}
		return num(float64(t.Cert.LifetimeUsed(r.Now)))
	case "issuer":
		if t.Cert == nil {
			return sortVal{}
		}
		return txt(t.Cert.IssuerName())
	case "tls":
		return txt(t.TLSVersion)
	case "grade":
		return numIf(t.Grade != "", float64(-check.GradeRank(t.Grade)))
	case "tags":
		return txt(strings.Join(t.Tags, " "))
	case "checked":
		return numIf(t.LastCheck > 0, float64(t.LastCheck))
	}
	return sortVal{}
}

// StatusToken is the chip value of the row's status.
func (r targetRow) StatusToken() string { return chipStatus(r.T.Status) }

type targetDetail struct {
	T         core.Target
	Eff       core.Effective
	Last      []core.Observation
	Chain     []core.ChainLink
	ChainOK   bool
	ChainNote string
	History   []core.HistoryEntry
	Findings  []core.Finding
	Alerts    []core.AlertEntry
	OpenMain  *core.Finding
	AlsoOn    []core.Served
	Channels  []string
	Hostname  string
	Slot      string
}

func (s *Server) targetDetail(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such target.")
		return
	}
	t, err := s.Core.Target(r.Context(), id)
	if err != nil {
		s.failErr(w, r, err, "No such target.")
		return
	}
	d, err := s.loadTargetDetail(r.Context(), t, info(r).settings)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "target", &Page{Title: t.Name, Nav: "targets", Data: d, Live: true})
}

// loadTargetDetail gathers what the target page shows.
func (s *Server) loadTargetDetail(ctx context.Context, t core.Target, st config.Settings) (targetDetail, error) {
	d := targetDetail{T: t, Eff: t.Effective(st.Defaults)}
	var err error
	if d.Last, err = s.Core.LastCheck(ctx, t.ID); err != nil {
		return d, err
	}
	for _, o := range d.Last {
		if o.LeafFP == t.CurrentFP && len(o.Chain) > 0 {
			d.Chain, d.ChainOK, d.ChainNote = s.Core.Chain(ctx, o), o.Verified, o.VerifyError
			break
		}
	}
	if d.History, err = s.Core.History(ctx, t); err != nil {
		return d, err
	}
	if d.Findings, d.OpenMain, err = s.targetFindings(ctx, t.ID); err != nil {
		return d, err
	}
	if d.Alerts, err = s.Core.Alerts(ctx, 0, t.ID, 8); err != nil {
		return d, err
	}
	if d.AlsoOn, err = s.alsoServedOn(ctx, t); err != nil {
		return d, err
	}
	chans, err := s.Core.Channels.List(ctx)
	if err != nil {
		return d, err
	}
	for _, c := range chans {
		if t.AllChannels || hasInt(t.ChannelIDs, c.ID) {
			d.Channels = append(d.Channels, c.Name)
		}
	}
	d.Slot = slotLabel(t.ID, d.Eff.IntervalS)
	return d, nil
}

// targetFindings returns the open findings, then the last 8 resolved, and
// the open finding the page leads with.
func (s *Server) targetFindings(ctx context.Context, id int64) ([]core.Finding, *core.Finding, error) {
	open, err := s.Core.Findings(ctx, core.FindingFilter{TargetID: id})
	if err != nil {
		return nil, nil, err
	}
	resolved, err := s.Core.Findings(ctx, core.FindingFilter{TargetID: id, Resolved: true, Limit: 8})
	if err != nil {
		return nil, nil, err
	}
	var main *core.Finding
	if len(open) > 0 {
		main = &open[0]
	}
	return append(open, resolved...), main, nil
}

// alsoServedOn lists the other targets serving t's current certificate,
// one entry per target.
func (s *Server) alsoServedOn(ctx context.Context, t core.Target) ([]core.Served, error) {
	if t.CurrentFP == "" {
		return nil, nil
	}
	served, err := s.Core.ServedOn(ctx, t.CurrentFP)
	if err != nil {
		return nil, err
	}
	var out []core.Served
	seen := map[int64]bool{t.ID: true}
	for _, sv := range served {
		if !seen[sv.TargetID] {
			seen[sv.TargetID] = true
			out = append(out, sv)
		}
	}
	return out, nil
}

// slotLabel is the daily check time of a target on a 24-hour interval, or
// "" for other intervals.
func slotLabel(id int64, intervalS int) string {
	if intervalS != 86400 {
		return ""
	}
	slot := core.Slot(id, 24*time.Hour)
	return fmt.Sprintf("%02d:%02d UTC", int(slot.Hours()), int(slot.Minutes())%60)
}

func hasInt(ids []int64, id int64) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// targetForm is the add/edit form state.
type targetForm struct {
	T         core.Target
	New       bool
	Errors    map[string]string
	Bundles   []core.Bundle
	Channels  []notify.Channel
	Renewal   string // auto, managed, manual
	Warn      string
	Crit      string
	Interval  string
	Timeout   string
	Retries   string
	Debounce  string
	RemindW   string
	RemindC   string
	TagsText  string
	Result    *testResult
	Protocols []probe.Protocol
	Nodes     []core.Node // confirmed nodes, for "Probe from"
}

func (s *Server) formData(ctx context.Context, f *targetForm) error {
	var err error
	if f.Bundles, err = s.Core.Bundles(ctx); err != nil {
		return err
	}
	if f.Channels, err = s.Core.Channels.List(ctx); err != nil {
		return err
	}
	f.Protocols = probe.Protocols
	nodes, err := s.Core.Nodes(ctx)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		if n.Assignable() {
			f.Nodes = append(f.Nodes, n)
		}
	}
	if f.Errors == nil {
		f.Errors = map[string]string{}
	}
	return nil
}

func itoaPtr(p *int) string {
	if p == nil {
		return ""
	}
	return strconv.Itoa(*p)
}

func formFromTarget(t core.Target) targetForm {
	f := targetForm{T: t, Warn: itoaPtr(t.WarnDays), Crit: itoaPtr(t.CritDays), Interval: itoaPtr(t.IntervalS),
		Timeout: itoaPtr(t.TimeoutS), Retries: itoaPtr(t.Retries), Debounce: itoaPtr(t.Debounce),
		RemindW: itoaPtr(t.RemindWarnS), RemindC: itoaPtr(t.RemindCritS), TagsText: strings.Join(t.Tags, ", ")}
	switch {
	case !t.RenewalSet:
		f.Renewal = "auto"
	case t.RenewalManaged:
		f.Renewal = "managed"
	default:
		f.Renewal = "manual"
	}
	return f
}

func (s *Server) targetNew(w http.ResponseWriter, r *http.Request) {
	f := formFromTarget(core.Target{Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem, AllAddresses: true, AllChannels: true, Enabled: true})
	f.New = true
	if h := r.URL.Query().Get("host"); h != "" {
		f.T.Host = h
	}
	if err := s.formData(r.Context(), &f); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "target-form", &Page{Title: "Add target", Nav: "targets", Data: f})
}

func (s *Server) targetEdit(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such target.")
		return
	}
	t, err := s.Core.Target(r.Context(), id)
	if err != nil {
		s.failErr(w, r, err, "No such target.")
		return
	}
	f := formFromTarget(t)
	if err := s.formData(r.Context(), &f); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "target-form", &Page{Title: "Edit " + t.Name, Nav: "targets", Data: f})
}

// parseTargetForm reads the form into a target and form state, validated.
func (s *Server) parseTargetForm(r *http.Request, existing *core.Target) targetForm {
	_ = r.ParseForm()
	f := readTargetForm(r.PostForm, existing)
	for k, e := range f.T.Validate(info(r).settings) {
		if _, ok := f.Errors[k]; !ok {
			f.Errors[k] = e
		}
	}
	return f
}

// readTargetForm reads the form's fields into a target and form state
// without validating; Errors holds what could not be read at all.
func readTargetForm(v url.Values, existing *core.Target) targetForm {
	var t core.Target
	if existing != nil {
		t = *existing
	} else {
		t.Enabled = true
	}
	f := targetForm{Errors: map[string]string{}}
	t.Host = strings.TrimSpace(v.Get("host"))
	t.Protocol = probe.Protocol(v.Get("protocol"))
	if p := strings.TrimSpace(v.Get("port")); p == "" {
		t.Port = probe.DefaultPort(t.Protocol)
	} else if n, err := strconv.Atoi(p); err == nil {
		t.Port = n
	} else {
		f.Errors["port"] = "Port must be a number"
	}
	t.Name = v.Get("name")
	t.NodeID, _ = strconv.ParseInt(v.Get("node_id"), 10, 64)
	t.ServerName = strings.TrimSpace(v.Get("servername"))
	// The server name defaults to the host for a DNS name.
	if t.ServerName == "" && !isIP(t.Host) {
		t.ServerName = strings.TrimSuffix(strings.ToLower(t.Host), ".")
	}
	t.Trust = probe.TrustMode(v.Get("trust_mode"))
	t.BundleID, _ = strconv.ParseInt(v.Get("bundle_id"), 10, 64)
	f.Renewal = v.Get("renewal")
	switch f.Renewal {
	case "managed":
		t.RenewalSet, t.RenewalManaged = true, true
	case "manual":
		t.RenewalSet, t.RenewalManaged = true, false
	default:
		f.Renewal = "auto"
		t.RenewalSet = false
	}
	t.ExpectedIssuer = strings.TrimSpace(v.Get("expected_issuer"))
	num := func(field string, raw string, mult int) *int {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil
		}
		n, err := strconv.Atoi(raw)
		if err != nil {
			f.Errors[field] = "Enter a whole number, or leave empty for the default"
			return nil
		}
		n *= mult
		return &n
	}
	f.Warn, f.Crit, f.Interval = v.Get("warn_days"), v.Get("crit_days"), v.Get("interval_s")
	f.Timeout, f.Retries, f.Debounce = v.Get("timeout_s"), v.Get("retries"), v.Get("debounce")
	f.RemindW, f.RemindC = v.Get("remind_warn_s"), v.Get("remind_crit_s")
	t.WarnDays = num("warn_days", f.Warn, 1)
	t.CritDays = num("crit_days", f.Crit, 1)
	t.IntervalS = num("interval_s", f.Interval, 1)
	t.TimeoutS = num("timeout_s", f.Timeout, 1)
	t.Retries = num("retries", f.Retries, 1)
	t.Debounce = num("debounce", f.Debounce, 1)
	t.RemindWarnS = num("remind_warn_s", f.RemindW, 1)
	t.RemindCritS = num("remind_crit_s", f.RemindC, 1)
	t.AllAddresses = v.Get("addresses") != "first"
	t.SkipLegacy = v.Get("legacy") == "off"
	f.TagsText = v.Get("tags")
	tags, err := core.ParseTags(f.TagsText)
	if err != nil {
		f.Errors["tags"] = err.Error()
	}
	t.Tags = tags
	t.AllChannels = v.Get("all_channels") == "1"
	t.ChannelIDs = nil
	for _, c := range v["channel"] {
		if id, err := strconv.ParseInt(c, 10, 64); err == nil {
			t.ChannelIDs = append(t.ChannelIDs, id)
		}
	}
	t.Notes = strings.TrimSpace(strings.ReplaceAll(v.Get("notes"), "\r\n", "\n"))
	f.T = t
	return f
}

func isIP(h string) bool {
	return net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")) != nil
}

func (s *Server) targetSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var existing *core.Target
	if r.PathValue("id") != "" {
		id, err := pathID(r)
		if err != nil {
			s.fail(w, r, http.StatusNotFound, "No such target.")
			return
		}
		t, err := s.Core.Target(ctx, id)
		if err != nil {
			s.failErr(w, r, err, "No such target.")
			return
		}
		existing = &t
	}
	f := s.parseTargetForm(r, existing)
	f.New = existing == nil
	title := "Add target"
	if !f.New {
		title = "Edit " + existing.Name
	}
	if err := s.formData(ctx, &f); err != nil {
		s.serverError(w, r, err)
		return
	}
	if r.PostFormValue("action") == "test" {
		if len(f.Errors) == 0 {
			res := s.testProbe(ctx, info(r).settings, f.T)
			f.Result = &res
		}
		s.render(w, r, "target-form", &Page{Title: title, Nav: "targets", Data: f})
		return
	}
	if len(f.Errors) > 0 {
		s.renderStatus(w, r, http.StatusBadRequest, "target-form", &Page{Title: title, Nav: "targets", Data: f})
		return
	}
	u := user(r)
	id, err := s.Core.SaveTarget(ctx, f.T, u.Email)
	if err != nil {
		if errors.Is(err, core.ErrTargetExists) {
			f.Errors["host"] = err.Error()
			s.renderStatus(w, r, http.StatusBadRequest, "target-form", &Page{Title: title, Nav: "targets", Data: f})
			return
		}
		if msg, ok := usererr.Message(err); ok {
			f.Errors["node_id"] = msg
			s.renderStatus(w, r, http.StatusBadRequest, "target-form", &Page{Title: title, Nav: "targets", Data: f})
			return
		}
		s.serverError(w, r, err)
		return
	}
	action, verb := "target.update", "saved"
	if f.New {
		action, verb = "target.create", "added"
	}
	s.Core.Audit(ctx, u.Email, action, fmt.Sprintf("target %d %s", id, f.T.HostPort()), targetAuditDetails(f.T))
	s.Sched.Reload()
	// Probe a new or changed target right away so the detail page has data.
	s.Sched.CheckSoon(id)
	s.back(w, r, fmt.Sprintf("/targets/%d", id), fmt.Sprintf("Target %s %s; the first check is running.", f.T.Name, verb), "ok")
}

func targetAuditDetails(t core.Target) string {
	parts := []string{"name=" + t.Name, "protocol=" + string(t.Protocol), "trust=" + string(t.Trust)}
	if t.NodeID != 0 {
		parts = append(parts, fmt.Sprintf("node=%d", t.NodeID))
	}
	if t.ServerName != "" {
		parts = append(parts, "servername="+t.ServerName)
	}
	if len(t.Tags) > 0 {
		parts = append(parts, "tags="+strings.Join(t.Tags, ","))
	}
	return strings.Join(parts, " ")
}

// testResult is the "Test without saving" panel.
type testResult struct {
	R        probe.Result
	O        check.Outcome
	Cert     *probe.CertInfo
	Status   string
	Findings []check.Finding
	Days     int
	Used     int
	ChainLen int
	Trust    string
	Err      string
}

// testProbe probes t without storing anything, for Test without saving.
func (s *Server) testProbe(ctx context.Context, st config.Settings, t core.Target) testResult {
	req, err := s.Core.ProbeRequest(ctx, t, st)
	if err != nil {
		return testResult{Err: err.Error(), Status: core.StatusUnreachable}
	}
	req.Legacy = !t.SkipLegacy
	var r probe.Result
	if t.NodeID != 0 {
		// Through the node, with the timeout of a job plus one poll.
		pctx, cancel := context.WithTimeout(ctx, node.NewProbeJob(req, s.now()).Timeout()+node.PollCeiling)
		defer cancel()
		if r, err = s.Nodes.Probe(pctx, t.NodeID, req); err != nil {
			msg := "The node did not answer: " + err.Error()
			if errors.Is(err, core.ErrNodeOffline) {
				msg = "The node is offline, so nothing was probed. Test again once it polls, or choose This server."
			}
			return testResult{Err: msg, Status: core.StatusUnreachable}
		}
	} else {
		pctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		r = probe.Probe(pctx, req)
	}
	// Evaluate as a first observation: no history, debounce of 1.
	t.ID, t.CurrentFP, t.PinnedFP, t.FailStreak, t.OkStreak, t.DNSFail, t.DNSOk = 0, "", "", 0, 0, 0, 0
	one := 1
	t.Debounce = &one
	o, err := s.Core.Evaluate(ctx, t, r, st)
	res := testResult{R: r, O: o}
	if err != nil {
		res.Err = err.Error()
	}
	res.Findings = o.Open
	res.Status = core.StatusOf(true, true, !o.Answered, o.Open)
	if o.Leaf != nil {
		ci := probe.Describe(o.Leaf)
		res.Cert = &ci
		now := s.now()
		res.Days = check.DaysLeft(o.NotAfter, now)
		res.Used = core.LifetimeUsed(ci.NotBefore.Unix(), ci.NotAfter.Unix(), now)
		for _, a := range r.Addresses {
			if a.OK && probe.Fingerprint(a.Chain[0]) == o.LeafFP {
				res.ChainLen = len(a.Chain)
				if len(a.VerifiedChain) > 0 {
					res.ChainLen = len(a.VerifiedChain)
				}
				switch {
				case t.Trust == probe.TrustSelfSigned:
					res.Trust = "not verified, the fingerprint will be pinned"
				case a.Verified && t.Trust == probe.TrustBundle:
					res.Trust = "verified against the CA bundle"
				case a.Verified:
					res.Trust = "verified against the system store"
				default:
					res.Trust = "not trusted: " + a.VerifyError
				}
				break
			}
		}
	}
	sort.SliceStable(res.Findings, func(i, j int) bool { return res.Findings[i].Severity.Rank() > res.Findings[j].Severity.Rank() })
	return res
}

func (s *Server) targetCheck(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such target.")
		return
	}
	t, err := s.Sched.CheckNow(r.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrNotFound):
			s.fail(w, r, http.StatusNotFound, "No such target.")
		case errors.Is(err, core.ErrNodeOffline):
			s.fail(w, r, http.StatusConflict, "The node this target is probed from is offline; the check runs as soon as it polls again.")
		case errors.Is(err, core.ErrNodeNoResult):
			s.fail(w, r, http.StatusGatewayTimeout, "The node did not return a result in time.")
		default:
			s.serverError(w, r, err)
		}
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "target.check", fmt.Sprintf("target %d %s", id, t.HostPort()), "")
	dest := safeNext(r.PostFormValue("next"))
	if dest == "/" {
		dest = fmt.Sprintf("/targets/%d", id)
	}
	s.back(w, r, dest, fmt.Sprintf("%s checked: %s.", t.Name, strings.ToLower(core.StatusLabel(t.Status))), "ok")
}

func (s *Server) setEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such target.")
		return
	}
	if err := s.Core.SetEnabled(r.Context(), id, enabled); err != nil {
		if errors.Is(err, core.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, "No such target.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	action, msg := "target.disable", "Target disabled; its open findings are closed and it is no longer checked."
	if enabled {
		action, msg = "target.enable", "Target enabled; it is checked now."
		s.Sched.CheckSoon(id)
	}
	s.Core.Audit(r.Context(), user(r).Email, action, fmt.Sprintf("target %d", id), "")
	s.Sched.Reload()
	dest := safeNext(r.PostFormValue("next"))
	if dest == "/" {
		dest = fmt.Sprintf("/targets/%d", id)
	}
	s.back(w, r, dest, msg, "ok")
}

func (s *Server) targetEnable(w http.ResponseWriter, r *http.Request)  { s.setEnabled(w, r, true) }
func (s *Server) targetDisable(w http.ResponseWriter, r *http.Request) { s.setEnabled(w, r, false) }

type deleteData struct {
	T      core.Target
	Impact core.DeleteImpact
}

// targetDeletePage asks for confirmation and shows what will be removed.
func (s *Server) targetDeletePage(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such target.")
		return
	}
	t, err := s.Core.Target(r.Context(), id)
	if err != nil {
		s.failErr(w, r, err, "No such target.")
		return
	}
	impact, err := s.Core.TargetDeleteImpact(r.Context(), id)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "target-delete", &Page{Title: "Delete " + t.Name, Nav: "targets", Data: deleteData{T: t, Impact: impact}})
}

func (s *Server) targetDelete(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such target.")
		return
	}
	t, err := s.Core.Target(r.Context(), id)
	if err != nil {
		s.failErr(w, r, err, "No such target.")
		return
	}
	if r.PostFormValue("confirm") != "yes" {
		http.Redirect(w, r, fmt.Sprintf("/targets/%d/delete", id), http.StatusSeeOther)
		return
	}
	if err := s.Core.DeleteTarget(r.Context(), id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "target.delete", fmt.Sprintf("target %d %s", id, t.HostPort()), "name="+t.Name)
	s.Sched.Reload()
	s.back(w, r, "/targets", "Target "+t.Name+" deleted with its history.", "ok")
}

func (s *Server) checkAll(w http.ResponseWriter, r *http.Request) {
	n, err := s.Sched.CheckAll(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "target.check_all", "", fmt.Sprintf("%d targets", n))
	s.back(w, r, safeNext(r.PostFormValue("next")), fmt.Sprintf("Checking %d targets; results appear as they come in.", n), "info")
}

// API.

func (s *Server) apiTargetCheck(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such target.")
		return
	}
	t, err := s.Sched.CheckNow(r.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, core.ErrNotFound):
			s.fail(w, r, http.StatusNotFound, "No such target.")
		case errors.Is(err, core.ErrNodeOffline):
			s.fail(w, r, http.StatusConflict, "The node this target is probed from is offline; the check runs as soon as it polls again.")
		case errors.Is(err, core.ErrNodeNoResult):
			s.fail(w, r, http.StatusGatewayTimeout, "The node did not return a result in time.")
		default:
			s.serverError(w, r, err)
		}
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "target.check", fmt.Sprintf("target %d %s", id, t.HostPort()), "")
	if r.PostFormValue("from") == "detail" {
		writeJSON(w, http.StatusOK, map[string]string{"redirect": fmt.Sprintf("/targets/%d", id)})
		return
	}
	nodes, err := s.Core.Nodes(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	html, err := s.fragment(r, "target-row", frag{P: s.fragPage(r), Item: targetRow{T: t, Now: s.now(), ShowNode: len(nodes) > 0}})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"html": html, "notice": fmt.Sprintf("%s checked: %s.", t.Name, strings.ToLower(core.StatusLabel(t.Status))), "notice_kind": "ok"})
}

func (s *Server) apiCheckAll(w http.ResponseWriter, r *http.Request) {
	n, err := s.Sched.CheckAll(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "target.check_all", "", fmt.Sprintf("%d targets", n))
	writeJSON(w, http.StatusOK, map[string]string{"notice": fmt.Sprintf("Checking %d targets; the page updates as results come in.", n), "notice_kind": "info"})
}

// apiStamp lets live pages poll for changes. Busy asks for a quicker poll
// while checks are queued, running or a target was never checked, and
// while a node is enrolling or updating.
func (s *Server) apiStamp(w http.ResponseWriter, r *http.Request) {
	_, pending, err := s.Core.Stamp(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	arriving, err := s.Core.NodesArriving(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	nodes, err := s.Core.Nodes(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	updating, _ := s.Nodes.Updating(nodes)
	st := s.Sched.Status()
	busy := pending > 0 || st.Backlog > 0 || st.Running > 0 || st.OnNodes > 0 || arriving || updating > 0
	writeJSON(w, http.StatusOK, map[string]any{"stamp": s.stamp(r.Context()), "busy": busy})
}

// stamp is the change stamp of the live pages: the database's change
// counter and the nodes' online epoch.
func (s *Server) stamp(ctx context.Context) string {
	st, _, _ := s.Core.Stamp(ctx)
	return fmt.Sprintf("%s.%d", st, s.Nodes.Epoch())
}

func (s *Server) apiTargetTest(w http.ResponseWriter, r *http.Request) {
	var existing *core.Target
	if id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64); err == nil && id > 0 {
		if t, err := s.Core.Target(r.Context(), id); err == nil {
			existing = &t
		}
	}
	f := s.parseTargetForm(r, existing)
	if len(f.Errors) > 0 {
		var msgs []string
		for _, e := range f.Errors {
			msgs = append(msgs, e)
		}
		sort.Strings(msgs)
		s.fail(w, r, http.StatusBadRequest, strings.Join(msgs, ". "))
		return
	}
	res := s.testProbe(r.Context(), info(r).settings, f.T)
	html, err := s.fragment(r, "test-result", frag{P: s.fragPage(r), Item: res})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"html": html})
}
