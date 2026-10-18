package web

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// ---------- Add many ----------

// bulkAddForm is the "Add targets" form: one endpoint per line and the
// settings they share.
type bulkAddForm struct {
	targetForm
	Lines    string   // the hosts as typed
	LineErrs []string // problems per line, in line order
}

// endpoint is one parsed line of the hosts list.
type endpoint struct {
	Line int
	Host string
	Port int
	Name string
}

// parseEndpoints reads one endpoint per line: a host, host:port or URL,
// followed by an optional name. Empty lines and lines starting with # are
// skipped; a port left out is the protocol's default. Problems come back
// as "Line N: ..." messages.
func parseEndpoints(text string, proto probe.Protocol) ([]endpoint, []string) {
	var eps []endpoint
	var errs []string
	seen := map[string]int{}
	for i, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		n := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		ep, name := fields[0], strings.Join(fields[1:], " ")
		if j := strings.Index(ep, "://"); j >= 0 {
			ep = ep[j+3:]
		}
		if j := strings.IndexAny(ep, "/?#"); j >= 0 {
			ep = ep[:j]
		}
		host, port := ep, probe.DefaultPort(proto)
		if h, p, err := net.SplitHostPort(ep); err == nil {
			host = h
			if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
				errs = append(errs, fmt.Sprintf("Line %d: port must be 1 to 65535", n))
				continue
			}
		}
		host, _ = core.CanonicalHost(host)
		if host == "" {
			errs = append(errs, fmt.Sprintf("Line %d: enter a host, or host:port", n))
			continue
		}
		key := net.JoinHostPort(host, strconv.Itoa(port))
		if first, ok := seen[key]; ok {
			errs = append(errs, fmt.Sprintf("Line %d: repeats line %d", n, first))
			continue
		}
		seen[key] = n
		eps = append(eps, endpoint{Line: n, Host: host, Port: port, Name: name})
	}
	return eps, errs
}

// hasNode reports whether id is one of the assignable nodes.
func hasNode(nodes []core.Node, id int64) bool {
	for _, n := range nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}

func (s *Server) bulkAddPage(w http.ResponseWriter, r *http.Request) {
	f := bulkAddForm{targetForm: formFromTarget(core.Target{Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem, AllAddresses: true, AllChannels: true, Enabled: true})}
	f.New = true
	if err := s.formData(r.Context(), &f.targetForm); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "targets-bulk-add", &Page{Title: "Add targets", Nav: "targets", Data: f})
}

// bulkAdd creates one target per line of the hosts list with the shared
// settings; nothing is saved while any line or field has a problem.
func (s *Server) bulkAdd(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = r.ParseForm()
	f := bulkAddForm{targetForm: readTargetForm(r.PostForm, nil), Lines: r.PostFormValue("hosts")}
	f.New = true
	if err := s.formData(ctx, &f.targetForm); err != nil {
		s.serverError(w, r, err)
		return
	}
	if f.T.NodeID != 0 && !hasNode(f.Nodes, f.T.NodeID) {
		f.Errors["node_id"] = "Choose a confirmed node, or This server"
	}
	if f.T.Trust == probe.TrustBundle && f.T.BundleID != 0 && !slices.ContainsFunc(f.Bundles, func(b core.Bundle) bool { return b.ID == f.T.BundleID }) {
		f.Errors["bundle_id"] = "Choose a CA bundle"
	}
	eps, lineErrs := parseEndpoints(f.Lines, f.T.Protocol)
	st := info(r).settings
	var targets []core.Target
	for _, ep := range eps {
		t := f.T
		t.Host, t.Port, t.Name, t.ServerName = ep.Host, ep.Port, ep.Name, ""
		if !isIP(t.Host) {
			t.ServerName = t.Host
		}
		errs := t.Validate(st)
		for k, e := range errs {
			switch k {
			case "servername":
				if errs["host"] != "" {
					continue // the server name followed the host
				}
				fallthrough
			case "host", "port", "name":
				lineErrs = append(lineErrs, fmt.Sprintf("Line %d: %s", ep.Line, e))
			default:
				if _, ok := f.Errors[k]; !ok {
					f.Errors[k] = e
				}
			}
		}
		targets = append(targets, t)
	}
	if len(eps) == 0 && len(lineErrs) == 0 {
		lineErrs = append(lineErrs, "Enter at least one host")
	}
	sortLineErrs(lineErrs)
	f.LineErrs = lineErrs
	if len(lineErrs) > 0 || len(f.Errors) > 0 {
		s.renderStatus(w, r, http.StatusBadRequest, "targets-bulk-add", &Page{Title: "Add targets", Nav: "targets", Data: f})
		return
	}
	// All or nothing: one transaction for every line.
	u := user(r)
	ids, i, err := s.Core.AddTargets(ctx, targets, u.Email)
	if err != nil {
		if msg, ok := usererr.Message(err); ok {
			f.LineErrs = []string{fmt.Sprintf("%s: %s", targets[i].HostPort(), msg)}
			s.renderStatus(w, r, http.StatusBadRequest, "targets-bulk-add", &Page{Title: "Add targets", Nav: "targets", Data: f})
			return
		}
		s.serverError(w, r, err)
		return
	}
	added, existed := 0, 0
	for i, id := range ids {
		if id == 0 {
			existed++
			continue
		}
		added++
		s.Core.Audit(ctx, u.Email, "target.create", fmt.Sprintf("target %d %s", id, targets[i].HostPort()), targetAuditDetails(targets[i])+" bulk=true")
		s.Sched.CheckSoon(id)
	}
	s.Sched.Reload()
	msg := fmt.Sprintf("%d %s added; the first checks are running.", added, plural(added, "target", "targets"))
	kind := "ok"
	if existed > 0 {
		msg += fmt.Sprintf(" %d already existed and %s skipped.", existed, plural(existed, "was", "were"))
	}
	if added == 0 {
		msg, kind = "Nothing added: every host already exists as a target.", "warn"
	}
	s.back(w, r, "/targets", msg, kind)
}

// sortLineErrs orders "Line N: ..." messages by line number.
func sortLineErrs(errs []string) {
	lineNo := func(e string) int {
		n, _ := strconv.Atoi(strings.TrimPrefix(strings.SplitN(e, ":", 2)[0], "Line "))
		return n
	}
	sort.SliceStable(errs, func(i, j int) bool { return lineNo(errs[i]) < lineNo(errs[j]) })
}

// ---------- Edit many ----------

// bulkFields are the settings the bulk edit form can change, each switched
// on by a "Change" box; tags and the enabled state are always offered.
var bulkFields = []string{"node_id", "trust", "renewal", "expected_issuer", "thresholds", "interval_s", "addresses",
	"probe", "legacy", "reminders", "channels", "notes"}

// bulkEditForm is the "Edit targets" form: the selected targets, which
// settings change and the values they take.
type bulkEditForm struct {
	targetForm
	Targets    []core.Target
	Change     map[string]bool
	AddTags    string
	RemoveTags string
	Enabled    string // "", "enable" or "disable"
}

// IDs are the selected targets' ids, for the form's hidden fields.
func (f bulkEditForm) IDs() []int64 {
	ids := make([]int64, 0, len(f.Targets))
	for _, t := range f.Targets {
		ids = append(ids, t.ID)
	}
	return ids
}

// parseIDs reads the selected ids, each once, in order.
func parseIDs(vals []string) []int64 {
	var ids []int64
	seen := map[int64]bool{}
	for _, v := range vals {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil && id > 0 && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

// loadSelected loads the targets with the given ids; ids that no longer
// exist are left out.
func (s *Server) loadSelected(r *http.Request, ids []int64) ([]core.Target, error) {
	var out []core.Target
	for _, id := range ids {
		t, err := s.Core.Target(r.Context(), id)
		if errors.Is(err, core.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// bulkSelect takes the selection from the targets list to the edit page.
func (s *Server) bulkSelect(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ids := parseIDs(r.PostForm["id"])
	if len(ids) == 0 {
		s.back(w, r, "/targets", "Select the targets to edit first.", "crit")
		return
	}
	q := url.Values{}
	for _, id := range ids {
		q.Add("id", strconv.FormatInt(id, 10))
	}
	http.Redirect(w, r, "/targets/bulk-edit?"+q.Encode(), http.StatusSeeOther)
}

func (s *Server) bulkEditPage(w http.ResponseWriter, r *http.Request) {
	ts, err := s.loadSelected(r, parseIDs(r.URL.Query()["id"]))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(ts) == 0 {
		s.back(w, r, "/targets", "Select the targets to edit first.", "crit")
		return
	}
	f := bulkEditForm{targetForm: formFromTarget(core.Target{Trust: probe.TrustSystem, AllAddresses: true, AllChannels: true}), Targets: ts, Change: map[string]bool{}}
	if err := s.formData(r.Context(), &f.targetForm); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "targets-bulk-edit", &Page{Title: "Edit targets", Nav: "targets", Data: f})
}

// applyBulk writes the changed settings of f onto t and returns which
// changed. Tags are removed, then added, keeping the order of the rest.
func applyBulk(t *core.Target, f *bulkEditForm, add, remove []string) []string {
	v, ch := f.T, f.Change
	var changed []string
	set := func(key string, apply func()) {
		if ch[key] {
			apply()
			changed = append(changed, key)
		}
	}
	set("node_id", func() { t.NodeID = v.NodeID })
	set("trust", func() { t.Trust, t.BundleID = v.Trust, v.BundleID })
	set("renewal", func() { t.RenewalSet, t.RenewalManaged = v.RenewalSet, v.RenewalManaged })
	set("expected_issuer", func() { t.ExpectedIssuer = v.ExpectedIssuer })
	set("thresholds", func() {
		t.WarnDays, t.CritDays, t.WarnPct, t.CritPct, t.RenewalPct = v.WarnDays, v.CritDays, v.WarnPct, v.CritPct, v.RenewalPct
	})
	set("interval_s", func() { t.IntervalS = v.IntervalS })
	set("addresses", func() { t.AllAddresses = v.AllAddresses })
	set("probe", func() { t.TimeoutS, t.Retries, t.Debounce = v.TimeoutS, v.Retries, v.Debounce })
	set("legacy", func() { t.SkipLegacy = v.SkipLegacy })
	set("reminders", func() { t.RemindWarnS, t.RemindCritS = v.RemindWarnS, v.RemindCritS })
	set("channels", func() { t.AllChannels, t.ChannelIDs = v.AllChannels, v.ChannelIDs })
	set("notes", func() { t.Notes = v.Notes })
	if len(add) > 0 || len(remove) > 0 {
		var tags []string
		for _, g := range t.Tags {
			if !contains(remove, g) {
				tags = append(tags, g)
			}
		}
		for _, g := range add {
			if !contains(tags, g) {
				tags = append(tags, g)
			}
		}
		if strings.Join(tags, ",") != strings.Join(t.Tags, ",") {
			t.Tags = tags
			changed = append(changed, "tags")
		}
	}
	return changed
}

// bulkEdit applies the changed settings to every selected target; nothing
// is saved while a value is invalid for any of them.
func (s *Server) bulkEdit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = r.ParseForm()
	v := r.PostForm
	ts, err := s.loadSelected(r, parseIDs(v["id"]))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(ts) == 0 {
		s.back(w, r, "/targets", "Select the targets to edit first.", "crit")
		return
	}
	f := bulkEditForm{targetForm: readTargetForm(v, nil), Targets: ts, Change: map[string]bool{},
		AddTags: v.Get("add_tags"), RemoveTags: v.Get("remove_tags"), Enabled: v.Get("enabled")}
	if err := s.formData(ctx, &f.targetForm); err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, c := range v["change"] {
		if contains(bulkFields, c) {
			f.Change[c] = true
		}
	}
	// Only the changed fields can be wrong; a number that failed to parse in
	// an untouched field is ignored.
	for k := range f.Errors {
		if !f.Change[bulkKey(k)] {
			delete(f.Errors, k)
		}
	}
	if f.Change["node_id"] && f.T.NodeID != 0 && !hasNode(f.Nodes, f.T.NodeID) {
		f.Errors["node_id"] = "Choose a confirmed node, or This server"
	}
	add, err := core.ParseTags(f.AddTags)
	if err != nil {
		f.Errors["add_tags"] = err.Error()
	}
	remove, err := core.ParseTags(f.RemoveTags)
	if err != nil {
		f.Errors["remove_tags"] = err.Error()
	}
	if f.Enabled != "enable" && f.Enabled != "disable" {
		f.Enabled = ""
	}
	if len(f.Change) == 0 && len(add) == 0 && len(remove) == 0 && f.Enabled == "" && len(f.Errors) == 0 {
		f.Errors["form"] = "Tick Change on a setting, or enter tags to add or remove."
	}
	st := info(r).settings
	type pending struct {
		t       core.Target
		changed []string
	}
	var work []pending
	for _, t := range ts {
		changed := applyBulk(&t, &f, add, remove)
		for k, e := range t.Validate(st) {
			if !f.Change[bulkKey(k)] {
				continue // already so before this edit
			}
			if _, ok := f.Errors[k]; !ok {
				f.Errors[k] = t.Name + ": " + e
			}
		}
		work = append(work, pending{t, changed})
	}
	if len(f.Errors) > 0 {
		s.renderStatus(w, r, http.StatusBadRequest, "targets-bulk-edit", &Page{Title: "Edit targets", Nav: "targets", Data: f})
		return
	}
	// All or nothing: one transaction for every target.
	u := user(r)
	ts = ts[:0]
	for _, p := range work {
		ts = append(ts, p.t)
	}
	var enable *bool
	if f.Enabled != "" {
		want := f.Enabled == "enable"
		enable = &want
	}
	if i, err := s.Core.SaveTargets(ctx, ts, enable, u.Email); err != nil {
		if msg, ok := usererr.Message(err); ok {
			f.Errors["form"] = ts[i].Name + ": " + msg
			s.renderStatus(w, r, http.StatusBadRequest, "targets-bulk-edit", &Page{Title: "Edit targets", Nav: "targets", Data: f})
			return
		}
		s.serverError(w, r, err)
		return
	}
	saved := 0
	for _, p := range work {
		t := p.t
		changed := p.changed
		if enable != nil && *enable != t.Enabled {
			changed = append(changed, f.Enabled)
			if *enable {
				s.Sched.CheckSoon(t.ID)
			}
		}
		if f.Change["trust"] || f.Change["node_id"] {
			s.Sched.CheckSoon(t.ID)
		}
		saved++
		s.Core.Audit(ctx, u.Email, "target.update", fmt.Sprintf("target %d %s", t.ID, t.HostPort()), "bulk=true changed="+strings.Join(changed, ","))
	}
	s.Sched.Reload()
	s.back(w, r, "/targets", fmt.Sprintf("%d %s updated.", saved, plural(saved, "target", "targets")), "ok")
}

// bulkKey maps a form field to the Change box that covers it.
func bulkKey(field string) string {
	switch field {
	case "warn_days", "crit_days", "warn_pct", "crit_pct", "renewal_pct":
		return "thresholds"
	case "bundle_id", "trust_mode":
		return "trust"
	case "timeout_s", "retries", "debounce":
		return "probe"
	case "remind_warn_s", "remind_crit_s":
		return "reminders"
	}
	return field
}
