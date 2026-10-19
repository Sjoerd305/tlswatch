package web

import (
	"encoding/csv"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

type certsData struct {
	Items   []certRow
	Shown   int
	Total   int
	Served  int
	Targets int
	Windows []Chip
	Issuers []Chip
	Keys    []Chip
	Query   string
	// ShowAll includes certificates no longer served; AllHref toggles it and
	// keeps the other filters.
	ShowAll bool
	AllHref string
	Sort    Sort
}

// certSortKeys are the sortable columns of the certificates table; "days"
// is the list's own order (expiry).
var certSortKeys = []string{"subject", "issuer", "days", "lifetime", "notafter", "key", "targets", "sha", "first"}

type certRow struct {
	core.InventoryItem
	Days     int
	Used     int    // share of the lifetime used, percent
	Window   string // "30 90" tokens for chip filtering
	Search   string
	Open     bool
	Hidden   bool
	Status   string // ok, warn, crit
	KeyClass string
}

// SortAttrs are the row's data-sort-* attributes.
func (r certRow) SortAttrs() template.HTMLAttr { return sortAttrs(certSortKeys, r.sortVal) }

func (r certRow) sortVal(key string) sortVal {
	switch key {
	case "subject":
		return txt(r.SubjectCN)
	case "issuer":
		return txt(r.IssuerName())
	case "days", "notafter":
		return num(float64(r.NotAfter))
	case "lifetime":
		return num(float64(r.Used))
	case "key":
		return txt(r.KeyDesc())
	case "targets":
		return num(float64(r.Targets))
	case "sha":
		return txt(r.Fingerprint)
	case "first":
		return num(float64(r.FirstSeen))
	}
	return sortVal{}
}

func (s *Server) certificates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	inv, err := s.Core.Inventory(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	q := r.URL.Query()
	f := certFilterFrom(q)
	d := certsData{Query: q.Get("q"), ShowAll: f.showAll, AllHref: chipHref(r, "all", "1"), Sort: sortFrom(r, "days", certSortKeys...)}
	if f.showAll {
		d.AllHref = chipHref(r, "all", "")
	}
	issuers, keys := map[string]int{}, map[string]int{}
	var w30, w90, distrusted int
	targets := map[int64]bool{}
	for _, it := range inv {
		if len(it.Served) == 0 && !f.showAll {
			continue
		}
		row := newCertRow(it, info(r).settings.Defaults.Manual, s.now())
		row.Open = f.open != "" && strings.HasPrefix(it.Fingerprint, f.open)
		if row.Open {
			// Only the open row's chain is rendered; the others load when
			// a row is expanded (apiCertChain).
			row.Chain = s.Core.InventoryChain(ctx, it.Fingerprint)
		}
		row.Hidden = !f.matches(row)
		if !row.Hidden {
			d.Shown++
		}
		if row.Targets > 0 {
			d.Served++
		}
		if row.Days < 30 {
			w30++
		}
		if row.Days < 90 {
			w90++
		}
		if it.Distrusted {
			distrusted++
		}
		issuers[it.IssuerName()]++
		keys[it.KeyType]++
		for _, sv := range it.Served {
			targets[sv.TargetID] = true
		}
		d.Items = append(d.Items, row)
	}
	d.Total, d.Targets = len(d.Items), len(targets)
	sortRows(d.Sort, d.Items, certRow.sortVal)
	d.Windows = []Chip{
		{Key: "window", Value: "", Label: "All", Count: d.Total, On: f.window == ""},
		{Key: "window", Value: "30", Label: "≤ 30 days", Count: w30, On: f.window == "30"},
		{Key: "window", Value: "90", Label: "≤ 90 days", Count: w90, On: f.window == "90"},
	}
	if distrusted > 0 || f.window == "distrusted" {
		d.Windows = append(d.Windows, Chip{Key: "window", Value: "distrusted", Label: "Distrusted", Count: distrusted, On: f.window == "distrusted", Class: "warn"})
	}
	d.Issuers = sortedChips("issuer", issuers, f.issuer)
	d.Keys = sortedChips("key", keys, f.key)
	for _, cs := range [][]Chip{d.Windows, d.Issuers, d.Keys} {
		for i := range cs {
			cs[i].Href = chipHref(r, cs[i].Key, cs[i].Value)
		}
	}
	s.render(w, r, "certificates", &Page{Title: "Certificates", Nav: "certificates", Data: d, Live: true})
}

// certFilter is the certificates page's filter, from the URL.
type certFilter struct {
	window, issuer, key string
	open                string // fingerprint prefix of the expanded row
	text                string
	showAll             bool // include certificates no longer served
}

func certFilterFrom(q url.Values) certFilter {
	return certFilter{window: q.Get("window"), issuer: q.Get("issuer"), key: q.Get("key"), open: strings.ToLower(q.Get("open")),
		text: strings.ToLower(strings.TrimSpace(q.Get("q"))), showAll: q.Get("all") == "1"}
}

// matches reports whether row passes the window, issuer, key and text
// filters; the page hides the rest, so the live filter can show them again.
func (f certFilter) matches(row certRow) bool {
	return (f.window == "" || strings.Contains(" "+row.Window+" ", " "+f.window+" ")) &&
		(f.issuer == "" || row.IssuerName() == f.issuer) && (f.key == "" || row.KeyType == f.key) &&
		(f.text == "" || strings.Contains(row.Search, f.text))
}

// newCertRow builds a row: days left, the expiry windows it falls in, its
// status by the manual thresholds, and the text the filter searches.
func newCertRow(it core.InventoryItem, th config.Thresholds, now time.Time) certRow {
	row := certRow{InventoryItem: it, Days: check.DaysLeft(time.Unix(it.NotAfter, 0), now), Used: it.LifetimeUsed(now), KeyClass: it.KeyType}
	var tokens []string
	for _, w := range []int{30, 90} {
		if row.Days < w {
			tokens = append(tokens, strconv.Itoa(w))
		}
	}
	if it.Distrusted {
		tokens = append(tokens, "distrusted")
	}
	row.Window = strings.Join(tokens, " ")
	ct := check.Thresholds{Warn: th.WarnDays, Crit: th.CritDays, WarnPct: th.WarnPct, CritPct: th.CritPct}
	switch ct.Due(row.Days, check.ShareLeft(time.Unix(it.NotBefore, 0), time.Unix(it.NotAfter, 0), now)) {
	case check.Critical:
		row.Status = "crit"
	case check.Warning:
		row.Status = "warn"
	default:
		row.Status = "ok"
	}
	row.Search = strings.ToLower(strings.Join(append([]string{it.SubjectCN, it.Subject, it.IssuerName(), it.Fingerprint, it.Serial}, it.SANs...), " "))
	return row
}

func sortedChips(key string, m map[string]int, on string) []Chip {
	var out []Chip
	for k, n := range m {
		out = append(out, Chip{Key: key, Value: k, Label: k, Count: n, On: on == k})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Label < out[j].Label
	})
	if on != "" {
		out = append([]Chip{{Key: key, Value: "", Label: "Any " + key, Bare: true}}, out...)
	}
	return out
}

func (s *Server) certificatesCSV(w http.ResponseWriter, r *http.Request) {
	inv, err := s.Core.Inventory(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	now := s.now()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="tlswatch-certificates-%s.csv"`, now.Format("2006-01-02")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"sha256", "subject_cn", "issuer", "serial", "not_before", "not_after", "days_left", "key", "signature", "sans", "served_on", "first_seen", "last_seen"})
	for _, it := range inv {
		var on []string
		for _, sv := range it.Served {
			on = append(on, sv.TargetName+" "+sv.HostPort+" "+sv.Address)
		}
		_ = cw.Write([]string{
			it.Fingerprint, csvSafe(it.SubjectCN), csvSafe(it.IssuerName()), it.Serial,
			time.Unix(it.NotBefore, 0).UTC().Format(time.RFC3339), time.Unix(it.NotAfter, 0).UTC().Format(time.RFC3339),
			strconv.Itoa(check.DaysLeft(time.Unix(it.NotAfter, 0), now)), it.KeyDesc(), it.SigAlg,
			csvSafe(strings.Join(it.SANs, " ")), csvSafe(strings.Join(on, "; ")),
			time.Unix(it.FirstSeen, 0).UTC().Format(time.RFC3339), time.Unix(it.LastSeen, 0).UTC().Format(time.RFC3339),
		})
	}
	cw.Flush()
}

// csvSafe defuses spreadsheet formulas in exported text.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func (s *Server) certificatePEM(w http.ResponseWriter, r *http.Request) {
	fp := strings.ToLower(r.PathValue("fp"))
	c, err := s.Core.Certificate(r.Context(), fp)
	if errors.Is(err, core.ErrNotFound) {
		s.fail(w, r, http.StatusNotFound, "No such certificate.")
		return
	} else if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	if r.URL.Query().Get("download") == "1" {
		// The CN comes from a server tlswatch does not control: only safe
		// characters reach the header.
		name := strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
				return r
			}
			return '_'
		}, strings.ReplaceAll(c.SubjectCN, "*", "wildcard"))
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.pem"`, name, fp[:8]))
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	_, _ = w.Write([]byte(c.PEM))
}

type findingsData struct {
	Items     []findingRow
	Resolved  bool
	State     []Chip
	Sev       []Chip
	Kinds     []Chip
	Sel       *findingPanel
	OpenCount int
	AckCount  int
	ResCount  int
	ResCapped bool // only the latest maxResolved resolved findings are listed
	Retention int
	Query     string
	Shown     int
	// Target narrows the list to one target; ClearTarget is the link without it.
	Target      *core.Target
	ClearTarget string
	// Bulk is true when the rows get checkboxes for bulk acknowledgement.
	Bulk bool
	// Next is this list without a selected finding, to return to after a
	// bulk acknowledgement; SelPrefix starts a link that selects a finding.
	Next      string
	SelPrefix string
	Sort      Sort
	// Group lists the findings per kind; GroupHref toggles it.
	Group     bool
	Groups    []findingGroup
	GroupHref string
}

// findingGroup is one kind's section of the grouped findings list.
type findingGroup struct {
	Kind check.Kind
	Rows []findingRow
}

// findingSortKeys are the sortable columns of the findings table; "sev" is
// the list's own order (severity, then days left; resolved: newest first).
var findingSortKeys = []string{"sev", "finding", "target", "since", "alert", "ack"}

// findingRow is a row of the findings table.
type findingRow struct {
	core.Finding
	Hidden bool
}

// Search is the text the live filter matches.
func (f findingRow) Search() string { return findingSearch(f.Finding) }

// SortAttrs are the row's data-sort-* attributes.
func (f findingRow) SortAttrs() template.HTMLAttr { return sortAttrs(findingSortKeys, f.sortVal) }

func (f findingRow) sortVal(key string) sortVal {
	switch key {
	case "sev":
		return num(float64(-f.Severity.Rank()))
	case "finding":
		return txt(f.Kind.Label())
	case "target":
		return txt(f.TargetName)
	case "since":
		if f.ResolvedAt > 0 {
			return num(float64(f.ResolvedAt))
		}
		return num(float64(f.OpenedAt))
	case "alert":
		return numIf(f.LastAlertAt > 0, float64(f.LastAlertAt))
	case "ack":
		if f.AckAt == 0 {
			return sortVal{}
		}
		return txt(f.AckBy)
	}
	return sortVal{}
}

// groupFindings splits rows per kind, in the order of check.Kinds, keeping
// the rows' order within a kind.
func groupFindings(rows []findingRow) []findingGroup {
	byKind := map[check.Kind][]findingRow{}
	for _, row := range rows {
		byKind[row.Kind] = append(byKind[row.Kind], row)
	}
	var out []findingGroup
	for _, k := range check.Kinds {
		if len(byKind[k]) > 0 {
			out = append(out, findingGroup{Kind: k, Rows: byKind[k]})
		}
	}
	return out
}

func findingSearch(f core.Finding) string {
	return strings.ToLower(strings.Join([]string{f.Kind.Label(), string(f.Kind), f.Details, f.TargetName, f.HostPort(), f.AckBy}, " "))
}

type findingPanel struct {
	// Next is the findings list to return to after acknowledging.
	Next    string
	F       core.Finding
	Alerts  []core.AlertEntry
	CanAck  bool
	Error   string
	Until   string
	Comment string
	// AddHosts are the names an unexpected_certificate offers as targets.
	AddHosts []string
}

// maxResolved caps the resolved findings listed on the findings page.
const maxResolved = 1000

func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	st := info(r).settings
	resolved := q.Get("state") == "resolved"
	since := s.now().Add(-time.Duration(st.Defaults.RetentionDays) * 24 * time.Hour).Unix()
	d := findingsData{Resolved: resolved, Retention: st.Defaults.RetentionDays, Query: q.Get("q"), Sort: sortFrom(r, "sev", findingSortKeys...)}
	var targetID int64
	if id, err := strconv.ParseInt(q.Get("target"), 10, 64); err == nil && id > 0 {
		if t, err := s.Core.Target(ctx, id); err == nil {
			targetID, d.Target = id, &t
			d.ClearTarget = findingsHref(r, "target", "", false)
		}
	}
	open, err := s.Core.Findings(ctx, core.FindingFilter{TargetID: targetID})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	done, err := s.Core.Findings(ctx, core.FindingFilter{TargetID: targetID, Resolved: true, Since: since, Limit: maxResolved})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.OpenCount, d.ResCount, d.ResCapped = len(open), len(done), len(done) == maxResolved
	d.Bulk = !resolved && s.can(r, authz.Acknowledge)
	d.Next, d.SelPrefix = "/findings", "?"
	if back := findingsHref(r, "sel", "", false); strings.HasPrefix(back, "?") {
		d.Next += back
		d.SelPrefix = back + "&"
	}
	now := s.now()
	for _, f := range open {
		if f.Acked(now) {
			d.AckCount++
		}
	}
	list := open
	if resolved {
		list = done
	}
	sev, kind := q.Get("sev"), q.Get("kind")
	var sevCount, kindCount map[string]int
	d.Items, d.Shown, sevCount, kindCount = filterFindings(list, sev, kind, strings.ToLower(strings.TrimSpace(d.Query)))
	sortRows(d.Sort, d.Items, findingRow.sortVal)
	d.Group = q.Get("group") == "kind"
	d.GroupHref = findingsHref(r, "group", "kind", d.Group)
	if d.Group {
		d.Groups = groupFindings(d.Items)
	}
	d.State, d.Sev, d.Kinds = findingChips(len(open), len(done), resolved, sev, kind, sevCount, kindCount)
	for _, cs := range [][]Chip{d.State, d.Sev, d.Kinds} {
		for i := range cs {
			cs[i].Href = findingsHref(r, cs[i].Key, cs[i].Value, cs[i].On)
		}
	}
	if sel, err := strconv.ParseInt(q.Get("sel"), 10, 64); err == nil && sel > 0 {
		if p, err := s.findingPanel(r, sel); err == nil {
			p.Next = d.Next
			d.Sel = &p
		}
	}
	s.render(w, r, "findings", &Page{Title: "Findings", Nav: "findings", Data: d, Live: true})
}

// filterFindings returns the rows of list that match the severity and kind
// chips, how many of them also match the text, and the counts per severity
// and kind for the chips. Like the targets list, rows that miss the text
// filter are returned hidden so the live filter can bring them back.
func filterFindings(list []core.Finding, sev, kind, text string) (rows []findingRow, shown int, sevCount, kindCount map[string]int) {
	sevCount, kindCount = map[string]int{}, map[string]int{}
	for _, f := range list {
		sevCount[string(f.Severity)]++
		kindCount[string(f.Kind)]++
		if (sev != "" && string(f.Severity) != sev) || (kind != "" && string(f.Kind) != kind) {
			continue
		}
		row := findingRow{Finding: f, Hidden: text != "" && !strings.Contains(findingSearch(f), text)}
		if !row.Hidden {
			shown++
		}
		rows = append(rows, row)
	}
	return rows, shown, sevCount, kindCount
}

// findingChips builds the state, severity and kind chips (without links).
// A severity or kind chip shows when the list has it or it is selected.
func findingChips(open, resolvedN int, resolved bool, sev, kind string, sevCount, kindCount map[string]int) (state, sevs, kinds []Chip) {
	state = []Chip{
		{Key: "state", Value: "", Label: "Open", Count: open, On: !resolved},
		{Key: "state", Value: "resolved", Label: "Resolved", Count: resolvedN, On: resolved},
	}
	for _, sv := range []check.Severity{check.Critical, check.Warning, check.Info} {
		if sevCount[string(sv)] > 0 || sev == string(sv) {
			sevs = append(sevs, Chip{Key: "sev", Value: string(sv), Label: sv.Short(), Class: sv.Class(), Count: sevCount[string(sv)], On: sev == string(sv)})
		}
	}
	for _, k := range check.Kinds {
		if kindCount[string(k)] > 0 || kind == string(k) {
			kinds = append(kinds, Chip{Key: "kind", Value: string(k), Label: k.Short(), Count: kindCount[string(k)], On: kind == string(k)})
		}
	}
	return state, sevs, kinds
}

// findingsHref toggles a chip: clicking an active severity or kind chip
// clears it.
func findingsHref(r *http.Request, key, value string, on bool) string {
	q := r.URL.Query()
	q.Del("sel")
	if key == "state" {
		q.Del("sev")
		q.Del("kind")
	}
	if value == "" || (on && key != "state") {
		q.Del(key)
	} else {
		q.Set(key, value)
	}
	if enc := q.Encode(); enc != "" {
		return "?" + enc
	}
	return r.URL.Path
}

func (s *Server) findingPanel(r *http.Request, id int64) (findingPanel, error) {
	f, err := s.Core.Finding(r.Context(), id)
	if err != nil {
		return findingPanel{}, err
	}
	alerts, err := s.Core.Alerts(r.Context(), id, 0, 30)
	if err != nil {
		return findingPanel{}, err
	}
	p := findingPanel{F: f, Alerts: alerts, CanAck: s.can(r, authz.Acknowledge)}
	if f.AckUntil > 0 {
		p.Until = time.Unix(f.AckUntil, 0).In(info(r).settings.Location()).Format("2006-01-02")
	}
	p.Comment = f.AckComment
	// The finding carries its issuance's ID; its names can become targets.
	if f.Kind == check.UnexpectedCertificate && f.Open() && s.can(r, authz.EditTargets) {
		if iid, err := strconv.ParseInt(f.Fingerprint, 10, 64); err == nil {
			if is, err := s.Core.Issuance(r.Context(), iid); err == nil {
				if d, err := s.Core.Domain(r.Context(), is.DomainID); err == nil {
					p.AddHosts = is.TargetNames(d)
				}
			}
		}
	}
	return p, nil
}

func (s *Server) can(r *http.Request, action authz.Action) bool {
	sess := info(r).session
	return sess != nil && authz.Allowed(sess.User.Role, action)
}

// apiCertChain renders the chain a certificate was last served with, for a
// row expanded on the certificates page.
func (s *Server) apiCertChain(w http.ResponseWriter, r *http.Request) {
	chain := s.Core.InventoryChain(r.Context(), strings.ToLower(r.PathValue("fp")))
	html, err := s.fragment(r, "cert-chain", frag{P: s.fragPage(r), Item: chain})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"html": html})
}

func (s *Server) apiFindingPanel(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such finding.")
		return
	}
	p, err := s.findingPanel(r, id)
	if err != nil {
		s.failErr(w, r, err, "No such finding.")
		return
	}
	// The list the panel was opened from, without the selection.
	p.Next = "/findings"
	if next, err := url.Parse(r.URL.Query().Get("next")); err == nil && next.Path == "/findings" {
		q := next.Query()
		q.Del("sel")
		if enc := q.Encode(); enc != "" {
			p.Next += "?" + enc
		}
	}
	html, err := s.fragment(r, "finding-panel", frag{P: s.fragPage(r), Item: p})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"html": html})
}

func (s *Server) findingAck(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such finding.")
		return
	}
	until, ok := s.parseUntil(r)
	if !ok {
		s.back(w, r, fmt.Sprintf("/findings?sel=%d", id), "Enter the until date as YYYY-MM-DD.", "crit")
		return
	}
	comment := r.PostFormValue("comment")
	if len(comment) > 2000 {
		comment = comment[:2000]
	}
	u := user(r)
	f, err := s.Core.Acknowledge(r.Context(), id, u.DisplayName(), until, comment)
	if err != nil {
		msg, ok := usererr.Message(err)
		if !ok {
			s.failErr(w, r, err, "No such finding.")
			return
		}
		s.back(w, r, fmt.Sprintf("/findings?sel=%d", id), msg, "crit")
		return
	}
	s.Core.Audit(r.Context(), u.Email, "finding.ack", fmt.Sprintf("finding %d %s on %s", id, f.Kind, f.HostPort()), ackDetail(until, comment))
	s.Sched.Reload()
	msg := "Acknowledged: reminders stop; escalation and the recovery notice still go out."
	if f.Kind.AckResolves() {
		msg = "Confirmed: the change is accepted and the finding resolved."
	}
	s.back(w, r, safeNext(r.PostFormValue("next")), msg, "ok")
}

// findingAckBulk acknowledges several open findings at once, with one
// until-date and comment.
func (s *Server) findingAckBulk(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	next := safeNext(r.PostFormValue("next"))
	until, ok := s.parseUntil(r)
	if !ok {
		s.back(w, r, next, "Enter the until date as YYYY-MM-DD.", "crit")
		return
	}
	var ids []int64
	for _, v := range r.PostForm["id"] {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil && id > 0 {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		s.back(w, r, next, "Select the findings to acknowledge first.", "crit")
		return
	}
	comment := r.PostFormValue("comment")
	if len(comment) > 2000 {
		comment = comment[:2000]
	}
	u := user(r)
	acked, confirmed, failed := 0, 0, 0
	for _, id := range ids {
		f, err := s.Core.Acknowledge(r.Context(), id, u.DisplayName(), until, comment)
		_, isUser := usererr.Message(err)
		switch {
		case errors.Is(err, core.ErrNotFound) || isUser:
			failed++ // resolved or gone meanwhile
			continue
		case err != nil:
			s.serverError(w, r, err)
			return
		}
		if f.Kind.AckResolves() {
			confirmed++
		} else {
			acked++
		}
		s.Core.Audit(r.Context(), u.Email, "finding.ack", fmt.Sprintf("finding %d %s on %s", id, f.Kind, f.HostPort()), ackDetail(until, comment)+" bulk=true")
	}
	s.Sched.Reload()
	var parts []string
	if acked > 0 {
		parts = append(parts, fmt.Sprintf("%d acknowledged", acked))
	}
	if confirmed > 0 {
		parts = append(parts, fmt.Sprintf("%d confirmed and resolved", confirmed))
	}
	if failed > 0 {
		parts = append(parts, fmt.Sprintf("%d no longer open", failed))
	}
	kind := "ok"
	if acked+confirmed == 0 {
		kind = "crit"
	}
	s.back(w, r, next, strings.ToUpper(parts[0][:1])+strings.Join(parts, "; ")[1:]+".", kind)
}

// parseUntil reads the optional until-date of an acknowledgement; it runs
// through the end of that day.
func (s *Server) parseUntil(r *http.Request) (time.Time, bool) {
	v := strings.TrimSpace(r.PostFormValue("until"))
	if v == "" {
		return time.Time{}, true
	}
	day, err := time.ParseInLocation("2006-01-02", v, info(r).settings.Location())
	if err != nil {
		return time.Time{}, false
	}
	return day.Add(24*time.Hour - time.Second), true
}

func ackDetail(until time.Time, comment string) string {
	detail := "comment=" + strings.TrimSpace(comment)
	if !until.IsZero() {
		detail = "until=" + until.Format("2006-01-02") + " " + detail
	}
	return detail
}

func (s *Server) findingUnack(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such finding.")
		return
	}
	if err := s.Core.Unacknowledge(r.Context(), id); err != nil {
		s.failErr(w, r, err, "No such open finding.")
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "finding.unack", fmt.Sprintf("finding %d", id), "")
	s.back(w, r, safeNext(r.PostFormValue("next")), "Acknowledgement removed; reminders resume.", "ok")
}
