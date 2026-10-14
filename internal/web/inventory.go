package web

import (
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/core"
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
}

type certRow struct {
	core.InventoryItem
	Days     int
	Window   string // "30 90" tokens for chip filtering
	Search   string
	Open     bool
	Hidden   bool
	Status   string // ok, warn, crit
	KeyClass string
}

func (s *Server) certificates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	inv, err := s.Core.Inventory(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	st := info(r).settings
	now := s.now()
	q := r.URL.Query()
	win, issuer, key, open := q.Get("window"), q.Get("issuer"), q.Get("key"), q.Get("open")
	text := strings.ToLower(strings.TrimSpace(q.Get("q")))
	showAll := q.Get("all") == "1"
	d := certsData{Query: q.Get("q"), ShowAll: showAll}
	if showAll {
		d.AllHref = chipHref(r, "all", "")
	} else {
		d.AllHref = chipHref(r, "all", "1")
	}
	issuers, keys := map[string]int{}, map[string]int{}
	var w30, w90 int
	targets := map[int64]bool{}
	for _, it := range inv {
		if len(it.Served) == 0 && !showAll {
			continue
		}
		row := certRow{InventoryItem: it, Days: check.DaysLeft(time.Unix(it.NotAfter, 0), now), KeyClass: it.KeyType}
		var tokens []string
		if row.Days < 30 {
			tokens = append(tokens, "30")
			w30++
		}
		if row.Days < 90 {
			tokens = append(tokens, "90")
			w90++
		}
		row.Window = strings.Join(tokens, " ")
		switch {
		case row.Days < st.Defaults.Manual.CritDays:
			row.Status = "crit"
		case row.Days < st.Defaults.Manual.WarnDays:
			row.Status = "warn"
		default:
			row.Status = "ok"
		}
		row.Search = strings.ToLower(strings.Join(append([]string{it.SubjectCN, it.Subject, it.IssuerName(), it.Fingerprint, it.Serial}, it.SANs...), " "))
		row.Open = open != "" && strings.HasPrefix(it.Fingerprint, strings.ToLower(open))
		if row.Open {
			row.Chain = s.Core.InventoryChain(ctx, it.Fingerprint)
		}
		issuers[it.IssuerName()]++
		keys[it.KeyType]++
		for _, sv := range it.Served {
			targets[sv.TargetID] = true
		}
		row.Hidden = !(win == "" || strings.Contains(" "+row.Window+" ", " "+win+" ")) ||
			(issuer != "" && it.IssuerName() != issuer) || (key != "" && it.KeyType != key) ||
			(text != "" && !strings.Contains(row.Search, text))
		if !row.Hidden {
			d.Shown++
		}
		d.Items = append(d.Items, row)
	}
	// Only the open row's chain is rendered; the others load when a row is
	// expanded (apiCertChain).
	d.Total = len(d.Items)
	for _, it := range d.Items {
		if it.Targets > 0 {
			d.Served++
		}
	}
	d.Targets = len(targets)
	d.Windows = []Chip{
		{Key: "window", Value: "", Label: "All", Count: d.Total, On: win == ""},
		{Key: "window", Value: "30", Label: "≤ 30 days", Count: w30, On: win == "30"},
		{Key: "window", Value: "90", Label: "≤ 90 days", Count: w90, On: win == "90"},
	}
	d.Issuers = sortedChips("issuer", issuers, issuer)
	d.Keys = sortedChips("key", keys, key)
	for _, cs := range [][]Chip{d.Windows, d.Issuers, d.Keys} {
		for i := range cs {
			cs[i].Href = chipHref(r, cs[i].Key, cs[i].Value)
		}
	}
	s.render(w, r, "certificates", &Page{Title: "Certificates", Nav: "certificates", Data: d, Live: true})
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
		out = append([]Chip{{Key: key, Value: "", Label: "Any " + key}}, out...)
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
		name := strings.NewReplacer("*", "wildcard", "/", "_", " ", "_").Replace(c.SubjectCN)
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
}

// findingRow is a row of the findings table.
type findingRow struct {
	core.Finding
	Hidden bool
}

// Search is the text the live filter matches.
func (f findingRow) Search() string { return findingSearch(f.Finding) }

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
}

func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	st := info(r).settings
	resolved := q.Get("state") == "resolved"
	since := s.now().Add(-time.Duration(st.Defaults.RetentionDays) * 24 * time.Hour).Unix()
	d := findingsData{Resolved: resolved, Retention: st.Defaults.RetentionDays, Query: q.Get("q")}
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
	done, err := s.Core.Findings(ctx, core.FindingFilter{TargetID: targetID, Resolved: true, Since: since, Limit: 1000})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.OpenCount, d.ResCount = len(open), len(done)
	d.Bulk = !resolved && s.can(r, "findings.ack")
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
	text := strings.ToLower(strings.TrimSpace(d.Query))
	sevCount, kindCount := map[string]int{}, map[string]int{}
	for _, f := range list {
		sevCount[string(f.Severity)]++
		kindCount[string(f.Kind)]++
		if (sev == "" || string(f.Severity) == sev) && (kind == "" || string(f.Kind) == kind) {
			// Like the targets list, rows that miss the text filter are
			// rendered hidden so the live filter can bring them back.
			row := findingRow{Finding: f, Hidden: text != "" && !strings.Contains(findingSearch(f), text)}
			if !row.Hidden {
				d.Shown++
			}
			d.Items = append(d.Items, row)
		}
	}
	d.State = []Chip{
		{Key: "state", Value: "", Label: "Open", Count: len(open), On: !resolved},
		{Key: "state", Value: "resolved", Label: "Resolved", Count: len(done), On: resolved},
	}
	for _, sv := range []string{"critical", "warning", "info"} {
		if sevCount[sv] > 0 || sev == sv {
			d.Sev = append(d.Sev, Chip{Key: "sev", Value: sv, Label: check.Severity(sv).Short(), Class: check.Severity(sv).Class(), Count: sevCount[sv], On: sev == sv})
		}
	}
	for _, k := range check.Kinds {
		if kindCount[string(k)] > 0 || kind == string(k) {
			d.Kinds = append(d.Kinds, Chip{Key: "kind", Value: string(k), Label: k.Short(), Count: kindCount[string(k)], On: kind == string(k)})
		}
	}
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
	p := findingPanel{F: f, Alerts: alerts, CanAck: s.can(r, "findings.ack")}
	if f.AckUntil > 0 {
		p.Until = time.Unix(f.AckUntil, 0).In(info(r).settings.Location()).Format("2006-01-02")
	}
	p.Comment = f.AckComment
	return p, nil
}

func (s *Server) can(r *http.Request, action string) bool {
	p := Page{}
	if sess := info(r).session; sess != nil {
		u := sess.User
		p.User = &u
	}
	return p.Can(action)
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
		var ie *core.InputError
		if !errors.As(err, &ie) {
			s.failErr(w, r, err, "No such finding.")
			return
		}
		s.back(w, r, fmt.Sprintf("/findings?sel=%d", id), ie.Msg, "crit")
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
		var ie *core.InputError
		switch {
		case errors.Is(err, core.ErrNotFound) || errors.As(err, &ie):
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
