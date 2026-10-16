package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/ct"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// Domain watches: the Domains list, a watch's page with its issuances, the
// add and edit form, and the delete confirmation. See the specification,
// "Certificate Transparency watching".

type domainsData struct {
	Domains  []domainRow
	Query    string
	Status   []Chip
	Tags     []Chip
	Shown    int
	NoSource bool // the source is not configured (no sources need no configuration, so this is reserved)
	Failing  int  // watches whose polls fail
}

type domainRow struct {
	D      core.Domain
	Now    time.Time
	Hidden bool
}

// Search is the text the live filter matches.
func (r domainRow) Search() string {
	return strings.ToLower(r.D.Name + " " + strings.Join(r.D.Tags, " "))
}

// StatusToken is the row's status chip value.
func (r domainRow) StatusToken() string { return r.D.Status() }

func (s *Server) domains(w http.ResponseWriter, r *http.Request) {
	ds, err := s.Core.Domains(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	q := r.URL.Query()
	status, tag, text := q.Get("status"), q.Get("tag"), strings.ToLower(strings.TrimSpace(q.Get("q")))
	d := domainsData{Query: q.Get("q")}
	counts := map[string]int{}
	tagCounts := map[string]int{}
	var tags []string
	for _, dm := range ds {
		counts[dm.Status()]++
		if dm.FailSince > 0 {
			d.Failing++
		}
		for _, t := range dm.Tags {
			if tagCounts[t] == 0 {
				tags = append(tags, t)
			}
			tagCounts[t]++
		}
	}
	d.Status = append(d.Status, Chip{Key: "status", Value: "", Label: "All", Count: len(ds), On: status == ""})
	for _, st := range []string{core.StatusWarning, core.StatusUnreachable, core.StatusHealthy, core.StatusPending, core.StatusDisabled} {
		if counts[st] == 0 {
			continue
		}
		label := core.StatusLabel(st)
		if st == core.StatusWarning {
			label = "Unexpected"
		} else if st == core.StatusUnreachable {
			label = "Source failing"
		}
		d.Status = append(d.Status, Chip{Key: "status", Value: st, Label: label, Class: core.StatusClass(st), Count: counts[st], On: status == st})
	}
	for _, t := range tags {
		d.Tags = append(d.Tags, Chip{Key: "tag", Value: t, Label: t, Count: tagCounts[t], On: tag == t})
	}
	if tag != "" {
		d.Tags = append([]Chip{{Key: "tag", Value: "", Label: "Any tag"}}, d.Tags...)
	}
	for i := range d.Status {
		d.Status[i].Href = chipHref(r, "status", d.Status[i].Value)
	}
	for i := range d.Tags {
		d.Tags[i].Href = chipHref(r, "tag", d.Tags[i].Value)
	}
	now := s.now()
	for _, dm := range ds {
		row := domainRow{D: dm, Now: now}
		row.Hidden = status != "" && dm.Status() != status || tag != "" && !contains(dm.Tags, tag) || text != "" && !strings.Contains(row.Search(), text)
		if !row.Hidden {
			d.Shown++
		}
		d.Domains = append(d.Domains, row)
	}
	s.render(w, r, "domains", &Page{Title: "Domains", Nav: "domains", Data: d, Live: true})
}

type domainDetail struct {
	D         core.Domain
	Issuances []core.Issuance
	States    []Chip
	State     string
	Shown     int
	Findings  []core.Finding
	Alerts    []core.AlertEntry
	Channels  []string
	Source    string
	Interval  int
}

func (s *Server) domainDetail(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such domain.")
		return
	}
	dm, err := s.Core.Domain(r.Context(), id)
	if err != nil {
		s.failErr(w, r, err, "No such domain.")
		return
	}
	ctx := r.Context()
	st := info(r).settings
	d := domainDetail{D: dm, Source: ct.Label(st.CT.Source), Interval: st.CT.IntervalS, State: r.URL.Query().Get("state")}
	if d.Issuances, err = s.Core.Issuances(ctx, id, 0); err != nil {
		s.serverError(w, r, err)
		return
	}
	counts := map[string]int{}
	for _, i := range d.Issuances {
		counts[i.State]++
		if d.State == "" || i.State == d.State {
			d.Shown++
		}
	}
	d.States = append(d.States, Chip{Key: "state", Value: "", Label: "All", Count: len(d.Issuances), On: d.State == ""})
	for _, state := range core.IssuanceStates {
		if counts[state] > 0 {
			d.States = append(d.States, Chip{Key: "state", Value: state, Label: state, Class: core.Issuance{State: state}.StateClass(), Count: counts[state], On: d.State == state})
		}
	}
	for i := range d.States {
		d.States[i].Href = chipHref(r, "state", d.States[i].Value)
	}
	open, err := s.Core.Findings(ctx, core.FindingFilter{DomainID: id})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	done, err := s.Core.Findings(ctx, core.FindingFilter{DomainID: id, Resolved: true, Limit: 8})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.Findings = append(open, done...)
	chans, err := s.Core.Channels.List(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, c := range chans {
		if dm.AllChannels || hasInt(dm.ChannelIDs, c.ID) {
			d.Channels = append(d.Channels, c.Name)
		}
	}
	s.render(w, r, "domain", &Page{Title: dm.Name, Nav: "domains", Data: d, Live: true})
}

// domainForm is the add/edit form state.
type domainForm struct {
	D        core.Domain
	TagsText string
	Channels []notify.Channel
	Error    string
	Edit     bool
}

func (s *Server) domainNew(w http.ResponseWriter, r *http.Request) {
	chans, _ := s.Core.Channels.List(r.Context())
	s.render(w, r, "domain-form", &Page{Title: "Add domain", Nav: "domains", Data: domainForm{D: core.Domain{Subdomains: true, AllChannels: true, Enabled: true}, Channels: chans}})
}

func (s *Server) domainEdit(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such domain.")
		return
	}
	dm, err := s.Core.Domain(r.Context(), id)
	if err != nil {
		s.failErr(w, r, err, "No such domain.")
		return
	}
	chans, _ := s.Core.Channels.List(r.Context())
	s.render(w, r, "domain-form", &Page{Title: "Edit " + dm.Name, Nav: "domains", Data: domainForm{D: dm, TagsText: strings.Join(dm.Tags, ", "), Channels: chans, Edit: true}})
}

func (s *Server) domainSave(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = r.ParseForm()
	v := r.PostForm
	var dm core.Domain
	edit := r.PathValue("id") != ""
	if edit {
		id, err := pathID(r)
		if err != nil {
			s.fail(w, r, http.StatusNotFound, "No such domain.")
			return
		}
		if dm, err = s.Core.Domain(ctx, id); err != nil {
			s.failErr(w, r, err, "No such domain.")
			return
		}
	} else {
		dm.Enabled = true
	}
	dm.Name = strings.TrimSpace(v.Get("name"))
	dm.Subdomains = v.Get("subdomains") == "1"
	dm.Notes = strings.TrimSpace(strings.ReplaceAll(v.Get("notes"), "\r\n", "\n"))
	dm.AllChannels = v.Get("all_channels") == "1"
	dm.ChannelIDs = nil
	for _, c := range v["channel"] {
		if id, err := strconv.ParseInt(c, 10, 64); err == nil {
			dm.ChannelIDs = append(dm.ChannelIDs, id)
		}
	}
	var id int64
	tags, err := core.ParseTags(v.Get("tags"))
	if err == nil {
		dm.Tags = tags
		id, err = s.Core.SaveDomain(ctx, dm, user(r).Email)
	}
	if err != nil {
		msg, ok := usererr.Message(err)
		if !ok {
			s.serverError(w, r, err)
			return
		}
		chans, _ := s.Core.Channels.List(ctx)
		title := "Add domain"
		if edit {
			title = "Edit " + dm.Name
		}
		s.renderStatus(w, r, http.StatusBadRequest, "domain-form", &Page{Title: title, Nav: "domains", Data: domainForm{D: dm, TagsText: v.Get("tags"), Channels: chans, Error: msg, Edit: edit}})
		return
	}
	if edit {
		s.Core.Audit(ctx, user(r).Email, "domain.update", fmt.Sprintf("domain %d %s", id, dm.Name), fmt.Sprintf("subdomains=%v tags=%s", dm.Subdomains, strings.Join(dm.Tags, ",")))
		s.back(w, r, fmt.Sprintf("/domains/%d", id), "Domain saved.", "ok")
		return
	}
	s.Core.Audit(ctx, user(r).Email, "domain.create", fmt.Sprintf("domain %d %s", id, dm.Name), fmt.Sprintf("subdomains=%v tags=%s", dm.Subdomains, strings.Join(dm.Tags, ",")))
	go s.pollDomainSoon(id)
	s.back(w, r, fmt.Sprintf("/domains/%d", id), "Domain added; its first poll runs now.", "ok")
}

// pollDomainSoon polls a new watch right away, in the background, so the
// page fills within seconds instead of at the next housekeeping minute.
func (s *Server) pollDomainSoon(id int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.Core.PollDomain(ctx, id); err != nil {
		s.Log.Warn("ct poll", "domain_id", id, "err", err)
	}
}

func (s *Server) domainEnable(w http.ResponseWriter, r *http.Request) { s.setDomainEnabled(w, r, true) }
func (s *Server) domainDisable(w http.ResponseWriter, r *http.Request) {
	s.setDomainEnabled(w, r, false)
}

func (s *Server) setDomainEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such domain.")
		return
	}
	if err := s.Core.SetDomainEnabled(r.Context(), id, enabled); err != nil {
		s.failErr(w, r, err, "No such domain.")
		return
	}
	action, msg := "domain.disable", "Domain disabled; its open findings are closed and it is no longer polled."
	if enabled {
		action, msg = "domain.enable", "Domain enabled; it is polled again."
	}
	s.Core.Audit(r.Context(), user(r).Email, action, fmt.Sprintf("domain %d", id), "")
	dest := safeNext(r.PostFormValue("next"))
	if dest == "/" {
		dest = fmt.Sprintf("/domains/%d", id)
	}
	s.back(w, r, dest, msg, "ok")
}

func (s *Server) domainPoll(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such domain.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if err := s.Core.PollDomain(ctx, id); err != nil {
		if errors.Is(err, core.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, "No such domain.")
			return
		}
		s.back(w, r, fmt.Sprintf("/domains/%d", id), "The poll failed: "+err.Error(), "crit")
		return
	}
	s.back(w, r, fmt.Sprintf("/domains/%d", id), "Polled.", "ok")
}

type domainDeleteData struct {
	D      core.Domain
	Impact core.DeleteImpact
}

func (s *Server) domainDeletePage(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such domain.")
		return
	}
	dm, err := s.Core.Domain(r.Context(), id)
	if err != nil {
		s.failErr(w, r, err, "No such domain.")
		return
	}
	impact, err := s.Core.DomainDeleteImpact(r.Context(), id)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "domain-delete", &Page{Title: "Delete " + dm.Name, Nav: "domains", Data: domainDeleteData{D: dm, Impact: impact}})
}

func (s *Server) domainDelete(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such domain.")
		return
	}
	dm, err := s.Core.Domain(r.Context(), id)
	if err != nil {
		s.failErr(w, r, err, "No such domain.")
		return
	}
	if r.PostFormValue("confirm") != "yes" {
		s.back(w, r, fmt.Sprintf("/domains/%d/delete", id), "Confirm the deletion.", "crit")
		return
	}
	if err := s.Core.DeleteDomain(r.Context(), id); err != nil {
		s.failErr(w, r, err, "No such domain.")
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "domain.delete", fmt.Sprintf("domain %d %s", id, dm.Name), "")
	s.back(w, r, "/domains", "Domain "+dm.Name+" deleted.", "ok")
}

// issuanceUnexpected marks an issuance unexpected by hand.
func (s *Server) issuanceUnexpected(w http.ResponseWriter, r *http.Request) {
	iid, err := strconv.ParseInt(r.PathValue("iid"), 10, 64)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such issuance.")
		return
	}
	i, err := s.Core.MarkUnexpected(r.Context(), iid)
	if err != nil {
		s.failErr(w, r, err, "No such issuance.")
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "issuance.unexpected", fmt.Sprintf("issuance %d on %s", i.ID, i.DomainName), strings.Join(i.Names, ","))
	s.back(w, r, fmt.Sprintf("/domains/%d", i.DomainID), "Marked unexpected; a finding is open.", "ok")
}

// issuanceAck acknowledges an unexpected issuance.
func (s *Server) issuanceAck(w http.ResponseWriter, r *http.Request) {
	iid, err := strconv.ParseInt(r.PathValue("iid"), 10, 64)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such issuance.")
		return
	}
	comment := r.PostFormValue("comment")
	if len(comment) > 2000 {
		comment = comment[:2000]
	}
	u := user(r)
	i, err := s.Core.AcknowledgeIssuance(r.Context(), iid, u.DisplayName(), comment)
	if err != nil {
		s.failErr(w, r, err, "No such issuance.")
		return
	}
	s.Core.Audit(r.Context(), u.Email, "issuance.ack", fmt.Sprintf("issuance %d on %s", i.ID, i.DomainName), comment)
	s.back(w, r, fmt.Sprintf("/domains/%d", i.DomainID), "Acknowledged.", "ok")
}

// Settings › Certificate Transparency.

type ctData struct {
	C       config.CT
	HasKey  bool
	Error   string
	Sources []string
	Test    []ct.Issuance
	TestFor string
	TestErr string
}

func (s *Server) settingsCT(w http.ResponseWriter, r *http.Request) {
	st := info(r).settings
	s.settingsPage(w, r, http.StatusOK, "settings-ct", "ct", "Settings", ctData{C: st.CT, HasKey: st.CT.APIKey != "", Sources: ct.Sources})
}

func (s *Server) settingsCTSave(w http.ResponseWriter, r *http.Request) {
	cur := info(r).settings.CT
	c := config.CT{Source: r.PostFormValue("source"), APIKey: strings.TrimSpace(r.PostFormValue("api_key"))}
	mins, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("interval_min")))
	if err != nil {
		s.settingsPage(w, r, http.StatusBadRequest, "settings-ct", "ct", "Settings", ctData{C: c, HasKey: cur.APIKey != "", Sources: ct.Sources, Error: "Enter the poll interval in minutes."})
		return
	}
	c.IntervalS = mins * 60
	clear := r.PostFormValue("clear_key") == "1"
	if err := s.Settings.SaveCT(r.Context(), c, clear); err != nil {
		if msg, ok := s.formError(w, r, err); ok {
			s.settingsPage(w, r, http.StatusBadRequest, "settings-ct", "ct", "Settings", ctData{C: c, HasKey: cur.APIKey != "", Sources: ct.Sources, Error: msg})
		}
		return
	}
	detail := fmt.Sprintf("source=%s interval_s=%d", c.Source, c.IntervalS)
	if c.APIKey != "" {
		detail += " api_key=set"
	} else if clear {
		detail += " api_key=removed"
	}
	s.Core.Audit(r.Context(), user(r).Email, "settings.ct", "certificate transparency", detail)
	s.back(w, r, "/settings/ct", "Certificate Transparency settings saved.", "ok")
}

func (s *Server) settingsCTTest(w http.ResponseWriter, r *http.Request) {
	st := info(r).settings
	name := strings.TrimSpace(r.PostFormValue("domain"))
	d := ctData{C: st.CT, HasKey: st.CT.APIKey != "", Sources: ct.Sources, TestFor: name}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	found, err := s.Core.TestCTSource(ctx, st, name)
	if err != nil {
		d.TestErr = err.Error()
		if msg, ok := usererr.Message(err); ok {
			d.TestErr = msg
		}
	}
	d.Test = found
	s.settingsPage(w, r, http.StatusOK, "settings-ct", "ct", "Settings", d)
}
