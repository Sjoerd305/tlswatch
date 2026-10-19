package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// The resources of the public API: their JSON shapes, and the handlers
// apiRoutes lists.

// stamp is a Unix time that marshals as RFC 3339 in UTC, or null for 0.
type stamp int64

func (t stamp) MarshalJSON() ([]byte, error) {
	if t == 0 {
		return []byte("null"), nil
	}
	return json.Marshal(time.Unix(int64(t), 0).UTC().Format(time.RFC3339))
}

func idKey(id int64) string { return fmt.Sprintf("%020d", id) }

func optID(id int64) *int64 {
	if id == 0 {
		return nil
	}
	return &id
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ---------- Targets ----------

type apiTarget struct {
	ID             int64        `json:"id"`
	Name           string       `json:"name"`
	Host           string       `json:"host"`
	Port           int          `json:"port"`
	Protocol       string       `json:"protocol" doc:"tls, smtp, imap, pop3, ftp or postgres."`
	ServerName     string       `json:"server_name" doc:"The SNI name sent; empty for none."`
	Trust          string       `json:"trust" doc:"system, bundle or self-signed."`
	BundleID       *int64       `json:"bundle_id" doc:"The CA bundle, with trust bundle."`
	Bundle         string       `json:"bundle"`
	NodeID         *int64       `json:"node_id" doc:"The node the target is probed from; null for this server."`
	Node           string       `json:"node"`
	Renewal        string       `json:"renewal" doc:"auto, managed or manual."`
	RenewalManaged bool         `json:"renewal_managed" doc:"Whether the target counts as renewal-managed now; auto decides by the issuer."`
	ExpectedIssuer string       `json:"expected_issuer"`
	WarnDays       *int         `json:"warn_days" doc:"An override; null follows Settings › Defaults. The same for the fields up to remind_crit_s."`
	CritDays       *int         `json:"crit_days"`
	WarnPct        *int         `json:"warn_pct"`
	CritPct        *int         `json:"crit_pct"`
	RenewalPct     *int         `json:"renewal_pct"`
	IntervalS      *int         `json:"interval_s"`
	TimeoutS       *int         `json:"timeout_s"`
	Retries        *int         `json:"retries"`
	Debounce       *int         `json:"debounce"`
	RemindWarnS    *int         `json:"remind_warn_s" doc:"0: never."`
	RemindCritS    *int         `json:"remind_crit_s" doc:"0: never."`
	Effective      apiEffective `json:"effective" doc:"The values in force after the defaults."`
	FirstAddress   bool         `json:"first_address_only"`
	SkipConfig     bool         `json:"skip_config_test"`
	ChannelIDs     *[]int64     `json:"channel_ids" doc:"The channels alerts go to; null for every channel."`
	Tags           []string     `json:"tags"`
	Notes          string       `json:"notes"`
	Enabled        bool         `json:"enabled"`
	CreatedAt      stamp        `json:"created_at"`
	CreatedBy      string       `json:"created_by"`
	UpdatedAt      stamp        `json:"updated_at"`
	Status         string       `json:"status" doc:"pending, healthy, warning, changed, critical, unreachable or disabled."`
	DaysLeft       *int         `json:"days_left" doc:"Whole days until the earliest expiry on any address."`
	NotAfter       stamp        `json:"not_after"`
	Fingerprint    string       `json:"fingerprint" doc:"SHA-256 of the current leaf."`
	TLSVersion     string       `json:"tls_version"`
	Grade          string       `json:"grade" doc:"A, B, C or F; empty before the first full test."`
	GradeReasons   []string     `json:"grade_reasons"`
	PQ             string       `json:"pq" doc:"yes, no, or empty when untested."`
	Addresses      int          `json:"address_count"`
	LastCheck      stamp        `json:"last_check"`
	NextCheck      stamp        `json:"next_check"`
	LastError      string       `json:"last_error"`
}

type apiEffective struct {
	WarnDays    int `json:"warn_days"`
	CritDays    int `json:"crit_days"`
	WarnPct     int `json:"warn_pct"`
	CritPct     int `json:"crit_pct"`
	RenewalPct  int `json:"renewal_pct"`
	IntervalS   int `json:"interval_s"`
	TimeoutS    int `json:"timeout_s"`
	Retries     int `json:"retries"`
	Debounce    int `json:"debounce"`
	RemindWarnS int `json:"remind_warn_s"`
	RemindCritS int `json:"remind_crit_s"`
}

func toAPITarget(t core.Target, d config.Defaults, now time.Time) apiTarget {
	e := t.Effective(d)
	a := apiTarget{ID: t.ID, Name: t.Name, Host: t.Host, Port: t.Port, Protocol: string(t.Protocol), ServerName: t.ServerName, Trust: string(t.Trust),
		BundleID: optID(t.BundleID), Bundle: t.BundleName, NodeID: optID(t.NodeID), Node: t.NodeName, Renewal: "auto", RenewalManaged: t.RenewalManaged,
		ExpectedIssuer: t.ExpectedIssuer, WarnDays: t.WarnDays, CritDays: t.CritDays, WarnPct: t.WarnPct, CritPct: t.CritPct, RenewalPct: t.RenewalPct,
		IntervalS: t.IntervalS, TimeoutS: t.TimeoutS, Retries: t.Retries, Debounce: t.Debounce, RemindWarnS: t.RemindWarnS, RemindCritS: t.RemindCritS,
		Effective: apiEffective{WarnDays: e.Warn, CritDays: e.Crit, WarnPct: e.WarnPct, CritPct: e.CritPct, RenewalPct: e.RenewalPct, IntervalS: e.IntervalS,
			TimeoutS: e.TimeoutS, Retries: e.Retries, Debounce: e.Debounce, RemindWarnS: e.RemindWarnS, RemindCritS: e.RemindCritS},
		FirstAddress: !t.AllAddresses, SkipConfig: t.SkipLegacy, Tags: nonNil(t.Tags), Notes: t.Notes, Enabled: t.Enabled,
		CreatedAt: stamp(t.CreatedAt), CreatedBy: t.CreatedBy, UpdatedAt: stamp(t.UpdatedAt), Status: t.Status, DaysLeft: t.DaysLeft(now),
		NotAfter: stamp(t.NotAfter), Fingerprint: t.CurrentFP, TLSVersion: t.TLSVersion, Grade: t.Grade, GradeReasons: nonNil(t.GradeReasons), PQ: t.PQ,
		Addresses: t.AddressCount, LastCheck: stamp(t.LastCheck), NextCheck: stamp(t.NextCheck), LastError: t.LastError}
	if t.RenewalSet {
		a.Renewal = "manual"
		if t.RenewalManaged {
			a.Renewal = "managed"
		}
	}
	if !t.AllChannels {
		ids := append([]int64{}, t.ChannelIDs...)
		a.ChannelIDs = &ids
	}
	return a
}

// apiTargetInput is the body of adding or changing a target. To add, host
// is required and everything else has the Add target form's default; to
// change, the fields sent change and the rest stay.
type apiTargetInput struct {
	Name           *string   `json:"name,omitempty" doc:"Defaults to the host."`
	Host           *string   `json:"host,omitempty" doc:"A DNS name or IP address; required to add."`
	Port           *int      `json:"port,omitempty" doc:"Defaults to the protocol's port."`
	Protocol       *string   `json:"protocol,omitempty" doc:"tls (the default), smtp, imap, pop3, ftp or postgres."`
	ServerName     *string   `json:"server_name,omitempty" doc:"Defaults to a DNS host; follows the host when it changes along."`
	Trust          *string   `json:"trust,omitempty" doc:"system (the default), bundle or self-signed."`
	BundleID       *int64    `json:"bundle_id,omitempty"`
	NodeID         *int64    `json:"node_id,omitempty" doc:"null or 0: this server."`
	Renewal        *string   `json:"renewal,omitempty" doc:"auto (the default), managed or manual."`
	ExpectedIssuer *string   `json:"expected_issuer,omitempty"`
	WarnDays       *int      `json:"warn_days,omitempty" doc:"null returns this and the other overrides to the default."`
	CritDays       *int      `json:"crit_days,omitempty"`
	WarnPct        *int      `json:"warn_pct,omitempty"`
	CritPct        *int      `json:"crit_pct,omitempty"`
	RenewalPct     *int      `json:"renewal_pct,omitempty"`
	IntervalS      *int      `json:"interval_s,omitempty"`
	TimeoutS       *int      `json:"timeout_s,omitempty"`
	Retries        *int      `json:"retries,omitempty"`
	Debounce       *int      `json:"debounce,omitempty"`
	RemindWarnS    *int      `json:"remind_warn_s,omitempty"`
	RemindCritS    *int      `json:"remind_crit_s,omitempty"`
	FirstAddress   *bool     `json:"first_address_only,omitempty"`
	SkipConfig     *bool     `json:"skip_config_test,omitempty"`
	ChannelIDs     *[]int64  `json:"channel_ids,omitempty" doc:"null: every channel."`
	Tags           *[]string `json:"tags,omitempty"`
	Notes          *string   `json:"notes,omitempty"`
	Enabled        *bool     `json:"enabled,omitempty"`
}

// targetNullable are the fields of apiTargetInput that take null: it
// returns them to their default.
var targetNullable = map[string]bool{"name": true, "port": true, "server_name": true, "bundle_id": true, "node_id": true, "expected_issuer": true,
	"warn_days": true, "crit_days": true, "warn_pct": true, "crit_pct": true, "renewal_pct": true, "interval_s": true, "timeout_s": true,
	"retries": true, "debounce": true, "remind_warn_s": true, "remind_crit_s": true, "channel_ids": true, "tags": true, "notes": true}

// apiFieldName maps the form fields Validate reports to the API's.
func apiFieldName(k string) string {
	switch k {
	case "servername":
		return "server_name"
	case "trust_mode":
		return "trust"
	}
	return k
}

func setInt(raw map[string]json.RawMessage, key string, v *int, dst **int) {
	if _, ok := raw[key]; ok {
		*dst = v
	}
}

// applyTargetInput writes the fields of in that raw holds onto t and
// validates the result; the problems come back by API field name.
func (s *Server) applyTargetInput(r *http.Request, t *core.Target, in apiTargetInput, raw map[string]json.RawMessage, adding bool) (map[string]string, error) {
	ctx := r.Context()
	errs := map[string]string{}
	for k, v := range raw {
		if isNull(v) && !targetNullable[k] {
			errs[k] = "cannot be null"
		}
	}
	oldHost, oldSNI := t.Host, t.ServerName
	if in.Host != nil {
		t.Host = strings.TrimSpace(*in.Host)
	}
	if adding && t.Host == "" {
		errs["host"] = "required"
	}
	if in.Protocol != nil {
		t.Protocol = probe.Protocol(strings.ToLower(strings.TrimSpace(*in.Protocol)))
	}
	if _, ok := raw["port"]; ok || adding {
		t.Port = probe.DefaultPort(t.Protocol)
		if in.Port != nil {
			t.Port = *in.Port
		}
	}
	sniFollows := func() {
		t.ServerName = ""
		if !isIP(t.Host) {
			t.ServerName = strings.TrimSuffix(strings.ToLower(t.Host), ".")
		}
	}
	if _, ok := raw["server_name"]; ok {
		if in.ServerName == nil || strings.TrimSpace(*in.ServerName) == "" {
			sniFollows()
		} else {
			t.ServerName = strings.TrimSpace(*in.ServerName)
		}
	} else if adding || in.Host != nil && oldSNI == oldHost {
		sniFollows()
	}
	if _, ok := raw["name"]; ok {
		t.Name = ""
		if in.Name != nil {
			t.Name = *in.Name
		}
	}
	if in.Trust != nil {
		t.Trust = probe.TrustMode(strings.TrimSpace(*in.Trust))
	}
	if _, ok := raw["bundle_id"]; ok {
		t.BundleID = 0
		if in.BundleID != nil {
			t.BundleID = *in.BundleID
		}
	}
	if _, ok := raw["node_id"]; ok {
		t.NodeID = 0
		if in.NodeID != nil {
			t.NodeID = *in.NodeID
		}
	}
	if in.Renewal != nil {
		switch *in.Renewal {
		case "auto":
			t.RenewalSet = false
		case "managed":
			t.RenewalSet, t.RenewalManaged = true, true
		case "manual":
			t.RenewalSet, t.RenewalManaged = true, false
		default:
			errs["renewal"] = "auto, managed or manual"
		}
	}
	if _, ok := raw["expected_issuer"]; ok {
		t.ExpectedIssuer = ""
		if in.ExpectedIssuer != nil {
			t.ExpectedIssuer = strings.TrimSpace(*in.ExpectedIssuer)
		}
	}
	setInt(raw, "warn_days", in.WarnDays, &t.WarnDays)
	setInt(raw, "crit_days", in.CritDays, &t.CritDays)
	setInt(raw, "warn_pct", in.WarnPct, &t.WarnPct)
	setInt(raw, "crit_pct", in.CritPct, &t.CritPct)
	setInt(raw, "renewal_pct", in.RenewalPct, &t.RenewalPct)
	setInt(raw, "interval_s", in.IntervalS, &t.IntervalS)
	setInt(raw, "timeout_s", in.TimeoutS, &t.TimeoutS)
	setInt(raw, "retries", in.Retries, &t.Retries)
	setInt(raw, "debounce", in.Debounce, &t.Debounce)
	setInt(raw, "remind_warn_s", in.RemindWarnS, &t.RemindWarnS)
	setInt(raw, "remind_crit_s", in.RemindCritS, &t.RemindCritS)
	if in.FirstAddress != nil {
		t.AllAddresses = !*in.FirstAddress
	}
	if in.SkipConfig != nil {
		t.SkipLegacy = *in.SkipConfig
	}
	if _, ok := raw["channel_ids"]; ok {
		t.AllChannels, t.ChannelIDs = in.ChannelIDs == nil, nil
		if in.ChannelIDs != nil {
			t.ChannelIDs = *in.ChannelIDs
			if msg, err := s.unknownChannel(ctx, t.ChannelIDs); err != nil {
				return nil, err
			} else if msg != "" {
				errs["channel_ids"] = msg
			}
		}
	}
	if _, ok := raw["tags"]; ok {
		t.Tags = nil
		if in.Tags != nil {
			tags, err := core.ParseTags(strings.Join(*in.Tags, ","))
			if err != nil {
				errs["tags"] = err.Error()
			}
			t.Tags = tags
		}
	}
	if _, ok := raw["notes"]; ok {
		t.Notes = ""
		if in.Notes != nil {
			t.Notes = strings.TrimSpace(strings.ReplaceAll(*in.Notes, "\r\n", "\n"))
		}
	}
	if len(errs) == 0 {
		for k, e := range t.Validate(info(r).settings) {
			errs[apiFieldName(k)] = e
		}
	}
	return errs, nil
}

// unknownChannel names a channel id that does not exist, or returns "".
func (s *Server) unknownChannel(ctx context.Context, ids []int64) (string, error) {
	chans, err := s.Core.Channels.List(ctx)
	if err != nil {
		return "", err
	}
	for _, id := range ids {
		if !hasInt(channelIDs(chans), id) {
			return fmt.Sprintf("there is no channel %d", id), nil
		}
	}
	return "", nil
}

func channelIDs(cs []notify.Channel) []int64 {
	ids := make([]int64, 0, len(cs))
	for _, c := range cs {
		ids = append(ids, c.ID)
	}
	return ids
}

func (s *Server) apiTargets(w http.ResponseWriter, r *http.Request) {
	ts, err := s.Core.Targets(r.Context())
	if err == nil {
		err = s.Core.TargetChannels(r.Context(), ts)
	}
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	f := targetFilterFrom(r.URL.Query())
	var out []core.Target
	for _, t := range ts {
		if f.matches(t, "") {
			out = append(out, t)
		}
	}
	d, now := info(r).settings.Defaults, s.now()
	writePage(w, r, out, func(t core.Target) string { return idKey(t.ID) }, func(t core.Target) any { return toAPITarget(t, d, now) })
}

func (s *Server) apiPathID(w http.ResponseWriter, r *http.Request, what string) (int64, bool) {
	id, err := pathID(r)
	if err != nil {
		apiFail(w, http.StatusNotFound, "not_found", "No such "+what+".")
		return 0, false
	}
	return id, true
}

func (s *Server) writeTarget(w http.ResponseWriter, r *http.Request, status int, id int64) {
	t, err := s.Core.Target(r.Context(), id)
	if err != nil {
		s.apiFailErr(w, r, err, "No such target.")
		return
	}
	writeJSON(w, status, toAPITarget(t, info(r).settings.Defaults, s.now()))
}

func (s *Server) apiTargetGet(w http.ResponseWriter, r *http.Request) {
	if id, ok := s.apiPathID(w, r, "target"); ok {
		s.writeTarget(w, r, http.StatusOK, id)
	}
}

func (s *Server) apiTargetCreate(w http.ResponseWriter, r *http.Request) {
	var in apiTargetInput
	raw, ok := readBody(w, r, &in)
	if !ok {
		return
	}
	t := core.Target{Protocol: probe.TLS, Trust: probe.TrustSystem, AllAddresses: true, AllChannels: true, Enabled: true}
	errs, err := s.applyTargetInput(r, &t, in, raw, true)
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	if in.Enabled != nil {
		t.Enabled = *in.Enabled
	}
	if len(errs) > 0 {
		apiInvalid(w, errs)
		return
	}
	sess := apiSession(r)
	id, err := s.Core.SaveTarget(r.Context(), t, sess.User.Email)
	if errors.Is(err, core.ErrTargetExists) {
		apiFail(w, http.StatusConflict, "conflict", err.Error())
		return
	}
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	s.apiAudit(r, "target.create", fmt.Sprintf("target %d %s", id, t.HostPort()), targetAuditDetails(t))
	s.Sched.Reload()
	if t.Enabled {
		s.Sched.CheckSoon(id)
	}
	w.Header().Set("Location", fmt.Sprintf("/api/v2/targets/%d", id))
	s.writeTarget(w, r, http.StatusCreated, id)
}

func (s *Server) apiTargetUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.apiPathID(w, r, "target")
	if !ok {
		return
	}
	t, err := s.Core.Target(r.Context(), id)
	if err != nil {
		s.apiFailErr(w, r, err, "No such target.")
		return
	}
	var in apiTargetInput
	raw, ok := readBody(w, r, &in)
	if !ok {
		return
	}
	errs, err := s.applyTargetInput(r, &t, in, raw, false)
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	if len(errs) > 0 {
		apiInvalid(w, errs)
		return
	}
	if _, err := s.Core.SaveTargets(r.Context(), []core.Target{t}, in.Enabled, apiSession(r).User.Email); err != nil {
		if errors.Is(err, core.ErrTargetExists) {
			apiFail(w, http.StatusConflict, "conflict", err.Error())
			return
		}
		s.apiFailErr(w, r, err, "No such target.")
		return
	}
	changed := make([]string, 0, len(raw))
	for k := range raw {
		changed = append(changed, k)
	}
	sort.Strings(changed)
	s.apiAudit(r, "target.update", fmt.Sprintf("target %d %s", id, t.HostPort()), "changed="+strings.Join(changed, ","))
	s.Sched.Reload()
	if in.Enabled != nil && *in.Enabled || in.Enabled == nil && t.Enabled {
		s.Sched.CheckSoon(id)
	}
	s.writeTarget(w, r, http.StatusOK, id)
}

func (s *Server) apiTargetDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := s.apiPathID(w, r, "target")
	if !ok {
		return
	}
	t, err := s.Core.Target(r.Context(), id)
	if err != nil {
		s.apiFailErr(w, r, err, "No such target.")
		return
	}
	if err := s.Core.DeleteTarget(r.Context(), id); err != nil {
		s.apiFailErr(w, r, err, "No such target.")
		return
	}
	s.apiAudit(r, "target.delete", fmt.Sprintf("target %d %s", id, t.HostPort()), "name="+t.Name)
	s.Sched.Reload()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiTargetCheckNow(w http.ResponseWriter, r *http.Request) {
	id, ok := s.apiPathID(w, r, "target")
	if !ok {
		return
	}
	t, err := s.Sched.CheckNow(r.Context(), id)
	switch {
	case errors.Is(err, core.ErrNodeOffline):
		apiFail(w, http.StatusConflict, "node_offline", "The node this target is probed from is offline; the check runs as soon as it polls again.")
		return
	case errors.Is(err, core.ErrNodeNoResult):
		apiFail(w, http.StatusGatewayTimeout, "timeout", "The node did not return a result in time.")
		return
	case err != nil:
		s.apiFailErr(w, r, err, "No such target.")
		return
	}
	s.apiAudit(r, "target.check", fmt.Sprintf("target %d %s", id, t.HostPort()), "")
	writeJSON(w, http.StatusOK, toAPITarget(t, info(r).settings.Defaults, s.now()))
}

// ---------- Certificates ----------

type apiCertificate struct {
	Fingerprint string      `json:"fingerprint" doc:"SHA-256 of the DER, lower-case hex."`
	Subject     string      `json:"subject"`
	SubjectCN   string      `json:"subject_cn"`
	Issuer      string      `json:"issuer"`
	IssuerCN    string      `json:"issuer_cn"`
	IssuerOrg   string      `json:"issuer_org"`
	Serial      string      `json:"serial"`
	NotBefore   stamp       `json:"not_before"`
	NotAfter    stamp       `json:"not_after"`
	DaysLeft    int         `json:"days_left"`
	Names       []string    `json:"names" doc:"The subject alternative names."`
	Key         string      `json:"key" doc:"Such as RSA 2048 or ECDSA P-256."`
	KeyType     string      `json:"key_type"`
	KeyBits     int         `json:"key_bits"`
	SigAlg      string      `json:"signature_algorithm"`
	SelfSigned  bool        `json:"self_signed"`
	Distrusted  bool        `json:"distrusted" doc:"An open distrusted_ca finding names it."`
	FirstSeen   stamp       `json:"first_seen"`
	LastSeen    stamp       `json:"last_seen"`
	Served      []apiServed `json:"served" doc:"Where it is served now: the addresses of each target's latest check."`
	PEM         string      `json:"pem,omitempty" doc:"Only when getting one certificate."`
}

type apiServed struct {
	TargetID   int64  `json:"target_id"`
	TargetName string `json:"target_name"`
	Endpoint   string `json:"endpoint"`
	Address    string `json:"address"`
	Current    bool   `json:"current" doc:"It is the target's current certificate."`
	CheckedAt  stamp  `json:"checked_at"`
}

func toAPICertificate(it core.InventoryItem, now time.Time) apiCertificate {
	c := it.Certificate
	a := apiCertificate{Fingerprint: c.Fingerprint, Subject: c.Subject, SubjectCN: c.SubjectCN, Issuer: c.Issuer, IssuerCN: c.IssuerCN, IssuerOrg: c.IssuerOrg,
		Serial: c.Serial, NotBefore: stamp(c.NotBefore), NotAfter: stamp(c.NotAfter), DaysLeft: check.DaysLeft(time.Unix(c.NotAfter, 0), now),
		Names: nonNil(c.SANs), Key: c.KeyDesc(), KeyType: c.KeyType, KeyBits: c.KeyBits, SigAlg: c.SigAlg, SelfSigned: c.SelfSigned,
		Distrusted: it.Distrusted, FirstSeen: stamp(c.FirstSeen), LastSeen: stamp(c.LastSeen), Served: []apiServed{}, PEM: c.PEM}
	for _, sv := range it.Served {
		a.Served = append(a.Served, apiServed{TargetID: sv.TargetID, TargetName: sv.TargetName, Endpoint: sv.HostPort, Address: sv.Address, Current: sv.Current, CheckedAt: stamp(sv.CheckedAt)})
	}
	return a
}

func (s *Server) apiCertificates(w http.ResponseWriter, r *http.Request) {
	inv, err := s.Core.Inventory(r.Context())
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	f := certFilterFrom(r.URL.Query())
	now := s.now()
	var out []core.InventoryItem
	for _, it := range inv {
		if len(it.Served) == 0 && !f.showAll {
			continue
		}
		if f.matches(newCertRow(it, info(r).settings.Defaults.Manual, now)) {
			out = append(out, it)
		}
	}
	writePage(w, r, out, func(it core.InventoryItem) string { return it.Fingerprint }, func(it core.InventoryItem) any { return toAPICertificate(it, now) })
}

func (s *Server) apiCertificateGet(w http.ResponseWriter, r *http.Request) {
	fp := strings.ToLower(r.PathValue("fp"))
	c, err := s.Core.Certificate(r.Context(), fp)
	if err != nil {
		s.apiFailErr(w, r, err, "No such certificate.")
		return
	}
	it := core.InventoryItem{Certificate: c}
	if it.Served, err = s.Core.ServedOn(r.Context(), fp); err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	n, err := s.Core.OpenFindings(r.Context(), check.DistrustedCA, fp)
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	it.Distrusted = n > 0
	writeJSON(w, http.StatusOK, toAPICertificate(it, s.now()))
}

// ---------- Findings ----------

type apiFinding struct {
	ID           int64     `json:"id"`
	TargetID     *int64    `json:"target_id" doc:"Set for a finding on a target."`
	DomainID     *int64    `json:"domain_id" doc:"Set for a finding on a domain watch."`
	NodeID       *int64    `json:"node_id" doc:"Set for a finding on a node (node_offline)."`
	Subject      string    `json:"subject" doc:"The name of the target, watch or node."`
	Endpoint     string    `json:"endpoint" doc:"host:port of a target, the domain, or the node's hostname."`
	Kind         string    `json:"kind"`
	Severity     string    `json:"severity" doc:"critical, warning or info."`
	OpenedAt     stamp     `json:"opened_at"`
	ResolvedAt   stamp     `json:"resolved_at" doc:"null while open."`
	Details      string    `json:"details"`
	Fingerprint  string    `json:"fingerprint" doc:"The certificate the finding is about, or for a domain watch the issuance id."`
	DaysLeft     *int      `json:"days_left"`
	Acknowledged *apiAcked `json:"acknowledged" doc:"null when not acknowledged, or the acknowledgement has run out."`
	LastAlertAt  stamp     `json:"last_alert_at"`
}

type apiAcked struct {
	By      string `json:"by"`
	At      stamp  `json:"at"`
	Until   stamp  `json:"until" doc:"null: until the finding resolves."`
	Comment string `json:"comment"`
}

func toAPIFinding(f core.Finding, now time.Time) apiFinding {
	a := apiFinding{ID: f.ID, TargetID: optID(f.TargetID), DomainID: optID(f.DomainID), NodeID: optID(f.NodeID), Subject: f.TargetName, Endpoint: f.HostPort(),
		Kind: string(f.Kind), Severity: string(f.Severity), OpenedAt: stamp(f.OpenedAt), ResolvedAt: stamp(f.ResolvedAt), Details: f.Details,
		Fingerprint: f.Fingerprint, DaysLeft: f.DaysLeft, LastAlertAt: stamp(f.LastAlertAt)}
	if f.Acked(now) || f.AckAt > 0 && !f.Open() {
		a.Acknowledged = &apiAcked{By: f.AckBy, At: stamp(f.AckAt), Until: stamp(f.AckUntil), Comment: f.AckComment}
	}
	return a
}

func (s *Server) apiFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ff := core.FindingFilter{}
	switch q.Get("state") {
	case "", "open":
	case "resolved":
		ff.Resolved = true
		ff.Since = s.now().Add(-time.Duration(info(r).settings.Defaults.RetentionDays) * 24 * time.Hour).Unix()
	default:
		apiFail(w, http.StatusBadRequest, "invalid", "state is open or resolved")
		return
	}
	for _, p := range []struct {
		name string
		dst  *int64
	}{{"target_id", &ff.TargetID}, {"domain_id", &ff.DomainID}} {
		if v := q.Get(p.name); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n <= 0 {
				apiFail(w, http.StatusBadRequest, "invalid", p.name+" is an id")
				return
			}
			*p.dst = n
		}
	}
	list, err := s.Core.Findings(r.Context(), ff)
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	sev, kind := q.Get("severity"), q.Get("kind")
	var out []core.Finding
	for _, f := range list {
		if (sev == "" || string(f.Severity) == sev) && (kind == "" || string(f.Kind) == kind) {
			out = append(out, f)
		}
	}
	now := s.now()
	writePage(w, r, out, func(f core.Finding) string { return idKey(f.ID) }, func(f core.Finding) any { return toAPIFinding(f, now) })
}

func (s *Server) apiFindingGet(w http.ResponseWriter, r *http.Request) {
	id, ok := s.apiPathID(w, r, "finding")
	if !ok {
		return
	}
	f, err := s.Core.Finding(r.Context(), id)
	if err != nil {
		s.apiFailErr(w, r, err, "No such finding.")
		return
	}
	writeJSON(w, http.StatusOK, toAPIFinding(f, s.now()))
}

// apiAckInput is the body of an acknowledgement.
type apiAckInput struct {
	Until   string `json:"until,omitempty" doc:"YYYY-MM-DD (through the end of that day in the instance's time zone) or an RFC 3339 time; left out, until the finding resolves."`
	Comment string `json:"comment,omitempty" doc:"Up to 2000 characters."`
}

func (s *Server) apiFindingAck(w http.ResponseWriter, r *http.Request) {
	id, ok := s.apiPathID(w, r, "finding")
	if !ok {
		return
	}
	var in apiAckInput
	if _, ok := readBody(w, r, &in); !ok {
		return
	}
	var until time.Time
	if v := strings.TrimSpace(in.Until); v != "" {
		if day, err := time.ParseInLocation("2006-01-02", v, info(r).settings.Location()); err == nil {
			until = day.Add(24*time.Hour - time.Second)
		} else if t, err := time.Parse(time.RFC3339, v); err == nil {
			until = t
		} else {
			apiInvalid(w, map[string]string{"until": "YYYY-MM-DD or an RFC 3339 time"})
			return
		}
	}
	if len(in.Comment) > 2000 {
		apiInvalid(w, map[string]string{"comment": "limited to 2000 characters"})
		return
	}
	f, err := s.Core.Acknowledge(r.Context(), id, actor(r), until, in.Comment)
	if msg, isUser := usererr.Message(err); isUser {
		apiFail(w, http.StatusConflict, "conflict", msg)
		return
	}
	if err != nil {
		s.apiFailErr(w, r, err, "No such finding.")
		return
	}
	s.apiAudit(r, "finding.ack", fmt.Sprintf("finding %d %s on %s", id, f.Kind, f.HostPort()), ackDetail(until, in.Comment))
	s.Sched.Reload()
	writeJSON(w, http.StatusOK, toAPIFinding(f, s.now()))
}

// ---------- Domain watches and issuances ----------

type apiDomain struct {
	ID           int64    `json:"id"`
	Name         string   `json:"name"`
	Subdomains   bool     `json:"subdomains"`
	ChannelIDs   *[]int64 `json:"channel_ids" doc:"null: every channel."`
	Tags         []string `json:"tags"`
	Notes        string   `json:"notes"`
	Enabled      bool     `json:"enabled"`
	Status       string   `json:"status" doc:"warning (an unexpected issuance or CAA violation), unreachable (the source fails), healthy, pending or disabled."`
	PolledAt     stamp    `json:"polled_at"`
	PolledOK     stamp    `json:"polled_ok"`
	PollError    string   `json:"poll_error"`
	Recent       int      `json:"recent_issuances" doc:"Issuances first seen in the last 30 days."`
	OpenFindings int      `json:"open_findings"`
	CAACheckedAt stamp    `json:"caa_checked_at"`
	CAAError     string   `json:"caa_error"`
	CreatedAt    stamp    `json:"created_at"`
	CreatedBy    string   `json:"created_by"`
	UpdatedAt    stamp    `json:"updated_at"`
}

func toAPIDomain(d core.Domain) apiDomain {
	a := apiDomain{ID: d.ID, Name: d.Name, Subdomains: d.Subdomains, Tags: nonNil(d.Tags), Notes: d.Notes, Enabled: d.Enabled, Status: d.Status(),
		PolledAt: stamp(d.PolledAt), PolledOK: stamp(d.PolledOK), PollError: d.PollError, Recent: d.Recent, OpenFindings: d.OpenFindings,
		CAACheckedAt: stamp(d.CAACheckedAt), CAAError: d.CAAError, CreatedAt: stamp(d.CreatedAt), CreatedBy: d.CreatedBy, UpdatedAt: stamp(d.UpdatedAt)}
	if !d.AllChannels {
		ids := append([]int64{}, d.ChannelIDs...)
		a.ChannelIDs = &ids
	}
	return a
}

// apiDomainInput is the body of adding or changing a domain watch.
type apiDomainInput struct {
	Name       *string   `json:"name,omitempty" doc:"Required to add. Changing it starts the watch over."`
	Subdomains *bool     `json:"subdomains,omitempty" doc:"Watch the names below it too; true when adding."`
	ChannelIDs *[]int64  `json:"channel_ids,omitempty" doc:"null: every channel."`
	Tags       *[]string `json:"tags,omitempty"`
	Notes      *string   `json:"notes,omitempty"`
	Enabled    *bool     `json:"enabled,omitempty"`
}

func (s *Server) applyDomainInput(ctx context.Context, d *core.Domain, in apiDomainInput, raw map[string]json.RawMessage) (map[string]string, error) {
	errs := map[string]string{}
	for k, v := range raw {
		if isNull(v) && k != "channel_ids" && k != "tags" && k != "notes" {
			errs[k] = "cannot be null"
		}
	}
	if in.Name != nil {
		d.Name = strings.TrimSpace(*in.Name)
	}
	if in.Subdomains != nil {
		d.Subdomains = *in.Subdomains
	}
	if _, ok := raw["channel_ids"]; ok {
		d.AllChannels, d.ChannelIDs = in.ChannelIDs == nil, nil
		if in.ChannelIDs != nil {
			d.ChannelIDs = *in.ChannelIDs
			if msg, err := s.unknownChannel(ctx, d.ChannelIDs); err != nil {
				return nil, err
			} else if msg != "" {
				errs["channel_ids"] = msg
			}
		}
	}
	if _, ok := raw["tags"]; ok {
		d.Tags = nil
		if in.Tags != nil {
			tags, err := core.ParseTags(strings.Join(*in.Tags, ","))
			if err != nil {
				errs["tags"] = err.Error()
			}
			d.Tags = tags
		}
	}
	if _, ok := raw["notes"]; ok {
		d.Notes = ""
		if in.Notes != nil {
			d.Notes = strings.TrimSpace(strings.ReplaceAll(*in.Notes, "\r\n", "\n"))
		}
	}
	return errs, nil
}

func (s *Server) apiDomains(w http.ResponseWriter, r *http.Request) {
	ds, err := s.Core.Domains(r.Context())
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	if err := s.Core.DomainChannels(r.Context(), ds); err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	q := r.URL.Query()
	status, tag, text := q.Get("status"), q.Get("tag"), strings.ToLower(strings.TrimSpace(q.Get("q")))
	var out []core.Domain
	for _, d := range ds {
		if (status == "" || d.Status() == status) && (tag == "" || contains(d.Tags, tag)) && (text == "" || strings.Contains(domainRow{D: d}.Search(), text)) {
			out = append(out, d)
		}
	}
	writePage(w, r, out, func(d core.Domain) string { return idKey(d.ID) }, func(d core.Domain) any { return toAPIDomain(d) })
}

func (s *Server) writeDomain(w http.ResponseWriter, r *http.Request, status int, id int64) {
	d, err := s.Core.Domain(r.Context(), id)
	if err != nil {
		s.apiFailErr(w, r, err, "No such domain.")
		return
	}
	writeJSON(w, status, toAPIDomain(d))
}

func (s *Server) apiDomainGet(w http.ResponseWriter, r *http.Request) {
	if id, ok := s.apiPathID(w, r, "domain"); ok {
		s.writeDomain(w, r, http.StatusOK, id)
	}
}

func (s *Server) apiDomainCreate(w http.ResponseWriter, r *http.Request) {
	var in apiDomainInput
	raw, ok := readBody(w, r, &in)
	if !ok {
		return
	}
	d := core.Domain{Subdomains: true, AllChannels: true, Enabled: true}
	errs, err := s.applyDomainInput(r.Context(), &d, in, raw)
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	if in.Name == nil {
		errs["name"] = "required"
	}
	if in.Enabled != nil {
		d.Enabled = *in.Enabled
	}
	if len(errs) > 0 {
		apiInvalid(w, errs)
		return
	}
	id, err := s.Core.SaveDomain(r.Context(), d, apiSession(r).User.Email)
	if errors.Is(err, core.ErrDomainExists) {
		apiFail(w, http.StatusConflict, "conflict", err.Error())
		return
	}
	if msg, isUser := usererr.Message(err); isUser {
		apiInvalid(w, map[string]string{"name": msg})
		return
	}
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	s.apiAudit(r, "domain.create", fmt.Sprintf("domain %d %s", id, d.Name), fmt.Sprintf("subdomains=%v tags=%s", d.Subdomains, strings.Join(d.Tags, ",")))
	if d.Enabled {
		go s.pollDomainSoon(id)
	}
	w.Header().Set("Location", fmt.Sprintf("/api/v2/domains/%d", id))
	s.writeDomain(w, r, http.StatusCreated, id)
}

func (s *Server) apiDomainUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.apiPathID(w, r, "domain")
	if !ok {
		return
	}
	d, err := s.Core.Domain(r.Context(), id)
	if err != nil {
		s.apiFailErr(w, r, err, "No such domain.")
		return
	}
	var in apiDomainInput
	raw, ok := readBody(w, r, &in)
	if !ok {
		return
	}
	errs, err := s.applyDomainInput(r.Context(), &d, in, raw)
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	if len(errs) > 0 {
		apiInvalid(w, errs)
		return
	}
	if _, err := s.Core.SaveDomain(r.Context(), d, apiSession(r).User.Email); err != nil {
		if errors.Is(err, core.ErrDomainExists) {
			apiFail(w, http.StatusConflict, "conflict", err.Error())
			return
		}
		if msg, isUser := usererr.Message(err); isUser {
			apiInvalid(w, map[string]string{"name": msg})
			return
		}
		s.apiFailErr(w, r, err, "No such domain.")
		return
	}
	// Enabling and disabling go through SetDomainEnabled, which reopens
	// what disabling closed.
	if in.Enabled != nil && *in.Enabled != d.Enabled {
		if err := s.Core.SetDomainEnabled(r.Context(), id, *in.Enabled); err != nil {
			s.apiFailErr(w, r, err, "No such domain.")
			return
		}
	}
	changed := make([]string, 0, len(raw))
	for k := range raw {
		changed = append(changed, k)
	}
	sort.Strings(changed)
	s.apiAudit(r, "domain.update", fmt.Sprintf("domain %d %s", id, d.Name), "changed="+strings.Join(changed, ","))
	s.writeDomain(w, r, http.StatusOK, id)
}

func (s *Server) apiDomainDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := s.apiPathID(w, r, "domain")
	if !ok {
		return
	}
	d, err := s.Core.Domain(r.Context(), id)
	if err != nil {
		s.apiFailErr(w, r, err, "No such domain.")
		return
	}
	if err := s.Core.DeleteDomain(r.Context(), id); err != nil {
		s.apiFailErr(w, r, err, "No such domain.")
		return
	}
	s.apiAudit(r, "domain.delete", fmt.Sprintf("domain %d %s", id, d.Name), "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiDomainPoll(w http.ResponseWriter, r *http.Request) {
	id, ok := s.apiPathID(w, r, "domain")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if err := s.Core.PollDomain(ctx, id); err != nil {
		if errors.Is(err, core.ErrNotFound) {
			apiFail(w, http.StatusNotFound, "not_found", "No such domain.")
			return
		}
		apiFail(w, http.StatusBadGateway, "poll_failed", "The poll failed: "+err.Error())
		return
	}
	s.writeDomain(w, r, http.StatusOK, id)
}

type apiIssuance struct {
	ID           int64     `json:"id"`
	DomainID     int64     `json:"domain_id"`
	Domain       string    `json:"domain"`
	State        string    `json:"state" doc:"known (a target serves it), pending (waiting to be served), unexpected or acknowledged."`
	Names        []string  `json:"names"`
	IssuerCN     string    `json:"issuer_cn"`
	IssuerOrg    string    `json:"issuer_org"`
	Serial       string    `json:"serial"`
	NotBefore    stamp     `json:"not_before"`
	NotAfter     stamp     `json:"not_after"`
	LogURL       string    `json:"log_url"`
	FirstSeen    stamp     `json:"first_seen"`
	Fingerprint  string    `json:"fingerprint" doc:"The served certificate it matched, if any."`
	TargetID     *int64    `json:"target_id" doc:"A target serving it."`
	CAA          string    `json:"caa" doc:"The CAA verdict; empty when not judged."`
	CAADetail    string    `json:"caa_detail"`
	Acknowledged *apiAcked `json:"acknowledged"`
}

func toAPIIssuance(i core.Issuance) apiIssuance {
	a := apiIssuance{ID: i.ID, DomainID: i.DomainID, Domain: i.DomainName, State: i.State, Names: nonNil(i.Names), IssuerCN: i.IssuerCN, IssuerOrg: i.IssuerOrg,
		Serial: i.Serial, NotBefore: stamp(i.NotBefore), NotAfter: stamp(i.NotAfter), LogURL: i.LogURL, FirstSeen: stamp(i.FirstSeen),
		Fingerprint: i.MatchedFP, TargetID: optID(i.TargetID), CAA: i.CAA, CAADetail: i.CAADetail}
	if i.AckAt > 0 {
		a.Acknowledged = &apiAcked{By: i.AckBy, At: stamp(i.AckAt), Comment: i.AckComment}
	}
	return a
}

func (s *Server) apiIssuances(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var domainID int64
	if v := q.Get("domain_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			apiFail(w, http.StatusBadRequest, "invalid", "domain_id is an id")
			return
		}
		domainID = n
	}
	list, err := s.Core.Issuances(r.Context(), domainID, 0)
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	state := q.Get("state")
	var out []core.Issuance
	for _, i := range list {
		if state == "" || i.State == state {
			out = append(out, i)
		}
	}
	writePage(w, r, out, func(i core.Issuance) string { return idKey(i.ID) }, func(i core.Issuance) any { return toAPIIssuance(i) })
}

// ---------- Channels ----------

type apiChannel struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind" doc:"smtp, telegram, slack, discord, ntfy, webhook, teams, matrix or pagerduty."`
	MinSeverity string `json:"min_severity"`
	Destination string `json:"destination" doc:"Where it delivers, without credentials."`
	Enabled     bool   `json:"enabled"`
	Unreadable  bool   `json:"unreadable" doc:"Its stored settings cannot be decrypted; enter them again."`
	LastState   string `json:"last_state"`
	LastAt      stamp  `json:"last_at"`
	LastError   string `json:"last_error"`
	Sent30d     int    `json:"sent_30d"`
}

func (s *Server) apiChannels(w http.ResponseWriter, r *http.Request) {
	cs, err := s.Core.Channels.List(r.Context())
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	writePage(w, r, cs, func(c notify.Channel) string { return idKey(c.ID) }, func(c notify.Channel) any {
		return apiChannel{ID: c.ID, Name: c.Name, Kind: c.Kind, MinSeverity: c.MinSeverity, Destination: c.Destination, Enabled: c.Enabled, Unreadable: c.Unreadable != "",
			LastState: c.LastState, LastAt: stamp(c.LastAt), LastError: c.LastError, Sent30d: c.Sent30d}
	})
}

type apiSent struct {
	Sent bool `json:"sent"`
}

func (s *Server) apiChannelTest(w http.ResponseWriter, r *http.Request) {
	id, ok := s.apiPathID(w, r, "channel")
	if !ok {
		return
	}
	if _, err := s.Core.Channels.Get(r.Context(), id); err != nil && !errors.Is(err, notify.ErrUnreadable) {
		s.apiFailErr(w, r, err, "No such channel.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 70*time.Second)
	defer cancel()
	err := s.Dispatch.SendTest(ctx, id, s.baseURL(r)+"/")
	s.apiAudit(r, "channel.test", fmt.Sprintf("channel %d", id), fmt.Sprintf("ok=%v", err == nil))
	if err != nil {
		apiFail(w, http.StatusBadGateway, "delivery_failed", "The test message failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, apiSent{Sent: true})
}

// ---------- Export ----------

func (s *Server) apiExport(w http.ResponseWriter, r *http.Request) {
	b, err := s.Core.Export(r.Context())
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	writeExport(w, b)
}

// writeExport sends an export document as a download.
func writeExport(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="tlswatch-export.yaml"`)
	_, _ = w.Write(b)
}
