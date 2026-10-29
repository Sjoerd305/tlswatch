package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/ct"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// Export and import of targets and domain watches as YAML (see the
// specification, "Export and import"): one document with every setting
// that differs from what the Add targets and Add domain forms start with,
// channels, CA bundles and nodes by name, and no credentials. Importing
// the document an export wrote changes nothing, so it can be kept in a
// repository as configuration.

// ExportVersion is the version of the document format.
const ExportVersion = 1

// ExportFile is the export document.
type ExportFile struct {
	Version int            `yaml:"version"`
	Targets []TargetRecord `yaml:"targets,omitempty"`
	Domains []DomainRecord `yaml:"domains,omitempty"`
}

// TargetRecord is one target in the export. A field left out takes the
// value a new target starts with: port the protocol's default, protocol
// tls, server name the host, name the host, trust system, renewal auto,
// the thresholds and probe settings of Settings › Defaults, every address
// probed, the configuration test on, every channel, enabled.
type TargetRecord struct {
	Host           string    `yaml:"host"`
	Port           int       `yaml:"port,omitempty"`
	Protocol       string    `yaml:"protocol,omitempty"`
	ServerName     string    `yaml:"server_name,omitempty"`
	Name           string    `yaml:"name,omitempty"`
	Node           string    `yaml:"node,omitempty"`
	Trust          string    `yaml:"trust,omitempty"`
	Bundle         string    `yaml:"bundle,omitempty"`
	Renewal        string    `yaml:"renewal,omitempty"`
	ExpectedIssuer string    `yaml:"expected_issuer,omitempty"`
	WarnDays       *int      `yaml:"warn_days,omitempty"`
	CritDays       *int      `yaml:"crit_days,omitempty"`
	WarnPct        *int      `yaml:"warn_pct,omitempty"`
	CritPct        *int      `yaml:"crit_pct,omitempty"`
	RenewalPct     *int      `yaml:"renewal_pct,omitempty"`
	IntervalS      *int      `yaml:"interval_s,omitempty"`
	TimeoutS       *int      `yaml:"timeout_s,omitempty"`
	Retries        *int      `yaml:"retries,omitempty"`
	Debounce       *int      `yaml:"debounce,omitempty"`
	RemindWarnS    *int      `yaml:"remind_warn_s,omitempty"`
	RemindCritS    *int      `yaml:"remind_crit_s,omitempty"`
	FirstAddress   bool      `yaml:"first_address_only,omitempty"`
	SkipConfigTest bool      `yaml:"skip_config_test,omitempty"`
	Channels       *[]string `yaml:"channels,omitempty,flow"` // absent: every channel
	Tags           []string  `yaml:"tags,omitempty,flow"`
	Notes          string    `yaml:"notes,omitempty"`
	Disabled       bool      `yaml:"disabled,omitempty"`
}

// DomainRecord is one domain watch in the export; a field left out takes
// the value a new watch starts with (subdomains included, every channel,
// enabled).
type DomainRecord struct {
	Name       string    `yaml:"name"`
	Subdomains *bool     `yaml:"subdomains,omitempty"`
	Channels   *[]string `yaml:"channels,omitempty,flow"`
	Tags       []string  `yaml:"tags,omitempty,flow"`
	Notes      string    `yaml:"notes,omitempty"`
	Disabled   bool      `yaml:"disabled,omitempty"`
}

// exportRefs translates the ids of CA bundles, nodes and channels to the
// names the document uses, and back.
type exportRefs struct {
	bundles  map[int64]string
	bundleID map[string]int64
	nodes    map[int64]string
	nodeIDs  map[string][]int64
	chans    map[int64]string
	chanID   map[string]int64
}

func (s *Service) exportRefs(ctx context.Context) (exportRefs, error) {
	r := exportRefs{bundles: map[int64]string{}, bundleID: map[string]int64{}, nodes: map[int64]string{}, nodeIDs: map[string][]int64{},
		chans: map[int64]string{}, chanID: map[string]int64{}}
	bs, err := s.Bundles(ctx)
	if err != nil {
		return r, err
	}
	for _, b := range bs {
		r.bundles[b.ID], r.bundleID[b.Name] = b.Name, b.ID
	}
	ns, err := s.Nodes(ctx)
	if err != nil {
		return r, err
	}
	// A node is named by its label; a confirmed node comes first when two
	// share one, as only it can take new targets.
	sort.SliceStable(ns, func(i, j int) bool { return ns[i].Assignable() && !ns[j].Assignable() })
	for _, n := range ns {
		r.nodes[n.ID] = n.Label()
		r.nodeIDs[n.Label()] = append(r.nodeIDs[n.Label()], n.ID)
	}
	cs, err := s.Channels.List(ctx)
	if err != nil {
		return r, err
	}
	for _, c := range cs {
		r.chans[c.ID], r.chanID[c.Name] = c.Name, c.ID
	}
	return r, nil
}

func (r exportRefs) channelNames(ids []int64) []string {
	out := []string{}
	for _, id := range ids {
		if n, ok := r.chans[id]; ok {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func (r exportRefs) channelIDs(names []string) ([]int64, error) {
	var out []int64
	for _, n := range names {
		id, ok := r.chanID[n]
		if !ok {
			return nil, fmt.Errorf("there is no channel named %q", n)
		}
		out = append(out, id)
	}
	return out, nil
}

// targetRecord describes a target's configuration as the export writes it.
func targetRecord(t Target, r exportRefs) TargetRecord {
	_, display := CanonicalHost(t.Host)
	rec := TargetRecord{Host: t.Host, ExpectedIssuer: t.ExpectedIssuer, WarnDays: t.WarnDays, CritDays: t.CritDays, WarnPct: t.WarnPct,
		CritPct: t.CritPct, RenewalPct: t.RenewalPct, IntervalS: t.IntervalS, TimeoutS: t.TimeoutS, Retries: t.Retries, Debounce: t.Debounce,
		RemindWarnS: t.RemindWarnS, RemindCritS: t.RemindCritS, FirstAddress: !t.AllAddresses, SkipConfigTest: t.SkipLegacy,
		Tags: t.Tags, Notes: t.Notes, Disabled: !t.Enabled}
	if t.Port != probe.DefaultPort(t.Protocol) {
		rec.Port = t.Port
	}
	if t.Protocol != probe.TLS {
		rec.Protocol = string(t.Protocol)
	}
	if t.ServerName != t.Host && !(t.ServerName == "" && net.ParseIP(t.Host) != nil) {
		rec.ServerName = t.ServerName
	}
	if t.Name != display {
		rec.Name = t.Name
	}
	if t.NodeID != 0 {
		rec.Node = r.nodes[t.NodeID]
	}
	if t.Trust != probe.TrustSystem {
		rec.Trust = string(t.Trust)
	}
	if t.Trust == probe.TrustBundle {
		rec.Bundle = r.bundles[t.BundleID]
	}
	if t.RenewalSet {
		rec.Renewal = "manual"
		if t.RenewalManaged {
			rec.Renewal = "managed"
		}
	}
	if !t.AllChannels {
		names := r.channelNames(t.ChannelIDs)
		rec.Channels = &names
	}
	return rec
}

// domainRecord describes a watch as the export writes it.
func domainRecord(d Domain, r exportRefs) DomainRecord {
	rec := DomainRecord{Name: d.Name, Tags: d.Tags, Notes: d.Notes, Disabled: !d.Enabled}
	if !d.Subdomains {
		f := false
		rec.Subdomains = &f
	}
	if !d.AllChannels {
		names := r.channelNames(d.ChannelIDs)
		rec.Channels = &names
	}
	return rec
}

// Export writes every target and domain watch as one YAML document,
// targets by host, port and protocol, watches by name.
func (s *Service) Export(ctx context.Context) ([]byte, error) {
	refs, err := s.exportRefs(ctx)
	if err != nil {
		return nil, err
	}
	ts, err := s.targetsWithChannels(ctx)
	if err != nil {
		return nil, err
	}
	ds, err := s.domainsWithChannels(ctx)
	if err != nil {
		return nil, err
	}
	f := ExportFile{Version: ExportVersion}
	for _, t := range ts {
		f.Targets = append(f.Targets, targetRecord(t, refs))
	}
	for _, d := range ds {
		f.Domains = append(f.Domains, domainRecord(d, refs))
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# tlswatch targets and domain watches, exported %s.\n", s.now().UTC().Format(time.RFC3339))
	b.WriteString("# A setting left out takes its default. Import through Targets › Add many.\n")
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// targetsWithChannels returns every target with its channels, ordered by
// endpoint, so an export is stable from one run to the next.
func (s *Service) targetsWithChannels(ctx context.Context) ([]Target, error) {
	ts, err := s.Targets(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.TargetChannels(ctx, ts); err != nil {
		return nil, err
	}
	sort.SliceStable(ts, func(i, j int) bool { return targetKey(ts[i]) < targetKey(ts[j]) })
	return ts, nil
}

func (s *Service) domainsWithChannels(ctx context.Context) ([]Domain, error) {
	ds, err := s.Domains(ctx)
	if err != nil {
		return nil, err
	}
	return ds, s.DomainChannels(ctx, ds)
}

// TargetChannels fills in the channels of targets from a list, which
// leaves them out.
func (s *Service) TargetChannels(ctx context.Context, ts []Target) error {
	const batch = 500
	for start := 0; start < len(ts); start += batch {
		targets := ts[start:min(start+batch, len(ts))]
		args := make([]any, len(targets))
		byID := make(map[int64]int, len(targets))
		for i := range targets {
			args[i] = targets[i].ID
			byID[targets[i].ID] = i
			targets[i].ChannelIDs = nil
		}
		// #nosec G202 -- only the number of bound placeholders varies
		rows, err := s.DB.R.QueryContext(ctx, "SELECT target_id, channel_id FROM target_channels WHERE target_id IN (?"+strings.Repeat(",?", len(args)-1)+") ORDER BY target_id, channel_id", args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, channel int64
			if err := rows.Scan(&id, &channel); err != nil {
				_ = rows.Close()
				return err
			}
			i := byID[id]
			targets[i].ChannelIDs = append(targets[i].ChannelIDs, channel)
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	return nil
}

// DomainChannels fills in the channels of watches from a list.
func (s *Service) DomainChannels(ctx context.Context, ds []Domain) error {
	links, err := s.channelLinks(ctx, "SELECT domain_id, channel_id FROM domain_channels")
	if err != nil {
		return err
	}
	for i := range ds {
		ds[i].ChannelIDs = links[ds[i].ID]
	}
	return nil
}

func (s *Service) channelLinks(ctx context.Context, q string) (map[int64][]int64, error) {
	rows, err := s.DB.R.QueryContext(ctx, q+" ORDER BY 1, 2")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[int64][]int64{}
	for rows.Next() {
		var id, c int64
		if err := rows.Scan(&id, &c); err != nil {
			return nil, err
		}
		m[id] = append(m[id], c)
	}
	return m, rows.Err()
}

// targetKey is a target's identity in an import: its endpoint, as the
// database's unique index has it.
func targetKey(t Target) string {
	return fmt.Sprintf("%s|%d|%s|%s", t.Host, t.Port, t.Protocol, t.ServerName)
}

// LooksLikeExport reports whether text is an export document rather than
// the one-endpoint-per-line format of Add many: its first line that is not
// blank or a comment is a document start or one of the document's keys.
func LooksLikeExport(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line == "---" || strings.HasPrefix(line, "version:") || strings.HasPrefix(line, "targets:") || strings.HasPrefix(line, "domains:")
	}
	return false
}

// Import operations.
const (
	ImportAdded     = "added"
	ImportChanged   = "changed"
	ImportUnchanged = "unchanged"
	ImportAbsent    = "absent" // here, but not in the file
)

// FieldDiff is one setting an import changes; "" is the default.
type FieldDiff struct {
	Field, Old, New string
}

// ImportChange is what an import does to one target or watch.
type ImportChange struct {
	Op     string // ImportAdded, …
	Domain bool   // a domain watch; a target otherwise
	Label  string // host:port and protocol, or the domain
	Name   string
	Diff   []FieldDiff

	id     int64  // the existing one
	target Target // the configuration the file gives a target
	domain Domain
}

// ImportPlan is the outcome of reading an import file against what is
// here: every target and watch with what the import does to it.
type ImportPlan struct {
	Changes []ImportChange
}

// Count returns how many changes have op, of targets or of domains.
func (p ImportPlan) Count(op string, domains bool) int {
	n := 0
	for _, c := range p.Changes {
		if c.Op == op && c.Domain == domains {
			n++
		}
	}
	return n
}

// Digest identifies the plan, so a confirmation can tell whether anything
// changed since the preview it confirms.
func (p ImportPlan) Digest() string {
	h := sha256.New()
	for _, c := range p.Changes {
		fmt.Fprintf(h, "%s\x00%v\x00%s\x00%d\x00", c.Op, c.Domain, c.Label, c.id)
		for _, d := range c.Diff {
			fmt.Fprintf(h, "%s\x00%s\x00%s\x00", d.Field, d.Old, d.New)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// ImportError lists every problem an import file has; nothing is saved
// while there is one.
type ImportError struct {
	Problems []string
}

func (e *ImportError) Error() string { return strings.Join(e.Problems, "; ") }

// Unwrap makes the problems a message for the user.
func (e *ImportError) Unwrap() error { return usererr.New(e.Error()) }

// maxImport is the largest number of targets plus watches a file may hold.
const maxImport = 5000

// PlanImport reads an export document and compares it with the targets and
// watches here. A problem anywhere in the file is an *ImportError and
// nothing is planned.
func (s *Service) PlanImport(ctx context.Context, data []byte) (ImportPlan, error) {
	var f ExportFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return ImportPlan{}, &ImportError{[]string{"The file is not a tlswatch export: " + yamlProblem(err)}}
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return ImportPlan{}, &ImportError{[]string{"The file holds more than one document; import one at a time"}}
	}
	if f.Version != ExportVersion {
		return ImportPlan{}, &ImportError{[]string{fmt.Sprintf("The file says version %d; this tlswatch reads version %d", f.Version, ExportVersion)}}
	}
	if len(f.Targets)+len(f.Domains) > maxImport {
		return ImportPlan{}, &ImportError{[]string{fmt.Sprintf("The file holds more than %d targets and domains", maxImport)}}
	}
	refs, err := s.exportRefs(ctx)
	if err != nil {
		return ImportPlan{}, err
	}
	st := s.CurrentSettings(ctx)
	have, err := s.targetsWithChannels(ctx)
	if err != nil {
		return ImportPlan{}, err
	}
	haveDomains, err := s.domainsWithChannels(ctx)
	if err != nil {
		return ImportPlan{}, err
	}
	var plan ImportPlan
	var problems []string
	byKey := map[string]Target{}
	for _, t := range have {
		byKey[targetKey(t)] = t
	}
	seen := map[string]int{}
	for i, rec := range f.Targets {
		where := fmt.Sprintf("targets[%d]", i+1)
		if rec.Host != "" {
			where += " " + rec.Host
		}
		t, errs := targetFromRecord(rec, refs, st)
		if len(errs) > 0 {
			for _, e := range errs {
				problems = append(problems, where+": "+e)
			}
			continue
		}
		key := targetKey(t)
		// A DNS host stored without a server name exports without one,
		// as the server name it would default to is left out: it is the
		// same target.
		if _, ok := byKey[key]; !ok && rec.ServerName == "" && t.ServerName != "" {
			bare := t
			bare.ServerName = ""
			if _, ok := byKey[targetKey(bare)]; ok {
				t, key = bare, targetKey(bare)
			}
		}
		if first, ok := seen[key]; ok {
			problems = append(problems, fmt.Sprintf("%s: repeats targets[%d]", where, first))
			continue
		}
		seen[key] = i + 1
		c := ImportChange{Op: ImportAdded, Label: endpointLabel(t), Name: t.Name, target: t}
		if old, ok := byKey[key]; ok {
			c.id = old.ID
			c.Diff = recordDiff(targetRecord(old, refs), targetRecord(t, refs))
			c.Op = ImportUnchanged
			if len(c.Diff) > 0 {
				c.Op = ImportChanged
			}
		}
		plan.Changes = append(plan.Changes, c)
	}
	for _, t := range have {
		if _, ok := seen[targetKey(t)]; !ok {
			plan.Changes = append(plan.Changes, ImportChange{Op: ImportAbsent, Label: endpointLabel(t), Name: t.Name, id: t.ID})
		}
	}
	byName := map[string]Domain{}
	for _, d := range haveDomains {
		byName[d.Name] = d
	}
	seenDomain := map[string]int{}
	for i, rec := range f.Domains {
		where := fmt.Sprintf("domains[%d]", i+1)
		if rec.Name != "" {
			where += " " + rec.Name
		}
		d, err := domainFromRecord(rec, refs)
		if err != nil {
			problems = append(problems, where+": "+err.Error())
			continue
		}
		if first, ok := seenDomain[d.Name]; ok {
			problems = append(problems, fmt.Sprintf("%s: repeats domains[%d]", where, first))
			continue
		}
		seenDomain[d.Name] = i + 1
		c := ImportChange{Op: ImportAdded, Domain: true, Label: d.Name, Name: d.Name, domain: d}
		if old, ok := byName[d.Name]; ok {
			c.id = old.ID
			c.Diff = recordDiff(domainRecord(old, refs), domainRecord(d, refs))
			c.Op = ImportUnchanged
			if len(c.Diff) > 0 {
				c.Op = ImportChanged
			}
		}
		plan.Changes = append(plan.Changes, c)
	}
	for _, d := range haveDomains {
		if _, ok := seenDomain[d.Name]; !ok {
			plan.Changes = append(plan.Changes, ImportChange{Op: ImportAbsent, Domain: true, Label: d.Name, Name: d.Name, id: d.ID})
		}
	}
	if len(problems) > 0 {
		return ImportPlan{}, &ImportError{problems}
	}
	return plan, nil
}

// yamlProblem is the YAML decoder's message without its package prefix.
func yamlProblem(err error) string {
	msg := strings.TrimPrefix(err.Error(), "yaml: ")
	if te := (*yaml.TypeError)(nil); errors.As(err, &te) {
		msg = strings.Join(te.Errors, "; ")
	}
	return msg
}

func endpointLabel(t Target) string {
	l := t.HostPort()
	if t.Protocol != probe.TLS {
		l += " " + string(t.Protocol)
	}
	if t.ServerName != "" && t.ServerName != t.Host {
		l += " sni=" + t.ServerName
	}
	return l
}

// targetFromRecord builds the target a record describes, validated; the
// problems come back as messages.
func targetFromRecord(rec TargetRecord, r exportRefs, st config.Settings) (Target, []string) {
	var errs []string
	t := Target{Host: rec.Host, Name: rec.Name, Protocol: probe.TLS, Trust: probe.TrustSystem, ExpectedIssuer: strings.TrimSpace(rec.ExpectedIssuer),
		WarnDays: rec.WarnDays, CritDays: rec.CritDays, WarnPct: rec.WarnPct, CritPct: rec.CritPct, RenewalPct: rec.RenewalPct,
		IntervalS: rec.IntervalS, TimeoutS: rec.TimeoutS, Retries: rec.Retries, Debounce: rec.Debounce,
		RemindWarnS: rec.RemindWarnS, RemindCritS: rec.RemindCritS, AllAddresses: !rec.FirstAddress, SkipLegacy: rec.SkipConfigTest,
		AllChannels: rec.Channels == nil, Notes: strings.TrimSpace(rec.Notes), Enabled: !rec.Disabled}
	if strings.TrimSpace(rec.Host) == "" {
		return t, []string{"host is required"}
	}
	if rec.Protocol != "" {
		p, err := probe.ParseProtocol(rec.Protocol)
		if err != nil {
			errs = append(errs, err.Error())
		}
		t.Protocol = p
	}
	t.Port = rec.Port
	if t.Port == 0 {
		t.Port = probe.DefaultPort(t.Protocol)
	}
	t.Host, _ = CanonicalHost(t.Host)
	t.ServerName = rec.ServerName
	if t.ServerName == "" && net.ParseIP(t.Host) == nil {
		t.ServerName = t.Host
	}
	if rec.Trust != "" {
		t.Trust = probe.TrustMode(rec.Trust)
	}
	if rec.Bundle != "" {
		id, ok := r.bundleID[rec.Bundle]
		if !ok {
			errs = append(errs, fmt.Sprintf("there is no CA bundle named %q", rec.Bundle))
		}
		t.BundleID = id
	} else if t.Trust == probe.TrustBundle {
		errs = append(errs, "trust bundle needs a bundle")
	}
	if rec.Bundle != "" && t.Trust != probe.TrustBundle {
		errs = append(errs, "bundle is only for trust bundle")
	}
	if rec.Node != "" {
		ids := r.nodeIDs[rec.Node]
		if len(ids) == 0 {
			errs = append(errs, fmt.Sprintf("there is no node named %q", rec.Node))
		} else {
			t.NodeID = ids[0]
		}
	}
	switch rec.Renewal {
	case "", "auto":
	case "managed":
		t.RenewalSet, t.RenewalManaged = true, true
	case "manual":
		t.RenewalSet = true
	default:
		errs = append(errs, "renewal is auto, managed or manual")
	}
	if rec.Channels != nil {
		ids, err := r.channelIDs(*rec.Channels)
		if err != nil {
			errs = append(errs, err.Error())
		}
		t.ChannelIDs = ids
	}
	tags, err := ParseTags(strings.Join(rec.Tags, ","))
	if err != nil {
		errs = append(errs, err.Error())
	}
	t.Tags = tags
	if len(errs) > 0 {
		return t, errs
	}
	fields := t.Validate(st)
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		errs = append(errs, fields[k])
	}
	return t, errs
}

func domainFromRecord(rec DomainRecord, r exportRefs) (Domain, error) {
	d := Domain{Subdomains: rec.Subdomains == nil || *rec.Subdomains, AllChannels: rec.Channels == nil, Notes: strings.TrimSpace(rec.Notes), Enabled: !rec.Disabled}
	name, err := ct.ValidDomain(rec.Name)
	if err != nil {
		return d, err
	}
	d.Name = name
	if len([]rune(d.Notes)) > 2000 {
		return d, errors.New("notes are limited to 2000 characters")
	}
	if rec.Channels != nil {
		if d.ChannelIDs, err = r.channelIDs(*rec.Channels); err != nil {
			return d, err
		}
	}
	if d.Tags, err = ParseTags(strings.Join(rec.Tags, ",")); err != nil {
		return d, err
	}
	return d, nil
}

// recordDiff lists the fields in which two records differ, by the names
// the document uses; a field left out is "".
func recordDiff(old, new any) []FieldDiff {
	a, b := recordFields(old), recordFields(new)
	keys := map[string]bool{}
	var order []string
	for _, m := range []*fieldList{&a, &b} {
		for _, k := range m.keys {
			if !keys[k] {
				keys[k] = true
				order = append(order, k)
			}
		}
	}
	var out []FieldDiff
	for _, k := range order {
		if a.vals[k] != b.vals[k] {
			out = append(out, FieldDiff{Field: k, Old: a.vals[k], New: b.vals[k]})
		}
	}
	return out
}

type fieldList struct {
	keys []string
	vals map[string]string
}

// recordFields renders each field of a record as the document writes it.
func recordFields(rec any) fieldList {
	fl := fieldList{vals: map[string]string{}}
	var n yaml.Node
	if err := n.Encode(rec); err != nil || n.Kind != yaml.MappingNode {
		return fl
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i].Value, n.Content[i+1]
		fl.keys = append(fl.keys, k)
		fl.vals[k] = nodeText(v)
	}
	return fl
}

func nodeText(v *yaml.Node) string {
	if v.Kind == yaml.SequenceNode {
		parts := make([]string, 0, len(v.Content))
		for _, c := range v.Content {
			parts = append(parts, c.Value)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return v.Value
}

// ImportResult counts what an import did, and names the targets and
// watches it added or changed.
type ImportResult struct {
	Added, Changed, Removed int
	Targets                 []int64 // added or changed targets
	Domains                 []int64 // added domain watches
	Audit                   []ImportAudit
}

// ImportAudit is one audit entry an import makes.
type ImportAudit struct {
	Action, Object, Details string
}

// ApplyImport carries out a plan in one transaction, all or nothing:
// targets and watches added or changed, and, with remove, those absent
// from the file deleted. Nothing is deleted without remove.
func (s *Service) ApplyImport(ctx context.Context, plan ImportPlan, remove bool, user string) (ImportResult, error) {
	var res ImportResult
	def := s.CurrentSettings(ctx).Defaults
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	var enabled []int64 // watches enabled again, whose findings reopen
	for _, c := range plan.Changes {
		switch {
		case c.Op == ImportUnchanged, c.Op == ImportAbsent && !remove:
			continue
		case c.Op == ImportAbsent:
			table, object := "targets", fmt.Sprintf("target %d %s", c.id, c.Label)
			if c.Domain {
				table, object = "domains", fmt.Sprintf("domain %d %s", c.id, c.Label)
			}
			// #nosec G202 -- table is one of the two literals above
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE id = ?", c.id); err != nil {
				return res, err
			}
			res.Removed++
			res.Audit = append(res.Audit, ImportAudit{strings.TrimSuffix(table, "s") + ".delete", object, "import=true name=" + c.Name})
		case c.Domain:
			d := c.domain
			d.ID = c.id
			var was bool
			if c.id != 0 {
				if err := tx.QueryRowContext(ctx, "SELECT enabled FROM domains WHERE id = ?", c.id).Scan(&was); err != nil {
					return res, err
				}
			}
			id, err := s.saveDomainTx(ctx, tx, d, user)
			if err != nil {
				return res, fmt.Errorf("%s: %w", c.Label, err)
			}
			action := "domain.update"
			if c.id == 0 {
				action = "domain.create"
				res.Added++
				res.Domains = append(res.Domains, id)
			} else {
				res.Changed++
				if d.Enabled && !was {
					enabled = append(enabled, id)
				}
			}
			res.Audit = append(res.Audit, ImportAudit{action, fmt.Sprintf("domain %d %s", id, d.Name), "import=true" + diffDetail(c.Diff)})
		default:
			t := c.target
			t.ID = c.id
			want := t.Enabled
			if c.id != 0 {
				if err := tx.QueryRowContext(ctx, "SELECT enabled FROM targets WHERE id = ?", c.id).Scan(&t.Enabled); err != nil {
					return res, err
				}
			}
			id, err := s.saveTargetTx(ctx, tx, t, def, user)
			if err != nil {
				return res, fmt.Errorf("%s: %w", c.Label, err)
			}
			if c.id != 0 && want != t.Enabled {
				if err := s.setEnabledTx(ctx, tx, id, want); err != nil {
					return res, err
				}
			}
			action := "target.update"
			if c.id == 0 {
				action = "target.create"
				res.Added++
			} else {
				res.Changed++
			}
			res.Targets = append(res.Targets, id)
			res.Audit = append(res.Audit, ImportAudit{action, fmt.Sprintf("target %d %s", id, t.HostPort()), "import=true" + diffDetail(c.Diff)})
		}
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}
	for _, id := range enabled {
		if err := s.reopenUnexpected(ctx, id); err != nil {
			return res, err
		}
	}
	return res, nil
}

func diffDetail(diff []FieldDiff) string {
	if len(diff) == 0 {
		return ""
	}
	fields := make([]string, 0, len(diff))
	for _, d := range diff {
		fields = append(fields, d.Field)
	}
	return " changed=" + strings.Join(fields, ",")
}

// CSVToLines turns a CSV file with the columns of the Add many line format
// (a header row naming host and optionally protocol, sni and name) into
// that format, one line per row, so row N is line N. ok is false when text
// is not such a file.
func CSVToLines(text string) (lines string, ok bool, err error) {
	first := strings.TrimSpace(strings.SplitN(strings.TrimLeft(text, "\ufeff \t\r\n"), "\n", 2)[0])
	if !strings.HasPrefix(strings.ToLower(first), "host,") && !strings.EqualFold(first, "host") {
		return "", false, nil
	}
	r := csvReader(strings.TrimLeft(text, "\ufeff \t\r\n"))
	rows, err := r.ReadAll()
	if err != nil {
		return "", true, usererr.New("The CSV file could not be read: " + strings.TrimPrefix(err.Error(), "record on "))
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		h = strings.ToLower(strings.TrimSpace(h))
		switch h {
		case "host", "protocol", "sni", "name":
		default:
			return "", true, usererr.New(fmt.Sprintf("The CSV column %q is not one of host, protocol, sni and name", h))
		}
		if _, dup := col[h]; dup {
			return "", true, usererr.New(fmt.Sprintf("The CSV column %q appears twice", h))
		}
		col[h] = i
	}
	get := func(row []string, k string) string {
		if i, ok := col[k]; ok && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}
	out := []string{"# " + strings.Join(rows[0], ",")}
	for _, row := range rows[1:] {
		parts := []string{}
		if h := get(row, "host"); h != "" {
			parts = append(parts, strings.ReplaceAll(h, " ", ""))
			if p := get(row, "protocol"); p != "" {
				parts = append(parts, "protocol="+p)
			}
			if sni := get(row, "sni"); sni != "" {
				parts = append(parts, "sni="+sni)
			}
			if n := get(row, "name"); n != "" {
				parts = append(parts, n)
			}
		}
		out = append(out, strings.Join(parts, " "))
	}
	return strings.Join(out, "\n"), true, nil
}

// saveDomainTx is SaveDomain inside a transaction the caller commits.
func (s *Service) saveDomainTx(ctx context.Context, tx *sql.Tx, d Domain, user string) (int64, error) {
	name, err := ct.ValidDomain(d.Name)
	if err != nil {
		return 0, usererr.Wrap(err)
	}
	d.Name = name
	if len([]rune(d.Notes)) > 2000 {
		return 0, usererr.New("Notes are limited to 2000 characters")
	}
	now := s.now().Unix()
	if d.ID == 0 {
		res, err := tx.ExecContext(ctx, `INSERT INTO domains(name, subdomains, tags, notes, all_channels, enabled, created_at, created_by, updated_at)
			VALUES(?,?,?,?,?,?,?,?,?)`, d.Name, d.Subdomains, strings.Join(d.Tags, ","), d.Notes, d.AllChannels, d.Enabled, now, user, now)
		if err != nil {
			return 0, uniqueDomain(err)
		}
		d.ID, _ = res.LastInsertId()
	} else {
		var oldName string
		if err := tx.QueryRowContext(ctx, "SELECT name FROM domains WHERE id = ?", d.ID).Scan(&oldName); errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		} else if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE domains SET name=?, subdomains=?, tags=?, notes=?, all_channels=?, enabled=?, updated_at=? WHERE id=?`,
			d.Name, d.Subdomains, strings.Join(d.Tags, ","), d.Notes, d.AllChannels, d.Enabled, now, d.ID); err != nil {
			return 0, uniqueDomain(err)
		}
		if oldName != d.Name {
			for _, q := range []string{"DELETE FROM issuances WHERE domain_id = ?", "DELETE FROM findings WHERE domain_id = ?",
				"UPDATE domains SET cursor = '', polled_at = 0, polled_ok = 0, poll_error = '', fail_since = 0 WHERE id = ?"} {
				if _, err := tx.ExecContext(ctx, q, d.ID); err != nil {
					return 0, err
				}
			}
		}
		if !d.Enabled {
			if _, err := tx.ExecContext(ctx, "UPDATE findings SET resolved_at = ? WHERE domain_id = ? AND resolved_at = 0", now, d.ID); err != nil {
				return 0, err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM domain_channels WHERE domain_id = ?", d.ID); err != nil {
		return 0, err
	}
	if !d.AllChannels {
		for _, c := range d.ChannelIDs {
			if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO domain_channels(domain_id, channel_id) SELECT ?, id FROM channels WHERE id = ?", d.ID, c); err != nil {
				return 0, err
			}
		}
	}
	return d.ID, nil
}

func csvReader(text string) *csv.Reader {
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	r.Comment = '#'
	return r
}
