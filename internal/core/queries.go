package core

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/notify"
)

// NavCounts are the live counts in the navigation.
type NavCounts struct {
	Targets      int
	Certificates int
	Findings     int
	Critical     bool
	LastCheck    int64
	NextCheck    int64
}

// Nav returns the navigation counts.
func (s *Service) Nav(ctx context.Context) NavCounts {
	var n NavCounts
	_ = s.DB.R.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MAX(last_check), 0),
		COALESCE((SELECT MIN(next_check) FROM targets WHERE enabled = 1 AND next_check > 0), 0) FROM targets`).Scan(&n.Targets, &n.LastCheck, &n.NextCheck)
	_ = s.DB.R.QueryRowContext(ctx, `SELECT COUNT(DISTINCT o.leaf_fp) FROM targets t
		JOIN observations o ON o.check_id = t.last_check_id AND o.target_id = t.id WHERE o.leaf_fp != ''`).Scan(&n.Certificates)
	var crit int
	_ = s.DB.R.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(severity = 'critical'), 0) FROM findings f JOIN targets t ON t.id = f.target_id
		WHERE f.resolved_at = 0 AND t.enabled = 1`).Scan(&n.Findings, &crit)
	n.Critical = crit > 0
	return n
}

// Stamp summarises everything the live pages show; it changes when a check
// lands, a target or finding changes, or an alert is queued or delivered
// (triggers bump the changes counter). Pending is the number of enabled
// targets that were never checked.
func (s *Service) Stamp(ctx context.Context) (stamp string, pending int, err error) {
	var n int64
	err = s.DB.R.QueryRowContext(ctx, `SELECT (SELECT n FROM changes),
		(SELECT COUNT(*) FROM targets WHERE enabled = 1 AND last_check = 0)`).Scan(&n, &pending)
	if err != nil {
		return "", 0, err
	}
	return strconv.FormatInt(n, 10), pending, nil
}

// Overview is the home screen.
type Overview struct {
	Targets     []Target
	Total       int
	Critical    int
	Warning     int
	Changed     int
	Expiring    int // targets warning because of expiry
	Healthy     int
	Unreachable int
	Disabled    int
	Pending     int
	DueWithin30 int
	Open        []Finding
	Changes     []Finding
	Last24h     RunSummary
	LastCheck   int64
	NextCheck   int64
	MinWarn     int
}

// RunSummary summarises the checks of a period.
type RunSummary struct {
	From, To    int64
	Checks      int
	Targets     int
	Addresses   int
	Unreachable int
	DNSFailed   int
	Alerts      int
	AlertVia    string
}

// Overview gathers the home screen.
func (s *Service) Overview(ctx context.Context) (Overview, error) {
	var o Overview
	ts, err := s.Targets(ctx)
	if err != nil {
		return o, err
	}
	now := s.now()
	st := s.CurrentSettings(ctx)
	o.MinWarn = st.Defaults.Manual.WarnDays
	o.Total = len(ts)
	for _, t := range ts {
		switch t.Status {
		case StatusCritical:
			o.Critical++
		case StatusWarning:
			o.Warning++
		case StatusChanged:
			o.Warning++
			o.Changed++
		case StatusHealthy:
			o.Healthy++
		case StatusUnreachable:
			o.Unreachable++
		case StatusDisabled:
			o.Disabled++
		case StatusPending:
			o.Pending++
		}
		if t.Enabled && t.NotAfter > 0 {
			if d := check.DaysLeft(time.Unix(t.NotAfter, 0), now); d < 30 {
				o.DueWithin30++
			}
		}
		if t.LastCheck > o.LastCheck {
			o.LastCheck = t.LastCheck
		}
		if t.Enabled && t.NextCheck > 0 && (o.NextCheck == 0 || t.NextCheck < o.NextCheck) {
			o.NextCheck = t.NextCheck
		}
		if t.Enabled && t.Cert != nil {
			o.Targets = append(o.Targets, t)
		}
	}
	if len(o.Targets) > 8 {
		o.Targets = o.Targets[:8]
	}
	if o.Open, err = s.Findings(ctx, FindingFilter{Limit: 8}); err != nil {
		return o, err
	}
	if o.Changes, err = s.RecentChanges(ctx, now.Add(-14*24*time.Hour).Unix(), 6); err != nil {
		return o, err
	}
	o.Last24h, err = s.Summary(ctx, now.Add(-24*time.Hour).Unix(), now.Unix())
	return o, err
}

// RecentChanges returns certificate changes and resolved findings since a
// moment, newest first.
func (s *Service) RecentChanges(ctx context.Context, since int64, limit int) ([]Finding, error) {
	rows, err := s.DB.R.QueryContext(ctx, "SELECT "+findingCols+`, t.name, t.host, t.port FROM findings f JOIN targets t ON t.id = f.target_id
		WHERE (f.kind = 'certificate_changed' AND f.opened_at >= ?) OR (f.resolved_at >= ? AND f.severity != 'info' AND f.resolved_at > f.opened_at)
		ORDER BY MAX(f.opened_at, f.resolved_at) DESC LIMIT ?`, since, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var name, host string
		var port int
		f, err := scanFinding(rows, &name, &host, &port)
		if err != nil {
			return nil, err
		}
		f.TargetName, f.TargetHost, f.TargetPort = name, host, port
		out = append(out, f)
	}
	return out, rows.Err()
}

// Summary summarises checks and alerts in a period.
func (s *Service) Summary(ctx context.Context, from, to int64) (RunSummary, error) {
	r := RunSummary{From: from, To: to}
	err := s.DB.R.QueryRowContext(ctx, `SELECT COUNT(DISTINCT check_id), COUNT(DISTINCT target_id), COUNT(DISTINCT CASE WHEN address != '' AND status != 'skipped' THEN target_id || '/' || address END),
		COALESCE(MIN(checked_at), 0), COALESCE(MAX(checked_at), 0)
		FROM observations WHERE checked_at >= ? AND checked_at <= ?`, from, to).Scan(&r.Checks, &r.Targets, &r.Addresses, &r.From, &r.To)
	if err != nil {
		return r, err
	}
	_ = s.DB.R.QueryRowContext(ctx, `SELECT COALESCE(SUM(kind = 'unreachable'), 0), COALESCE(SUM(kind = 'dns_failed'), 0) FROM findings
		WHERE resolved_at = 0 AND kind IN ('unreachable', 'dns_failed')`).Scan(&r.Unreachable, &r.DNSFailed)
	_ = s.DB.R.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(GROUP_CONCAT(DISTINCT c.name), '') FROM alerts a JOIN channels c ON c.id = a.channel_id
		WHERE a.state = 'sent' AND a.sent_at >= ? AND a.event != 'test'`, from).Scan(&r.Alerts, &r.AlertVia)
	if r.From == 0 {
		r.From = from
	}
	return r, nil
}

// Observation is one probe of one address.
type Observation struct {
	ID          int64
	CheckID     string
	Address     string
	CheckedAt   int64
	Status      string
	TLSVersion  string
	Cipher      string
	LeafFP      string
	Chain       []string
	Verified    bool
	VerifyError string
	Error       string
	DurationMS  int64
}

// LastCheck returns the observations of a target's most recent check.
func (s *Service) LastCheck(ctx context.Context, targetID int64) ([]Observation, error) {
	rows, err := s.DB.R.QueryContext(ctx, `SELECT id, check_id, address, checked_at, status, tls_version, cipher, leaf_fp, chain, verified, verify_error, error, duration_ms
		FROM observations WHERE target_id = ?1 AND check_id = (SELECT last_check_id FROM targets WHERE id = ?1) ORDER BY id`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Observation
	for rows.Next() {
		var o Observation
		var chain string
		if err := rows.Scan(&o.ID, &o.CheckID, &o.Address, &o.CheckedAt, &o.Status, &o.TLSVersion, &o.Cipher, &o.LeafFP, &chain, &o.Verified, &o.VerifyError, &o.Error, &o.DurationMS); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(chain), &o.Chain)
		out = append(out, o)
	}
	return out, rows.Err()
}

// ChainLink is one certificate in a served chain.
type ChainLink struct {
	Certificate
	Role    string // leaf, intermediate, root
	InStore bool   // root added from the trust store or bundle
	Weak    bool
	Worst   bool // the link that expires first
}

// Chain resolves an observation's chain to certificates.
func (s *Service) Chain(ctx context.Context, o Observation) []ChainLink {
	var out []ChainLink
	for i, ref := range o.Chain {
		fp, inStore := strings.CutPrefix(ref, "root:")
		c, err := s.Certificate(ctx, fp)
		if err != nil {
			continue
		}
		l := ChainLink{Certificate: c, InStore: inStore}
		switch {
		case i == 0:
			l.Role = "leaf"
		case c.SelfSigned:
			l.Role = "root"
		default:
			l.Role = "intermediate"
		}
		l.Weak = isWeak(c) && !(c.SelfSigned && c.IsCA)
		out = append(out, l)
	}
	worst := -1
	for i, l := range out {
		if l.InStore {
			continue
		}
		if worst < 0 || l.NotAfter < out[worst].NotAfter {
			worst = i
		}
	}
	if worst >= 0 {
		out[worst].Worst = true
	}
	return out
}

func isWeak(c Certificate) bool {
	sa := strings.ToUpper(c.SigAlg)
	return strings.Contains(sa, "SHA1") || strings.Contains(sa, "SHA-1") || strings.Contains(sa, "MD5") || strings.Contains(sa, "MD2") ||
		(c.KeyType == "RSA" && c.KeyBits < 2048)
}

// HistoryEntry is a certificate seen on a target.
type HistoryEntry struct {
	Certificate
	First, Last int64
	Current     bool
}

// History lists the leaf certificates seen on a target, newest first.
func (s *Service) History(ctx context.Context, t Target) ([]HistoryEntry, error) {
	rows, err := s.DB.R.QueryContext(ctx, `SELECT leaf_fp, MIN(checked_at), MAX(checked_at) FROM observations
		WHERE target_id = ? AND leaf_fp != '' GROUP BY leaf_fp ORDER BY MAX(checked_at) DESC, MIN(checked_at) DESC`, t.ID)
	if err != nil {
		return nil, err
	}
	type row struct {
		fp          string
		first, last int64
	}
	var rs []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.fp, &r.first, &r.last); err != nil {
			rows.Close()
			return nil, err
		}
		rs = append(rs, r)
	}
	rows.Close()
	var out []HistoryEntry
	for _, r := range rs {
		c, err := s.Certificate(ctx, r.fp)
		if err != nil {
			continue
		}
		out = append(out, HistoryEntry{Certificate: c, First: r.first, Last: r.last, Current: r.fp == t.CurrentFP})
	}
	return out, nil
}

// Served is a place a certificate is currently served.
type Served struct {
	TargetID   int64
	TargetName string
	HostPort   string
	Address    string
	Status     string
	CheckedAt  int64
	Current    bool // the target's current certificate
	Addresses  int  // addresses of the target in its last check
}

// InventoryItem is one row of the certificate inventory.
type InventoryItem struct {
	Certificate
	Served  []Served
	Targets int
	Stale   bool // served on only some addresses of a target
	Chain   []ChainLink
}

// served returns where leaf certificates are served now, per fingerprint:
// the addresses of every target's latest check. A non-empty fp limits it to
// that certificate.
func (s *Service) served(ctx context.Context, fp string) (map[string][]Served, error) {
	rows, err := s.DB.R.QueryContext(ctx, `SELECT o.leaf_fp, o.target_id, t.name, t.host, t.port, o.address, o.status, o.checked_at, t.current_fp, t.address_count
		FROM targets t JOIN observations o ON o.check_id = t.last_check_id AND o.target_id = t.id
		WHERE o.leaf_fp != '' AND (?1 = '' OR o.leaf_fp = ?1)
		ORDER BY t.name, o.address`, fp)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]Served{}
	for rows.Next() {
		var leaf, cur string
		var sv Served
		var host string
		var port int
		if err := rows.Scan(&leaf, &sv.TargetID, &sv.TargetName, &host, &port, &sv.Address, &sv.Status, &sv.CheckedAt, &cur, &sv.Addresses); err != nil {
			return nil, err
		}
		sv.HostPort = Target{Host: host, Port: port}.HostPort()
		sv.Current = cur == leaf
		out[leaf] = append(out[leaf], sv)
	}
	return out, rows.Err()
}

// ServedOn returns where one certificate is served now.
func (s *Service) ServedOn(ctx context.Context, fp string) ([]Served, error) {
	m, err := s.served(ctx, fp)
	return m[fp], err
}

// Inventory returns every leaf certificate seen, with where it is served now.
func (s *Service) Inventory(ctx context.Context) ([]InventoryItem, error) {
	served, err := s.served(ctx, "")
	if err != nil {
		return nil, err
	}
	crow, err := s.DB.R.QueryContext(ctx, "SELECT "+certCols+" FROM certificates WHERE fingerprint IN (SELECT DISTINCT leaf_fp FROM observations WHERE leaf_fp != '') ORDER BY not_after")
	if err != nil {
		return nil, err
	}
	defer crow.Close()
	var out []InventoryItem
	for crow.Next() {
		c, err := scanCert(crow)
		if err != nil {
			return nil, err
		}
		it := InventoryItem{Certificate: c, Served: served[c.Fingerprint]}
		tg := map[int64]int{}
		for _, sv := range it.Served {
			tg[sv.TargetID]++
			if !sv.Current {
				it.Stale = true
			}
		}
		it.Targets = len(tg)
		out = append(out, it)
	}
	return out, crow.Err()
}

// InventoryChain returns the chain under which a certificate was last served.
func (s *Service) InventoryChain(ctx context.Context, fp string) []ChainLink {
	var o Observation
	var chain string
	err := s.DB.R.QueryRowContext(ctx, "SELECT chain, verified FROM observations WHERE leaf_fp = ? ORDER BY id DESC LIMIT 1", fp).Scan(&chain, &o.Verified)
	if err != nil {
		return nil
	}
	_ = json.Unmarshal([]byte(chain), &o.Chain)
	return s.Chain(ctx, o)
}

// AuditEntry is one change in the tool itself.
type AuditEntry struct {
	ID      int64
	At      int64
	User    string
	Action  string
	Object  string
	Details string
}

// AuditLog lists audit entries, newest first, optionally filtered by a
// substring over user, action and object.
func (s *Service) AuditLog(ctx context.Context, filter string, limit int) ([]AuditEntry, error) {
	q := "SELECT id, at, user_email, action, object, details FROM audit"
	var args []any
	if f := strings.TrimSpace(filter); f != "" {
		q += " WHERE user_email LIKE ? OR action LIKE ? OR object LIKE ? OR details LIKE ?"
		like := "%" + strings.ReplaceAll(strings.ReplaceAll(f, "%", ""), "_", "") + "%"
		args = append(args, like, like, like, like)
	}
	q += " ORDER BY id DESC"
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := s.DB.R.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.ID, &a.At, &a.User, &a.Action, &a.Object, &a.Details); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// pruneBatch is how many rows one prune statement deletes, so checks and
// sign-ins get the writer between batches.
const pruneBatch = 5000

// Prune removes history older than the retention period. The current state
// of every target is kept regardless of age.
func (s *Service) Prune(ctx context.Context) error {
	st := s.CurrentSettings(ctx)
	cut := s.now().Add(-time.Duration(st.Defaults.RetentionDays) * 24 * time.Hour).Unix()
	batched := []string{
		// Keep each target's latest check.
		`DELETE FROM observations WHERE id IN (SELECT id FROM observations WHERE checked_at < ?1
			AND check_id NOT IN (SELECT last_check_id FROM targets) LIMIT ?2)`,
		"DELETE FROM alerts WHERE id IN (SELECT id FROM alerts WHERE created_at < ?1 AND state != 'pending' LIMIT ?2)",
		"DELETE FROM findings WHERE id IN (SELECT id FROM findings WHERE resolved_at > 0 AND resolved_at < ?1 LIMIT ?2)",
		"DELETE FROM audit WHERE id IN (SELECT id FROM audit WHERE at < ?1 LIMIT ?2)",
		"DELETE FROM tokens WHERE expires_at < ?1",
	}
	for _, q := range batched {
		for {
			res, err := s.DB.W.ExecContext(ctx, q, cut, pruneBatch)
			if err != nil {
				return fmt.Errorf("prune: %w", err)
			}
			if n, _ := res.RowsAffected(); n < pruneBatch {
				break
			}
		}
	}
	if err := s.pruneCertificates(ctx, cut); err != nil {
		return fmt.Errorf("prune certificates: %w", err)
	}
	return nil
}

// pruneCertificates removes certificates not seen since cut that no
// remaining observation, current state or pin refers to. The references are
// collected in one pass over the observations on the read pool; the delete
// checks last_seen again, so a certificate seen meanwhile stays.
func (s *Service) pruneCertificates(ctx context.Context, cut int64) error {
	rows, err := s.DB.R.QueryContext(ctx, `SELECT fingerprint FROM certificates WHERE last_seen < ?
		AND fingerprint NOT IN (SELECT current_fp FROM targets) AND fingerprint NOT IN (SELECT pinned_fp FROM targets)`, cut)
	if err != nil {
		return err
	}
	candidates := map[string]bool{}
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			rows.Close()
			return err
		}
		candidates[fp] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(candidates) == 0 {
		return err
	}
	rows, err = s.DB.R.QueryContext(ctx, "SELECT leaf_fp, chain FROM observations")
	if err != nil {
		return err
	}
	for rows.Next() {
		var leaf, chain string
		if err := rows.Scan(&leaf, &chain); err != nil {
			rows.Close()
			return err
		}
		delete(candidates, leaf)
		var refs []string
		_ = json.Unmarshal([]byte(chain), &refs)
		for _, ref := range refs {
			delete(candidates, strings.TrimPrefix(ref, "root:"))
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for fp := range candidates {
		if _, err := s.DB.W.ExecContext(ctx, "DELETE FROM certificates WHERE fingerprint = ? AND last_seen < ?", fp, cut); err != nil {
			return err
		}
	}
	return nil
}

// Digest builds the weekly digest: open findings, certificates expiring in
// the next 30 days and targets whose last check failed.
func (s *Service) Digest(ctx context.Context) (notify.Message, error) {
	st := s.CurrentSettings(ctx)
	loc := st.Location()
	now := s.now()
	findings, err := s.Findings(ctx, FindingFilter{})
	if err != nil {
		return notify.Message{}, err
	}
	ts, err := s.Targets(ctx)
	if err != nil {
		return notify.Message{}, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "tlswatch weekly digest, %s\n\n", now.In(loc).Format("Monday 2 January 2006"))
	fmt.Fprintf(&b, "Open findings (%d)\n", len(findings))
	for _, f := range findings {
		ack := ""
		if f.Acked(now) {
			ack = " (acknowledged by " + f.AckBy + ")"
		}
		fmt.Fprintf(&b, "  [%s] %s %s: %s%s\n", f.Severity, f.HostPort(), f.Kind.Label(), f.Details, ack)
	}
	if len(findings) == 0 {
		b.WriteString("  none\n")
	}
	var exp []Target
	var failed []Target
	for _, t := range ts {
		if !t.Enabled {
			continue
		}
		if t.NotAfter > 0 && check.DaysLeft(time.Unix(t.NotAfter, 0), now) < 30 {
			exp = append(exp, t)
		}
		if t.LastError != "" || t.Status == StatusUnreachable {
			failed = append(failed, t)
		}
	}
	sort.Slice(exp, func(i, j int) bool { return exp[i].NotAfter < exp[j].NotAfter })
	fmt.Fprintf(&b, "\nExpiring in the next 30 days (%d)\n", len(exp))
	for _, t := range exp {
		fmt.Fprintf(&b, "  %s  %4d d  %s (%s)\n", time.Unix(t.NotAfter, 0).In(loc).Format("2006-01-02"), check.DaysLeft(time.Unix(t.NotAfter, 0), now), t.Name, t.HostPort())
	}
	if len(exp) == 0 {
		b.WriteString("  none\n")
	}
	fmt.Fprintf(&b, "\nFailed their last check (%d)\n", len(failed))
	for _, t := range failed {
		fmt.Fprintf(&b, "  %s (%s): %s\n", t.Name, t.HostPort(), t.LastError)
	}
	if len(failed) == 0 {
		b.WriteString("  none\n")
	}
	if st.General.BaseURL != "" {
		b.WriteString("\n" + st.General.BaseURL + "/\n")
	}
	sev := "info"
	for _, f := range findings {
		if f.Severity == check.Critical {
			sev = "critical"
			break
		}
		if f.Severity == check.Warning {
			sev = "warning"
		}
	}
	return notify.Message{
		Subject: fmt.Sprintf("[%s] tlswatch weekly digest: %d open, %d expiring within 30 days", sev, len(findings), len(exp)),
		Body:    b.String(),
	}, nil
}
