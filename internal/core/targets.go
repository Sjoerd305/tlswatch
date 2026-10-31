package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

const targetCols = `t.id, t.name, t.host, t.port, t.protocol, t.servername, t.trust_mode, COALESCE(t.bundle_id, 0), COALESCE(b.name, ''),
	t.renewal_managed, t.renewal_set, t.expected_issuer, t.warn_days, t.crit_days, t.interval_s, t.timeout_s, t.retries, t.debounce,
	t.remind_warn_s, t.remind_crit_s, t.all_addresses, t.all_channels, t.tags, t.notes, t.enabled, t.created_at, t.created_by, t.updated_at, t.revision,
	t.status, t.pinned_fp, t.current_fp, t.not_after, t.tls_version, t.address_count, t.last_check, t.last_error,
	t.fail_streak, t.ok_streak, t.dns_fail_streak, t.dns_ok_streak, t.next_check, t.legacy_check, t.legacy_checked, t.legacy_accepted,
	t.grade, t.grade_reasons, t.grade_rules, t.config_test, t.warn_pct, t.crit_pct, t.renewal_pct, t.pq,
	COALESCE(t.node_id, 0), COALESCE(n.name, '')`

const targetFrom = ` FROM targets t LEFT JOIN ca_bundles b ON b.id = t.bundle_id LEFT JOIN nodes n ON n.id = t.node_id `

func scanTarget(r interface{ Scan(...any) error }) (Target, error) {
	var t Target
	var proto, trust, tags, legacy, reasons, configTest string
	var legacyCheck bool
	var warn, crit, interval, timeout, retries, debounce, rw, rc, warnPct, critPct, renewalPct sql.NullInt64
	err := r.Scan(&t.ID, &t.Name, &t.Host, &t.Port, &proto, &t.ServerName, &trust, &t.BundleID, &t.BundleName,
		&t.RenewalManaged, &t.RenewalSet, &t.ExpectedIssuer, &warn, &crit, &interval, &timeout, &retries, &debounce,
		&rw, &rc, &t.AllAddresses, &t.AllChannels, &tags, &t.Notes, &t.Enabled, &t.CreatedAt, &t.CreatedBy, &t.UpdatedAt, &t.Revision,
		&t.Status, &t.PinnedFP, &t.CurrentFP, &t.NotAfter, &t.TLSVersion, &t.AddressCount, &t.LastCheck, &t.LastError,
		&t.FailStreak, &t.OkStreak, &t.DNSFail, &t.DNSOk, &t.NextCheck, &legacyCheck, &t.LegacyChecked, &legacy,
		&t.Grade, &reasons, &t.GradeRules, &configTest, &warnPct, &critPct, &renewalPct, &t.PQ,
		&t.NodeID, &t.NodeName)
	if err != nil {
		return t, err
	}
	t.Protocol, t.Trust = probe.Protocol(proto), probe.TrustMode(trust)
	t.WarnDays, t.CritDays, t.IntervalS, t.TimeoutS = intPtr(warn), intPtr(crit), intPtr(interval), intPtr(timeout)
	t.Retries, t.Debounce, t.RemindWarnS, t.RemindCritS = intPtr(retries), intPtr(debounce), intPtr(rw), intPtr(rc)
	t.WarnPct, t.CritPct, t.RenewalPct = intPtr(warnPct), intPtr(critPct), intPtr(renewalPct)
	if tags != "" {
		t.Tags = strings.Split(tags, ",")
	}
	t.SkipLegacy = !legacyCheck
	if legacy != "" {
		t.LegacyAccepted = strings.Split(legacy, ",")
	}
	if reasons != "" {
		t.GradeReasons = strings.Split(reasons, "\n")
	}
	if configTest != "" {
		if err := json.Unmarshal([]byte(configTest), &t.ConfigTest); err != nil {
			return t, fmt.Errorf("target %d: config_test: %w", t.ID, err)
		}
	}
	return t, nil
}

// Targets returns every target with its current certificate, sorted by
// expiry (unknown and disabled last).
func (s *Service) Targets(ctx context.Context) ([]Target, error) {
	return s.queryTargets(ctx, "", 0)
}

// targetOrder sorts by expiry, unknown and disabled last.
const targetOrder = " ORDER BY t.enabled DESC, CASE WHEN t.not_after = 0 THEN 1 ELSE 0 END, t.not_after, t.name"

// queryTargets returns the targets matching where (empty: all) in
// targetOrder, at most limit (0: all), with their current certificates.
func (s *Service) queryTargets(ctx context.Context, where string, limit int, args ...any) ([]Target, error) {
	q := "SELECT " + targetCols + targetFrom
	if where != "" {
		q += " WHERE " + where // #nosec G202 -- a clause of this package's own; its values are in args
	}
	q += targetOrder
	if limit > 0 {
		q += " LIMIT ?"
		args = append(args, limit)
	}
	return s.readTargets(ctx, q, args...)
}

// readTargets materializes the rows selected by the caller, then attaches summaries.
func (s *Service) readTargets(ctx context.Context, q string, args ...any) ([]Target, error) {
	rows, err := s.DB.R.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	var fps []any
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		if t.CurrentFP != "" {
			fps = append(fps, t.CurrentFP)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	_ = rows.Close()
	certs, err := s.certificatesByFP(ctx, fps)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if c, ok := certs[out[i].CurrentFP]; ok {
			out[i].Cert = &c
		}
	}
	return out, nil
}

// certificatesByFP loads the given certificates (without PEM).
func (s *Service) certificatesByFP(ctx context.Context, fps []any) (map[string]Certificate, error) {
	m := map[string]Certificate{}
	seen := map[any]bool{}
	unique := make([]any, 0, len(fps))
	for _, fp := range fps {
		if !seen[fp] {
			seen[fp] = true
			unique = append(unique, fp)
		}
	}
	// Stay well below SQLite's variable limit even for a complete export.
	const batch = 500
	for start := 0; start < len(unique); start += batch {
		args := unique[start:min(start+batch, len(unique))]
		// #nosec G202 -- constant columns and one placeholder per bound value
		rows, err := s.DB.R.QueryContext(ctx, "SELECT "+certListCols+" FROM certificates WHERE fingerprint IN (?"+strings.Repeat(",?", len(args)-1)+")", args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			c, err := scanCert(rows)
			if err != nil {
				_ = rows.Close()
				return nil, err
			}
			m[c.Fingerprint] = c
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// Target returns one target with its current certificate and channels.
func (s *Service) Target(ctx context.Context, id int64) (Target, error) {
	t, err := scanTarget(s.DB.R.QueryRowContext(ctx, "SELECT "+targetCols+targetFrom+" WHERE t.id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	if err != nil {
		return t, err
	}
	if t.CurrentFP != "" {
		if c, err := s.Certificate(ctx, t.CurrentFP); err == nil {
			t.Cert = &c
		}
	}
	rows, err := s.DB.R.QueryContext(ctx, "SELECT channel_id FROM target_channels WHERE target_id = ?", id)
	if err != nil {
		return t, err
	}
	defer rows.Close()
	for rows.Next() {
		var c int64
		if err := rows.Scan(&c); err != nil {
			return t, err
		}
		t.ChannelIDs = append(t.ChannelIDs, c)
	}
	return t, rows.Err()
}

// CanonicalHost returns the one spelling of a host that is stored and
// probed: lower case, without a trailing dot or IPv6 brackets, an IP
// address in its canonical form and a Unicode name in punycode. display
// is the name as people read it: the Unicode form of a punycode name.
func CanonicalHost(h string) (host, display string) {
	h = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(h)), ".")
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if ip := net.ParseIP(h); ip != nil {
		h = ip.String()
		return h, h
	}
	if a, err := idna.Lookup.ToASCII(h); err == nil {
		h = a
	}
	if u, err := idna.Lookup.ToUnicode(h); err == nil {
		return h, u
	}
	return h, h
}

// Validate normalises the target in place (host and server name in their
// CanonicalHost form, the name trimmed and defaulting
// to the host, the bundle cleared unless bundle trust is chosen) and returns
// the problems keyed by form field.
func (t *Target) Validate(st config.Settings) map[string]string {
	errs := map[string]string{}
	var display string
	t.Host, display = CanonicalHost(t.Host)
	t.ServerName, _ = CanonicalHost(t.ServerName)
	t.Name = strings.TrimSpace(t.Name)
	if err := probe.ValidateHost(t.Host); err != nil {
		errs["host"] = "Enter a DNS name or an IP address"
	} else if ip := net.ParseIP(t.Host); ip != nil && probe.IsLocalIP(ip) && !st.General.AllowLocal {
		errs["host"] = "Loopback and link-local addresses are not allowed (Settings › General)"
	}
	if t.Port < 1 || t.Port > 65535 {
		errs["port"] = "Port must be 1 to 65535"
	}
	if _, err := probe.ParseProtocol(string(t.Protocol)); err != nil {
		errs["protocol"] = "Unknown protocol"
	}
	if t.ServerName != "" {
		if err := probe.ValidateHost(t.ServerName); err != nil || net.ParseIP(t.ServerName) != nil {
			errs["servername"] = "Enter a DNS name, or leave empty"
		}
	}
	switch t.Trust {
	case probe.TrustSystem, probe.TrustSelfSigned:
		t.BundleID = 0
	case probe.TrustBundle:
		if t.BundleID == 0 {
			errs["bundle_id"] = "Choose a CA bundle"
		}
	default:
		errs["trust_mode"] = "Choose a trust mode"
	}
	if t.Name == "" {
		t.Name = display
	}
	if len(t.Name) > 120 {
		errs["name"] = "Name is limited to 120 characters"
	}
	rng := func(field string, p *int, lo, hi int, msg string) {
		if p != nil && (*p < lo || *p > hi) {
			errs[field] = msg
		}
	}
	rng("warn_days", t.WarnDays, 1, 365, "Warning must be 1 to 365 days")
	eff := t.Effective(st.Defaults)
	if t.CritDays != nil || t.WarnDays != nil {
		if eff.Crit < 1 || eff.Crit > eff.Warn-1 {
			errs["crit_days"] = fmt.Sprintf("Critical must be 1 to %d days (warning minus 1)", eff.Warn-1)
		}
	}
	if t.WarnPct != nil || t.CritPct != nil {
		if msg := config.CheckPct(eff.WarnPct, eff.CritPct); msg != "" {
			field := "crit_pct"
			if eff.WarnPct < 0 || eff.WarnPct > 99 {
				field = "warn_pct"
			}
			errs[field] = strings.ToUpper(msg[:1]) + msg[1:]
		}
	}
	rng("renewal_pct", t.RenewalPct, 50, 95, "The renewal point must be 50 to 95 % of the lifetime")
	rng("interval_s", t.IntervalS, 3600, 7*86400, "Interval must be 1 hour to 7 days")
	rng("timeout_s", t.TimeoutS, 2, 60, "Timeout must be 2 to 60 seconds")
	rng("retries", t.Retries, 0, 5, "Retries must be 0 to 5")
	rng("debounce", t.Debounce, 1, 5, "Debounce must be 1 to 5 checks")
	if t.RemindWarnS != nil && *t.RemindWarnS != 0 && *t.RemindWarnS < 86400 {
		errs["remind_warn_s"] = "At least 1 day, or never"
	}
	if t.RemindCritS != nil && *t.RemindCritS != 0 && *t.RemindCritS < 3600 {
		errs["remind_crit_s"] = "At least 1 hour, or never"
	}
	if len(t.Notes) > 4000 {
		errs["notes"] = "Notes are limited to 4000 characters"
	}
	return errs
}

// SaveTarget creates (ID 0) or updates a target's configuration.
func (s *Service) SaveTarget(ctx context.Context, t Target, user string) (int64, error) {
	st := s.CurrentSettings(ctx) // read before the write transaction
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	id, err := s.saveTargetTx(ctx, tx, t, st, user)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.wake() // recovery notices of an endpoint now covered
	return id, nil
}

// SaveTargets saves several targets in one transaction, all or none, as a
// bulk edit does; enable, when set, then enables or disables each as
// SetEnabled does. On an error it returns the index of the target that
// failed.
func (s *Service) SaveTargets(ctx context.Context, ts []Target, enable *bool, user string) (int, error) {
	st := s.CurrentSettings(ctx)
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for i, t := range ts {
		if _, err := s.saveTargetTx(ctx, tx, t, st, user); err != nil {
			return i, err
		}
		if enable != nil && *enable != t.Enabled {
			if err := s.setEnabledTx(ctx, tx, t.ID, *enable); err != nil {
				return i, err
			}
		}
	}
	return 0, tx.Commit()
}

// AddTargets creates several targets in one transaction, all or none, as
// Add many does; one that exists already is skipped. It returns the IDs of
// those added (0 for a skipped one), or on an error the index of the
// target that failed.
func (s *Service) AddTargets(ctx context.Context, ts []Target, user string) ([]int64, int, error) {
	st := s.CurrentSettings(ctx)
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	ids := make([]int64, len(ts))
	for i, t := range ts {
		t.ID = 0
		id, err := s.saveTargetTx(ctx, tx, t, st, user)
		if errors.Is(err, ErrTargetExists) {
			continue // a failed statement leaves the transaction as it was
		}
		if err != nil {
			return nil, i, err
		}
		ids[i] = id
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	s.wake() // recovery notices of endpoints now covered
	return ids, 0, nil
}

func (s *Service) saveTargetTx(ctx context.Context, tx *sql.Tx, t Target, st config.Settings, user string) (int64, error) {
	def := st.Defaults
	now := s.now().Unix()
	// Only a new assignment needs a confirmed node: a target stays editable
	// while its node re-enrols.
	if t.NodeID != 0 {
		var cur sql.NullInt64
		if t.ID != 0 {
			if err := tx.QueryRowContext(ctx, "SELECT node_id FROM targets WHERE id = ?", t.ID).Scan(&cur); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return 0, err
			}
		}
		if cur.Int64 != t.NodeID {
			if err := assignableNodeTx(ctx, tx, t.NodeID); err != nil {
				return 0, err
			}
		}
	}
	if t.BundleID != 0 {
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM ca_bundles WHERE id = ?", t.BundleID).Scan(&n); err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, usererr.New("The chosen CA bundle no longer exists; choose another")
		}
	}
	args := []any{t.Name, t.Host, t.Port, string(t.Protocol), t.ServerName, string(t.Trust), nullID(t.BundleID),
		t.RenewalManaged, t.RenewalSet, t.ExpectedIssuer, nullInt(t.WarnDays), nullInt(t.CritDays), nullInt(t.IntervalS),
		nullInt(t.TimeoutS), nullInt(t.Retries), nullInt(t.Debounce), nullInt(t.RemindWarnS), nullInt(t.RemindCritS),
		t.AllAddresses, !t.SkipLegacy, t.AllChannels, strings.Join(t.Tags, ","), t.Notes, nullID(t.NodeID), t.Enabled,
		nullInt(t.WarnPct), nullInt(t.CritPct), nullInt(t.RenewalPct), now}
	if t.ID == 0 {
		res, err := tx.ExecContext(ctx, `INSERT INTO targets(name, host, port, protocol, servername, trust_mode, bundle_id,
			renewal_managed, renewal_set, expected_issuer, warn_days, crit_days, interval_s, timeout_s, retries, debounce,
			remind_warn_s, remind_crit_s, all_addresses, legacy_check, all_channels, tags, notes, node_id, enabled, warn_pct, crit_pct, renewal_pct,
			updated_at, created_at, created_by, status, next_check)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)`, append(args, now, user, StatusPending)...)
		if err != nil {
			return 0, uniqueTarget(err)
		}
		t.ID, _ = res.LastInsertId()
		// An endpoint discovery reported is in the inventory now.
		if _, err := s.coverUnknownEndpointsTx(ctx, tx, st, t.Host, t.Port, s.now()); err != nil {
			return 0, err
		}
	} else {
		var oldTrust, oldHost, oldSNI, oldProto string
		var oldPort int
		var oldLegacy bool
		var oldNode, oldInterval sql.NullInt64
		err := tx.QueryRowContext(ctx, "SELECT trust_mode, host, servername, port, protocol, legacy_check, node_id, interval_s FROM targets WHERE id = ?", t.ID).
			Scan(&oldTrust, &oldHost, &oldSNI, &oldPort, &oldProto, &oldLegacy, &oldNode, &oldInterval)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		if err != nil {
			return 0, err
		}
		_, err = tx.ExecContext(ctx, `UPDATE targets SET name=?, host=?, port=?, protocol=?, servername=?, trust_mode=?, bundle_id=?,
			renewal_managed=?, renewal_set=?, expected_issuer=?, warn_days=?, crit_days=?, interval_s=?, timeout_s=?, retries=?, debounce=?,
			remind_warn_s=?, remind_crit_s=?, all_addresses=?, legacy_check=?, all_channels=?, tags=?, notes=?, node_id=?, enabled=?,
			warn_pct=?, crit_pct=?, renewal_pct=?, updated_at=?, revision = revision + 1 WHERE id = ?`,
			append(args, t.ID)...)
		if err != nil {
			return 0, uniqueTarget(err)
		}
		// A new endpoint or trust mode starts a new pin; a new endpoint also
		// starts a new baseline, so its certificate is not a replacement.
		newEndpoint := oldHost != t.Host || oldSNI != t.ServerName || oldPort != t.Port || oldProto != string(t.Protocol)
		if newEndpoint || oldTrust != string(t.Trust) {
			if _, err := tx.ExecContext(ctx, "UPDATE targets SET pinned_fp = '', next_check = 0 WHERE id = ?", t.ID); err != nil {
				return 0, err
			}
		}
		if newEndpoint {
			if _, err := tx.ExecContext(ctx, "UPDATE targets SET current_fp = '', not_after = 0 WHERE id = ?", t.ID); err != nil {
				return 0, err
			}
		}
		// A new endpoint, or the test switched on or off, forgets the last
		// test of the old versions, so the next check runs it.
		if newEndpoint || oldLegacy == t.SkipLegacy {
			if _, err := tx.ExecContext(ctx, "UPDATE targets SET legacy_checked = 0, legacy_accepted = '', grade = '', grade_reasons = '', grade_rules = 0, config_test = '', pq = '' WHERE id = ?", t.ID); err != nil {
				return 0, err
			}
		}
		// A shorter interval takes effect now, not after the old slot: the
		// next check moves to the first slot of the new interval.
		was := def.IntervalS
		if oldInterval.Valid {
			was = int(oldInterval.Int64)
		}
		if iv := t.Effective(def).IntervalS; iv < was {
			next := NextCheck(t.ID, time.Duration(iv)*time.Second, s.now())
			if _, err := tx.ExecContext(ctx, "UPDATE targets SET next_check = ? WHERE id = ? AND next_check > ?", next.Unix(), t.ID, next.Unix()); err != nil {
				return 0, err
			}
		}
		// Another node is a new view of the service, as a new host is.
		if oldNode.Int64 != t.NodeID {
			if err := newVantageTx(ctx, tx, "id = ?", t.ID); err != nil {
				return 0, err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM target_channels WHERE target_id = ?", t.ID); err != nil {
		return 0, err
	}
	if !t.AllChannels {
		for _, c := range t.ChannelIDs {
			if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO target_channels(target_id, channel_id) SELECT ?, id FROM channels WHERE id = ?", t.ID, c); err != nil {
				return 0, err
			}
		}
	}
	if _, err := s.refreshStatusTx(ctx, tx, t.ID); err != nil {
		return 0, err
	}
	return t.ID, nil
}

func uniqueTarget(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrTargetExists
	}
	return err
}

// SetEnabled enables or disables a target. Disabling resolves its open
// findings without recovery notices.
func (s *Service) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.setEnabledTx(ctx, tx, id, enabled); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) setEnabledTx(ctx context.Context, tx *sql.Tx, id int64, enabled bool) error {
	res, err := tx.ExecContext(ctx, "UPDATE targets SET enabled = ?, next_check = 0, updated_at = ?, revision = revision + 1 WHERE id = ?", enabled, s.now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if !enabled {
		if _, err := tx.ExecContext(ctx, "UPDATE findings SET resolved_at = ? WHERE target_id = ? AND resolved_at = 0", s.now().Unix(), id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE targets SET fail_streak = 0, ok_streak = 0, dns_fail_streak = 0, dns_ok_streak = 0 WHERE id = ?", id); err != nil {
			return err
		}
	}
	_, err = s.refreshStatusTx(ctx, tx, id)
	return err
}

// DeleteImpact counts what deleting a target removes.
type DeleteImpact struct {
	Observations int
	Findings     int
	OpenFindings int
	Alerts       int
}

// TargetDeleteImpact returns what deleting a target would remove.
func (s *Service) TargetDeleteImpact(ctx context.Context, id int64) (DeleteImpact, error) {
	var d DeleteImpact
	err := s.DB.R.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM observations WHERE target_id = ?1),
		(SELECT COUNT(*) FROM findings WHERE target_id = ?1),
		(SELECT COUNT(*) FROM findings WHERE target_id = ?1 AND resolved_at = 0),
		(SELECT COUNT(*) FROM alerts a JOIN findings f ON f.id = a.finding_id WHERE f.target_id = ?1)`, id).
		Scan(&d.Observations, &d.Findings, &d.OpenFindings, &d.Alerts)
	return d, err
}

// DeleteTarget removes a target with its history.
func (s *Service) DeleteTarget(ctx context.Context, id int64) error {
	res, err := s.DB.W.ExecContext(ctx, "DELETE FROM targets WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Slotted is a target's place in the schedule.
type Slotted struct {
	Next int64 // next check, Unix seconds; 0: as soon as possible
	Node int64 // the node it is probed from, 0 for this server
}

// Schedule returns the next check time and node of every enabled target.
func (s *Service) Schedule(ctx context.Context) (map[int64]Slotted, error) {
	rows, err := s.DB.R.QueryContext(ctx, "SELECT id, next_check, COALESCE(node_id, 0) FROM targets WHERE enabled = 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[int64]Slotted{}
	for rows.Next() {
		var id int64
		var sl Slotted
		if err := rows.Scan(&id, &sl.Next, &sl.Node); err != nil {
			return nil, err
		}
		m[id] = sl
	}
	return m, rows.Err()
}

// newVantageTx resets the targets matching where for a new vantage point:
// the legacy test is forgotten, the debounce streaks start over and the
// next check is due now.
func newVantageTx(ctx context.Context, tx *sql.Tx, where string, args ...any) error {
	// #nosec G202 -- where is a clause of this package's own; its values are in args
	_, err := tx.ExecContext(ctx, `UPDATE targets SET legacy_checked = 0, legacy_accepted = '', grade = '', grade_reasons = '', grade_rules = 0, config_test = '', pq = '', fail_streak = 0, ok_streak = 0,
		dns_fail_streak = 0, dns_ok_streak = 0, next_check = 0 WHERE `+where, args...)
	return err
}

// Slot is the target's fixed offset within its interval, so checks are
// spread over the day and keep their time of day across restarts.
func Slot(id int64, interval time.Duration) time.Duration {
	h := fnv.New64a()
	fmt.Fprintf(h, "tlswatch-%d", id)
	return time.Duration(h.Sum64()%uint64(interval/time.Second)) * time.Second // #nosec G115 -- below the interval, which is positive
}

// NextCheck returns the next slot of the target after a check at now.
func NextCheck(id int64, interval time.Duration, now time.Time) time.Time {
	off := Slot(id, interval)
	base := now.Add(interval).Truncate(time.Second)
	k := (base.Unix() - int64(off/time.Second)) / int64(interval/time.Second)
	cand := time.Unix(k*int64(interval/time.Second)+int64(off/time.Second), 0)
	if cand.Before(now.Add(interval / 2)) {
		cand = cand.Add(interval)
	}
	return cand
}

// TagCounts returns every tag of ts with the number of targets carrying it.
func TagCounts(ts []Target) []TagCount {
	m := map[string]int{}
	var order []string
	for _, t := range ts {
		for _, g := range t.Tags {
			if m[g] == 0 {
				order = append(order, g)
			}
			m[g]++
		}
	}
	out := make([]TagCount, 0, len(order))
	for _, g := range order {
		out = append(out, TagCount{Tag: g, Count: m[g]})
	}
	sortTagCounts(out)
	return out
}

// TagCount is a tag and its number of targets.
type TagCount struct {
	Tag   string
	Count int
}

func sortTagCounts(ts []TagCount) {
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].Count != ts[j].Count {
			return ts[i].Count > ts[j].Count
		}
		return ts[i].Tag < ts[j].Tag
	})
}
