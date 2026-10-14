package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

const targetCols = `t.id, t.name, t.host, t.port, t.protocol, t.servername, t.trust_mode, COALESCE(t.bundle_id, 0), COALESCE(b.name, ''),
	t.renewal_managed, t.renewal_set, t.expected_issuer, t.warn_days, t.crit_days, t.interval_s, t.timeout_s, t.retries, t.debounce,
	t.remind_warn_s, t.remind_crit_s, t.all_addresses, t.all_channels, t.tags, t.notes, t.enabled, t.created_at, t.created_by, t.updated_at,
	t.status, t.pinned_fp, t.current_fp, t.not_after, t.tls_version, t.address_count, t.last_check, t.last_error,
	t.fail_streak, t.ok_streak, t.dns_fail_streak, t.dns_ok_streak, t.next_check`

const targetFrom = ` FROM targets t LEFT JOIN ca_bundles b ON b.id = t.bundle_id `

func scanTarget(r interface{ Scan(...any) error }) (Target, error) {
	var t Target
	var proto, trust, tags string
	var warn, crit, interval, timeout, retries, debounce, rw, rc sql.NullInt64
	err := r.Scan(&t.ID, &t.Name, &t.Host, &t.Port, &proto, &t.ServerName, &trust, &t.BundleID, &t.BundleName,
		&t.RenewalManaged, &t.RenewalSet, &t.ExpectedIssuer, &warn, &crit, &interval, &timeout, &retries, &debounce,
		&rw, &rc, &t.AllAddresses, &t.AllChannels, &tags, &t.Notes, &t.Enabled, &t.CreatedAt, &t.CreatedBy, &t.UpdatedAt,
		&t.Status, &t.PinnedFP, &t.CurrentFP, &t.NotAfter, &t.TLSVersion, &t.AddressCount, &t.LastCheck, &t.LastError,
		&t.FailStreak, &t.OkStreak, &t.DNSFail, &t.DNSOk, &t.NextCheck)
	if err != nil {
		return t, err
	}
	t.Protocol, t.Trust = probe.Protocol(proto), probe.TrustMode(trust)
	t.WarnDays, t.CritDays, t.IntervalS, t.TimeoutS = intPtr(warn), intPtr(crit), intPtr(interval), intPtr(timeout)
	t.Retries, t.Debounce, t.RemindWarnS, t.RemindCritS = intPtr(retries), intPtr(debounce), intPtr(rw), intPtr(rc)
	if tags != "" {
		t.Tags = strings.Split(tags, ",")
	}
	return t, nil
}

// Targets returns every target with its current certificate, sorted by
// expiry (unknown and disabled last).
func (s *Service) Targets(ctx context.Context) ([]Target, error) {
	rows, err := s.DB.R.QueryContext(ctx, "SELECT "+targetCols+targetFrom+
		" ORDER BY t.enabled DESC, CASE WHEN t.not_after = 0 THEN 1 ELSE 0 END, t.not_after, t.name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	certs, err := s.currentCerts(ctx)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if c, ok := certs[out[i].CurrentFP]; ok {
			cc := c
			out[i].Cert = &cc
		}
	}
	return out, nil
}

func (s *Service) currentCerts(ctx context.Context) (map[string]Certificate, error) {
	rows, err := s.DB.R.QueryContext(ctx, "SELECT "+certCols+" FROM certificates WHERE fingerprint IN (SELECT current_fp FROM targets)")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]Certificate{}
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		m[c.Fingerprint] = c
	}
	return m, rows.Err()
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

// Validate normalises the target in place (host and server name lower case
// without a trailing dot or IPv6 brackets, the name trimmed and defaulting
// to the host, the bundle cleared unless bundle trust is chosen) and returns
// the problems keyed by form field.
func (t *Target) Validate(st config.Settings) map[string]string {
	errs := map[string]string{}
	t.Host = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(t.Host)), ".")
	t.Host = strings.TrimSuffix(strings.TrimPrefix(t.Host, "["), "]")
	t.ServerName = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(t.ServerName)), ".")
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
		t.Name = t.Host
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
	now := s.now().Unix()
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var bundle any
	if t.BundleID != 0 {
		bundle = t.BundleID
	}
	args := []any{t.Name, t.Host, t.Port, string(t.Protocol), t.ServerName, string(t.Trust), bundle,
		t.RenewalManaged, t.RenewalSet, t.ExpectedIssuer, nullInt(t.WarnDays), nullInt(t.CritDays), nullInt(t.IntervalS),
		nullInt(t.TimeoutS), nullInt(t.Retries), nullInt(t.Debounce), nullInt(t.RemindWarnS), nullInt(t.RemindCritS),
		t.AllAddresses, t.AllChannels, strings.Join(t.Tags, ","), t.Notes, t.Enabled, now}
	if t.ID == 0 {
		res, err := tx.ExecContext(ctx, `INSERT INTO targets(name, host, port, protocol, servername, trust_mode, bundle_id,
			renewal_managed, renewal_set, expected_issuer, warn_days, crit_days, interval_s, timeout_s, retries, debounce,
			remind_warn_s, remind_crit_s, all_addresses, all_channels, tags, notes, enabled, updated_at, created_at, created_by, status, next_check)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)`, append(args, now, user, StatusPending)...)
		if err != nil {
			return 0, uniqueTarget(err)
		}
		t.ID, _ = res.LastInsertId()
	} else {
		var oldTrust, oldHost, oldSNI string
		err := tx.QueryRowContext(ctx, "SELECT trust_mode, host, servername FROM targets WHERE id = ?", t.ID).Scan(&oldTrust, &oldHost, &oldSNI)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		if err != nil {
			return 0, err
		}
		_, err = tx.ExecContext(ctx, `UPDATE targets SET name=?, host=?, port=?, protocol=?, servername=?, trust_mode=?, bundle_id=?,
			renewal_managed=?, renewal_set=?, expected_issuer=?, warn_days=?, crit_days=?, interval_s=?, timeout_s=?, retries=?, debounce=?,
			remind_warn_s=?, remind_crit_s=?, all_addresses=?, all_channels=?, tags=?, notes=?, enabled=?, updated_at=? WHERE id = ?`,
			append(args, t.ID)...)
		if err != nil {
			return 0, uniqueTarget(err)
		}
		// A new endpoint or trust mode starts a new pin and history baseline.
		if oldTrust != string(t.Trust) || oldHost != t.Host || oldSNI != t.ServerName {
			if _, err := tx.ExecContext(ctx, "UPDATE targets SET pinned_fp = '', next_check = 0 WHERE id = ?", t.ID); err != nil {
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
	return t.ID, tx.Commit()
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
	res, err := tx.ExecContext(ctx, "UPDATE targets SET enabled = ?, next_check = 0, updated_at = ? WHERE id = ?", enabled, s.now().Unix(), id)
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
	if _, err := s.refreshStatusTx(ctx, tx, id); err != nil {
		return err
	}
	return tx.Commit()
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

// Schedule returns the next check time of every enabled target.
func (s *Service) Schedule(ctx context.Context) (map[int64]int64, error) {
	rows, err := s.DB.R.QueryContext(ctx, "SELECT id, next_check FROM targets WHERE enabled = 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[int64]int64{}
	for rows.Next() {
		var id, next int64
		if err := rows.Scan(&id, &next); err != nil {
			return nil, err
		}
		m[id] = next
	}
	return m, rows.Err()
}

// Slot is the target's fixed offset within its interval, so checks are
// spread over the day and keep their time of day across restarts.
func Slot(id int64, interval time.Duration) time.Duration {
	h := fnv.New64a()
	fmt.Fprintf(h, "tlswatch-%d", id)
	return time.Duration(h.Sum64()%uint64(interval/time.Second)) * time.Second
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
