package core

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strconv"
	"time"
)

// NavCounts are the live counts in the navigation.
type NavCounts struct {
	Targets      int
	Domains      int
	Certificates int
	Findings     int
	Critical     bool
	LastCheck    int64
	NextCheck    int64
}

// Nav returns the navigation counts. They decorate every page, so an error
// is logged and the page renders without them.
func (s *Service) Nav(ctx context.Context) NavCounts {
	var n NavCounts
	var crit int
	err := errors.Join(
		s.DB.R.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MAX(last_check), 0),
			COALESCE((SELECT MIN(next_check) FROM targets WHERE enabled = 1 AND next_check > 0), 0) FROM targets`).Scan(&n.Targets, &n.LastCheck, &n.NextCheck),
		s.DB.R.QueryRowContext(ctx, `SELECT COUNT(DISTINCT o.leaf_fp) FROM targets t
			JOIN observations o ON o.check_id = t.last_check_id AND o.target_id = t.id WHERE o.leaf_fp != ''`).Scan(&n.Certificates),
		s.DB.R.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(severity = 'critical'), 0) FROM findings f LEFT JOIN targets t ON t.id = f.target_id
			LEFT JOIN domains d ON d.id = f.domain_id WHERE f.resolved_at = 0 AND (t.enabled = 1 OR f.node_id IS NOT NULL OR d.enabled = 1)`).Scan(&n.Findings, &crit),
		s.DB.R.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains`).Scan(&n.Domains),
	)
	if err != nil && ctx.Err() == nil && s.Log != nil {
		s.Log.Warn("navigation counts", "err", err)
	}
	n.Critical = crit > 0
	return n
}

// Stamp summarises everything the live pages show; it changes when a check
// lands, a target or finding changes, or an alert is queued or delivered
// (triggers bump the changes counter), or a scan moves. Pending counts
// the work under way that the pages follow closely: enabled targets never
// checked, and running scans.
func (s *Service) Stamp(ctx context.Context) (stamp string, pending int, err error) {
	var n int64
	err = s.DB.R.QueryRowContext(ctx, `SELECT (SELECT n FROM changes),
		(SELECT COUNT(*) FROM targets WHERE enabled = 1 AND last_check = 0) + (SELECT COUNT(*) FROM scans WHERE state = 'running')`).Scan(&n, &pending)
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

// Overview gathers the home screen: counts from aggregate queries, and
// only the eight targets it lists.
func (s *Service) Overview(ctx context.Context) (Overview, error) {
	var o Overview
	now := s.now()
	o.MinWarn = s.CurrentSettings(ctx).Defaults.Manual.WarnDays
	rows, err := s.DB.R.QueryContext(ctx, "SELECT status, COUNT(*) FROM targets GROUP BY status")
	if err != nil {
		return o, err
	}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			rows.Close()
			return o, err
		}
		o.Total += n
		switch status {
		case StatusCritical:
			o.Critical = n
		case StatusWarning:
			o.Warning += n
		case StatusChanged:
			o.Warning += n
			o.Changed = n
		case StatusHealthy:
			o.Healthy = n
		case StatusUnreachable:
			o.Unreachable = n
		case StatusDisabled:
			o.Disabled = n
		case StatusPending:
			o.Pending = n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return o, err
	}
	// Fewer than 30 whole days left (check.DaysLeft) is less than 30 days.
	// Only healthy targets count: the line is under the Healthy tile, and a
	// target past its warning threshold is already in another tile.
	err = s.DB.R.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(enabled = 1 AND status = ? AND not_after > 0 AND not_after < ?), 0),
		COALESCE(MAX(last_check), 0),
		COALESCE(MIN(CASE WHEN enabled = 1 AND next_check > 0 THEN next_check END), 0)
		FROM targets`, StatusHealthy, now.Add(30*24*time.Hour).Unix()).Scan(&o.DueWithin30, &o.LastCheck, &o.NextCheck)
	if err != nil {
		return o, err
	}
	if o.Targets, err = s.queryTargets(ctx, "t.enabled = 1 AND t.current_fp IN (SELECT fingerprint FROM certificates)", 0); err != nil {
		return o, err
	}
	SortExpiring(o.Targets, now)
	if o.Open, err = s.Findings(ctx, FindingFilter{Limit: 8}); err != nil {
		return o, err
	}
	if o.Changes, err = s.RecentChanges(ctx, now.Add(-14*24*time.Hour).Unix(), 6); err != nil {
		return o, err
	}
	o.Last24h, err = s.Summary(ctx, now.Add(-24*time.Hour).Unix(), now.Unix())
	return o, err
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

// RecentChanges returns certificate changes and resolved findings since a
// moment, newest first.
func (s *Service) RecentChanges(ctx context.Context, since int64, limit int) ([]Finding, error) {
	rows, err := s.DB.R.QueryContext(ctx, "SELECT "+findingCols+", "+findingSubject+" FROM findings f"+findingJoins+`
		WHERE (f.kind IN ('certificate_changed', 'grade_changed', 'certificate_issued') AND f.opened_at >= ?) OR (f.resolved_at >= ? AND f.severity != 'info' AND f.resolved_at > f.opened_at)
		ORDER BY MAX(f.opened_at, f.resolved_at) DESC LIMIT ?`, since, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var name, host, proto string
		var port int
		f, err := scanFinding(rows, &name, &host, &port, &proto)
		if err != nil {
			return nil, err
		}
		f.TargetName, f.TargetHost, f.TargetPort, f.TargetProtocol = name, host, port, proto
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
	err = s.DB.R.QueryRowContext(ctx, `SELECT COALESCE(SUM(kind = 'unreachable'), 0), COALESCE(SUM(kind = 'dns_failed'), 0) FROM findings
		WHERE resolved_at = 0 AND kind IN ('unreachable', 'dns_failed')`).Scan(&r.Unreachable, &r.DNSFailed)
	if err != nil {
		return r, err
	}
	err = s.DB.R.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(GROUP_CONCAT(DISTINCT c.name), '') FROM alerts a JOIN channels c ON c.id = a.channel_id
		WHERE a.state = 'sent' AND a.sent_at >= ? AND a.event != 'test'`, from).Scan(&r.Alerts, &r.AlertVia)
	if err != nil {
		return r, err
	}
	if r.From == 0 {
		r.From = from
	}
	return r, nil
}

// SortExpiring orders targets by expiry, soonest first. When the lifetimes
// of their leaves differ by more than a factor of four it orders by the
// share of the lifetime remaining instead, so a 1-year certificate with 20
// days (5 %) left ranks above a 6-day certificate with two days (33 %)
// left, which is on its normal cycle.
func SortExpiring(ts []Target, now time.Time) {
	var shortest, longest int64
	for _, t := range ts {
		if t.Cert == nil || t.Cert.NotAfter <= t.Cert.NotBefore {
			continue
		}
		l := t.Cert.NotAfter - t.Cert.NotBefore
		if shortest == 0 || l < shortest {
			shortest = l
		}
		longest = max(longest, l)
	}
	if shortest > 0 && longest > 4*shortest {
		slices.SortStableFunc(ts, func(a, b Target) int { return cmp.Compare(a.ShareLeft(now), b.ShareLeft(now)) })
		return
	}
	slices.SortStableFunc(ts, func(a, b Target) int { return cmp.Compare(a.NotAfter, b.NotAfter) })
}
