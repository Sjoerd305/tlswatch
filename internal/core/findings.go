package core

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

const findingCols = `f.id, f.target_id, f.kind, f.severity, f.opened_at, f.resolved_at, f.details, f.fingerprint, f.days_left,
	f.ack_by, f.ack_at, f.ack_until, f.ack_comment, f.last_alert_at`

func scanFinding(r interface{ Scan(...any) error }, extra ...any) (Finding, error) {
	var f Finding
	var kind, sev string
	var days sql.NullInt64
	dest := append([]any{&f.ID, &f.TargetID, &kind, &sev, &f.OpenedAt, &f.ResolvedAt, &f.Details, &f.Fingerprint, &days,
		&f.AckBy, &f.AckAt, &f.AckUntil, &f.AckComment, &f.LastAlertAt}, extra...)
	if err := r.Scan(dest...); err != nil {
		return f, err
	}
	f.Kind, f.Severity, f.DaysLeft = check.Kind(kind), check.Severity(sev), intPtr(days)
	return f, nil
}

// FindingFilter selects findings.
type FindingFilter struct {
	Resolved bool // false: open findings
	TargetID int64
	Limit    int
	Since    int64 // resolved findings: resolved at or after
}

// Findings lists findings with their target. Open findings are sorted by
// severity, then days left; resolved ones newest first.
func (s *Service) Findings(ctx context.Context, ff FindingFilter) ([]Finding, error) {
	q := "SELECT " + findingCols + `, t.name, t.host, t.port, t.protocol,
		COALESCE((SELECT GROUP_CONCAT(name, ', ') FROM (SELECT DISTINCT c.name FROM alerts a JOIN channels c ON c.id = a.channel_id
			WHERE a.finding_id = f.id AND a.created_at = f.last_alert_at)), '')
		FROM findings f JOIN targets t ON t.id = f.target_id WHERE `
	var args []any
	if ff.Resolved {
		q += "f.resolved_at > 0 AND f.severity != 'info'"
		if ff.Since > 0 {
			q += " AND f.resolved_at >= ?"
			args = append(args, ff.Since)
		}
	} else {
		q += "f.resolved_at = 0"
	}
	if ff.TargetID != 0 {
		q += " AND f.target_id = ?"
		args = append(args, ff.TargetID)
	}
	if ff.Resolved {
		q += " ORDER BY f.resolved_at DESC"
	} else {
		q += ` ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
			CASE WHEN f.days_left IS NULL THEN 1 ELSE 0 END, f.days_left, f.opened_at`
	}
	if ff.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, ff.Limit)
	}
	rows, err := s.DB.R.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		var name, host, proto, via string
		var port int
		f, err := scanFinding(rows, &name, &host, &port, &proto, &via)
		if err != nil {
			return nil, err
		}
		f.TargetName, f.TargetHost, f.TargetPort, f.TargetProtocol, f.LastAlertVia = name, host, port, proto, via
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !ff.Resolved {
		// Acknowledged findings sink below unacknowledged ones of the same severity.
		now := s.now()
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].Severity != out[j].Severity {
				return false
			}
			return !out[i].Acked(now) && out[j].Acked(now)
		})
	}
	return out, nil
}

// Finding returns one finding with its target.
func (s *Service) Finding(ctx context.Context, id int64) (Finding, error) {
	var name, host, proto string
	var port int
	f, err := scanFinding(s.DB.R.QueryRowContext(ctx, "SELECT "+findingCols+", t.name, t.host, t.port, t.protocol FROM findings f JOIN targets t ON t.id = f.target_id WHERE f.id = ?", id),
		&name, &host, &port, &proto)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	f.TargetName, f.TargetHost, f.TargetPort, f.TargetProtocol = name, host, port, proto
	return f, err
}

// AlertEntry is one delivery in the alert log.
type AlertEntry struct {
	ID          int64
	FindingID   int64
	Channel     string
	Event       string
	CreatedAt   int64
	State       string
	Attempts    int
	SentAt      int64
	Error       string
	Subject     string
	NextAttempt int64
	Ref         string // the SMTP Message-ID it went out under
}

// Alerts returns the alert log of a finding or of all findings of a target.
func (s *Service) Alerts(ctx context.Context, findingID, targetID int64, limit int) ([]AlertEntry, error) {
	q := `SELECT a.id, COALESCE(a.finding_id, 0), c.name, a.event, a.created_at, a.state, a.attempts, a.sent_at, a.error, a.subject, a.next_attempt, a.ref
		FROM alerts a JOIN channels c ON c.id = a.channel_id `
	var arg int64
	if findingID != 0 {
		q += "WHERE a.finding_id = ?"
		arg = findingID
	} else {
		q += "JOIN findings f ON f.id = a.finding_id WHERE f.target_id = ?"
		arg = targetID
	}
	q += " ORDER BY a.id DESC LIMIT ?"
	rows, err := s.DB.R.QueryContext(ctx, q, arg, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertEntry
	for rows.Next() {
		var a AlertEntry
		if err := rows.Scan(&a.ID, &a.FindingID, &a.Channel, &a.Event, &a.CreatedAt, &a.State, &a.Attempts, &a.SentAt, &a.Error, &a.Subject, &a.NextAttempt, &a.Ref); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Acknowledge acknowledges a finding, optionally until a date. On a change
// finding it resolves the finding and, for a pinned target, re-pins.
func (s *Service) Acknowledge(ctx context.Context, id int64, user string, until time.Time, comment string) (Finding, error) {
	f, err := s.Finding(ctx, id)
	if err != nil {
		return f, err
	}
	if !f.Open() {
		return f, &InputError{"The finding is already resolved"}
	}
	now := s.now().Unix()
	var untilU int64
	if !until.IsZero() {
		if until.Unix() <= now {
			return f, &InputError{"The until date must be in the future"}
		}
		untilU = until.Unix()
	}
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return f, err
	}
	defer tx.Rollback()
	resolved := int64(0)
	if f.Kind.AckResolves() {
		resolved = now
		untilU = 0
		if f.Kind == check.CertificateChanged && f.Fingerprint != "" {
			if _, err := tx.ExecContext(ctx, "UPDATE targets SET pinned_fp = ? WHERE id = ? AND trust_mode = ?", f.Fingerprint, f.TargetID, string(probe.TrustSelfSigned)); err != nil {
				return f, err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE findings SET ack_by=?, ack_at=?, ack_until=?, ack_comment=?, resolved_at=? WHERE id=?",
		user, now, untilU, strings.TrimSpace(comment), resolved, id); err != nil {
		return f, err
	}
	if _, err := s.refreshStatusTx(ctx, tx, f.TargetID); err != nil {
		return f, err
	}
	if err := tx.Commit(); err != nil {
		return f, err
	}
	return s.Finding(ctx, id)
}

// Unacknowledge removes an acknowledgement so reminders resume.
func (s *Service) Unacknowledge(ctx context.Context, id int64) error {
	res, err := s.DB.W.ExecContext(ctx, "UPDATE findings SET ack_by='', ack_at=0, ack_until=0, ack_comment='' WHERE id=? AND resolved_at = 0", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Remind queues reminders for open, unacknowledged findings whose reminder
// interval has passed.
func (s *Service) Remind(ctx context.Context) (int, error) {
	st := s.CurrentSettings(ctx)
	now := s.now()
	findings, err := s.Findings(ctx, FindingFilter{})
	if err != nil {
		return 0, err
	}
	targets := map[int64]Target{}
	queued := 0
	for _, f := range findings {
		if f.Severity == check.Info || f.Acked(now) {
			continue
		}
		t, ok := targets[f.TargetID]
		if !ok {
			if t, err = s.Target(ctx, f.TargetID); err != nil {
				continue
			}
			targets[f.TargetID] = t
		}
		if !t.Enabled {
			continue
		}
		eff := t.Effective(st.Defaults)
		every := eff.RemindWarnS
		if f.Severity == check.Critical {
			every = eff.RemindCritS
		}
		if every <= 0 || f.LastAlertAt+int64(every) > now.Unix() {
			continue
		}
		chans, err := s.recipients(ctx, t)
		if err != nil {
			return queued, err
		}
		if f.Kind == check.Expiring && t.NotAfter > 0 {
			days := check.DaysLeft(time.Unix(t.NotAfter, 0), now) // as of now, not of the last check
			f.DaysLeft = &days
		}
		tx, err := s.DB.W.BeginTx(ctx, nil)
		if err != nil {
			return queued, err
		}
		al := s.newAlerter(tx, st, t, chans, now)
		if err := al.send(ctx, f, notify.EventRemind); err != nil {
			tx.Rollback()
			return queued, err
		}
		queued += al.queued
		if _, err := tx.ExecContext(ctx, "UPDATE findings SET last_alert_at = ? WHERE id = ?", now.Unix(), f.ID); err != nil {
			tx.Rollback()
			return queued, err
		}
		if err := tx.Commit(); err != nil {
			return queued, err
		}
	}
	if queued > 0 {
		s.wake()
	}
	return queued, nil
}
