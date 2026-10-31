package core

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

const findingCols = `f.id, COALESCE(f.target_id, 0), f.kind, f.severity, f.opened_at, f.resolved_at, f.details, f.fingerprint, f.days_left,
	f.ack_by, f.ack_at, f.ack_until, f.ack_comment, f.last_alert_at, COALESCE(f.node_id, 0), COALESCE(f.domain_id, 0), COALESCE(f.schedule_id, 0)`

// findingSubject joins a finding's target, its node, its domain watch or
// its scan schedule, and selects the name, host, port and protocol shown
// with it. A schedule finding shows the schedule's label and the endpoint.
const findingSubject = `COALESCE(t.name, n.name, d.name, CASE WHEN ss.id IS NULL THEN NULL WHEN ss.name != '' THEN ss.name ELSE 'scan of ' || ss.ranges END, ''),
	COALESCE(t.host, json_extract(n.facts, '$.hostname'), d.name, CASE WHEN ss.id IS NULL THEN NULL ELSE f.fingerprint END, ''), COALESCE(t.port, 0), COALESCE(t.protocol, '')`

const findingJoins = ` LEFT JOIN targets t ON t.id = f.target_id LEFT JOIN nodes n ON n.id = f.node_id LEFT JOIN domains d ON d.id = f.domain_id LEFT JOIN scan_schedules ss ON ss.id = f.schedule_id `

// findingAcked is the condition that an acknowledgement is in force on a
// finding at the time given as its one parameter.
const findingAcked = `(f.ack_at > 0 AND (f.ack_until = 0 OR f.ack_until > ?))`

// findingSubjectLive is the condition that a finding's subject is enabled,
// for the counts that leave disabled targets and watches out.
const findingSubjectLive = `(t.enabled = 1 OR f.node_id IS NOT NULL OR d.enabled = 1 OR ss.enabled = 1)`

func scanFinding(r interface{ Scan(...any) error }, extra ...any) (Finding, error) {
	var f Finding
	var kind, sev string
	var days sql.NullInt64
	dest := append([]any{&f.ID, &f.TargetID, &kind, &sev, &f.OpenedAt, &f.ResolvedAt, &f.Details, &f.Fingerprint, &days,
		&f.AckBy, &f.AckAt, &f.AckUntil, &f.AckComment, &f.LastAlertAt, &f.NodeID, &f.DomainID, &f.ScheduleID}, extra...)
	if err := r.Scan(dest...); err != nil {
		return f, err
	}
	f.Kind, f.Severity, f.DaysLeft = check.Kind(kind), check.Severity(sev), intPtr(days)
	return f, nil
}

// FindingFilter selects findings.
type FindingFilter struct {
	Resolved   bool // false: open findings
	TargetID   int64
	DomainID   int64
	ScheduleID int64
	// Unacknowledged leaves out the open findings an acknowledgement is in
	// force on: the lists of things to look at.
	Unacknowledged bool
	Limit          int
	Since          int64 // resolved findings: resolved at or after
}

// Findings lists findings with their target. Open findings are sorted by
// severity, then days left; resolved ones newest first.
func (s *Service) Findings(ctx context.Context, ff FindingFilter) ([]Finding, error) {
	q := "SELECT " + findingCols + ", " + findingSubject + `,
		COALESCE((SELECT GROUP_CONCAT(name, ', ') FROM (SELECT DISTINCT c.name FROM alerts a JOIN channels c ON c.id = a.channel_id
			WHERE a.finding_id = f.id AND a.created_at = f.last_alert_at)), '')
		FROM findings f` + findingJoins + `WHERE `
	var args []any
	if ff.Resolved {
		q += "f.resolved_at > 0 AND f.severity != 'info'"
		if ff.Since > 0 {
			q += " AND f.resolved_at >= ?"
			args = append(args, ff.Since)
		}
	} else {
		q += "f.resolved_at = 0"
		if ff.Unacknowledged {
			q += " AND NOT " + findingAcked
			args = append(args, s.now().Unix())
		}
	}
	if ff.TargetID != 0 {
		q += " AND f.target_id = ?"
		args = append(args, ff.TargetID)
	}
	if ff.DomainID != 0 {
		q += " AND f.domain_id = ?"
		args = append(args, ff.DomainID)
	}
	if ff.ScheduleID != 0 {
		q += " AND f.schedule_id = ?"
		args = append(args, ff.ScheduleID)
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
	f, err := scanFinding(s.DB.R.QueryRowContext(ctx, "SELECT "+findingCols+", "+findingSubject+" FROM findings f"+findingJoins+"WHERE f.id = ?", id),
		&name, &host, &port, &proto)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	f.TargetName, f.TargetHost, f.TargetPort, f.TargetProtocol = name, host, port, proto
	return f, err
}

// OpenFindings counts the open findings of a kind about a certificate.
func (s *Service) OpenFindings(ctx context.Context, kind check.Kind, fp string) (int, error) {
	var n int
	err := s.DB.R.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings WHERE kind = ? AND fingerprint = ? AND resolved_at = 0", string(kind), fp).Scan(&n)
	return n, err
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
	Ref         string // the SMTP Message-ID, Telegram "chat:message_id" per chat, a Discord or ntfy message ID, or the ref a webhook payload carried
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
		return f, usererr.New("The finding is already resolved")
	}
	now := s.now().Unix()
	var untilU int64
	if !until.IsZero() {
		if until.Unix() <= now {
			return f, usererr.New("The until date must be in the future")
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
	// Only while still open: a check may have resolved it since it was
	// read, and an acknowledgement must not reopen it.
	res, err := tx.ExecContext(ctx, "UPDATE findings SET ack_by=?, ack_at=?, ack_until=?, ack_comment=?, resolved_at=? WHERE id=? AND resolved_at = 0",
		user, now, untilU, strings.TrimSpace(comment), resolved, id)
	if err != nil {
		return f, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return f, usererr.New("The finding is already resolved")
	}
	if f.TargetID != 0 {
		if _, err := s.refreshStatusTx(ctx, tx, f.TargetID); err != nil {
			return f, err
		}
	}
	if err := tx.Commit(); err != nil {
		return f, err
	}
	if f.DomainID != 0 && f.Kind == check.CAAViolation {
		if _, err := s.DB.W.ExecContext(ctx, "UPDATE issuances SET caa = ? WHERE id = ? AND domain_id = ?", CAAAcknowledged, f.Fingerprint, f.DomainID); err != nil {
			return f, err
		}
	}
	if f.DomainID != 0 && f.Kind == check.UnexpectedCertificate {
		if iid, err := strconv.ParseInt(f.Fingerprint, 10, 64); err == nil {
			if err := s.ackIssuanceRow(ctx, iid, user, comment); err != nil {
				return f, err
			}
		}
	}
	return s.Finding(ctx, id)
}

// Unacknowledge removes an acknowledgement so reminders resume and the
// target, if it was acknowledged, is a warning again.
func (s *Service) Unacknowledge(ctx context.Context, id int64) error {
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var targetID int64
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(target_id, 0) FROM findings WHERE id = ? AND resolved_at = 0", id).Scan(&targetID); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE findings SET ack_by='', ack_at=0, ack_until=0, ack_comment='' WHERE id=? AND resolved_at = 0", id); err != nil {
		return err
	}
	if targetID != 0 {
		if _, err := s.refreshStatusTx(ctx, tx, targetID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// RefreshStatuses recomputes every target's stored status from its state
// and findings, and reports how many changed. Run once at start, so a
// status rule that changed with an upgrade (acknowledged, say) applies to
// every target at once and not only after its next check.
func (s *Service) RefreshStatuses(ctx context.Context) (int, error) {
	rows, err := s.DB.R.QueryContext(ctx, "SELECT id, status FROM targets")
	if err != nil {
		return 0, err
	}
	var ids []int64
	was := map[int64]string{}
	for rows.Next() {
		var id int64
		var status string
		if err := rows.Scan(&id, &status); err != nil {
			_ = rows.Close()
			return 0, err
		}
		ids = append(ids, id)
		was[id] = status
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	n := 0
	for _, id := range ids {
		status, err := s.refreshStatusTx(ctx, tx, id)
		if err != nil {
			return 0, err
		}
		if status != was[id] {
			n++
		}
	}
	return n, tx.Commit()
}

// ExpireAcknowledgements returns to warning the acknowledged targets whose
// acknowledgement has passed its until-date, and reports how many. The
// status is stored, so the passing of a date has to be noticed by someone;
// the scheduler asks every minute.
func (s *Service) ExpireAcknowledgements(ctx context.Context) (int, error) {
	rows, err := s.DB.R.QueryContext(ctx, `SELECT DISTINCT f.target_id FROM findings f JOIN targets t ON t.id = f.target_id
		WHERE t.status = ? AND f.resolved_at = 0 AND f.ack_at > 0 AND f.ack_until > 0 AND f.ack_until <= ?`, StatusAcknowledged, s.now().Unix())
	if err != nil {
		return 0, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		tx, err := s.DB.W.BeginTx(ctx, nil)
		if err != nil {
			return n, err
		}
		status, err := s.refreshStatusTx(ctx, tx, id)
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if err != nil {
			return n, err
		}
		if status != StatusAcknowledged {
			n++
		}
	}
	return n, nil
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
	recipients := map[int64][]notify.Channel{} // per target, listed once per run
	// An open renewal_overdue speaks for a warning-level expiring, as when
	// they opened.
	overdue := map[int64]bool{}
	for _, f := range findings {
		if f.Kind == check.RenewalOverdue {
			overdue[f.TargetID] = true
		}
	}
	queued := 0
	for _, f := range findings {
		if f.Severity == check.Info || f.Acked(now) {
			continue
		}
		if f.Kind == check.Expiring && f.Severity == check.Warning && overdue[f.TargetID] {
			continue
		}
		if f.NodeID != 0 {
			n, err := s.remindNode(ctx, st, f, now)
			if err != nil {
				return queued, err
			}
			queued += n
			continue
		}
		if f.DomainID != 0 {
			n, err := s.remindDomain(ctx, st, f, now)
			if err != nil {
				return queued, err
			}
			queued += n
			continue
		}
		if f.ScheduleID != 0 {
			n, err := s.remindSchedule(ctx, st, f, now)
			if err != nil {
				return queued, err
			}
			queued += n
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
		chans, ok := recipients[t.ID]
		if !ok {
			if chans, err = s.recipients(ctx, t); err != nil {
				return queued, err
			}
			recipients[t.ID] = chans
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
			_ = tx.Rollback()
			return queued, err
		}
		queued += al.queued
		if _, err := tx.ExecContext(ctx, "UPDATE findings SET last_alert_at = ? WHERE id = ?", now.Unix(), f.ID); err != nil {
			_ = tx.Rollback()
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
