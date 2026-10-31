package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// Scheduled discovery (see the specification, "Discovery"): a scan
// definition that repeats daily or weekly. Each run is an ordinary scan,
// and every endpoint a run finds that no target covers opens an
// unknown_endpoint finding on the schedule, which alerts through the
// channels like any warning. The schedule stays what the specification
// calls discovery: it offers endpoints, it monitors none.

// Schedule repeats.
const (
	ScheduleDaily  = "day"
	ScheduleWeekly = "week"
)

// ScanSchedule is a scan that repeats.
type ScanSchedule struct {
	ID        int64
	Name      string // a label; Label falls back to the ranges
	Ranges    []string
	Ports     []int
	Rate      int
	NodeID    int64 // 0: this server
	NodeName  string
	Every     string // ScheduleDaily or ScheduleWeekly
	Weekday   int    // 0 Sunday to 6 Saturday, for ScheduleWeekly
	Hour      int    // 0 to 23, in the instance's time zone
	Enabled   bool
	CreatedAt int64
	CreatedBy string
	UpdatedAt int64
	// LastRun is when the last slot ran, or was skipped with LastNote;
	// LastScanID is that run's scan while it is kept, with LastScanState.
	LastRun       int64
	LastScanID    int64
	LastScanState string
	LastScanFound int
	LastNote      string
	OpenFindings  int
}

// Label is the schedule's name, or a description of its ranges.
func (sc ScanSchedule) Label() string {
	if sc.Name != "" {
		return sc.Name
	}
	return "scan of " + strings.Join(sc.Ranges, ", ")
}

// When says how often the schedule runs: "daily at 03:00" or "weekly on
// Monday at 03:00".
func (sc ScanSchedule) When() string {
	at := fmt.Sprintf("%02d:00", sc.Hour)
	if sc.Every == ScheduleWeekly {
		return "weekly on " + time.Weekday(sc.Weekday).String() + " at " + at
	}
	return "daily at " + at
}

// Slot is the latest scheduled moment at or before now, in now's location.
func (sc ScanSchedule) Slot(now time.Time) time.Time {
	slot := time.Date(now.Year(), now.Month(), now.Day(), sc.Hour, 0, 0, 0, now.Location())
	if sc.Every == ScheduleWeekly {
		back := (int(now.Weekday()) - sc.Weekday + 7) % 7
		slot = time.Date(now.Year(), now.Month(), now.Day()-back, sc.Hour, 0, 0, 0, now.Location())
		if slot.After(now) {
			slot = slot.AddDate(0, 0, -7)
		}
		return slot
	}
	if slot.After(now) {
		slot = slot.AddDate(0, 0, -1)
	}
	return slot
}

// NextRun is the first scheduled moment after now, or the slot that has
// not run yet when the schedule is behind.
func (sc ScanSchedule) NextRun(now time.Time) time.Time {
	slot := sc.Slot(now)
	if sc.LastRun < slot.Unix() {
		return slot
	}
	if sc.Every == ScheduleWeekly {
		return slot.AddDate(0, 0, 7)
	}
	return slot.AddDate(0, 0, 1)
}

// Due reports whether the schedule's latest slot has not run yet.
func (sc ScanSchedule) Due(now time.Time) bool {
	return sc.Enabled && sc.LastRun < sc.Slot(now).Unix()
}

// ScanScheduleInput is a schedule as an operator asks for it.
type ScanScheduleInput struct {
	Name    string
	Ranges  string
	Ports   string // empty: probe.DefaultScanPorts
	Rate    int    // 0: probe.DefaultScanRate
	NodeID  int64
	Every   string // ScheduleDaily or ScheduleWeekly
	Weekday int
	Hour    int
	Enabled bool
}

// validateSchedule checks a schedule the way CreateScan checks a scan, and
// returns it ready to store.
func (s *Service) validateSchedule(ctx context.Context, in ScanScheduleInput) (ScanSchedule, error) {
	sc := ScanSchedule{Name: Clip(strings.TrimSpace(in.Name), ShortMax), NodeID: in.NodeID, Every: in.Every, Weekday: in.Weekday, Hour: in.Hour, Enabled: in.Enabled}
	st := s.CurrentSettings(ctx)
	prefixes, _, err := ParseScanRanges(in.Ranges, st.General.PublicDiscovery, st.General.AllowLocal)
	if err != nil {
		return sc, err
	}
	for _, p := range prefixes {
		sc.Ranges = append(sc.Ranges, p.String())
	}
	if sc.Ports, err = ParseScanPorts(in.Ports); err != nil {
		return sc, err
	}
	sc.Rate = in.Rate
	if sc.Rate == 0 {
		sc.Rate = probe.DefaultScanRate
	}
	if sc.Rate < 1 || sc.Rate > probe.MaxScanRate {
		return sc, usererr.New(fmt.Sprintf("The rate must be 1 to %d connects per second", probe.MaxScanRate))
	}
	if sc.Every != ScheduleDaily && sc.Every != ScheduleWeekly {
		return sc, usererr.New("Choose daily or weekly")
	}
	if sc.Weekday < 0 || sc.Weekday > 6 {
		return sc, usererr.New("Choose a weekday")
	}
	if sc.Hour < 0 || sc.Hour > 23 {
		return sc, usererr.New("The hour must be 0 to 23")
	}
	if in.NodeID != 0 {
		n, err := s.Node(ctx, in.NodeID)
		if errors.Is(err, ErrNotFound) || err == nil && !n.Assignable() {
			return sc, usererr.New("Choose a confirmed node, or This server")
		}
		if err != nil {
			return sc, err
		}
		sc.NodeName = n.Label()
	}
	return sc, nil
}

// SaveScanSchedule adds a schedule (id 0) or changes one, and returns its
// id. A changed schedule keeps its findings: the next run settles them.
func (s *Service) SaveScanSchedule(ctx context.Context, id int64, in ScanScheduleInput, user string) (int64, error) {
	sc, err := s.validateSchedule(ctx, in)
	if err != nil {
		return 0, err
	}
	sc.ID = id
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if id, err = s.saveScheduleTx(ctx, tx, sc, user); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	action := "scan_schedule.update"
	if sc.ID == 0 {
		action = "scan_schedule.create"
	}
	s.Audit(ctx, user, action, fmt.Sprintf("scan schedule %d", id), scheduleDetail(sc))
	return id, nil
}

// saveScheduleTx writes a validated schedule: inserted when its ID is 0,
// else changed in place. Pausing one resolves its open findings quietly.
func (s *Service) saveScheduleTx(ctx context.Context, tx *sql.Tx, sc ScanSchedule, user string) (int64, error) {
	now := s.now().Unix()
	ranges, ports := strings.Join(sc.Ranges, ","), joinInts(sc.Ports)
	if sc.ID == 0 {
		res, err := tx.ExecContext(ctx, `INSERT INTO scan_schedules(name, ranges, ports, rate, node_id, every, weekday, hour, enabled, created_at, created_by, updated_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, sc.Name, ranges, ports, sc.Rate, nullID(sc.NodeID), sc.Every, sc.Weekday, sc.Hour, sc.Enabled, now, user, now)
		if err != nil {
			return 0, err
		}
		id, _ := res.LastInsertId()
		return id, nil
	}
	res, err := tx.ExecContext(ctx, `UPDATE scan_schedules SET name=?, ranges=?, ports=?, rate=?, node_id=?, every=?, weekday=?, hour=?, enabled=?, updated_at=? WHERE id = ?`,
		sc.Name, ranges, ports, sc.Rate, nullID(sc.NodeID), sc.Every, sc.Weekday, sc.Hour, sc.Enabled, now, sc.ID)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrNotFound
	}
	if !sc.Enabled {
		if _, err := tx.ExecContext(ctx, "UPDATE findings SET resolved_at = ? WHERE schedule_id = ? AND resolved_at = 0", now, sc.ID); err != nil {
			return 0, err
		}
	}
	return sc.ID, nil
}

func scheduleDetail(sc ScanSchedule) string {
	from := "this server"
	if sc.NodeName != "" {
		from = "node " + sc.NodeName
	}
	return fmt.Sprintf("ranges=%s ports=%s rate=%d from=%s every=%s weekday=%d hour=%d enabled=%v", strings.Join(sc.Ranges, ","), joinInts(sc.Ports), sc.Rate, from, sc.Every, sc.Weekday, sc.Hour, sc.Enabled)
}

// ScheduleEndpoint returns what a schedule's latest kept run recorded for
// an endpoint (address:port), for "Add as target" on its finding; ok is
// false when the runs that saw it are gone.
func (s *Service) ScheduleEndpoint(ctx context.Context, scheduleID int64, endpoint string) (ScanResult, Scan, bool, error) {
	host, portS, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ScanResult{}, Scan{}, false, nil
	}
	port, _ := strconv.Atoi(portS)
	var scanID int64
	err = s.DB.R.QueryRowContext(ctx, `SELECT r.scan_id FROM scan_results r JOIN scans s ON s.id = r.scan_id
		WHERE s.schedule_id = ? AND r.address = ? AND r.port = ? ORDER BY r.scan_id DESC LIMIT 1`, scheduleID, host, port).Scan(&scanID)
	if errors.Is(err, sql.ErrNoRows) {
		return ScanResult{}, Scan{}, false, nil
	}
	if err != nil {
		return ScanResult{}, Scan{}, false, err
	}
	scan, err := s.Scan(ctx, scanID)
	if err != nil {
		return ScanResult{}, Scan{}, false, err
	}
	results, err := s.ScanResults(ctx, scanID)
	if err != nil {
		return ScanResult{}, Scan{}, false, err
	}
	for _, r := range results {
		if r.Address == host && r.Port == port {
			return r, scan, true, nil
		}
	}
	return ScanResult{}, Scan{}, false, nil
}

// SetScanScheduleEnabled pauses or resumes a schedule. Pausing resolves its
// open findings without a notice; the first run after resuming opens what
// is still there.
func (s *Service) SetScanScheduleEnabled(ctx context.Context, id int64, enabled bool, user string) error {
	res, err := s.DB.W.ExecContext(ctx, "UPDATE scan_schedules SET enabled = ?, updated_at = ? WHERE id = ?", enabled, s.now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if !enabled {
		if err := s.resolveScheduleFindings(ctx, id); err != nil {
			return err
		}
	}
	s.Audit(ctx, user, "scan_schedule.update", fmt.Sprintf("scan schedule %d", id), fmt.Sprintf("enabled=%v", enabled))
	return nil
}

// resolveScheduleFindings resolves a schedule's open findings quietly.
func (s *Service) resolveScheduleFindings(ctx context.Context, id int64) error {
	_, err := s.DB.W.ExecContext(ctx, "UPDATE findings SET resolved_at = ? WHERE schedule_id = ? AND resolved_at = 0", s.now().Unix(), id)
	return err
}

// DeleteScanSchedule removes a schedule with its findings; its scans stay
// for their 7 days as one-off scans.
func (s *Service) DeleteScanSchedule(ctx context.Context, id int64, user string) error {
	sc, err := s.ScanSchedule(ctx, id)
	if err != nil {
		return err
	}
	if _, err := s.DB.W.ExecContext(ctx, "DELETE FROM scan_schedules WHERE id = ?", id); err != nil {
		return err
	}
	s.Audit(ctx, user, "scan_schedule.delete", fmt.Sprintf("scan schedule %d", id), "ranges="+strings.Join(sc.Ranges, ","))
	return nil
}

const scheduleCols = `ss.id, ss.name, ss.ranges, ss.ports, ss.rate, COALESCE(ss.node_id, 0), COALESCE(n.name, ''), ss.every, ss.weekday, ss.hour, ss.enabled,
	ss.created_at, ss.created_by, ss.updated_at, ss.last_run, COALESCE(ss.last_scan_id, 0), COALESCE(s.state, ''), COALESCE((SELECT COUNT(*) FROM scan_results r WHERE r.scan_id = s.id), 0), ss.last_note,
	(SELECT COUNT(*) FROM findings f WHERE f.schedule_id = ss.id AND f.resolved_at = 0)`

const scheduleFrom = ` FROM scan_schedules ss LEFT JOIN nodes n ON n.id = ss.node_id LEFT JOIN scans s ON s.id = ss.last_scan_id `

func scanSchedule(r interface{ Scan(...any) error }) (ScanSchedule, error) {
	var sc ScanSchedule
	var ranges, ports string
	err := r.Scan(&sc.ID, &sc.Name, &ranges, &ports, &sc.Rate, &sc.NodeID, &sc.NodeName, &sc.Every, &sc.Weekday, &sc.Hour, &sc.Enabled,
		&sc.CreatedAt, &sc.CreatedBy, &sc.UpdatedAt, &sc.LastRun, &sc.LastScanID, &sc.LastScanState, &sc.LastScanFound, &sc.LastNote, &sc.OpenFindings)
	if ranges != "" {
		sc.Ranges = strings.Split(ranges, ",")
	}
	for _, p := range strings.Split(ports, ",") {
		if n, err := strconv.Atoi(p); err == nil {
			sc.Ports = append(sc.Ports, n)
		}
	}
	return sc, err
}

// ScanSchedule returns one schedule.
func (s *Service) ScanSchedule(ctx context.Context, id int64) (ScanSchedule, error) {
	sc, err := scanSchedule(s.DB.R.QueryRowContext(ctx, "SELECT "+scheduleCols+scheduleFrom+"WHERE ss.id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return sc, ErrNotFound
	}
	return sc, err
}

// ScanSchedules returns every schedule, oldest first.
func (s *Service) ScanSchedules(ctx context.Context) ([]ScanSchedule, error) {
	rows, err := s.DB.R.QueryContext(ctx, "SELECT "+scheduleCols+scheduleFrom+"ORDER BY ss.id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanSchedule
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// DueScanSchedules returns the enabled schedules whose latest slot has not
// run, in the instance's time zone.
func (s *Service) DueScanSchedules(ctx context.Context) ([]ScanSchedule, error) {
	all, err := s.ScanSchedules(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now().In(s.CurrentSettings(ctx).Location())
	var due []ScanSchedule
	for _, sc := range all {
		if sc.Due(now) {
			due = append(due, sc)
		}
	}
	return due, nil
}

// ScheduleRunner is the user name a scheduled run is recorded under.
const ScheduleRunner = "schedule"

// StartScheduledScan records a run of a schedule: a scan with the
// schedule's settings, returned with its addresses for the scheduler to
// run. The slot counts as taken either way: a run that cannot start (a
// scan is already running from there, the node is gone, the ranges are no
// longer allowed) is noted on the schedule and not tried again before the
// next slot. user is ScheduleRunner for the scheduler and the operator's
// e-mail for Run now.
func (s *Service) StartScheduledScan(ctx context.Context, sc ScanSchedule, user string) (Scan, []netip.Addr, error) {
	now := s.now().Unix()
	in := ScanInput{Ranges: strings.Join(sc.Ranges, " "), Ports: joinInts(sc.Ports), Rate: sc.Rate, NodeID: sc.NodeID, ScheduleID: sc.ID}
	scan, addrs, err := s.CreateScan(ctx, in, user)
	if err != nil {
		note := "could not start: " + err.Error()
		if errors.Is(err, ErrScanBusy) {
			note = "skipped: a scan was already running from there"
		}
		if _, uerr := s.DB.W.ExecContext(ctx, "UPDATE scan_schedules SET last_run = ?, last_note = ? WHERE id = ?", now, Clip(note, TextMax), sc.ID); uerr != nil {
			return scan, nil, uerr
		}
		return scan, nil, err
	}
	_, err = s.DB.W.ExecContext(ctx, "UPDATE scan_schedules SET last_run = ?, last_scan_id = ?, last_note = '' WHERE id = ?", now, scan.ID, sc.ID)
	return scan, addrs, err
}

// ScheduleLink is the address of a schedule's page in alerts.
func (s *Service) ScheduleLink(st config.Settings, id int64) string {
	if st.General.BaseURL == "" {
		return ""
	}
	return fmt.Sprintf("%s/targets/discover/schedules/%d", st.General.BaseURL, id)
}

func (s *Service) scheduleAlerter(tx *sql.Tx, st config.Settings, sc ScanSchedule, chans []notify.Channel, now time.Time) *alerter {
	base := notify.AlertData{Discovery: true, TargetName: sc.Label(), Link: s.ScheduleLink(st, sc.ID), Loc: st.Location()}
	return &alerter{tx: tx, chans: chans, now: now, base: base}
}

// ReconcileScan settles a schedule's findings after one of its runs ended:
// an endpoint without a target that is not acknowledged opens or keeps an
// unknown_endpoint finding; one that a target now covers resolves its
// finding; and, when the run completed, so does an endpoint the run no
// longer found. A failed run resolves nothing it did not see: it may have
// stopped before reaching it. A one-off scan is left alone.
func (s *Service) ReconcileScan(ctx context.Context, scanID int64) error {
	scan, err := s.Scan(ctx, scanID)
	if err != nil {
		return err
	}
	if scan.ScheduleID == 0 {
		return nil
	}
	sc, err := s.ScanSchedule(ctx, scan.ScheduleID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	results, err := s.ScanResults(ctx, scanID)
	if err != nil {
		return err
	}
	st := s.CurrentSettings(ctx)
	chans, err := s.Channels.Enabled(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	open := map[string]Finding{}
	rows, err := tx.QueryContext(ctx, "SELECT "+findingCols+" FROM findings f WHERE f.schedule_id = ? AND f.kind = ? AND f.resolved_at = 0", sc.ID, string(check.UnknownEndpoint))
	if err != nil {
		return err
	}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			_ = rows.Close()
			return err
		}
		open[f.Fingerprint] = f
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// An endpoint an operator acknowledged is known and fine; it is not
	// reported again by this schedule.
	acked := map[string]bool{}
	rows, err = tx.QueryContext(ctx, "SELECT DISTINCT fingerprint FROM findings WHERE schedule_id = ? AND kind = ? AND resolved_at > 0 AND ack_at > 0", sc.ID, string(check.UnknownEndpoint))
	if err != nil {
		return err
	}
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			_ = rows.Close()
			return err
		}
		acked[ref] = true
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	al := s.scheduleAlerter(tx, st, sc, chans, now)
	resolve := func(f Finding) error {
		if _, err := tx.ExecContext(ctx, "UPDATE findings SET resolved_at = ? WHERE id = ? AND resolved_at = 0", now.Unix(), f.ID); err != nil {
			return err
		}
		delete(open, f.Fingerprint)
		return al.recover(ctx, f)
	}
	seen := map[string]bool{}
	for _, r := range results {
		ref := r.HostPort()
		seen[ref] = true
		if r.TargetID != 0 {
			if f, ok := open[ref]; ok {
				if err := resolve(f); err != nil {
					return err
				}
			}
			continue
		}
		if acked[ref] {
			continue
		}
		details := describeEndpoint(r, scan, st.Location())
		if old, ok := open[ref]; ok {
			if old.Details != details {
				if _, err := tx.ExecContext(ctx, "UPDATE findings SET details = ? WHERE id = ?", details, old.ID); err != nil {
					return err
				}
			}
			continue
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO findings(schedule_id, kind, severity, opened_at, details, fingerprint, last_alert_at) VALUES(?,?,?,?,?,?,?)`,
			sc.ID, string(check.UnknownEndpoint), string(check.Warning), now.Unix(), details, ref, now.Unix())
		if err != nil {
			return err
		}
		f := Finding{ScheduleID: sc.ID, Kind: check.UnknownEndpoint, Severity: check.Warning, Details: details, Fingerprint: ref, OpenedAt: now.Unix()}
		f.ID, _ = res.LastInsertId()
		open[ref] = f
		if err := al.send(ctx, f, notify.EventOpen); err != nil {
			return err
		}
	}
	if scan.State == ScanDone {
		for ref, f := range open {
			if !seen[ref] {
				if err := resolve(f); err != nil {
					return err
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if al.queued > 0 {
		s.wake()
	}
	return nil
}

// describeEndpoint is the finding text for an endpoint: what certificate
// it serves, from where it was seen.
func describeEndpoint(r ScanResult, scan Scan, loc *time.Location) string {
	var parts []string
	switch {
	case r.SubjectCN != "":
		parts = append(parts, r.SubjectCN)
	case len(r.SANs) > 0:
		parts = append(parts, r.SANs[0])
	default:
		parts = append(parts, "certificate without a name")
	}
	if r.SelfSigned {
		parts = append(parts, "self-signed")
	} else if r.Issuer != "" {
		parts = append(parts, "issued by "+r.Issuer)
	}
	if r.NotAfter > 0 {
		parts = append(parts, "expires "+time.Unix(r.NotAfter, 0).In(loc).Format("2006-01-02"))
	}
	if r.TLSVersion != "" {
		parts = append(parts, r.TLSVersion)
	}
	if scan.NodeName != "" {
		parts = append(parts, "seen from node "+scan.NodeName)
	}
	return Clip(strings.Join(parts, " · "), TextMax)
}

// coverUnknownEndpointsTx resolves, with a recovery notice, the
// unknown_endpoint findings of an endpoint a new target now covers.
func (s *Service) coverUnknownEndpointsTx(ctx context.Context, tx *sql.Tx, st config.Settings, host string, port int, now time.Time) (int, error) {
	rows, err := tx.QueryContext(ctx, "SELECT "+findingCols+" FROM findings f WHERE f.schedule_id IS NOT NULL AND f.kind = ? AND f.fingerprint = ? AND f.resolved_at = 0",
		string(check.UnknownEndpoint), net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return 0, err
	}
	var fs []Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			_ = rows.Close()
			return 0, err
		}
		fs = append(fs, f)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil || len(fs) == 0 {
		return 0, err
	}
	queued := 0
	for _, f := range fs {
		if _, err := tx.ExecContext(ctx, "UPDATE findings SET resolved_at = ? WHERE id = ? AND resolved_at = 0", now.Unix(), f.ID); err != nil {
			return queued, err
		}
		al := &alerter{tx: tx, chans: nil, now: now, base: notify.AlertData{Discovery: true, TargetName: "scan schedule", Link: s.ScheduleLink(st, f.ScheduleID), Loc: st.Location()}}
		if err := al.recover(ctx, f); err != nil {
			return queued, err
		}
		queued += al.queued
	}
	return queued, nil
}

// remindSchedule queues a reminder for an open finding on a schedule whose
// reminder interval (from Settings › Defaults) has passed.
func (s *Service) remindSchedule(ctx context.Context, st config.Settings, f Finding, now time.Time) (int, error) {
	every := st.Defaults.RemindWarnS
	if f.Severity == check.Critical {
		every = st.Defaults.RemindCritS
	}
	if every <= 0 || f.LastAlertAt+int64(every) > now.Unix() {
		return 0, nil
	}
	sc, err := s.ScanSchedule(ctx, f.ScheduleID)
	if err != nil || !sc.Enabled {
		return 0, nil
	}
	chans, err := s.Channels.Enabled(ctx)
	if err != nil {
		return 0, err
	}
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	al := s.scheduleAlerter(tx, st, sc, chans, now)
	if err := al.send(ctx, f, notify.EventRemind); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE findings SET last_alert_at = ? WHERE id = ?", now.Unix(), f.ID); err != nil {
		return 0, err
	}
	return al.queued, tx.Commit()
}
