package core

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

const certCols = `fingerprint, subject, subject_cn, issuer, issuer_cn, issuer_org, serial, not_before, not_after, sans,
	key_type, key_bits, sig_alg, is_ca, self_signed, pem, first_seen, last_seen`

func scanCert(r interface{ Scan(...any) error }) (Certificate, error) {
	var c Certificate
	var sans string
	err := r.Scan(&c.Fingerprint, &c.Subject, &c.SubjectCN, &c.Issuer, &c.IssuerCN, &c.IssuerOrg, &c.Serial, &c.NotBefore, &c.NotAfter,
		&sans, &c.KeyType, &c.KeyBits, &c.SigAlg, &c.IsCA, &c.SelfSigned, &c.PEM, &c.FirstSeen, &c.LastSeen)
	if err == nil {
		_ = json.Unmarshal([]byte(sans), &c.SANs)
	}
	return c, err
}

// Certificate returns one certificate by fingerprint.
func (s *Service) Certificate(ctx context.Context, fp string) (Certificate, error) {
	c, err := scanCert(s.DB.R.QueryRowContext(ctx, "SELECT "+certCols+" FROM certificates WHERE fingerprint = ?", strings.ToLower(fp)))
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

func storeCert(ctx context.Context, tx *sql.Tx, info probe.CertInfo, now int64) error {
	sans, _ := json.Marshal(info.SANs)
	_, err := tx.ExecContext(ctx, `INSERT INTO certificates(`+certCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(fingerprint) DO UPDATE SET last_seen = excluded.last_seen`,
		info.Fingerprint, info.Subject, info.SubjectCN, info.Issuer, info.IssuerCN, info.IssuerOrg, info.Serial,
		info.NotBefore.Unix(), info.NotAfter.Unix(), string(sans), info.KeyType, info.KeyBits, info.SigAlg,
		info.IsCA, info.SelfSigned, info.PEM, now, now)
	return err
}

// ProbeRequest builds the probe request for a target.
func (s *Service) ProbeRequest(ctx context.Context, t Target, st config.Settings) (probe.Request, error) {
	eff := t.Effective(st.Defaults)
	req := probe.Request{
		Host: t.Host, Port: t.Port, Protocol: t.Protocol, ServerName: t.ServerName, Trust: t.Trust,
		FirstOnly: !t.AllAddresses, Timeout: time.Duration(eff.TimeoutS) * time.Second, Retries: eff.Retries,
		AllowLocal: st.General.AllowLocal, Now: s.Now,
	}
	if t.Trust == probe.TrustBundle {
		p, err := s.BundlePool(ctx, t.BundleID)
		if err != nil {
			return req, err
		}
		req.Roots = p
	}
	return req, nil
}

// Evaluate runs the checks for a target against a probe result without
// storing anything; Apply and the "Test without saving" preview share it.
func (s *Service) Evaluate(ctx context.Context, t Target, r probe.Result, st config.Settings) (check.Outcome, error) {
	prev := check.Previous{
		LeafFP: t.CurrentFP, FailStreak: t.FailStreak, OkStreak: t.OkStreak, DNSFail: t.DNSFail, DNSOk: t.DNSOk,
		Open: map[check.Kind]bool{},
	}
	if t.CurrentFP != "" {
		if c, err := s.Certificate(ctx, t.CurrentFP); err == nil {
			prev.IssuerOrg, prev.IssuerCN, prev.SANs = c.IssuerOrg, c.IssuerCN, c.SANs
		}
	}
	if t.ID != 0 {
		rows, err := s.DB.R.QueryContext(ctx, "SELECT kind FROM findings WHERE target_id = ? AND resolved_at = 0", t.ID)
		if err != nil {
			return check.Outcome{}, err
		}
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				rows.Close()
				return check.Outcome{}, err
			}
			prev.Open[check.Kind(k)] = true
		}
		rows.Close()
	}
	eff := t.Effective(st.Defaults)
	ct := check.Target{
		Trust: t.Trust, ServerName: t.ServerName, Warn: t.WarnDays, Crit: t.CritDays,
		Manual:         check.Thresholds{Warn: st.Defaults.Manual.WarnDays, Crit: st.Defaults.Manual.CritDays},
		Managed:        check.Thresholds{Warn: st.Defaults.Managed.WarnDays, Crit: st.Defaults.Managed.CritDays},
		RenewalManaged: t.RenewalManaged, RenewalSet: t.RenewalSet, ExpectedIssuer: t.ExpectedIssuer,
		Debounce: eff.Debounce, PinnedFP: t.PinnedFP,
	}
	return check.Evaluate(ct, prev, r, s.now()), nil
}

func newCheckID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// recipients returns the channels a target alerts to.
func (s *Service) recipients(ctx context.Context, t Target) ([]notify.Channel, error) {
	all, err := s.Channels.Enabled(ctx)
	if err != nil {
		return nil, err
	}
	if t.AllChannels {
		return all, nil
	}
	want := map[int64]bool{}
	for _, id := range t.ChannelIDs {
		want[id] = true
	}
	var out []notify.Channel
	for _, c := range all {
		if want[c.ID] {
			out = append(out, c)
		}
	}
	return out, nil
}

// TargetLink is the UI URL of a target.
func (s *Service) TargetLink(st config.Settings, id int64) string {
	if st.General.BaseURL == "" {
		return ""
	}
	return fmt.Sprintf("%s/targets/%d", st.General.BaseURL, id)
}

// CheckSummary is what one Apply changed, for the check log: it answers
// "why did (or didn't) this alert".
type CheckSummary struct {
	CheckID   string
	Status    string
	Opened    []check.Kind
	Escalated []check.Kind
	Resolved  []check.Kind
	Events    []check.Kind
	Waiting   []check.Kind // failing, held back by the debounce
	Queued    int          // alerts queued
	// BelowFloor counts alerts not queued to a channel because the
	// finding's severity is under the channel's floor.
	BelowFloor int
	Channels   int // channels the target alerts to
}

// LogAttrs returns the summary as log attributes.
func (c CheckSummary) LogAttrs() []any {
	return []any{"check_id", c.CheckID, "status", c.Status, "opened", c.Opened, "escalated", c.Escalated, "resolved", c.Resolved,
		"events", c.Events, "waiting", c.Waiting, "alerts_queued", c.Queued, "below_floor", c.BelowFloor, "channels", c.Channels}
}

// Apply stores one probe result: certificates, observations, finding
// transitions with their alerts, and the target's new state.
func (s *Service) Apply(ctx context.Context, t Target, r probe.Result) (CheckSummary, error) {
	st := s.CurrentSettings(ctx)
	out, err := s.Evaluate(ctx, t, r, st)
	if err != nil {
		return CheckSummary{}, err
	}
	chans, err := s.recipients(ctx, t)
	if err != nil {
		return CheckSummary{}, err
	}
	now := s.now()
	sum := CheckSummary{CheckID: newCheckID(), Waiting: out.Waiting, Channels: len(chans)}
	checkedAt := r.StartedAt
	if checkedAt.IsZero() {
		checkedAt = now
	}

	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return sum, err
	}
	defer tx.Rollback()
	if err := unchangedTx(ctx, tx, t); err != nil {
		return sum, err
	}
	if err := storeObservationsTx(ctx, tx, t.ID, sum.CheckID, r, out, checkedAt.Unix(), now.Unix()); err != nil {
		return sum, err
	}
	al := s.outcomeAlerter(tx, st, t, chans, out, now)
	if err := applyFindingsTx(ctx, tx, t.ID, out, al, &sum, now.Unix()); err != nil {
		return sum, err
	}
	sum.Queued, sum.BelowFloor = al.queued, al.belowFloor
	if err := updateTargetTx(ctx, tx, t, r, out, st, sum.CheckID, checkedAt.Unix(), now); err != nil {
		return sum, err
	}
	if sum.Status, err = s.refreshStatusTx(ctx, tx, t.ID); err != nil {
		return sum, err
	}
	if err := tx.Commit(); err != nil {
		return sum, err
	}
	if sum.Queued > 0 {
		s.wake()
	}
	return sum, nil
}

// storeObservationsTx stores the certificates seen and one observation per
// address (and per skipped IPv6 address, or one for a DNS failure).
func storeObservationsTx(ctx context.Context, tx *sql.Tx, targetID int64, checkID string, r probe.Result, out check.Outcome, checkedAt, now int64) error {
	for _, a := range r.Addresses {
		var chain []string
		leafFP := ""
		for i, c := range a.Chain {
			info := probe.Describe(c)
			if err := storeCert(ctx, tx, info, now); err != nil {
				return err
			}
			chain = append(chain, info.Fingerprint)
			if i == 0 {
				leafFP = info.Fingerprint
			}
		}
		// Store the root that completed verification too, so the chain view
		// can show it.
		if len(a.VerifiedChain) > len(a.Chain) {
			root := a.VerifiedChain[len(a.VerifiedChain)-1]
			info := probe.Describe(root)
			if err := storeCert(ctx, tx, info, now); err != nil {
				return err
			}
			chain = append(chain, "root:"+info.Fingerprint)
		}
		cj, _ := json.Marshal(chain)
		status := out.Addresses[a.IP].Status
		if status == "" {
			status = "error"
		}
		errText := a.Error
		if a.ErrorKind == probe.ErrRefused && errText == "" {
			errText = "address not allowed"
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO observations(target_id, check_id, address, checked_at, status, tls_version, cipher,
			leaf_fp, chain, verified, verify_error, error, duration_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			targetID, checkID, a.IP, checkedAt, status, a.TLSVersion, a.Cipher, leafFP, string(cj), a.Verified, a.VerifyError,
			errText, a.Duration.Milliseconds()); err != nil {
			return err
		}
	}
	for _, ip := range r.SkippedIPv6 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO observations(target_id, check_id, address, checked_at, status, error)
			VALUES(?,?,?,?,'skipped','no IPv6 route from this host')`, targetID, checkID, ip, checkedAt); err != nil {
			return err
		}
	}
	if r.DNSError != "" && len(r.Addresses) == 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO observations(target_id, check_id, address, checked_at, status, error)
			VALUES(?,?,'',?,'error',?)`, targetID, checkID, checkedAt, "DNS: "+r.DNSError); err != nil {
			return err
		}
	}
	return nil
}

// applyFindingsTx moves the target's findings to the outcome: opens new
// ones, updates (and on a higher severity escalates) open ones, resolves
// the ones neither opened nor kept, and records events as resolved
// findings. Alerts go through al; sum records the transitions.
func applyFindingsTx(ctx context.Context, tx *sql.Tx, targetID int64, out check.Outcome, al *alerter, sum *CheckSummary, now int64) error {
	open, err := openFindingsTx(ctx, tx, targetID)
	if err != nil {
		return err
	}
	want := map[check.Kind]bool{}
	for _, k := range out.Keep {
		want[k] = true
	}
	expiredNow := false
	for _, f := range out.Open {
		want[f.Kind] = true
		expiredNow = expiredNow || f.Kind == check.Expired
	}
	for _, cf := range out.Open {
		if old, ok := open[cf.Kind]; ok {
			if _, err := tx.ExecContext(ctx, "UPDATE findings SET severity=?, details=?, fingerprint=?, days_left=? WHERE id=?",
				string(cf.Severity), cf.Details, cf.Fingerprint, nullInt(cf.DaysLeft), old.ID); err != nil {
				return err
			}
			if cf.Severity.Rank() > old.Severity.Rank() {
				old.Severity, old.Details, old.DaysLeft = cf.Severity, cf.Details, cf.DaysLeft
				if err := al.send(ctx, old, notify.EventEscalate); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, "UPDATE findings SET last_alert_at=? WHERE id=?", now, old.ID); err != nil {
					return err
				}
				sum.Escalated = append(sum.Escalated, cf.Kind)
			}
			continue
		}
		nf, err := insertFindingTx(ctx, tx, targetID, cf, now, 0)
		if err != nil {
			return err
		}
		if err := al.send(ctx, nf, notify.EventOpen); err != nil {
			return err
		}
		sum.Opened = append(sum.Opened, cf.Kind)
	}
	for kind, f := range open {
		if want[kind] {
			continue
		}
		if _, err := tx.ExecContext(ctx, "UPDATE findings SET resolved_at=? WHERE id=?", now, f.ID); err != nil {
			return err
		}
		sum.Resolved = append(sum.Resolved, kind)
		// An expiring certificate that has now expired is not a recovery.
		if kind == check.Expiring && expiredNow {
			continue
		}
		if err := al.recover(ctx, f); err != nil {
			return err
		}
	}
	for _, ev := range out.Events {
		nf, err := insertFindingTx(ctx, tx, targetID, ev, now, now)
		if err != nil {
			return err
		}
		if err := al.send(ctx, nf, notify.EventOpen); err != nil {
			return err
		}
		sum.Events = append(sum.Events, ev.Kind)
	}
	return nil
}

// insertFindingTx stores a new finding; resolved is 0 for an open one.
func insertFindingTx(ctx context.Context, tx *sql.Tx, targetID int64, cf check.Finding, now, resolved int64) (Finding, error) {
	res, err := tx.ExecContext(ctx, `INSERT INTO findings(target_id, kind, severity, opened_at, resolved_at, details, fingerprint, days_left, last_alert_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, targetID, string(cf.Kind), string(cf.Severity), now, resolved, cf.Details, cf.Fingerprint, nullInt(cf.DaysLeft), now)
	if err != nil {
		return Finding{}, err
	}
	f := Finding{TargetID: targetID, Kind: cf.Kind, Severity: cf.Severity, Details: cf.Details, Fingerprint: cf.Fingerprint,
		DaysLeft: cf.DaysLeft, OpenedAt: now, ResolvedAt: resolved}
	f.ID, err = res.LastInsertId()
	return f, err
}

// updateTargetTx stores the target's new state: streaks, next slot and,
// when an address answered, the current certificate.
func updateTargetTx(ctx context.Context, tx *sql.Tx, t Target, r probe.Result, out check.Outcome, st config.Settings, checkID string, checkedAt int64, now time.Time) error {
	eff := t.Effective(st.Defaults)
	next := NextCheck(t.ID, time.Duration(eff.IntervalS)*time.Second, now)
	set := []string{"last_check=?", "last_check_id=?", "fail_streak=?", "ok_streak=?", "dns_fail_streak=?", "dns_ok_streak=?", "next_check=?", "last_error=?", "address_count=?"}
	args := []any{checkedAt, checkID, out.FailStreak, out.OkStreak, out.DNSFail, out.DNSOk, next.Unix(), out.Error, len(r.Addresses)}
	if out.Answered {
		set = append(set, "current_fp=?", "not_after=?", "tls_version=?")
		args = append(args, out.LeafFP, out.NotAfter.Unix(), out.TLSVersion)
		if !t.RenewalSet {
			set = append(set, "renewal_managed=?")
			args = append(args, out.RenewalManaged)
		}
	}
	if out.PinFP != "" {
		set = append(set, "pinned_fp=?")
		args = append(args, out.PinFP)
	}
	args = append(args, t.ID)
	_, err := tx.ExecContext(ctx, "UPDATE targets SET "+strings.Join(set, ", ")+" WHERE id=?", args...)
	return err
}

// unchangedTx returns ErrStale when the target was disabled or edited since
// t was read, so a probe that ran meanwhile cannot reopen the findings that
// disabling resolved, or store the old endpoint's certificate as current.
func unchangedTx(ctx context.Context, tx *sql.Tx, t Target) error {
	var enabled bool
	var host, protocol, sni, trust string
	var port int
	var bundle sql.NullInt64
	var updated int64
	err := tx.QueryRowContext(ctx, "SELECT enabled, host, port, protocol, servername, trust_mode, bundle_id, updated_at FROM targets WHERE id = ?", t.ID).
		Scan(&enabled, &host, &port, &protocol, &sni, &trust, &bundle, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !enabled || updated != t.UpdatedAt || host != t.Host || port != t.Port || protocol != string(t.Protocol) ||
		sni != t.ServerName || trust != string(t.Trust) || bundle.Int64 != t.BundleID {
		return ErrStale
	}
	return nil
}

func openFindingsTx(ctx context.Context, tx *sql.Tx, targetID int64) (map[check.Kind]Finding, error) {
	rows, err := tx.QueryContext(ctx, "SELECT "+findingCols+" FROM findings f WHERE f.target_id = ? AND f.resolved_at = 0", targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[check.Kind]Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		m[f.Kind] = f
	}
	return m, rows.Err()
}

// refreshStatusTx recomputes and stores a target's status from its state
// and open findings.
func (s *Service) refreshStatusTx(ctx context.Context, tx *sql.Tx, id int64) (string, error) {
	var enabled bool
	var lastCheck int64
	var failStreak, dnsFail int
	if err := tx.QueryRowContext(ctx, "SELECT enabled, last_check, fail_streak, dns_fail_streak FROM targets WHERE id = ?", id).Scan(&enabled, &lastCheck, &failStreak, &dnsFail); err != nil {
		return "", err
	}
	var open []check.Finding
	if enabled && lastCheck > 0 {
		rows, err := tx.QueryContext(ctx, "SELECT kind, severity FROM findings WHERE target_id = ? AND resolved_at = 0", id)
		if err != nil {
			return "", err
		}
		for rows.Next() {
			var f check.Finding
			if err := rows.Scan(&f.Kind, &f.Severity); err != nil {
				rows.Close()
				return "", err
			}
			open = append(open, f)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return "", err
		}
	}
	status := StatusOf(enabled, lastCheck > 0, failStreak > 0 || dnsFail > 0, open)
	_, err := tx.ExecContext(ctx, "UPDATE targets SET status = ? WHERE id = ?", status, id)
	return status, err
}

// StatusOf derives a target's status. failing is whether the last check
// reached no address: the target shows unreachable right away, while the
// finding and its alert wait for the debounce. Critical certificate
// findings outrank unreachable; a warning that is only a certificate or
// issuer change is "changed".
func StatusOf(enabled, checked, failing bool, open []check.Finding) string {
	switch {
	case !enabled:
		return StatusDisabled
	case !checked:
		return StatusPending
	}
	worst, changeOnly, unreachable := 0, true, failing
	for _, f := range open {
		if f.Kind.Network() {
			unreachable = true
			continue
		}
		r := f.Severity.Rank()
		if r >= check.Warning.Rank() && f.Kind != check.CertificateChanged && f.Kind != check.IssuerChanged {
			changeOnly = false
		}
		worst = max(worst, r)
	}
	switch {
	case worst == check.Critical.Rank():
		return StatusCritical
	case unreachable:
		return StatusUnreachable
	case worst == check.Warning.Rank() && changeOnly:
		return StatusChanged
	case worst == check.Warning.Rank():
		return StatusWarning
	}
	return StatusHealthy
}
