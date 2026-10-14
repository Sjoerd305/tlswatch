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

// CheckTarget probes a target and applies the result.
func (s *Service) CheckTarget(ctx context.Context, id int64) (Target, probe.Result, error) {
	t, err := s.Target(ctx, id)
	if err != nil {
		return t, probe.Result{}, err
	}
	st := s.CurrentSettings(ctx)
	req, err := s.ProbeRequest(ctx, t, st)
	if err != nil {
		return t, probe.Result{}, err
	}
	r := probe.Probe(ctx, req)
	if ctx.Err() != nil {
		return t, r, ctx.Err()
	}
	if err := s.Apply(ctx, t, r); err != nil {
		return t, r, err
	}
	t, err = s.Target(ctx, id)
	return t, r, err
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

// Apply stores one probe result: certificates, observations, finding
// transitions with their alerts, and the target's new state.
func (s *Service) Apply(ctx context.Context, t Target, r probe.Result) error {
	st := s.CurrentSettings(ctx)
	out, err := s.Evaluate(ctx, t, r, st)
	if err != nil {
		return err
	}
	chans, err := s.recipients(ctx, t)
	if err != nil {
		return err
	}
	now := s.now()
	nowU := now.Unix()
	checkedAt := r.StartedAt.Unix()
	if r.StartedAt.IsZero() {
		checkedAt = nowU
	}
	checkID := newCheckID()

	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := unchangedTx(ctx, tx, t); err != nil {
		return err
	}

	// Certificates and observations.
	for _, a := range r.Addresses {
		var chain []string
		leafFP := ""
		for i, c := range a.Chain {
			info := probe.Describe(c)
			if err := storeCert(ctx, tx, info, nowU); err != nil {
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
			if err := storeCert(ctx, tx, info, nowU); err != nil {
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
			t.ID, checkID, a.IP, checkedAt, status, a.TLSVersion, a.Cipher, leafFP, string(cj), a.Verified, a.VerifyError,
			errText, a.Duration.Milliseconds()); err != nil {
			return err
		}
	}
	for _, ip := range r.SkippedIPv6 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO observations(target_id, check_id, address, checked_at, status, error)
			VALUES(?,?,?,?,'skipped','no IPv6 route from this host')`, t.ID, checkID, ip, checkedAt); err != nil {
			return err
		}
	}
	if r.DNSError != "" && len(r.Addresses) == 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO observations(target_id, check_id, address, checked_at, status, error)
			VALUES(?,?,'',?,'error',?)`, t.ID, checkID, checkedAt, "DNS: "+r.DNSError); err != nil {
			return err
		}
	}

	var leafInfo *probe.CertInfo
	if out.Leaf != nil {
		li := probe.Describe(out.Leaf)
		leafInfo = &li
	}
	failing := failingAddresses(out)
	alerts := 0
	alertData := func(f Finding, event string) notify.AlertData {
		d := notify.AlertData{
			Event: event, Severity: string(f.Severity), Kind: string(f.Kind), KindLabel: f.Kind.Label(),
			TargetName: t.Name, HostPort: t.HostPort(), Details: f.Details, DaysLeft: f.DaysLeft,
			Fingerprint: f.Fingerprint, Address: failing, Link: s.TargetLink(st, t.ID),
			OpenedAt: time.Unix(f.OpenedAt, 0), Loc: st.Location(),
		}
		if leafInfo != nil {
			d.SubjectCN, d.IssuerCN = leafInfo.SubjectCN, leafInfo.IssuerCN
			if d.Fingerprint == "" {
				d.Fingerprint = leafInfo.Fingerprint
			}
		}
		if !out.NotAfter.IsZero() {
			d.NotAfter = out.NotAfter
		} else if t.NotAfter > 0 {
			d.NotAfter = time.Unix(t.NotAfter, 0)
		}
		return d
	}
	send := func(f Finding, event string) error {
		m := notify.Render(alertData(f, event))
		for _, c := range chans {
			floor, _ := check.ParseSeverity(c.MinSeverity)
			if !f.Severity.Meets(floor) {
				continue
			}
			if err := notify.Enqueue(ctx, tx, f.ID, c.ID, event, m, now); err != nil {
				return err
			}
			alerts++
		}
		return nil
	}

	// Finding transitions.
	open, err := openFindingsTx(ctx, tx, t.ID)
	if err != nil {
		return err
	}
	want := map[check.Kind]bool{}
	for _, k := range out.Keep {
		want[k] = true
	}
	expiredNow := false
	for _, f := range out.Open {
		if f.Kind == check.Expired {
			expiredNow = true
		}
	}
	for _, cf := range out.Open {
		want[cf.Kind] = true
		var days any
		if cf.DaysLeft != nil {
			days = *cf.DaysLeft
		}
		if old, ok := open[cf.Kind]; ok {
			if _, err := tx.ExecContext(ctx, "UPDATE findings SET severity=?, details=?, fingerprint=?, days_left=? WHERE id=?",
				string(cf.Severity), cf.Details, cf.Fingerprint, days, old.ID); err != nil {
				return err
			}
			if cf.Severity.Rank() > old.Severity.Rank() {
				old.Severity, old.Details, old.DaysLeft = cf.Severity, cf.Details, cf.DaysLeft
				if err := send(old, notify.EventEscalate); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, "UPDATE findings SET last_alert_at=? WHERE id=?", nowU, old.ID); err != nil {
					return err
				}
			}
			continue
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO findings(target_id, kind, severity, opened_at, details, fingerprint, days_left, last_alert_at)
			VALUES(?,?,?,?,?,?,?,?)`, t.ID, string(cf.Kind), string(cf.Severity), nowU, cf.Details, cf.Fingerprint, days, nowU)
		if err != nil {
			return err
		}
		nf := Finding{Kind: cf.Kind, Severity: cf.Severity, Details: cf.Details, Fingerprint: cf.Fingerprint, DaysLeft: cf.DaysLeft, OpenedAt: nowU}
		nf.ID, _ = res.LastInsertId()
		if err := send(nf, notify.EventOpen); err != nil {
			return err
		}
	}
	for kind, f := range open {
		if want[kind] {
			continue
		}
		if _, err := tx.ExecContext(ctx, "UPDATE findings SET resolved_at=? WHERE id=?", nowU, f.ID); err != nil {
			return err
		}
		// An expiring certificate that has now expired is not a recovery.
		if kind == check.Expiring && expiredNow {
			continue
		}
		if err := s.recoverTx(ctx, tx, f, alertData(f, notify.EventRecover), now); err != nil {
			return err
		}
	}
	for _, ev := range out.Events {
		var days any
		if ev.DaysLeft != nil {
			days = *ev.DaysLeft
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO findings(target_id, kind, severity, opened_at, resolved_at, details, fingerprint, days_left)
			VALUES(?,?,?,?,?,?,?,?)`, t.ID, string(ev.Kind), string(ev.Severity), nowU, nowU, ev.Details, ev.Fingerprint, days)
		if err != nil {
			return err
		}
		nf := Finding{Kind: ev.Kind, Severity: ev.Severity, Details: ev.Details, Fingerprint: ev.Fingerprint, OpenedAt: nowU}
		nf.ID, _ = res.LastInsertId()
		if err := send(nf, notify.EventOpen); err != nil {
			return err
		}
	}

	// Target state.
	eff := t.Effective(st.Defaults)
	next := NextCheck(t.ID, time.Duration(eff.IntervalS)*time.Second, now)
	set := []string{"last_check=?", "fail_streak=?", "ok_streak=?", "dns_fail_streak=?", "dns_ok_streak=?", "next_check=?", "last_error=?", "address_count=?"}
	args := []any{checkedAt, out.FailStreak, out.OkStreak, out.DNSFail, out.DNSOk, next.Unix(), out.Error, len(r.Addresses)}
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
	if _, err := tx.ExecContext(ctx, "UPDATE targets SET "+strings.Join(set, ", ")+" WHERE id=?", args...); err != nil {
		return err
	}
	if err := s.refreshStatusTx(ctx, tx, t.ID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if alerts > 0 {
		s.wake()
	}
	return nil
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

func failingAddresses(out check.Outcome) string {
	var bad []string
	for ip, a := range out.Addresses {
		if a.Status != "ok" {
			bad = append(bad, ip)
		}
	}
	if len(bad) > 4 {
		bad = append(bad[:4], fmt.Sprintf("+%d", len(bad)-4))
	}
	return strings.Join(bad, ", ")
}

// recoverTx queues recovery notices to the channels that received the
// finding's open or escalation alert.
func (s *Service) recoverTx(ctx context.Context, tx *sql.Tx, f Finding, d notify.AlertData, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT channel_id FROM alerts WHERE finding_id = ? AND event IN ('open','escalate') AND state != 'failed'`, f.ID)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) == 0 {
		return nil
	}
	m := notify.Render(d)
	for _, id := range ids {
		if err := notify.Enqueue(ctx, tx, f.ID, id, notify.EventRecover, m, now); err != nil {
			return err
		}
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

// refreshStatusTx recomputes a target's status from its open findings.
func (s *Service) refreshStatusTx(ctx context.Context, tx *sql.Tx, id int64) error {
	var enabled bool
	var lastCheck int64
	var failStreak, dnsFail int
	if err := tx.QueryRowContext(ctx, "SELECT enabled, last_check, fail_streak, dns_fail_streak FROM targets WHERE id = ?", id).Scan(&enabled, &lastCheck, &failStreak, &dnsFail); err != nil {
		return err
	}
	status := StatusHealthy
	switch {
	case !enabled:
		status = StatusDisabled
	case lastCheck == 0:
		status = StatusPending
	default:
		rows, err := tx.QueryContext(ctx, "SELECT kind, severity FROM findings WHERE target_id = ? AND resolved_at = 0", id)
		if err != nil {
			return err
		}
		// The last check reaching no address makes the target unreachable
		// right away; only the finding and its alert wait for the debounce.
		worst, changeOnly, unreachable := 0, true, failStreak > 0 || dnsFail > 0
		for rows.Next() {
			var k, sev string
			if err := rows.Scan(&k, &sev); err != nil {
				rows.Close()
				return err
			}
			kind := check.Kind(k)
			if kind.Network() {
				unreachable = true
				continue
			}
			r := check.Severity(sev).Rank()
			if r >= check.Warning.Rank() && kind != check.CertificateChanged && kind != check.IssuerChanged {
				changeOnly = false
			}
			if r > worst {
				worst = r
			}
		}
		rows.Close()
		switch {
		case worst == check.Critical.Rank():
			status = StatusCritical
		case unreachable:
			status = StatusUnreachable
		case worst == check.Warning.Rank() && changeOnly:
			status = StatusChanged
		case worst == check.Warning.Rank():
			status = StatusWarning
		}
	}
	_, err := tx.ExecContext(ctx, "UPDATE targets SET status = ? WHERE id = ?", status, id)
	return err
}
