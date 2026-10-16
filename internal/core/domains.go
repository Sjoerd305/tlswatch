package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/ct"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// Certificate Transparency watching. A domain watch is a name whose public
// issuance is followed through a source (see internal/ct); each issuance
// is matched against the certificates the targets serve, and one that no
// target serves is a finding on the watch. See the specification,
// "Certificate Transparency watching".

// Domain is one watched domain.
type Domain struct {
	ID          int64
	Name        string
	Subdomains  bool
	Tags        []string
	Notes       string
	AllChannels bool
	ChannelIDs  []int64
	Enabled     bool
	Cursor      string
	PolledAt    int64 // the last poll, whatever its outcome
	PolledOK    int64 // the last poll that succeeded
	PollError   string
	FailSince   int64
	CreatedAt   int64
	CreatedBy   string
	UpdatedAt   int64

	// Joined for the list.
	Recent       int // issuances first seen in the last 30 days
	OpenFindings int
	Unexpected   int // open unexpected_certificate findings
}

// Status is the watch's state for the list: disabled, failing, pending
// (never polled), unexpected (an open finding), or healthy.
func (d Domain) Status() string {
	switch {
	case !d.Enabled:
		return StatusDisabled
	case d.FailSince > 0 && d.PolledOK == 0, d.OpenFindings > d.Unexpected:
		return StatusUnreachable
	case d.Unexpected > 0:
		return StatusWarning
	case d.PolledOK == 0:
		return StatusPending
	}
	return StatusHealthy
}

// Issuance states.
const (
	IssuanceKnown        = "known"
	IssuanceUnexpected   = "unexpected"
	IssuancePending      = "pending"
	IssuanceAcknowledged = "acknowledged"
)

// IssuanceStates lists the states, for chips.
var IssuanceStates = []string{IssuanceUnexpected, IssuancePending, IssuanceKnown, IssuanceAcknowledged}

// Issuance is one certificate for a watched domain as the logs published it.
type Issuance struct {
	ID         int64
	DomainID   int64
	SourceID   string
	IssuerCN   string
	IssuerOrg  string
	Serial     string
	Names      []string
	NotBefore  int64
	NotAfter   int64
	LogURL     string
	FirstSeen  int64
	State      string
	MatchedFP  string
	AckBy      string
	AckAt      int64
	AckComment string

	// Joined for display: the target serving the matched certificate.
	TargetID   int64
	TargetName string
	DomainName string
}

// Issuer is the issuer as shown: the organisation, else the CN.
func (i Issuance) Issuer() string {
	if i.IssuerOrg != "" {
		return i.IssuerOrg
	}
	return i.IssuerCN
}

// StateClass is the status colour of an issuance state.
func (i Issuance) StateClass() string {
	switch i.State {
	case IssuanceUnexpected:
		return "warn"
	case IssuancePending:
		return "info"
	case IssuanceAcknowledged:
		return "off"
	}
	return "ok"
}

// PendingHold is how long an issuance whose names and issuer match a
// target waits to be served before it is unexpected: the time an ACME
// client needs at most to deploy what it just obtained.
const PendingHold = 48 * time.Hour

// Backlog is how far back a new watch's first poll looks; those issuances
// are recorded as known, without findings.
const Backlog = 90 * 24 * time.Hour

// sourceFailAfter is how long polls may fail before ct_source_failed opens.
const sourceFailAfter = 24 * time.Hour

// ErrDomainExists is returned when a watch with the name exists.
var ErrDomainExists = usererr.New("A watch for this domain already exists")

const domainCols = `d.id, d.name, d.subdomains, d.tags, d.notes, d.all_channels, d.enabled, d.cursor, d.polled_at, d.polled_ok, d.poll_error, d.fail_since,
	d.created_at, d.created_by, d.updated_at,
	(SELECT COUNT(*) FROM issuances i WHERE i.domain_id = d.id AND i.first_seen >= ?1),
	(SELECT COUNT(*) FROM findings f WHERE f.domain_id = d.id AND f.resolved_at = 0),
	(SELECT COUNT(*) FROM findings f WHERE f.domain_id = d.id AND f.resolved_at = 0 AND f.kind = 'unexpected_certificate')`

func scanDomain(r interface{ Scan(...any) error }) (Domain, error) {
	var d Domain
	var tags string
	err := r.Scan(&d.ID, &d.Name, &d.Subdomains, &tags, &d.Notes, &d.AllChannels, &d.Enabled, &d.Cursor, &d.PolledAt, &d.PolledOK, &d.PollError, &d.FailSince,
		&d.CreatedAt, &d.CreatedBy, &d.UpdatedAt, &d.Recent, &d.OpenFindings, &d.Unexpected)
	if err != nil {
		return d, err
	}
	if tags != "" {
		d.Tags = strings.Split(tags, ",")
	}
	return d, nil
}

// Domains lists every watch, by name.
func (s *Service) Domains(ctx context.Context) ([]Domain, error) {
	since := s.now().Add(-30 * 24 * time.Hour).Unix()
	rows, err := s.DB.R.QueryContext(ctx, "SELECT "+domainCols+" FROM domains d ORDER BY d.name", since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Domain returns one watch with its channels.
func (s *Service) Domain(ctx context.Context, id int64) (Domain, error) {
	since := s.now().Add(-30 * 24 * time.Hour).Unix()
	d, err := scanDomain(s.DB.R.QueryRowContext(ctx, "SELECT "+domainCols+" FROM domains d WHERE d.id = ?2", since, id))
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	rows, err := s.DB.R.QueryContext(ctx, "SELECT channel_id FROM domain_channels WHERE domain_id = ?", id)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	for rows.Next() {
		var c int64
		if err := rows.Scan(&c); err != nil {
			return d, err
		}
		d.ChannelIDs = append(d.ChannelIDs, c)
	}
	return d, rows.Err()
}

// SaveDomain creates or updates a watch and returns its id. A changed name
// starts the watch over: the cursor and the issuances go.
func (s *Service) SaveDomain(ctx context.Context, d Domain, user string) (int64, error) {
	name, err := ct.ValidDomain(d.Name)
	if err != nil {
		return 0, usererr.Wrap(err)
	}
	d.Name = name
	if len([]rune(d.Notes)) > 2000 {
		return 0, usererr.New("Notes are limited to 2000 characters")
	}
	now := s.now().Unix()
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
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
	return d.ID, tx.Commit()
}

func uniqueDomain(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrDomainExists
	}
	return err
}

// SetDomainEnabled enables or disables a watch. Disabling resolves its
// open findings without recovery notices and stops its polls.
func (s *Service) SetDomainEnabled(ctx context.Context, id int64, enabled bool) error {
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now().Unix()
	res, err := tx.ExecContext(ctx, "UPDATE domains SET enabled = ?, updated_at = ? WHERE id = ?", enabled, now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if !enabled {
		if _, err := tx.ExecContext(ctx, "UPDATE findings SET resolved_at = ? WHERE domain_id = ? AND resolved_at = 0", now, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DomainDeleteImpact returns what deleting a watch removes.
func (s *Service) DomainDeleteImpact(ctx context.Context, id int64) (DeleteImpact, error) {
	var d DeleteImpact
	err := s.DB.R.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM issuances WHERE domain_id = ?1),
		(SELECT COUNT(*) FROM findings WHERE domain_id = ?1),
		(SELECT COUNT(*) FROM findings WHERE domain_id = ?1 AND resolved_at = 0),
		(SELECT COUNT(*) FROM alerts a JOIN findings f ON f.id = a.finding_id WHERE f.domain_id = ?1)`, id).
		Scan(&d.Observations, &d.Findings, &d.OpenFindings, &d.Alerts)
	return d, err
}

// DeleteDomain removes a watch with its issuances and findings.
func (s *Service) DeleteDomain(ctx context.Context, id int64) error {
	res, err := s.DB.W.ExecContext(ctx, "DELETE FROM domains WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DomainLink is the UI URL of a watch.
func (s *Service) DomainLink(st config.Settings, id int64) string {
	if st.General.BaseURL == "" {
		return ""
	}
	return fmt.Sprintf("%s/domains/%d", st.General.BaseURL, id)
}

const issuanceCols = `i.id, i.domain_id, i.source_id, i.issuer_cn, i.issuer_org, i.serial, i.names, i.not_before, i.not_after, i.log_url, i.first_seen, i.state,
	i.matched_fp, i.ack_by, i.ack_at, i.ack_comment, COALESCE(t.id, 0), COALESCE(t.name, ''), d.name`

// issuanceFrom joins the watch and the target serving the matched
// certificate (one of them, by id).
const issuanceFrom = ` FROM issuances i JOIN domains d ON d.id = i.domain_id
	LEFT JOIN targets t ON t.id = (SELECT MIN(id) FROM targets WHERE current_fp = i.matched_fp AND i.matched_fp != '') `

func scanIssuance(r interface{ Scan(...any) error }) (Issuance, error) {
	var i Issuance
	var names string
	err := r.Scan(&i.ID, &i.DomainID, &i.SourceID, &i.IssuerCN, &i.IssuerOrg, &i.Serial, &names, &i.NotBefore, &i.NotAfter, &i.LogURL, &i.FirstSeen, &i.State,
		&i.MatchedFP, &i.AckBy, &i.AckAt, &i.AckComment, &i.TargetID, &i.TargetName, &i.DomainName)
	if err != nil {
		return i, err
	}
	if names != "" {
		_ = json.Unmarshal([]byte(names), &i.Names)
	}
	return i, nil
}

// Issuances lists a watch's issuances, newest first; since limits them to
// those first seen at or after it (0: all).
func (s *Service) Issuances(ctx context.Context, domainID int64, since int64) ([]Issuance, error) {
	q := "SELECT " + issuanceCols + issuanceFrom + " WHERE 1=1"
	var args []any
	if domainID != 0 {
		q += " AND i.domain_id = ?"
		args = append(args, domainID)
	}
	if since > 0 {
		q += " AND i.first_seen >= ?"
		args = append(args, since)
	}
	rows, err := s.DB.R.QueryContext(ctx, q+" ORDER BY i.first_seen DESC, i.id DESC", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Issuance
	for rows.Next() {
		i, err := scanIssuance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// Issuance returns one issuance.
func (s *Service) Issuance(ctx context.Context, id int64) (Issuance, error) {
	i, err := scanIssuance(s.DB.R.QueryRowContext(ctx, "SELECT "+issuanceCols+issuanceFrom+" WHERE i.id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return i, ErrNotFound
	}
	return i, err
}

// ctSource builds the configured source. Tests set CTClient and CTBase.
func (s *Service) ctSource(st config.Settings) (ct.Source, error) {
	src, err := ct.New(st.CT.Source, st.CT.APIKey, s.CTClient)
	if err != nil {
		return nil, err
	}
	if s.CTBase != "" {
		switch v := src.(type) {
		case *ct.CertSpotter:
			v.BaseURL = s.CTBase
		case *ct.CrtSh:
			v.BaseURL = s.CTBase
		}
	}
	return src, nil
}

// DomainDue reports whether a watch is due for a poll: never polled, or
// the interval (with a per-watch jitter of up to a tenth) has passed.
func (s *Service) DomainDue(d Domain, st config.Settings, now time.Time) bool {
	if !d.Enabled {
		return false
	}
	if d.PolledAt == 0 {
		return true
	}
	every := time.Duration(st.CT.IntervalS) * time.Second
	h := fnv.New32a()
	_, _ = h.Write([]byte(d.Name))
	jitter := time.Duration(h.Sum32()%uint32(every/10/time.Second+1)) * time.Second
	return now.Sub(time.Unix(d.PolledAt, 0)) >= every-time.Minute+jitter
}

// PollDomains polls every watch that is due and then sweeps the pending
// issuances. It is the hourly housekeeping of the watches; errors of one
// watch are logged and recorded on it, not returned.
func (s *Service) PollDomains(ctx context.Context) error {
	st := s.CurrentSettings(ctx)
	ds, err := s.Domains(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	for _, d := range ds {
		if !s.DomainDue(d, st, now) {
			continue
		}
		if err := s.PollDomain(ctx, d.ID); err != nil && s.Log != nil {
			s.Log.Warn("ct poll", "domain", d.Name, "err", err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return s.SweepIssuances(ctx)
}

// PollDomain asks the source for the issuances of one watch since its
// cursor, records them, and keeps the watch's poll state. A failing source
// opens ct_source_failed after a day; a successful poll resolves it.
func (s *Service) PollDomain(ctx context.Context, id int64) error {
	d, err := s.Domain(ctx, id)
	if err != nil {
		return err
	}
	st := s.CurrentSettings(ctx)
	now := s.now()
	src, err := s.ctSource(st)
	if err != nil {
		return s.pollFailed(ctx, d, now, err)
	}
	found, cursor, err := src.Issuances(ctx, d.Name, d.Subdomains, d.Cursor)
	if err != nil {
		return s.pollFailed(ctx, d, now, err)
	}
	backlog := d.Cursor == "" && d.PolledOK == 0
	if err := s.recordIssuances(ctx, d, found, backlog, now); err != nil {
		return err
	}
	if _, err := s.DB.W.ExecContext(ctx, "UPDATE domains SET cursor = ?, polled_at = ?, polled_ok = ?, poll_error = '', fail_since = 0 WHERE id = ?",
		cursor, now.Unix(), now.Unix(), d.ID); err != nil {
		return err
	}
	return s.resolveDomainFinding(ctx, d, check.CTSourceFailed, true)
}

// pollFailed records a failed poll and, after a day of failures, opens
// ct_source_failed on the watch. A rate limit postpones the next poll by
// what the source asked.
func (s *Service) pollFailed(ctx context.Context, d Domain, now time.Time, cause error) error {
	since := d.FailSince
	if since == 0 {
		since = now.Unix()
	}
	polled := now.Unix()
	var ra *ct.RetryAfterError
	if errors.As(cause, &ra) {
		// The next poll is due when the interval has passed since the time
		// the source asked for, so polled_at moves ahead.
		polled = now.Add(ra.After).Unix()
	}
	msg := cause.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	if _, err := s.DB.W.ExecContext(ctx, "UPDATE domains SET polled_at = ?, poll_error = ?, fail_since = ? WHERE id = ?", polled, msg, since, d.ID); err != nil {
		return err
	}
	if now.Unix()-since >= int64(sourceFailAfter/time.Second) {
		f := check.Finding{Kind: check.CTSourceFailed, Severity: check.Warning,
			Details: fmt.Sprintf("%s has answered no poll since %s: %s", ct.Label(s.CurrentSettings(ctx).CT.Source), time.Unix(since, 0).In(s.CurrentSettings(ctx).Location()).Format("2006-01-02 15:04"), msg)}
		if err := s.openDomainFinding(ctx, d, f, ""); err != nil {
			return err
		}
	}
	return cause
}

// recordIssuances stores issuances the source returned that are new to
// the watch, in the state the matching rules give them. A first poll's
// backlog is recorded as known, within the backlog window, and opens no
// finding.
func (s *Service) recordIssuances(ctx context.Context, d Domain, found []ct.Issuance, backlog bool, now time.Time) error {
	if len(found) == 0 {
		return nil
	}
	ts, err := s.Targets(ctx)
	if err != nil {
		return err
	}
	for _, in := range found {
		if backlog && in.NotBefore.Before(now.Add(-Backlog)) {
			continue
		}
		if in.Serial == "" || in.IssuerCN == "" && in.IssuerOrg == "" {
			continue
		}
		var exists int
		if err := s.DB.R.QueryRowContext(ctx, "SELECT COUNT(*) FROM issuances WHERE domain_id = ? AND issuer_cn = ? AND serial = ?", d.ID, in.IssuerCN, in.Serial).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		fp, _ := s.servedCertificate(ctx, in.IssuerCN, in.Serial)
		state := IssuanceUnexpected
		switch {
		case fp != "":
			state = IssuanceKnown
		case backlog, !in.NotAfter.IsZero() && in.NotAfter.Before(now):
			state = IssuanceKnown
		case renewalExpected(d, in, ts):
			state = IssuancePending
		}
		names, _ := json.Marshal(in.Names)
		res, err := s.DB.W.ExecContext(ctx, `INSERT INTO issuances(domain_id, source_id, issuer_cn, issuer_org, serial, names, not_before, not_after, log_url, first_seen, state, matched_fp)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, d.ID, in.ID, in.IssuerCN, in.IssuerOrg, in.Serial, string(names), unixOrZero(in.NotBefore), unixOrZero(in.NotAfter), in.LogURL, now.Unix(), state, fp)
		if err != nil {
			return err
		}
		id, _ := res.LastInsertId()
		if state == IssuanceUnexpected {
			i := Issuance{ID: id, DomainID: d.ID, IssuerCN: in.IssuerCN, IssuerOrg: in.IssuerOrg, Names: in.Names, NotBefore: unixOrZero(in.NotBefore), LogURL: in.LogURL}
			if err := s.openDomainFinding(ctx, d, unexpectedFinding(i, "no target serves it", s.CurrentSettings(ctx).Location()), strconv.FormatInt(id, 10)); err != nil {
				return err
			}
		}
	}
	return nil
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// servedCertificate finds a certificate in the inventory by issuer CN and
// serial, the two fields a precertificate and its certificate share.
func (s *Service) servedCertificate(ctx context.Context, issuerCN, serial string) (string, error) {
	var fp string
	err := s.DB.R.QueryRowContext(ctx, "SELECT fingerprint FROM certificates WHERE serial = ? AND issuer_cn = ? COLLATE NOCASE LIMIT 1", ct.SerialHex(serial), issuerCN).Scan(&fp)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return fp, err
}

// renewalExpected reports whether an issuance looks like a renewal on its
// way to a target: every name under the watched domain is covered by an
// enabled target, and the issuer is the one that target serves today.
func renewalExpected(d Domain, in ct.Issuance, ts []Target) bool {
	judged := 0
	for _, name := range in.Names {
		if !ct.Under(name, d.Name, d.Subdomains) {
			continue
		}
		judged++
		covered := false
		for _, t := range ts {
			if !t.Enabled || t.Cert == nil {
				continue
			}
			host := t.ServerName
			if host == "" {
				host = t.Host
			}
			if !ct.Covers(name, host) && !ct.Covers(name, t.Host) {
				continue
			}
			if strings.EqualFold(t.Cert.IssuerCN, in.IssuerCN) || in.IssuerOrg != "" && strings.EqualFold(t.Cert.IssuerOrg, in.IssuerOrg) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return judged > 0
}

// unexpectedFinding is the finding text for an issuance.
func unexpectedFinding(i Issuance, why string, loc *time.Location) check.Finding {
	when := "recently"
	if i.NotBefore > 0 {
		when = "on " + time.Unix(i.NotBefore, 0).In(loc).Format("2 Jan")
	}
	return check.Finding{Kind: check.UnexpectedCertificate, Severity: check.Warning,
		Details: fmt.Sprintf("a certificate for %s was issued by %s %s and %s", strings.Join(i.Names, ", "), i.Issuer(), when, why)}
}

// SweepIssuances moves pending issuances past their hold to unexpected,
// closes the findings of expired ones silently, and matches what a check
// may have brought in meanwhile.
func (s *Service) SweepIssuances(ctx context.Context) error {
	now := s.now()
	rows, err := s.DB.R.QueryContext(ctx, "SELECT "+issuanceCols+issuanceFrom+" WHERE i.state IN ('pending', 'unexpected')")
	if err != nil {
		return err
	}
	var list []Issuance
	for rows.Next() {
		i, err := scanIssuance(rows)
		if err != nil {
			rows.Close()
			return err
		}
		list = append(list, i)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	st := s.CurrentSettings(ctx)
	for _, i := range list {
		if fp, _ := s.servedCertificate(ctx, i.IssuerCN, i.Serial); fp != "" {
			if err := s.issuanceServed(ctx, i, fp, st); err != nil {
				return err
			}
			continue
		}
		d, err := s.Domain(ctx, i.DomainID)
		if err != nil {
			return err
		}
		switch {
		case i.NotAfter > 0 && i.NotAfter < now.Unix() && i.State == IssuanceUnexpected:
			// Expired: whatever it was, it is over. The finding closes
			// without a notice; the issuance keeps its state as history.
			if err := s.resolveDomainFinding(ctx, d, check.UnexpectedCertificate, false, strconv.FormatInt(i.ID, 10)); err != nil {
				return err
			}
		case i.State == IssuancePending && now.Sub(time.Unix(i.FirstSeen, 0)) >= PendingHold:
			if _, err := s.DB.W.ExecContext(ctx, "UPDATE issuances SET state = ? WHERE id = ?", IssuanceUnexpected, i.ID); err != nil {
				return err
			}
			if d.Enabled {
				if err := s.openDomainFinding(ctx, d, unexpectedFinding(i, "no target served it within two days", st.Location()), strconv.FormatInt(i.ID, 10)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// MatchIssuances is called when a check stores a certificate: an issuance
// waiting for it becomes known, and its finding, if any, resolves with a
// recovery notice.
func (s *Service) MatchIssuances(ctx context.Context, fp string) error {
	if fp == "" {
		return nil
	}
	c, err := s.Certificate(ctx, fp)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	rows, err := s.DB.R.QueryContext(ctx, "SELECT "+issuanceCols+issuanceFrom+" WHERE i.serial = ? AND i.issuer_cn = ? COLLATE NOCASE AND i.state IN ('pending', 'unexpected')", c.Serial, c.IssuerCN)
	if err != nil {
		return err
	}
	var list []Issuance
	for rows.Next() {
		i, err := scanIssuance(rows)
		if err != nil {
			rows.Close()
			return err
		}
		list = append(list, i)
	}
	rows.Close()
	st := s.CurrentSettings(ctx)
	for _, i := range list {
		if err := s.issuanceServed(ctx, i, fp, st); err != nil {
			return err
		}
	}
	return nil
}

// issuanceServed marks an issuance known: a pending one is recorded as a
// quiet change, an unexpected one resolves its finding with a recovery
// notice, since the certificate turned out to be yours after all.
func (s *Service) issuanceServed(ctx context.Context, i Issuance, fp string, st config.Settings) error {
	if _, err := s.DB.W.ExecContext(ctx, "UPDATE issuances SET state = ?, matched_fp = ? WHERE id = ?", IssuanceKnown, fp, i.ID); err != nil {
		return err
	}
	d, err := s.Domain(ctx, i.DomainID)
	if err != nil {
		return err
	}
	now := s.now().Unix()
	if i.State == IssuancePending {
		_, err := s.DB.W.ExecContext(ctx, `INSERT INTO findings(domain_id, kind, severity, opened_at, resolved_at, details, fingerprint, last_alert_at) VALUES(?,?,?,?,?,?,?,?)`,
			d.ID, string(check.CertificateIssued), string(check.Info), now, now,
			fmt.Sprintf("%s issued by %s for %s, now served", i.Issuer(), i.Issuer(), strings.Join(i.Names, ", ")), strconv.FormatInt(i.ID, 10), now)
		return err
	}
	return s.resolveDomainFinding(ctx, d, check.UnexpectedCertificate, true, strconv.FormatInt(i.ID, 10))
}

// MarkUnexpected makes a known (or backlog) issuance unexpected by hand and
// opens its finding.
func (s *Service) MarkUnexpected(ctx context.Context, id int64) (Issuance, error) {
	i, err := s.Issuance(ctx, id)
	if err != nil {
		return i, err
	}
	if i.State == IssuanceUnexpected {
		return i, nil
	}
	d, err := s.Domain(ctx, i.DomainID)
	if err != nil {
		return i, err
	}
	if _, err := s.DB.W.ExecContext(ctx, "UPDATE issuances SET state = ?, matched_fp = '', ack_by = '', ack_at = 0, ack_comment = '' WHERE id = ?", IssuanceUnexpected, i.ID); err != nil {
		return i, err
	}
	if err := s.openDomainFinding(ctx, d, unexpectedFinding(i, "was marked unexpected", s.CurrentSettings(ctx).Location()), strconv.FormatInt(i.ID, 10)); err != nil {
		return i, err
	}
	return s.Issuance(ctx, id)
}

// AcknowledgeIssuance acknowledges an unexpected issuance: its finding is
// acknowledged (which resolves it) and the issuance keeps who and why.
func (s *Service) AcknowledgeIssuance(ctx context.Context, id int64, user, comment string) (Issuance, error) {
	i, err := s.Issuance(ctx, id)
	if err != nil {
		return i, err
	}
	var fid int64
	err = s.DB.R.QueryRowContext(ctx, "SELECT id FROM findings WHERE domain_id = ? AND kind = ? AND fingerprint = ? AND resolved_at = 0",
		i.DomainID, string(check.UnexpectedCertificate), strconv.FormatInt(i.ID, 10)).Scan(&fid)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if err := s.ackIssuanceRow(ctx, i.ID, user, comment); err != nil {
			return i, err
		}
	case err != nil:
		return i, err
	default:
		if _, err := s.Acknowledge(ctx, fid, user, time.Time{}, comment); err != nil {
			return i, err
		}
	}
	return s.Issuance(ctx, id)
}

// ackIssuanceRow records the acknowledgement on the issuance; Acknowledge
// calls it for a finding on a domain.
func (s *Service) ackIssuanceRow(ctx context.Context, id int64, user, comment string) error {
	_, err := s.DB.W.ExecContext(ctx, "UPDATE issuances SET state = ?, ack_by = ?, ack_at = ?, ack_comment = ? WHERE id = ?",
		IssuanceAcknowledged, user, s.now().Unix(), strings.TrimSpace(comment), id)
	return err
}

// domainRecipients returns the channels a watch alerts to.
func (s *Service) domainRecipients(ctx context.Context, d Domain) ([]notify.Channel, error) {
	all, err := s.Channels.Enabled(ctx)
	if err != nil {
		return nil, err
	}
	if d.AllChannels {
		return all, nil
	}
	want := map[int64]bool{}
	for _, id := range d.ChannelIDs {
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

func (s *Service) domainAlerter(tx *sql.Tx, st config.Settings, d Domain, chans []notify.Channel, now time.Time) *alerter {
	base := notify.AlertData{Domain: true, TargetName: d.Name, HostPort: "domain " + d.Name, Link: s.DomainLink(st, d.ID), Loc: st.Location()}
	return &alerter{tx: tx, chans: chans, now: now, base: base}
}

// openDomainFinding opens, or updates, a finding on a watch; ref is the
// issuance id for unexpected_certificate and "" for the one-per-kind
// findings. Opening alerts; an update of the text does not.
func (s *Service) openDomainFinding(ctx context.Context, d Domain, cf check.Finding, ref string) error {
	st := s.CurrentSettings(ctx)
	chans, err := s.domainRecipients(ctx, d)
	if err != nil {
		return err
	}
	now := s.now()
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	al := s.domainAlerter(tx, st, d, chans, now)
	old, err := scanFinding(tx.QueryRowContext(ctx, "SELECT "+findingCols+" FROM findings f WHERE f.domain_id = ? AND f.kind = ? AND f.fingerprint = ? AND f.resolved_at = 0", d.ID, string(cf.Kind), ref))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, err := tx.ExecContext(ctx, `INSERT INTO findings(domain_id, kind, severity, opened_at, details, fingerprint, last_alert_at) VALUES(?,?,?,?,?,?,?)`,
			d.ID, string(cf.Kind), string(cf.Severity), now.Unix(), cf.Details, ref, now.Unix())
		if err != nil {
			return err
		}
		f := Finding{DomainID: d.ID, Kind: cf.Kind, Severity: cf.Severity, Details: cf.Details, Fingerprint: ref, OpenedAt: now.Unix()}
		f.ID, _ = res.LastInsertId()
		if err := al.send(ctx, f, notify.EventOpen); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		if _, err := tx.ExecContext(ctx, "UPDATE findings SET details = ? WHERE id = ?", cf.Details, old.ID); err != nil {
			return err
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

// resolveDomainFinding resolves an open finding on a watch, with a
// recovery notice when notice is set; ref as for openDomainFinding.
func (s *Service) resolveDomainFinding(ctx context.Context, d Domain, kind check.Kind, notice bool, ref ...string) error {
	r := ""
	if len(ref) > 0 {
		r = ref[0]
	}
	f, err := scanFinding(s.DB.R.QueryRowContext(ctx, "SELECT "+findingCols+" FROM findings f WHERE f.domain_id = ? AND f.kind = ? AND f.fingerprint = ? AND f.resolved_at = 0", d.ID, string(kind), r))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	now := s.now()
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE findings SET resolved_at = ? WHERE id = ? AND resolved_at = 0", now.Unix(), f.ID); err != nil {
		return err
	}
	al := s.domainAlerter(tx, s.CurrentSettings(ctx), d, nil, now)
	if notice {
		if err := al.recover(ctx, f); err != nil {
			return err
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

// remindDomain queues a reminder for an open finding on a watch whose
// reminder interval (from Settings › Defaults) has passed.
func (s *Service) remindDomain(ctx context.Context, st config.Settings, f Finding, now time.Time) (int, error) {
	every := st.Defaults.RemindWarnS
	if f.Severity == check.Critical {
		every = st.Defaults.RemindCritS
	}
	if every <= 0 || f.LastAlertAt+int64(every) > now.Unix() {
		return 0, nil
	}
	d, err := s.Domain(ctx, f.DomainID)
	if err != nil || !d.Enabled {
		return 0, nil
	}
	chans, err := s.domainRecipients(ctx, d)
	if err != nil {
		return 0, err
	}
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	al := s.domainAlerter(tx, st, d, chans, now)
	if err := al.send(ctx, f, notify.EventRemind); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE findings SET last_alert_at = ? WHERE id = ?", now.Unix(), f.ID); err != nil {
		return 0, err
	}
	return al.queued, tx.Commit()
}

// TestCTSource polls one domain name through the configured source
// without storing anything, for the settings page's Test button.
func (s *Service) TestCTSource(ctx context.Context, st config.Settings, domain string) ([]ct.Issuance, error) {
	name, err := ct.ValidDomain(domain)
	if err != nil {
		return nil, usererr.Wrap(err)
	}
	src, err := s.ctSource(st)
	if err != nil {
		return nil, err
	}
	found, _, err := src.Issuances(ctx, name, true, "")
	if err != nil {
		return nil, err
	}
	sort.Slice(found, func(i, j int) bool { return found[i].NotBefore.After(found[j].NotBefore) })
	if len(found) > 10 {
		found = found[:10]
	}
	return found, nil
}

// IssuanceStats counts issuances by state and the last successful poll of
// each enabled watch, for /metrics.
func (s *Service) IssuanceStats(ctx context.Context) (map[string]int, []Domain, error) {
	by := map[string]int{}
	rows, err := s.DB.R.QueryContext(ctx, "SELECT state, COUNT(*) FROM issuances GROUP BY state")
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return nil, nil, err
		}
		by[k] = n
	}
	rows.Close()
	ds, err := s.Domains(ctx)
	return by, ds, err
}

// ctClient is the HTTP client a source uses; nil means a default with a
// timeout. Tests point CTBase at a stub server.
var _ = http.DefaultClient
