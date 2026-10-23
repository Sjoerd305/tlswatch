package core

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// alerter queues the alerts of one transaction for one target: it renders
// a finding into a message and enqueues it to every channel whose severity
// floor the finding meets.
type alerter struct {
	tx    *sql.Tx
	chans []notify.Channel
	now   time.Time
	base  notify.AlertData // the target's fields, shared by every alert

	queued     int
	belowFloor int
}

// newAlerter starts an alerter for t with the certificate fields from the
// target's stored state.
func (s *Service) newAlerter(tx *sql.Tx, st config.Settings, t Target, chans []notify.Channel, now time.Time) *alerter {
	base := notify.AlertData{TargetName: t.Name, HostPort: t.HostPort(), Link: s.TargetLink(st, t.ID), Loc: st.Location()}
	if t.Cert != nil {
		base.SubjectCN, base.IssuerCN, base.Fingerprint = t.Cert.SubjectCN, t.Cert.IssuerCN, t.Cert.Fingerprint
	}
	if t.NotAfter > 0 {
		base.NotAfter = time.Unix(t.NotAfter, 0)
	}
	return &alerter{tx: tx, chans: chans, now: now, base: base}
}

// outcomeAlerter starts an alerter for a check: the certificate fields and
// failing addresses come from the outcome where it read a certificate.
func (s *Service) outcomeAlerter(tx *sql.Tx, st config.Settings, t Target, chans []notify.Channel, out check.Outcome, now time.Time) *alerter {
	a := s.newAlerter(tx, st, t, chans, now)
	if out.Leaf != nil {
		li := probe.Describe(out.Leaf)
		a.base.SubjectCN, a.base.IssuerCN, a.base.Fingerprint = li.SubjectCN, li.IssuerCN, li.Fingerprint
	}
	if !out.NotAfter.IsZero() {
		a.base.NotAfter = out.NotAfter
	}
	a.base.Address = failingAddresses(out)
	return a
}

// data is the alert content for f.
func (a *alerter) data(f Finding, event string) notify.AlertData {
	d := a.base
	d.Event, d.Severity, d.Kind, d.KindLabel = event, string(f.Severity), string(f.Kind), f.Kind.Label()
	d.Details, d.DaysLeft, d.OpenedAt = f.Details, f.DaysLeft, time.Unix(f.OpenedAt, 0)
	if f.DaysLeft != nil && *f.DaysLeft >= 0 && *f.DaysLeft < check.HoursUnder && !d.NotAfter.IsZero() {
		h := int(d.NotAfter.Sub(a.now) / time.Hour)
		d.HoursLeft = &h
	}
	if f.Fingerprint != "" {
		d.Fingerprint = f.Fingerprint
	}
	return d
}

// send queues f to every channel whose severity floor it meets.
func (a *alerter) send(ctx context.Context, f Finding, event string) error {
	m := notify.Render(a.data(f, event))
	for _, c := range a.chans {
		floor, _ := check.ParseSeverity(c.MinSeverity)
		if !f.Severity.Meets(floor) {
			a.belowFloor++
			continue
		}
		if err := notify.Enqueue(ctx, a.tx, f.ID, c.ID, event, m, a.now); err != nil {
			return err
		}
		a.queued++
	}
	return nil
}

// recover queues recovery notices to the channels that were told about
// the finding (its open, escalation or reminder alerts), whatever their
// floor is now.
func (a *alerter) recover(ctx context.Context, f Finding) error {
	rows, err := a.tx.QueryContext(ctx, `SELECT DISTINCT channel_id FROM alerts WHERE finding_id = ? AND event IN ('open','escalate','remind') AND state != 'failed'`, f.ID)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil || len(ids) == 0 {
		return err
	}
	m := notify.Render(a.data(f, notify.EventRecover))
	for _, id := range ids {
		if err := notify.Enqueue(ctx, a.tx, f.ID, id, notify.EventRecover, m, a.now); err != nil {
			return err
		}
		a.queued++
	}
	return nil
}

// failingAddresses lists the addresses that did not check out, for the
// alert text.
func failingAddresses(out check.Outcome) string {
	var bad []string
	for ip, a := range out.Addresses {
		if a.Status != "ok" {
			bad = append(bad, ip)
		}
	}
	// In address order, so the same outage names the same addresses.
	slices.SortFunc(bad, func(a, b string) int {
		x, errx := netip.ParseAddr(a)
		y, erry := netip.ParseAddr(b)
		if errx != nil || erry != nil {
			return strings.Compare(a, b)
		}
		return x.Compare(y)
	})
	if len(bad) > 4 {
		bad = append(bad[:4], fmt.Sprintf("+%d", len(bad)-4))
	}
	return strings.Join(bad, ", ")
}
