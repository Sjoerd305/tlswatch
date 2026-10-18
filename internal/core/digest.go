package core

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// Digest builds the weekly digest: open findings, certificates expiring in
// the next 30 days, targets whose last check failed, and targets whose
// configuration grade dropped during the week, and the distrust events
// ahead.
func (s *Service) Digest(ctx context.Context) (notify.Message, error) {
	st := s.CurrentSettings(ctx)
	loc := st.Location()
	now := s.now()
	findings, err := s.Findings(ctx, FindingFilter{})
	if err != nil {
		return notify.Message{}, err
	}
	ts, err := s.Targets(ctx)
	if err != nil {
		return notify.Message{}, err
	}
	d := notify.DigestData{Date: now.In(loc).Format("Monday 2 January 2006")}
	if st.General.BaseURL != "" {
		d.Link = st.General.BaseURL + "/"
	}
	tag := "info"
	for _, f := range findings {
		df := notify.DigestFinding{Severity: string(f.Severity), HostPort: f.HostPort(), Kind: f.Kind.Label(), Details: f.Details}
		if f.Acked(now) {
			df.AckBy = f.AckBy
		}
		d.Findings = append(d.Findings, df)
		switch {
		case f.Severity == check.Critical:
			tag = "critical"
		case f.Severity == check.Warning && tag != "critical":
			tag = "warning"
		}
	}
	var exp []Target
	for _, t := range ts {
		if !t.Enabled {
			continue
		}
		if t.NotAfter > 0 && check.DaysLeft(time.Unix(t.NotAfter, 0), now) < 30 {
			exp = append(exp, t)
		}
		if t.LastError != "" || t.Status == StatusUnreachable {
			d.Failed = append(d.Failed, notify.DigestFailure{Name: t.Name, HostPort: t.HostPort(), Error: t.LastError})
		}
	}
	changes, err := s.RecentChanges(ctx, now.Add(-7*24*time.Hour).Unix(), 1000)
	if err != nil {
		return notify.Message{}, err
	}
	for _, f := range changes {
		if f.Kind == check.GradeChanged && gradeDropped(f.Details) {
			d.Grades = append(d.Grades, notify.DigestGrade{Name: f.TargetName, HostPort: f.HostPort(), Details: f.Details})
		}
	}
	issued, err := s.Issuances(ctx, 0, now.Add(-7*24*time.Hour).Unix())
	if err != nil {
		return notify.Message{}, err
	}
	for _, i := range issued {
		d.Issued = append(d.Issued, notify.DigestIssuance{Domain: i.DomainName, Names: strings.Join(i.Names, ", "), Issuer: i.Issuer(), State: i.State,
			Date: time.Unix(i.FirstSeen, 0).In(loc).Format("2006-01-02")})
	}
	if d.Distrust, err = s.digestDistrust(ctx, ts, now, loc); err != nil {
		return notify.Message{}, err
	}
	SortExpiring(exp, now)
	for _, t := range exp {
		d.Expiring = append(d.Expiring, digestExpiry(t, st.Defaults, now, loc))
	}
	return notify.RenderDigest(d, tag), nil
}

// digestExpiry is a target's line in the digest's expiring list, critical
// by the target's own threshold: a managed or tuned one is not judged by
// the manual default.
func digestExpiry(t Target, def config.Defaults, now time.Time, loc *time.Location) notify.DigestExpiry {
	days := check.DaysLeft(time.Unix(t.NotAfter, 0), now)
	e := notify.DigestExpiry{Date: time.Unix(t.NotAfter, 0).In(loc).Format("2006-01-02"), Days: days, Tag: "warning", Name: t.Name, HostPort: t.HostPort()}
	if t.ExpiryClass(def, now) == "crit" {
		e.Tag = "critical"
	}
	return e
}

// gradeDropped reads a grade_changed event's "grade X → Y" and reports
// whether Y is the lower grade.
func gradeDropped(details string) bool {
	var from, to string
	if _, err := fmt.Sscanf(details, "grade %1s → %1s", &from, &to); err != nil {
		return false
	}
	return check.GradeRank(to) < check.GradeRank(from)
}

// DistrustAhead is how far ahead the digest lists distrust events.
const DistrustAhead = 90 * 24 * time.Hour

// digestDistrust lists the distrust events taking effect within
// DistrustAhead, each with the enabled targets whose certificate it will
// affect. A private PKI is in no root program, so only targets verified
// against the system store count.
func (s *Service) digestDistrust(ctx context.Context, ts []Target, now time.Time, loc *time.Location) ([]notify.DigestDistrust, error) {
	var ahead []check.DistrustEvent
	for _, ev := range check.Distrusts {
		if ev.Effective.After(now) && !ev.Effective.After(now.Add(DistrustAhead)) {
			ahead = append(ahead, ev)
		}
	}
	if len(ahead) == 0 {
		return nil, nil
	}
	touched := map[string][]string{} // per event, by eventKey
	for _, t := range ts {
		if !t.Enabled || t.Trust != probe.TrustSystem || t.CurrentFP == "" {
			continue
		}
		chain, verified, err := s.servedChain(ctx, t)
		if err != nil {
			return nil, err
		}
		for _, h := range check.Distrusted(chain, verified) {
			k := eventKey(h.Event)
			touched[k] = append(touched[k], fmt.Sprintf("%s (%s)", t.Name, t.HostPort()))
		}
	}
	slices.SortStableFunc(ahead, func(a, b check.DistrustEvent) int { return a.Effective.Compare(b.Effective) })
	var out []notify.DigestDistrust
	for _, ev := range ahead {
		out = append(out, notify.DigestDistrust{Date: ev.Effective.In(loc).Format("2006-01-02"), CA: ev.CA, Phrase: ev.Phrase(now),
			Link: ev.Link, Targets: touched[eventKey(ev)]})
	}
	return out, nil
}

func eventKey(ev check.DistrustEvent) string {
	return ev.CA + "|" + ev.Program + "|" + ev.Effective.String()
}

// servedChain returns the chain the target's current certificate was last
// served with, leaf first, and the roots verification added from the store.
func (s *Service) servedChain(ctx context.Context, t Target) (chain, verified []*x509.Certificate, err error) {
	obs, err := s.LastCheck(ctx, t.ID)
	if err != nil {
		return nil, nil, err
	}
	for _, o := range obs {
		if o.LeafFP != t.CurrentFP || len(o.Chain) == 0 {
			continue
		}
		for _, ref := range o.Chain {
			fp, inStore := strings.CutPrefix(ref, "root:")
			c, err := s.Certificate(ctx, fp)
			if err != nil {
				continue
			}
			x, err := c.X509()
			if err != nil {
				continue
			}
			if inStore {
				verified = append(verified, x)
			} else {
				chain = append(chain, x)
			}
		}
		return chain, verified, nil
	}
	return nil, nil, nil
}
