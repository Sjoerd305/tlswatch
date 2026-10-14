package core

import (
	"context"
	"sort"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/notify"
)

// Digest builds the weekly digest: open findings, certificates expiring in
// the next 30 days and targets whose last check failed.
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
	sort.Slice(exp, func(i, j int) bool { return exp[i].NotAfter < exp[j].NotAfter })
	for _, t := range exp {
		days := check.DaysLeft(time.Unix(t.NotAfter, 0), now)
		e := notify.DigestExpiry{Date: time.Unix(t.NotAfter, 0).In(loc).Format("2006-01-02"), Days: days, Tag: "warning", Name: t.Name, HostPort: t.HostPort()}
		if days < st.Defaults.Manual.CritDays {
			e.Tag = "critical"
		}
		d.Expiring = append(d.Expiring, e)
	}
	return notify.RenderDigest(d, tag), nil
}
