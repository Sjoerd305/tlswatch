package core

import (
	"context"
	"fmt"
	"sort"
	"strings"
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
	var b strings.Builder
	fmt.Fprintf(&b, "tlswatch weekly digest, %s\n\n", now.In(loc).Format("Monday 2 January 2006"))
	fmt.Fprintf(&b, "Open findings (%d)\n", len(findings))
	for _, f := range findings {
		ack := ""
		if f.Acked(now) {
			ack = " (acknowledged by " + f.AckBy + ")"
		}
		fmt.Fprintf(&b, "  [%s] %s %s: %s%s\n", f.Severity, f.HostPort(), f.Kind.Label(), f.Details, ack)
	}
	if len(findings) == 0 {
		b.WriteString("  none\n")
	}
	var exp []Target
	var failed []Target
	for _, t := range ts {
		if !t.Enabled {
			continue
		}
		if t.NotAfter > 0 && check.DaysLeft(time.Unix(t.NotAfter, 0), now) < 30 {
			exp = append(exp, t)
		}
		if t.LastError != "" || t.Status == StatusUnreachable {
			failed = append(failed, t)
		}
	}
	sort.Slice(exp, func(i, j int) bool { return exp[i].NotAfter < exp[j].NotAfter })
	fmt.Fprintf(&b, "\nExpiring in the next 30 days (%d)\n", len(exp))
	for _, t := range exp {
		fmt.Fprintf(&b, "  %s  %4d d  %s (%s)\n", time.Unix(t.NotAfter, 0).In(loc).Format("2006-01-02"), check.DaysLeft(time.Unix(t.NotAfter, 0), now), t.Name, t.HostPort())
	}
	if len(exp) == 0 {
		b.WriteString("  none\n")
	}
	fmt.Fprintf(&b, "\nFailed their last check (%d)\n", len(failed))
	for _, t := range failed {
		fmt.Fprintf(&b, "  %s (%s): %s\n", t.Name, t.HostPort(), t.LastError)
	}
	if len(failed) == 0 {
		b.WriteString("  none\n")
	}
	if st.General.BaseURL != "" {
		b.WriteString("\n" + st.General.BaseURL + "/\n")
	}
	sev := "info"
	for _, f := range findings {
		if f.Severity == check.Critical {
			sev = "critical"
			break
		}
		if f.Severity == check.Warning {
			sev = "warning"
		}
	}
	return notify.Message{
		Subject: fmt.Sprintf("[%s] tlswatch weekly digest: %d open, %d expiring within 30 days", sev, len(findings), len(exp)),
		Body:    b.String(),
	}, nil
}
