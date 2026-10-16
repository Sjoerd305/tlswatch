package web

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/core"
)

// metrics serves the Prometheus text format when Settings › General enables
// it; otherwise it is not found.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if !info(r).settings.General.Metrics {
		http.NotFound(w, r)
		return
	}
	m, err := s.Core.Metrics(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	st := s.Sched.Status()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	p := promWriter{w: w}
	p.metric("tlswatch_build_info", "gauge", "The running version.")
	p.sample("tlswatch_build_info", map[string]string{"version": s.Version}, 1)
	p.metric("tlswatch_targets", "gauge", "Targets by status.")
	for _, status := range []string{core.StatusHealthy, core.StatusWarning, core.StatusChanged, core.StatusCritical, core.StatusUnreachable, core.StatusPending, core.StatusDisabled} {
		p.sample("tlswatch_targets", map[string]string{"status": status}, float64(m.TargetsByStatus[status]))
	}
	p.metric("tlswatch_findings_open", "gauge", "Open findings on enabled targets by severity.")
	for _, sev := range []check.Severity{check.Info, check.Warning, check.Critical} {
		p.sample("tlswatch_findings_open", map[string]string{"severity": string(sev)}, float64(m.OpenBySeverity[string(sev)]))
	}
	p.metric("tlswatch_alerts", "gauge", "Alerts in the outbox waiting to be sent, or given up.")
	for _, state := range []string{"pending", "failed"} {
		p.sample("tlswatch_alerts", map[string]string{"state": state}, float64(m.AlertsByState[state]))
	}
	p.metric("tlswatch_certificate_not_after_seconds", "gauge", "Expiry of each enabled target's current certificate, as a Unix time.")
	for _, e := range m.CertificateTimes {
		p.sample("tlswatch_certificate_not_after_seconds", map[string]string{"target": e.Name, "endpoint": e.Endpoint}, float64(e.NotAfter))
	}
	p.metric("tlswatch_targets_by_grade", "gauge", "Enabled targets by TLS configuration grade.")
	for _, g := range check.Grades {
		p.sample("tlswatch_targets_by_grade", map[string]string{"grade": g}, float64(m.TargetsByGrade[g]))
	}
	if len(m.TargetGrades) > 0 {
		p.metric("tlswatch_target_grade", "gauge", "Each enabled target's TLS configuration grade as a label; the value ranks it, 4 for A down to 1 for F.")
		for _, g := range m.TargetGrades {
			p.sample("tlswatch_target_grade", map[string]string{"target": g.Name, "endpoint": g.Endpoint, "grade": g.Grade}, float64(check.GradeRank(g.Grade)))
		}
	}
	p.metric("tlswatch_checks_total", "counter", "Checks stored since the process started.")
	p.sample("tlswatch_checks_total", nil, float64(st.Checks))
	p.metric("tlswatch_scheduler_backlog", "gauge", "Checks due and not yet started.")
	p.sample("tlswatch_scheduler_backlog", nil, float64(st.Backlog))
	p.metric("tlswatch_scheduler_overdue_seconds", "gauge", "How long the oldest due check has waited.")
	p.sample("tlswatch_scheduler_overdue_seconds", nil, st.Overdue.Seconds())
	p.metric("tlswatch_scheduler_running", "gauge", "Checks running now.")
	p.sample("tlswatch_scheduler_running", nil, float64(st.Running))
	p.metric("tlswatch_scheduler_node_checks", "gauge", "Checks running on nodes now.")
	p.sample("tlswatch_scheduler_node_checks", nil, float64(st.OnNodes))
	p.metric("tlswatch_scheduler_held", "gauge", "Targets held while their node is offline.")
	p.sample("tlswatch_scheduler_held", nil, float64(st.Held))
	stats := s.Nodes.Stats()
	sort.Slice(stats, func(i, j int) bool { return stats[i].Node.Label() < stats[j].Node.Label() })
	online := 0
	for _, n := range stats {
		if n.Online {
			online++
		}
	}
	p.metric("tlswatch_nodes", "gauge", "Confirmed nodes by state.")
	p.sample("tlswatch_nodes", map[string]string{"state": "online"}, float64(online))
	p.sample("tlswatch_nodes", map[string]string{"state": "offline"}, float64(len(stats)-online))
	if len(stats) > 0 {
		now := s.now()
		p.metric("tlswatch_node_last_seen_seconds", "gauge", "Seconds since each node's last request.")
		for _, n := range stats {
			if !n.LastSeen.IsZero() {
				p.sample("tlswatch_node_last_seen_seconds", map[string]string{"node": n.Node.Label()}, now.Sub(n.LastSeen).Seconds())
			}
		}
		p.metric("tlswatch_node_jobs_total", "counter", "Probe jobs per node since the process started, by result.")
		for _, n := range stats {
			p.sample("tlswatch_node_jobs_total", map[string]string{"node": n.Node.Label(), "result": "completed"}, float64(n.Completed))
			p.sample("tlswatch_node_jobs_total", map[string]string{"node": n.Node.Label(), "result": "failed"}, float64(n.Failed))
		}
	}
	if !st.LastCheck.IsZero() {
		p.metric("tlswatch_last_check_seconds", "gauge", "When the last check was stored, as a Unix time.")
		p.sample("tlswatch_last_check_seconds", nil, float64(st.LastCheck.Unix()))
	}
}

// promWriter writes the Prometheus text exposition format.
type promWriter struct{ w io.Writer }

func (p promWriter) metric(name, kind, help string) {
	fmt.Fprintf(p.w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
}

func (p promWriter) sample(name string, labels map[string]string, v float64) {
	if len(labels) == 0 {
		fmt.Fprintf(p.w, "%s %g\n", name, v)
		return
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		// %q escapes backslashes, quotes and newlines as the format wants.
		parts[i] = fmt.Sprintf("%s=%q", k, labels[k])
	}
	fmt.Fprintf(p.w, "%s{%s} %g\n", name, strings.Join(parts, ","), v)
}
