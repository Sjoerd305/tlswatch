package core

import "context"

// Metrics is the state exported at /metrics.
type Metrics struct {
	TargetsByStatus  map[string]int
	OpenBySeverity   map[string]int
	AlertsByState    map[string]int // pending and failed alerts in the outbox
	CertificateTimes []TargetExpiry
	TargetsByGrade   map[string]int // enabled targets by configuration grade
	TargetsByPQ      map[string]int // enabled targets by post-quantum state: yes, no, untested
	TargetGrades     []TargetGrade
}

// TargetGrade is one enabled target's configuration grade.
type TargetGrade struct {
	Name, Endpoint, Grade string
}

// TargetExpiry is one enabled target's current certificate expiry.
type TargetExpiry struct {
	Name, Endpoint string
	NotAfter       int64
}

// Metrics gathers the counts and expiry times for /metrics.
func (s *Service) Metrics(ctx context.Context) (Metrics, error) {
	m := Metrics{TargetsByStatus: map[string]int{}, OpenBySeverity: map[string]int{}, AlertsByState: map[string]int{}, TargetsByGrade: map[string]int{}, TargetsByPQ: map[string]int{}}
	counts := []struct {
		q    string
		into map[string]int
	}{
		{"SELECT status, COUNT(*) FROM targets GROUP BY status", m.TargetsByStatus},
		{`SELECT f.severity, COUNT(*) FROM findings f LEFT JOIN targets t ON t.id = f.target_id LEFT JOIN domains d ON d.id = f.domain_id
			WHERE f.resolved_at = 0 AND (t.enabled = 1 OR f.node_id IS NOT NULL OR d.enabled = 1) GROUP BY f.severity`, m.OpenBySeverity},
		{"SELECT state, COUNT(*) FROM alerts WHERE state IN ('pending', 'failed') GROUP BY state", m.AlertsByState},
		{"SELECT grade, COUNT(*) FROM targets WHERE enabled = 1 AND grade != '' GROUP BY grade", m.TargetsByGrade},
		{"SELECT CASE pq WHEN '' THEN 'untested' ELSE pq END, COUNT(*) FROM targets WHERE enabled = 1 GROUP BY 1", m.TargetsByPQ},
	}
	for _, c := range counts {
		rows, err := s.DB.R.QueryContext(ctx, c.q)
		if err != nil {
			return m, err
		}
		for rows.Next() {
			var k string
			var n int
			if err := rows.Scan(&k, &n); err != nil {
				rows.Close()
				return m, err
			}
			c.into[k] = n
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return m, err
		}
	}
	rows, err := s.DB.R.QueryContext(ctx, "SELECT name, host, port, not_after FROM targets WHERE enabled = 1 AND not_after > 0 ORDER BY name")
	if err != nil {
		return m, err
	}
	defer rows.Close()
	for rows.Next() {
		var t Target
		var e TargetExpiry
		if err := rows.Scan(&e.Name, &t.Host, &t.Port, &e.NotAfter); err != nil {
			return m, err
		}
		e.Endpoint = t.HostPort()
		m.CertificateTimes = append(m.CertificateTimes, e)
	}
	if err := rows.Err(); err != nil {
		return m, err
	}
	grades, err := s.DB.R.QueryContext(ctx, "SELECT name, host, port, grade FROM targets WHERE enabled = 1 AND grade != '' ORDER BY name")
	if err != nil {
		return m, err
	}
	defer grades.Close()
	for grades.Next() {
		var t Target
		var g TargetGrade
		if err := grades.Scan(&g.Name, &t.Host, &t.Port, &g.Grade); err != nil {
			return m, err
		}
		g.Endpoint = t.HostPort()
		m.TargetGrades = append(m.TargetGrades, g)
	}
	return m, grades.Err()
}
