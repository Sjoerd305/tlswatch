package core

import "context"

// Metrics is the state exported at /metrics.
type Metrics struct {
	TargetsByStatus  map[string]int
	OpenBySeverity   map[string]int
	AlertsByState    map[string]int // pending and failed alerts in the outbox
	CertificateTimes []TargetExpiry
}

// TargetExpiry is one enabled target's current certificate expiry.
type TargetExpiry struct {
	Name, Endpoint string
	NotAfter       int64
}

// Metrics gathers the counts and expiry times for /metrics.
func (s *Service) Metrics(ctx context.Context) (Metrics, error) {
	m := Metrics{TargetsByStatus: map[string]int{}, OpenBySeverity: map[string]int{}, AlertsByState: map[string]int{}}
	counts := []struct {
		q    string
		into map[string]int
	}{
		{"SELECT status, COUNT(*) FROM targets GROUP BY status", m.TargetsByStatus},
		{`SELECT f.severity, COUNT(*) FROM findings f LEFT JOIN targets t ON t.id = f.target_id
			WHERE f.resolved_at = 0 AND (t.enabled = 1 OR f.node_id IS NOT NULL) GROUP BY f.severity`, m.OpenBySeverity},
		{"SELECT state, COUNT(*) FROM alerts WHERE state IN ('pending', 'failed') GROUP BY state", m.AlertsByState},
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
	return m, rows.Err()
}
