package web

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/node"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

// BenchmarkTargetScale measures the existing list handlers, including their
// database reads, filtering, sorting and serialization. Authentication,
// middleware, sockets and browser work are deliberately excluded. The fixture
// uses a temporary on-disk WAL database, two tags and 256 bytes of notes per
// target, one certificate per ten targets, and no observation history or nodes.
// Run without -race for timing: go test ./internal/web -run '^$' \
// -bench '^BenchmarkTargetScale$' -benchtime=3x -count=3 -benchmem
func BenchmarkTargetScale(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("N%d", n), func(b *testing.B) {
			s, ri := targetScaleFixture(b, n)
			b.Run("CoreList", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					ts, err := s.Core.Targets(context.Background())
					if err != nil || len(ts) != n {
						b.Fatalf("targets: count=%d err=%v", len(ts), err)
					}
				}
			})
			cases := []struct {
				name, path string
				h          http.HandlerFunc
			}{
				{"APILimit1", "/api/v2/targets?limit=1", s.apiTargets},
				{"APILimit100", "/api/v2/targets?limit=100", s.apiTargets},
				{"APINoMatch", "/api/v2/targets?limit=1&q=no-such-target", s.apiTargets},
				{"UI", "/targets", s.targets},
				{"UINoMatch", "/targets?q=no-such-target", s.targets},
				{"UIGrouped", "/targets?group=tag", s.targets},
			}
			for _, tc := range cases {
				b.Run(tc.name, func(b *testing.B) {
					req := httptest.NewRequest(http.MethodGet, tc.path, nil)
					req = req.WithContext(context.WithValue(req.Context(), keyReq, ri))
					// Warm caches and verify success before collecting timings.
					w := &scaleWriter{header: make(http.Header)}
					tc.h(w, req)
					if w.status != http.StatusOK || w.bytes == 0 {
						b.Fatalf("warm request: status=%d bytes=%d", w.status, w.bytes)
					}
					b.ReportAllocs()
					b.ResetTimer()
					var size int
					for i := 0; i < b.N; i++ {
						w := &scaleWriter{header: make(http.Header)}
						tc.h(w, req)
						if w.status != http.StatusOK {
							b.Fatalf("request: status=%d", w.status)
						}
						size = w.bytes
					}
					b.ReportMetric(float64(size), "response-B")
				})
			}
		})
	}
}

// BenchmarkTargetScaleConcurrent measures API handler contention at 10,000
// targets. Use -cpu=8 -benchtime=40x for eight workers and forty requests.
// Latency includes database pool waiting; ns/op describes throughput instead.
// It is a short local experiment, not a sustained production load test.
func BenchmarkTargetScaleConcurrent(b *testing.B) {
	s, ri := targetScaleFixture(b, 10000)
	req := httptest.NewRequest(http.MethodGet, "/api/v2/targets?limit=1", nil)
	req = req.WithContext(context.WithValue(req.Context(), keyReq, ri))
	latencies := make(chan time.Duration, b.N)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			start := time.Now()
			w := &scaleWriter{header: make(http.Header)}
			s.apiTargets(w, req)
			latencies <- time.Since(start)
			if w.status != http.StatusOK {
				b.Errorf("request: status=%d", w.status)
			}
		}
	})
	b.StopTimer()
	close(latencies)
	var samples []time.Duration
	for d := range latencies {
		samples = append(samples, d)
	}
	slices.Sort(samples)
	b.ReportMetric(float64(samples[(len(samples)-1)/2])/float64(time.Millisecond), "p50-ms")
	b.ReportMetric(float64(samples[(len(samples)*95+99)/100-1])/float64(time.Millisecond), "p95-ms")
}

// scaleWriter counts uncompressed response bytes without keeping a second
// copy of the HTML already buffered by renderStatus.
type scaleWriter struct {
	header http.Header
	status int
	bytes  int
}

func (w *scaleWriter) Header() http.Header    { return w.header }
func (w *scaleWriter) WriteHeader(status int) { w.status = status }
func (w *scaleWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.bytes += len(p)
	return len(p), nil
}

func targetScaleFixture(tb testing.TB, n int) (*Server, *reqInfo) {
	tb.Helper()
	d, err := db.Open(filepath.Join(tb.TempDir(), "scale.db"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = d.Close() })
	ctx := context.Background()
	// SQL seeding excludes application/audit writes from measured list work.
	_, err = d.W.ExecContext(ctx, `WITH RECURSIVE seq(i) AS (
		VALUES(1) UNION ALL SELECT i+1 FROM seq WHERE i < ?)
		INSERT INTO certificates(fingerprint, subject, subject_cn, issuer, issuer_cn,
		issuer_org, serial, not_before, not_after, sans, key_type, key_bits,
		sig_alg, is_ca, self_signed, pem, first_seen, last_seen)
		SELECT printf('%064x', i), 'CN=*.example.test', '*.example.test', 'CN=Test CA',
		'Test CA', 'Test CA', CAST(i AS TEXT), 1790000000, 1800000000,
		'["*.example.test"]', 'ECDSA', 256, 'ECDSA-SHA256', 0, 0, '', 1790000000, 1790000000
		FROM seq`, (n+9)/10)
	if err != nil {
		tb.Fatal(err)
	}
	_, err = d.W.ExecContext(ctx, `WITH RECURSIVE seq(i) AS (
		VALUES(1) UNION ALL SELECT i+1 FROM seq WHERE i < ?)
		INSERT INTO targets(id, name, host, port, servername, tags, notes,
		created_at, updated_at, status, current_fp, not_after, tls_version,
		address_count, last_check, next_check, grade)
		SELECT i, printf('Target %06d', i), printf('host%06d.example.test', i), 443,
		printf('host%06d.example.test', i), 'production,site:ams', ?,
		1790000000, 1790000000, CASE WHEN i%10=0 THEN 'critical' ELSE 'healthy' END,
		printf('%064x', (i+9)/10), 1800000000+((i*7919)%100003), 'TLS 1.3', 1, 1790000000, 1800000000, 'A'
		FROM seq`, n, strings.Repeat("n", 256))
	if err != nil {
		tb.Fatal(err)
	}
	key, err := secret.New(make([]byte, 32))
	if err != nil {
		tb.Fatal(err)
	}
	st := config.NewStore(d, key)
	settings, err := st.Get(ctx)
	if err != nil {
		tb.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	now := func() time.Time { return time.Unix(1790000000, 0) }
	s := &Server{Core: &core.Service{DB: d, Settings: st, Log: log, Now: now},
		Settings: st, Log: log, Now: now, Version: "benchmark"}
	s.Nodes = &node.Dispatcher{Core: s.Core, Log: log}
	if err := s.loadTemplates(); err != nil {
		tb.Fatal(err)
	}
	ri := &reqInfo{settings: settings, session: &auth.Session{
		User: auth.User{Email: "benchmark@example.test", Role: authz.Admin, Enabled: true}, CSRF: "benchmark"}}
	return s, ri
}
