package sched

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

func setup(t *testing.T, n int) (*Scheduler, *core.Service, *int64) {
	t.Helper()
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	key, _ := secret.New(make([]byte, 32))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	chans := &notify.Channels{DB: d, Key: key}
	c := &core.Service{DB: d, Settings: config.NewStore(d, key), Channels: chans, Dispatcher: &notify.Dispatcher{DB: d, Channels: chans, Log: log}, Log: log}
	var calls int64
	s := &Scheduler{Core: c, Log: log, Probe: func(_ context.Context, req probe.Request) probe.Result {
		atomic.AddInt64(&calls, 1)
		time.Sleep(5 * time.Millisecond)
		return probe.Result{Host: req.Host, Port: req.Port, StartedAt: time.Now(),
			Addresses: []probe.Address{{IP: "192.0.2.1", ErrorKind: probe.ErrConnect, Error: "refused"}}}
	}}
	for i := 0; i < n; i++ {
		if _, err := c.SaveTarget(context.Background(), core.Target{Name: "t", Host: "example.org", Port: 1000 + i, Protocol: probe.TLS,
			Trust: probe.TrustSystem, AllAddresses: true, AllChannels: true, Enabled: true}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	return s, c, &calls
}

func TestRunChecksNewTargetsAndSchedulesNext(t *testing.T) {
	s, c, calls := setup(t, 20)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for atomic.LoadInt64(calls) < 20 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := atomic.LoadInt64(calls); n != 20 {
		t.Fatalf("checked %d of 20 new targets", n)
	}
	time.Sleep(100 * time.Millisecond)
	ts, _ := c.Targets(context.Background())
	for _, tg := range ts {
		if tg.LastCheck == 0 || tg.NextCheck < time.Now().Add(11*time.Hour).Unix() {
			t.Fatalf("target %d: last %d next %d", tg.ID, tg.LastCheck, tg.NextCheck)
		}
	}
	// Nothing runs again before the next slot.
	time.Sleep(1200 * time.Millisecond)
	if n := atomic.LoadInt64(calls); n != 20 {
		t.Fatalf("re-checked early: %d", n)
	}
	if st := s.Status(); st.Checks != 20 || st.Backlog != 0 {
		t.Fatalf("status %+v", st)
	}
	// Check all queues every target again.
	if n, _ := s.CheckAll(ctx); n != 20 {
		t.Fatalf("check all queued %d", n)
	}
	deadline = time.Now().Add(10 * time.Second)
	for atomic.LoadInt64(calls) < 40 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := atomic.LoadInt64(calls); n != 40 {
		t.Fatalf("after check all: %d", n)
	}
}

func TestCheckNow(t *testing.T) {
	s, _, calls := setup(t, 1)
	tg, err := s.CheckNow(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(calls) != 1 || tg.LastCheck == 0 || tg.FailStreak != 1 {
		t.Fatalf("calls %d, target %+v", *calls, tg)
	}
	if _, err := s.CheckNow(context.Background(), 99); err == nil {
		t.Fatal("unknown target checked")
	}
}
