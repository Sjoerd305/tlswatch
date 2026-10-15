package sched

import (
	"context"
	"errors"
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

func (s *Scheduler) nextOf(id int64) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if it, ok := s.byID[id]; ok {
		return it.next
	}
	return -1
}

// The periodic reload merges with the queue: Check all and the startup
// spread survive it, a changed target is picked up.
func TestReloadKeepsQueuedTimes(t *testing.T) {
	s, c, _ := setup(t, 3)
	ctx := context.Background()
	s.init()
	for id := int64(1); id <= 3; id++ {
		if _, err := s.CheckNow(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().Unix()
	if _, err := s.CheckAll(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.load(ctx, false); err != nil {
		t.Fatal(err)
	}
	for id := int64(1); id <= 3; id++ {
		if n := s.nextOf(id); n > now+1 {
			t.Fatalf("target %d moved back to %d after reload", id, n)
		}
	}

	// Startup spread: overdue targets are spread, and stay spread.
	if _, err := c.DB.W.Exec("UPDATE targets SET next_check = ?", now-3600); err != nil {
		t.Fatal(err)
	}
	if err := s.load(ctx, true); err != nil {
		t.Fatal(err)
	}
	spread := map[int64]int64{}
	for id := int64(1); id <= 3; id++ {
		spread[id] = s.nextOf(id)
		if spread[id] < now {
			t.Fatalf("target %d not spread: %d", id, spread[id])
		}
	}
	if err := s.load(ctx, false); err != nil {
		t.Fatal(err)
	}
	for id := int64(1); id <= 3; id++ {
		if s.nextOf(id) != spread[id] {
			t.Fatalf("target %d spread undone by reload", id)
		}
	}

	// An edited target (next_check reset) and a disabled one are picked up.
	if _, err := c.DB.W.Exec("UPDATE targets SET next_check = 0 WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DB.W.Exec("UPDATE targets SET enabled = 0 WHERE id = 2"); err != nil {
		t.Fatal(err)
	}
	if err := s.load(ctx, false); err != nil {
		t.Fatal(err)
	}
	if s.nextOf(1) != 0 || s.nextOf(2) != -1 {
		t.Fatalf("edited %d, disabled %d", s.nextOf(1), s.nextOf(2))
	}
}

// A check that could not be stored is retried after a growing delay, not
// straight away.
func TestFailedCheckBacksOff(t *testing.T) {
	s, c, _ := setup(t, 1)
	ctx := context.Background()
	s.init()
	fail := errors.New("disk full")
	for n, want := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute} {
		s.requeue(ctx, 1, core.Target{}, fail)
		if got := s.nextOf(1) - time.Now().Unix(); got < int64(want/time.Second)-1 || got > int64(want/time.Second) {
			t.Fatalf("failure %d: retry in %d s, want %v", n+1, got, want)
		}
	}
	if retryDelay(20) != maxRetryDelay {
		t.Fatal("retry delay not capped")
	}
	tg, _ := c.Target(ctx, 1)
	s.requeue(ctx, 1, tg, nil)
	if s.nextOf(1) != tg.NextCheck || s.fails[1] != 0 {
		t.Fatalf("success did not restore the slot: %d", s.nextOf(1))
	}
}

// Run returns only after the checks it started have finished, so the
// database is not closed under them.
func TestRunWaitsForChecksOnShutdown(t *testing.T) {
	s, _, _ := setup(t, 1)
	started, finished := make(chan struct{}), make(chan struct{})
	s.Probe = func(_ context.Context, req probe.Request) probe.Result {
		close(started)
		time.Sleep(200 * time.Millisecond)
		close(finished)
		return probe.Result{Host: req.Host, Port: req.Port, DNSError: "no such host"}
	}
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan struct{})
	go func() { s.Run(ctx); close(returned) }()
	<-started
	cancel()
	<-returned
	select {
	case <-finished:
	default:
		t.Fatal("Run returned while a check was running")
	}
}

func TestCheckSoon(t *testing.T) {
	s, _, calls := setup(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := s.CheckNow(ctx, 1); err != nil {
		t.Fatal(err)
	}
	go s.Run(ctx)
	time.Sleep(100 * time.Millisecond)
	s.CheckSoon(1)
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt64(calls) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := atomic.LoadInt64(calls); n != 2 {
		t.Fatalf("CheckSoon did not run the target: %d checks", n)
	}
}

// A target disabled while it is probed is discarded and not queued again.
func TestDisabledDuringCheckIsNotRequeued(t *testing.T) {
	s, c, _ := setup(t, 1)
	ctx := context.Background()
	s.init()
	s.Probe = func(_ context.Context, req probe.Request) probe.Result {
		if err := c.SetEnabled(ctx, 1, false); err != nil {
			t.Error(err)
		}
		return probe.Result{Host: req.Host, Port: req.Port, DNSError: "no such host"}
	}
	s.mu.Lock()
	s.inflight[1] = make(chan struct{})
	s.running++
	done := s.inflight[1]
	s.mu.Unlock()
	s.run(ctx, 1, done)
	if n := s.nextOf(1); n != -1 {
		t.Fatalf("disabled target queued at %d", n)
	}
	if tg, _ := c.Target(ctx, 1); tg.LastCheck != 0 {
		t.Fatal("check of a disabled target stored")
	}
}

func TestPauseWaitsAndStopsChecks(t *testing.T) {
	s, _, calls := setup(t, 5)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	// Pause as checks start: it returns once none run.
	for atomic.LoadInt64(calls) == 0 {
		time.Sleep(time.Millisecond)
	}
	if err := s.Pause(ctx); err != nil {
		t.Fatal(err)
	}
	if st := s.Status(); st.Running != 0 {
		t.Fatalf("%d checks still running while paused", st.Running)
	}
	before := atomic.LoadInt64(calls)
	if _, err := s.CheckNow(ctx, 1); !errors.Is(err, ErrPaused) {
		t.Fatalf("CheckNow while paused: %v", err)
	}
	s.CheckSoon(1)
	time.Sleep(1500 * time.Millisecond)
	if n := atomic.LoadInt64(calls); n != before {
		t.Fatalf("%d checks started while paused", n-before)
	}
	s.Resume(ctx, true)
	deadline := time.Now().Add(10 * time.Second)
	for atomic.LoadInt64(calls) < 5 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := atomic.LoadInt64(calls); n < 5 {
		t.Fatalf("checked %d of 5 targets after resume", n)
	}
}
