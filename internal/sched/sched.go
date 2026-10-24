// Package sched runs the checks: a priority queue of targets by next-run
// time, a bounded worker pool, the Check now / Check all requests and the
// periodic housekeeping (reminders, retention, digest).
package sched

import (
	"container/heap"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

type item struct {
	id     int64
	next   int64 // when to run; held while its node is offline
	stored int64 // next_check in the database when next was set; -1: unknown
	node   int64 // the node the target is probed from, 0 for this server
	idx    int
}

// held is the run time of a target whose node is offline: it stays in the
// queue, behind everything else, until the node polls again.
const held = math.MaxInt64

// NodeProber runs probes on nodes (node.Dispatcher).
type NodeProber interface {
	// Online reports whether jobs can go to the node now.
	Online(id int64) bool
	// Probe runs a probe on the node and waits for its result; it fails
	// with core.ErrNodeOffline when the node is offline.
	Probe(ctx context.Context, nodeID int64, req probe.Request) (probe.Result, error)
	// Scan runs one chunk of a discovery scan on the node.
	Scan(ctx context.Context, nodeID int64, req probe.ScanRequest) (probe.ScanResult, error)
	// FetchCRL fetches a CRL on the node and returns its bytes.
	FetchCRL(ctx context.Context, nodeID int64, url string) ([]byte, error)
}

type queue []*item

func (q queue) Len() int           { return len(q) }
func (q queue) Less(i, j int) bool { return q[i].next < q[j].next }
func (q queue) Swap(i, j int)      { q[i], q[j] = q[j], q[i]; q[i].idx = i; q[j].idx = j }
func (q *queue) Push(x any)        { it := x.(*item); it.idx = len(*q); *q = append(*q, it) }
func (q *queue) Pop() any {
	old := *q
	it := old[len(old)-1]
	*q = old[:len(old)-1]
	it.idx = -1
	return it
}

// Scheduler owns the check schedule.
type Scheduler struct {
	Core *core.Service
	Log  *slog.Logger
	Now  func() time.Time
	// Probe and Scan are replaceable in tests.
	Probe func(ctx context.Context, req probe.Request) probe.Result
	Scan  func(ctx context.Context, req probe.ScanRequest) (probe.ScanResult, error)
	// PruneSessions removes expired sessions and tokens; run hourly with
	// the retention.
	PruneSessions func(ctx context.Context) error
	// Nodes probes the targets assigned to a node. Their checks run
	// outside the worker pool, which stays free for local probes; the
	// node's own pool size bounds them.
	Nodes NodeProber

	mu       sync.Mutex
	q        queue
	byID     map[int64]*item
	inflight map[int64]chan struct{}
	fails    map[int64]int            // consecutive checks that could not be stored
	held     map[int64]map[int64]bool // node → targets held while it is offline
	running  int
	nodeRun  int            // checks running on nodes, outside the pool
	onNodes  int            // queued targets that are probed from a node
	wg       sync.WaitGroup // checks and housekeeping started by Run
	wake     chan struct{}
	reload   chan struct{}
	once     sync.Once
	paused   bool       // a restore runs: start no checks
	hk       sync.Mutex // held by each housekeeping run, and by a pause
	// digestWarned is the digest slot whose failure was logged, so a
	// missing channel is logged once, not every minute of the catch-up.
	digestWarned string

	base context.Context // Run's context: scans end with it

	statMu    sync.Mutex
	lastLoop  time.Time
	lastCheck time.Time
	checks    int64
}

func (s *Scheduler) init() {
	s.once.Do(func() {
		s.byID = map[int64]*item{}
		s.inflight = map[int64]chan struct{}{}
		s.fails = map[int64]int{}
		s.held = map[int64]map[int64]bool{}
		s.wake = make(chan struct{}, 1)
		s.reload = make(chan struct{}, 1)
	})
}

func (s *Scheduler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// Reload re-reads the schedule from the database, after targets changed.
func (s *Scheduler) Reload() { s.init(); signal(s.reload) }

// Status is reported by /healthz.
type Status struct {
	LastLoop  time.Time
	LastCheck time.Time
	Backlog   int           // targets due and not yet started
	Overdue   time.Duration // how long the oldest of them has waited
	Running   int
	OnNodes   int // checks running on nodes
	Held      int // targets held while their node is offline
	Checks    int64
}

// Status returns scheduler progress.
func (s *Scheduler) Status() Status {
	s.init()
	now := s.now().Unix()
	s.mu.Lock()
	backlog, heldN := 0, 0
	for _, it := range s.q {
		switch {
		case it.next == held:
			heldN++
		case it.next <= now:
			backlog++
		}
	}
	var overdue time.Duration
	if len(s.q) > 0 && s.q[0].next > 0 && s.q[0].next < now {
		overdue = time.Duration(now-s.q[0].next) * time.Second
	}
	running, onNodes := s.running, s.nodeRun
	s.mu.Unlock()
	s.statMu.Lock()
	defer s.statMu.Unlock()
	return Status{LastLoop: s.lastLoop, LastCheck: s.lastCheck, Backlog: backlog, Overdue: overdue, Running: running, OnNodes: onNodes,
		Held: heldN, Checks: s.checks}
}

// load merges the database schedule into the queue. A queued target keeps
// its time unless its next_check changed in the database (it was edited,
// or checked elsewhere), so a reload does not undo Check all, the startup
// spread or a retry delay. Targets no longer enabled are dropped. At
// startup, overdue targets that were already checked once are spread over
// the next few minutes, so a restart does not fire every probe at once;
// never-checked targets run right away.
func (s *Scheduler) load(ctx context.Context, startup bool) error {
	sched, err := s.Core.Schedule(ctx)
	if err != nil {
		return err
	}
	now := s.now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	spread := max(int64(300), int64(len(sched))) // at least one second per target
	for id, it := range s.byID {
		if _, ok := sched[id]; !ok {
			s.removeLocked(it)
		}
	}
	for id, sl := range sched {
		if it, ok := s.byID[id]; ok && it.stored == sl.Next {
			s.nodeLocked(it, sl.Node)
			continue
		}
		next := sl.Next
		if startup && next != 0 && next < now {
			next = now + rand.Int64N(spread) // #nosec G404 -- schedule jitter, not a secret
		}
		s.setLocked(id, next, sl.Next)
		s.nodeLocked(s.byID[id], sl.Node)
	}
	return nil
}

// Run processes the schedule until ctx ends, then waits for the checks it
// started, which end early as their context is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	s.init()
	defer s.wg.Wait()
	s.mu.Lock()
	s.base = ctx
	s.mu.Unlock()
	if err := s.Core.FailRunningScans(ctx); err != nil {
		s.Log.Error("end interrupted scans", "err", err)
	}
	if err := s.load(ctx, true); err != nil {
		s.Log.Error("load schedule", "err", err)
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.housekeeping(ctx)
	}()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	refresh := time.NewTicker(time.Minute) // picks up targets added outside the UI
	defer refresh.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.wake:
		case <-refresh.C:
			if err := s.load(ctx, false); err != nil {
				s.Log.Error("load schedule", "err", err)
			}
		case <-s.reload:
			if err := s.load(ctx, false); err != nil {
				s.Log.Error("load schedule", "err", err)
			}
		}
		s.statMu.Lock()
		s.lastLoop = s.now()
		s.statMu.Unlock()
		s.dispatch(ctx)
	}
}

func (s *Scheduler) workers(ctx context.Context) int {
	n := s.Core.CurrentSettings(ctx).Defaults.Workers
	if n < 1 {
		n = 1
	}
	return n
}

// ErrPaused is returned by CheckNow while a restore runs.
var ErrPaused = errors.New("checks are paused while a backup is restored")

// Pause stops starting checks and housekeeping, and waits until the running
// ones have finished, so the database can be replaced under them. After a
// nil return, Resume ends it.
func (s *Scheduler) Pause(ctx context.Context) error {
	s.init()
	s.mu.Lock()
	s.paused = true
	s.mu.Unlock()
	for {
		s.mu.Lock()
		var wait chan struct{}
		for _, done := range s.inflight {
			wait = done
			break
		}
		s.mu.Unlock()
		if wait == nil {
			break
		}
		select {
		case <-wait:
		case <-ctx.Done():
			s.mu.Lock()
			s.paused = false
			s.mu.Unlock()
			return ctx.Err()
		}
	}
	s.hk.Lock()
	return nil
}

// Resume starts checks again after a successful Pause. With reset, the
// database was replaced: the schedule and retry state are rebuilt from it
// as at startup.
func (s *Scheduler) Resume(ctx context.Context, reset bool) {
	s.mu.Lock()
	if reset {
		s.q, s.byID, s.fails, s.held, s.onNodes = nil, map[int64]*item{}, map[int64]int{}, map[int64]map[int64]bool{}, 0
	}
	s.mu.Unlock()
	if reset {
		if err := s.load(ctx, true); err != nil {
			s.Log.Error("load schedule", "err", err)
		}
	}
	s.mu.Lock()
	s.paused = false
	s.mu.Unlock()
	s.hk.Unlock()
	signal(s.wake)
}

// dispatch starts due checks: local ones while workers are free, node ones
// whenever their node is online (the node's pool bounds them). A due
// target whose node is offline is held until the node polls again.
func (s *Scheduler) dispatch(ctx context.Context) {
	limit := s.workers(ctx)
	now := s.now().Unix()
	var waiting []*item // local checks due while the pool is full
	defer func() {
		s.mu.Lock()
		for _, it := range waiting {
			if _, dup := s.byID[it.id]; !dup {
				s.pushLocked(it)
			}
		}
		s.mu.Unlock()
	}()
	for {
		s.mu.Lock()
		full := s.running >= limit
		if s.paused || len(s.q) == 0 || s.q[0].next > now || full && s.onNodes == 0 {
			s.mu.Unlock()
			return
		}
		it := s.popLocked()
		if _, busy := s.inflight[it.id]; busy {
			s.mu.Unlock()
			continue
		}
		if it.node == 0 && full {
			waiting = append(waiting, it)
			s.mu.Unlock()
			continue
		}
		if it.node != 0 {
			s.mu.Unlock()
			online := s.Nodes != nil && s.Nodes.Online(it.node)
			s.mu.Lock()
			_, dup := s.byID[it.id]
			_, busy := s.inflight[it.id]
			switch {
			case dup || busy:
				s.mu.Unlock()
				continue
			case !online:
				s.holdLocked(it, it.stored)
				s.mu.Unlock()
				continue
			}
			s.nodeRun++
		} else {
			s.running++
		}
		done := make(chan struct{})
		s.inflight[it.id] = done
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.run(ctx, it.id, it.node, done)
		}()
	}
}

// pushLocked puts an item into the queue.
func (s *Scheduler) pushLocked(it *item) {
	s.byID[it.id] = it
	heap.Push(&s.q, it)
	if it.node != 0 {
		s.onNodes++
	}
}

// popLocked takes the first item off the queue.
func (s *Scheduler) popLocked() *item {
	it := heap.Pop(&s.q).(*item)
	delete(s.byID, it.id)
	if it.node != 0 {
		s.onNodes--
	}
	return it
}

// removeLocked drops a queued item.
func (s *Scheduler) removeLocked(it *item) {
	heap.Remove(&s.q, it.idx)
	delete(s.byID, it.id)
	if it.node != 0 {
		s.onNodes--
	}
}

// nodeLocked records the node a queued target is probed from.
func (s *Scheduler) nodeLocked(it *item, node int64) {
	if it == nil || it.node == node {
		return
	}
	switch {
	case it.node == 0:
		s.onNodes++
	case node == 0:
		s.onNodes--
	}
	it.node = node
}

// holdLocked keeps a target queued, behind everything else, until its node
// polls again.
func (s *Scheduler) holdLocked(it *item, stored int64) {
	if _, ok := s.byID[it.id]; !ok {
		it.next, it.stored = held, stored
		s.pushLocked(it)
	} else {
		s.setLocked(it.id, held, stored)
	}
	if s.held[it.node] == nil {
		s.held[it.node] = map[int64]bool{}
	}
	s.held[it.node][it.id] = true
}

// NodeOnline releases the targets held for a node that polls again: the
// overdue ones are checked right away, spread over a few minutes.
func (s *Scheduler) NodeOnline(node int64) {
	s.init()
	now := s.now().Unix()
	s.mu.Lock()
	ids := s.held[node]
	delete(s.held, node)
	spread := min(int64(300), max(int64(30), 3*int64(len(ids))))
	n := 0
	for id := range ids {
		if it, ok := s.byID[id]; ok && it.next == held {
			s.setLocked(id, now+rand.Int64N(spread), it.stored) // #nosec G404 -- schedule jitter, not a secret
			n++
		}
	}
	s.mu.Unlock()
	if n > 0 {
		s.Log.Info("node back: checking its held targets", "node_id", node, "targets", n, "spread_s", spread)
		signal(s.wake)
	}
}

func (s *Scheduler) run(ctx context.Context, id, node int64, done chan struct{}) {
	t, err := s.check(ctx, id, false)
	offline := errors.Is(err, core.ErrNodeOffline)
	switch {
	case offline:
		s.Log.Info("check held: the node is offline", "target_id", id, "target", t.Name, "node_id", t.NodeID)
	case errors.Is(err, core.ErrNodesPaused):
	case errors.Is(err, core.ErrStale):
		// Edited or disabled meanwhile; the reload picks up the new slot.
		s.Log.Info("check discarded: target changed during the check", "target_id", id, "target", t.Name)
		t, err = core.Target{}, nil // t is from before the change: requeue reads it again
	case err != nil && ctx.Err() == nil && !errors.Is(err, core.ErrNotFound):
		s.Log.Error("check failed", "target_id", id, "target", t.Name, "err", err)
	}
	s.mu.Lock()
	if node != 0 {
		s.nodeRun--
	} else {
		s.running--
	}
	delete(s.inflight, id)
	if offline && ctx.Err() == nil && t.Enabled {
		s.holdLocked(&item{id: id, node: t.NodeID}, t.NextCheck)
	}
	s.mu.Unlock()
	close(done)
	if ctx.Err() != nil || offline {
		return
	}
	s.requeue(ctx, id, t, err)
	signal(s.wake)
}

// maxRetryDelay caps the delay before a check that could not be stored is
// tried again.
const maxRetryDelay = time.Hour

// retryDelay is the wait after n consecutive checks that could not be
// stored: 1, 2, 4 … minutes, up to maxRetryDelay.
func retryDelay(n int) time.Duration {
	if n > 7 {
		return maxRetryDelay
	}
	return min(time.Minute<<(n-1), maxRetryDelay)
}

// requeue puts a target back after a check: at the slot the check stored,
// or, when the check could not be stored (the slot did not move), after a
// growing delay so a persistent error does not re-probe in a loop. After a
// stored check t is the state check read back; otherwise it is read again.
func (s *Scheduler) requeue(ctx context.Context, id int64, t core.Target, checkErr error) {
	if checkErr != nil || t.ID == 0 {
		var err error
		if t, err = s.Core.Target(ctx, id); err != nil {
			return
		}
	}
	if !t.Enabled {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if checkErr == nil {
		delete(s.fails, id)
		s.setLocked(id, t.NextCheck, t.NextCheck)
	} else {
		s.fails[id]++
		s.setLocked(id, s.now().Add(retryDelay(s.fails[id])).Unix(), t.NextCheck)
	}
	s.nodeLocked(s.byID[id], t.NodeID)
}

// runAt queues a target to run at next, keeping what is known of its
// stored slot.
func (s *Scheduler) runAt(id, next int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := int64(-1)
	if it, ok := s.byID[id]; ok {
		stored = it.stored
	}
	s.setLocked(id, next, stored)
}

func (s *Scheduler) setLocked(id, next, stored int64) {
	if it, ok := s.byID[id]; ok {
		it.next, it.stored = next, stored
		heap.Fix(&s.q, it.idx)
		return
	}
	s.pushLocked(&item{id: id, next: next, stored: stored})
}

// check probes and stores one target; legacy tests the old versions even
// when the daily test is not due.
// check runs one check and never panics: a fault in the probe, the
// evaluation or the store becomes an error for this target, logged with
// its stack, and the process goes on.
func (s *Scheduler) check(ctx context.Context, id int64, legacy bool) (t core.Target, err error) {
	defer func() {
		if v := recover(); v != nil {
			s.Log.Error("check panicked", "target_id", id, "err", v, "stack", string(debug.Stack()))
			err = fmt.Errorf("check failed: %v", v)
		}
	}()
	return s.checkTarget(ctx, id, legacy)
}

func (s *Scheduler) checkTarget(ctx context.Context, id int64, legacy bool) (core.Target, error) {
	t, err := s.Core.Target(ctx, id)
	if err != nil {
		return t, err
	}
	st := s.Core.CurrentSettings(ctx)
	req, err := s.Core.ProbeRequest(ctx, t, st)
	if err != nil {
		return t, err
	}
	req.Legacy = req.Legacy || legacy && !t.SkipLegacy
	var r probe.Result
	if t.NodeID != 0 {
		if s.Nodes == nil {
			return t, core.ErrNodeOffline
		}
		if r, err = s.Nodes.Probe(ctx, t.NodeID, req); err != nil {
			return t, err
		}
	} else {
		pf := probe.Probe
		if s.Probe != nil {
			pf = s.Probe
		}
		r = pf(ctx, req)
	}
	if ctx.Err() != nil {
		return t, ctx.Err()
	}
	// A CRL a day old or missing is fetched before the checks, so a
	// revocation shows on the first observation after it is listed.
	var onNode core.NodeCRLFetch
	if s.Nodes != nil {
		onNode = s.Nodes.FetchCRL
	}
	s.Core.RefreshCRLs(ctx, t, r, onNode)
	sum, err := s.Core.Apply(ctx, t, r)
	if err != nil {
		return t, err
	}
	s.statMu.Lock()
	s.lastCheck = s.now()
	s.checks++
	s.statMu.Unlock()
	attrs := append([]any{"target_id", t.ID, "target", t.Name, "endpoint", t.HostPort(), "node_id", t.NodeID, "addresses", len(r.Addresses),
		"dns_error", r.DNSError, "ms", r.Duration.Milliseconds()}, sum.LogAttrs()...)
	s.Log.Info("checked", attrs...)
	return s.Core.Target(ctx, id)
}

// CheckNow probes one target right away and returns its new state. A check
// already running for the target is waited for instead of duplicated.
func (s *Scheduler) CheckNow(ctx context.Context, id int64) (core.Target, error) {
	s.init()
	s.mu.Lock()
	if s.paused {
		s.mu.Unlock()
		return core.Target{}, ErrPaused
	}
	if done, busy := s.inflight[id]; busy {
		s.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return core.Target{}, ctx.Err()
		}
		return s.Core.Target(ctx, id)
	}
	done := make(chan struct{})
	s.inflight[id] = done
	s.running++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running--
		delete(s.inflight, id)
		s.mu.Unlock()
		close(done)
	}()
	t, err := s.check(ctx, id, true)
	if errors.Is(err, core.ErrStale) {
		return s.Core.Target(ctx, id) // edited meanwhile; it is checked again soon
	}
	if err == nil && t.Enabled {
		s.mu.Lock()
		delete(s.fails, id)
		s.setLocked(id, t.NextCheck, t.NextCheck)
		s.nodeLocked(s.byID[id], t.NodeID)
		s.mu.Unlock()
	}
	return t, err
}

// CheckSoon queues one target to run now, through the pool: after it was
// added, changed or enabled.
func (s *Scheduler) CheckSoon(id int64) {
	s.init()
	s.runAt(id, s.now().Unix())
	signal(s.wake)
}

// CheckAll queues every enabled target to run now, through the pool.
func (s *Scheduler) CheckAll(ctx context.Context) (int, error) {
	s.init()
	sched, err := s.Core.Schedule(ctx)
	if err != nil {
		return 0, err
	}
	now := s.now().Unix()
	for id := range sched {
		s.runAt(id, now)
	}
	s.mu.Lock()
	for id, sl := range sched {
		s.nodeLocked(s.byID[id], sl.Node)
	}
	s.mu.Unlock()
	signal(s.wake)
	return len(sched), nil
}

// housekeeping runs reminders, retention, the digest and the Certificate
// Transparency polls (each watch on its own interval; PollDomains decides
// which are due).
func (s *Scheduler) housekeeping(ctx context.Context) {
	remind := time.NewTicker(5 * time.Minute)
	prune := time.NewTicker(time.Hour)
	minute := time.NewTicker(time.Minute)
	defer remind.Stop()
	defer prune.Stop()
	defer minute.Stop()
	s.housework(func() { s.prune(ctx) })
	for {
		select {
		case <-ctx.Done():
			return
		case <-remind.C:
			s.housework(func() {
				if n, err := s.Core.Remind(ctx); err != nil {
					s.Log.Error("reminders", "err", err)
				} else if n > 0 {
					s.Log.Info("reminders queued", "alerts", n)
				}
			})
		case <-prune.C:
			s.housework(func() { s.prune(ctx) })
		case <-minute.C:
			s.housework(func() { s.digest(ctx) })
			s.housework(func() {
				if err := s.Core.PollDomains(ctx); err != nil && ctx.Err() == nil {
					s.Log.Error("ct polls", "err", err)
				}
			})
		}
	}
}

// housework runs one housekeeping task, waiting while a restore runs.
func (s *Scheduler) housework(f func()) {
	s.hk.Lock()
	defer s.hk.Unlock()
	f()
}

func (s *Scheduler) prune(ctx context.Context) {
	if err := s.Core.Prune(ctx); err != nil {
		s.Log.Error("retention", "err", err)
	}
	if s.PruneSessions != nil {
		if err := s.PruneSessions(ctx); err != nil {
			s.Log.Error("prune sessions", "err", err)
		}
	}
}

// DigestCatchUp is how long after its slot a digest missed (the server
// was down) is still sent; after that the week is skipped.
const DigestCatchUp = 24 * time.Hour

// digestSlot is the latest configured weekday and hour at or before now.
func digestSlot(now time.Time, weekday, hour int) time.Time {
	back := (int(now.Weekday()) - weekday + 7) % 7
	slot := time.Date(now.Year(), now.Month(), now.Day()-back, hour, 0, 0, 0, now.Location())
	if slot.After(now) {
		slot = time.Date(now.Year(), now.Month(), now.Day()-back-7, hour, 0, 0, 0, now.Location())
	}
	return slot
}

// digest sends the weekly digest once per week: in the configured hour, or
// as soon as possible within DigestCatchUp after it.
func (s *Scheduler) digest(ctx context.Context) {
	st := s.Core.CurrentSettings(ctx)
	d := st.Defaults
	if !d.DigestEnabled {
		return
	}
	now := s.now().In(st.Location())
	slot := digestSlot(now, d.DigestWeekday, d.DigestHour)
	if now.Sub(slot) >= DigestCatchUp {
		return
	}
	stamp := slot.Format("2006-01-02")
	var last string
	err := s.Core.DB.R.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'digest.last'").Scan(&last)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.Log.Error("digest", "err", err)
		return
	}
	if last == strconv.Quote(stamp) {
		return
	}
	if err := s.SendDigest(ctx); err != nil {
		if s.digestWarned != stamp {
			s.digestWarned = stamp
			s.Log.Error("digest", "err", err)
		}
		return
	}
	_, _ = s.Core.DB.W.ExecContext(ctx, "INSERT INTO settings(key, value) VALUES('digest.last', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", strconv.Quote(stamp))
}

// SendDigest queues the digest to the digest channels (every SMTP channel
// when none are chosen).
func (s *Scheduler) SendDigest(ctx context.Context) error {
	st := s.Core.CurrentSettings(ctx)
	m, err := s.Core.Digest(ctx)
	if err != nil {
		return err
	}
	chans, err := s.Core.Channels.Enabled(ctx)
	if err != nil {
		return err
	}
	want := map[int64]bool{}
	for _, id := range st.Defaults.DigestChannels {
		want[id] = true
	}
	var ids []int64
	for _, c := range chans {
		if (len(want) == 0 && c.Kind == "smtp") || want[c.ID] {
			ids = append(ids, c.ID)
		}
	}
	if len(ids) == 0 {
		return errors.New("no channel for the digest; add an SMTP channel")
	}
	return s.Core.Dispatcher.SendNow(ctx, ids, "digest", m)
}
