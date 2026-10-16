package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// Dispatcher is the server's side of the nodes: a queue of jobs per node,
// leased to the node's polls up to its pool size, the results handed back
// to whoever waits for them, and the monitor that judges nodes offline,
// opens node_offline findings and rolls updates out. Nothing about jobs is
// persisted: after a restart the scheduler dispatches due targets again.
type Dispatcher struct {
	Core    *core.Service
	Version string // the server's version, which nodes converge on
	Log     *slog.Logger
	Now     func() time.Time
	// ClientIP returns the address a request came from, following the
	// proxy-trust rule as sign-in does.
	ClientIP func(*http.Request) string
	// OnOnline is called when a node polls again after it was offline, so
	// the scheduler checks its held targets.
	OnOnline func(nodeID int64)
	// Executable is the binary served to nodes of the server's own
	// platform; nil means os.Executable.
	Executable func() (string, error)
	// Releases is the base URL of the release assets for other platforms.
	Releases string
	// ReleaseKey verifies the release's SHA256SUMS; nil means
	// ReleasePublicKey. Tests sign with a key of their own.
	ReleaseKey ed25519.PublicKey
	// HTTP fetches the release checksums; nil uses a default client.
	HTTP *http.Client

	once    sync.Once
	mu      sync.Mutex
	started time.Time
	nodes   map[int64]*nodeState
	jobs    map[string]*job
	paused  bool
	epoch   int64
	stop    chan struct{} // closed when Run ends: held polls answer at once
	updMu   sync.Mutex    // one update decision at a time
	auth    limiter       // failed enrolments and credentials per address
	binary  binaryCache
}

type nodeState struct {
	meta     core.Node // as last loaded by the monitor or a poll
	known    bool      // meta is loaded
	lastSeen time.Time // the node's last request
	queue    []*job    // waiting for a poll, oldest first
	control  []Job     // cancel jobs for the next poll; they take no slot
	leased   int
	wake     chan struct{}
	online   bool // as last judged; changes bump the epoch
	judged   bool
	heard    bool // polled within the offline window, in this process

	factsAt time.Time // when the node's facts were last stored

	completed, failed int64
}

type job struct {
	id       string
	node     int64
	wire     Job
	req      probe.Request
	timeout  time.Duration
	leasedAt time.Time
	attempts int
	done     chan outcome
}

type outcome struct {
	res probe.Result
	err error
}

func (d *Dispatcher) init() {
	d.once.Do(func() {
		d.nodes = map[int64]*nodeState{}
		d.jobs = map[string]*job{}
		d.started = d.now()
		d.stop = make(chan struct{})
	})
}

func (d *Dispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Dispatcher) state(id int64) *nodeState {
	ns, ok := d.nodes[id]
	if !ok {
		ns = &nodeState{wake: make(chan struct{}, 1)}
		d.nodes[id] = ns
	}
	return ns
}

func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

func newID() string {
	b := make([]byte, 9)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// inGrace reports whether the server started less than d ago: after an
// outage every node needs its reconnect backoff before it can be judged.
func (d *Dispatcher) inGrace(after time.Duration) bool { return d.now().Sub(d.started) < after }

// seen is the last time the node was heard from: in this process, or as
// stored.
func (ns *nodeState) seen() time.Time {
	if ns.lastSeen.IsZero() && ns.meta.LastSeen > 0 {
		return time.Unix(ns.meta.LastSeen, 0)
	}
	return ns.lastSeen
}

// onlineLocked reports whether jobs can go to the node: confirmed, enabled
// and heard from within OfflineAfter (or the server only just started).
func (d *Dispatcher) onlineLocked(id int64) bool {
	ns, ok := d.nodes[id]
	if !ok || !ns.known || ns.meta.State != core.NodeConfirmed || !ns.meta.Enabled || !ns.meta.HasCredential {
		return false
	}
	if d.inGrace(OfflineAfter) {
		return true
	}
	return d.now().Sub(ns.seen()) <= OfflineAfter
}

// Online reports whether targets on the node can be checked now. A node
// that is offline, disabled or not confirmed holds its targets.
func (d *Dispatcher) Online(id int64) bool {
	d.init()
	d.mu.Lock()
	ns, ok := d.nodes[id]
	known := ok && ns.known
	d.mu.Unlock()
	if !known {
		d.load(context.Background(), id)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.onlineLocked(id)
}

// load reads one node into the cache.
func (d *Dispatcher) load(ctx context.Context, id int64) {
	n, err := d.Core.Node(ctx, id)
	d.mu.Lock()
	defer d.mu.Unlock()
	ns := d.state(id)
	if err != nil {
		ns.known, ns.meta = true, core.Node{ID: id}
		return
	}
	ns.meta, ns.known = n, true
}

// Refresh reloads a node after the UI changed it (enabled, confirmed,
// rotated, deleted).
func (d *Dispatcher) Refresh(ctx context.Context, id int64) {
	d.init()
	d.load(ctx, id)
	d.judge(ctx)
}

// Epoch changes whenever a node goes online or offline, for the change
// stamp of the live pages.
func (d *Dispatcher) Epoch() int64 {
	d.init()
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.epoch
}

// Status is what the UI shows of a node besides its stored state.
type Status struct {
	Online    bool
	LastSeen  time.Time
	Queued    int
	Running   int
	Completed int64
	Failed    int64
}

// Status returns a node's live state.
func (d *Dispatcher) Status(id int64) Status {
	online := d.Online(id)
	d.mu.Lock()
	defer d.mu.Unlock()
	ns := d.state(id)
	return Status{Online: online, LastSeen: ns.seen(), Queued: len(ns.queue), Running: ns.leased, Completed: ns.completed, Failed: ns.failed}
}

// Probe runs a probe on a node and waits for its result, which is judged
// on the server (see ProbeResult.Decode). It fails at once with
// core.ErrNodeOffline when the node is offline, so nothing is held for it.
// The job waits in the node's queue until a poll leases it; from then the
// node has the job's timeout to answer, after which the job is queued once
// more and then given up with core.ErrNodeNoResult.
func (d *Dispatcher) Probe(ctx context.Context, nodeID int64, req probe.Request) (probe.Result, error) {
	d.init()
	if !d.Online(nodeID) {
		return probe.Result{}, core.ErrNodeOffline
	}
	started := d.now()
	j := &job{id: newID(), node: nodeID, req: req, done: make(chan outcome, 1)}
	j.wire = Job{ID: j.id, Kind: KindProbe, Probe: NewProbeJob(req, started)}
	j.timeout = j.wire.Probe.Timeout()
	d.mu.Lock()
	if d.paused {
		d.mu.Unlock()
		return probe.Result{}, core.ErrNodesPaused
	}
	ns := d.state(nodeID)
	ns.queue = append(ns.queue, j)
	d.jobs[j.id] = j
	signal(ns.wake)
	d.mu.Unlock()
	select {
	case o := <-j.done:
		if o.err == nil && o.res.StartedAt.IsZero() {
			o.res.StartedAt = started
		}
		return o.res, o.err
	case <-ctx.Done():
		d.mu.Lock()
		if _, ok := d.jobs[j.id]; ok {
			if j.leasedAt.IsZero() {
				d.finishLocked(j, outcome{err: ctx.Err()})
			} else {
				// Tell the node to stop; its slot frees when the
				// cancelled probe returns, or at the job timeout.
				ns.control = append(ns.control, Job{ID: newID(), Kind: KindCancel, Cancel: j.id})
				signal(ns.wake)
				d.finishLocked(j, outcome{err: ctx.Err()})
			}
		}
		d.mu.Unlock()
		return probe.Result{}, ctx.Err()
	}
}

// finishLocked removes a job and hands its outcome to the waiter.
func (d *Dispatcher) finishLocked(j *job, o outcome) {
	if _, ok := d.jobs[j.id]; !ok {
		return
	}
	delete(d.jobs, j.id)
	ns := d.state(j.node)
	if j.leasedAt.IsZero() {
		for i, q := range ns.queue {
			if q == j {
				ns.queue = append(ns.queue[:i], ns.queue[i+1:]...)
				break
			}
		}
	} else {
		ns.leased--
	}
	if o.err != nil && o.err != context.Canceled && o.err != context.DeadlineExceeded {
		ns.failed++
	}
	select {
	case j.done <- o:
	default:
	}
}

// lease hands up to the node's free slots of queued jobs to a poll, with
// any cancel jobs.
func (d *Dispatcher) lease(id int64, pool int) []Job {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.paused {
		return nil
	}
	ns := d.state(id)
	out := ns.control
	ns.control = nil
	now := d.now()
	for len(ns.queue) > 0 && ns.leased < pool {
		j := ns.queue[0]
		ns.queue = ns.queue[1:]
		j.leasedAt, j.attempts = now, j.attempts+1
		ns.leased++
		out = append(out, j.wire)
	}
	return out
}

// complete takes a node's result for one of its jobs; an unknown, expired
// or foreign job id is discarded.
func (d *Dispatcher) complete(nodeID int64, id string, res Result) {
	d.mu.Lock()
	j, ok := d.jobs[id]
	if !ok || j.node != nodeID || j.leasedAt.IsZero() {
		d.mu.Unlock()
		return
	}
	req, leasedAt := j.req, j.leasedAt
	d.mu.Unlock()
	// The certificates are parsed outside the lock: a result is up to a
	// few megabytes of DER, and every poll waits on the lock.
	o := outcome{err: core.ErrNodeNoResult}
	switch {
	case res.Error != "":
		o.err = &nodeError{msg: core.Clip(res.Error, core.TextMax)}
	case res.Probe != nil:
		o.res, o.err = res.Probe.Decode(req, leasedAt)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if cur, ok := d.jobs[id]; !ok || cur != j || j.leasedAt != leasedAt {
		return // expired or re-leased meanwhile
	}
	if o.err == nil {
		d.state(nodeID).completed++
	}
	d.finishLocked(j, o)
}

// nodeError is a job a node could not run at all.
type nodeError struct{ msg string }

func (e *nodeError) Error() string { return "node: " + e.msg }

// Pause drops every queued and leased job, for a restore: the waiting
// checks end at once, polls are answered empty and late results are
// discarded until Resume.
func (d *Dispatcher) Pause() {
	d.init()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.paused = true
	for _, j := range d.jobs {
		d.finishLocked(j, outcome{err: core.ErrNodesPaused})
	}
}

// Resume ends a pause. The node cache is dropped: the database may have
// been replaced.
func (d *Dispatcher) Resume() {
	d.init()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.paused = false
	for _, ns := range d.nodes {
		ns.known, ns.queue, ns.control, ns.leased = false, nil, nil, 0
	}
	d.epoch++
}

// Run is the monitor: every few seconds it reloads the nodes, judges them
// online or offline, re-queues or gives up jobs past their timeout, opens
// node_offline findings, ends updates that did not come back and expires
// unfinished enrolments.
func (d *Dispatcher) Run(ctx context.Context) {
	d.init()
	defer close(d.stop)
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	tick := 0
	for {
		d.reload(ctx)
		d.judge(ctx)
		d.expireJobs()
		if tick%6 == 0 {
			d.findings(ctx)
			if err := d.Core.ExpireNodes(ctx); err != nil && ctx.Err() == nil {
				d.Log.Error("expire nodes", "err", err)
			}
		}
		tick++
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// reload refreshes the cache of every node from the database.
func (d *Dispatcher) reload(ctx context.Context) {
	d.init()
	nodes, err := d.Core.Nodes(ctx)
	if err != nil {
		if ctx.Err() == nil {
			d.Log.Error("load nodes", "err", err)
		}
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	present := map[int64]bool{}
	for _, n := range nodes {
		present[n.ID] = true
		ns := d.state(n.ID)
		ns.meta, ns.known = n, true
	}
	for id, ns := range d.nodes {
		if !present[id] {
			ns.meta, ns.known = core.Node{ID: id}, true
		}
	}
}

// judge records online/offline transitions. A node that goes offline
// fails its queued jobs, so the scheduler holds their targets. One that is
// heard from again (a poll, not the start grace, which would resolve the
// finding of a node that is still down) has its node_offline finding
// resolved and its held targets checked.
func (d *Dispatcher) judge(ctx context.Context) {
	var back []core.Node
	d.mu.Lock()
	now := d.now()
	for id, ns := range d.nodes {
		if !ns.known {
			continue
		}
		heard := !ns.lastSeen.IsZero() && now.Sub(ns.lastSeen) <= OfflineAfter && d.onlineLocked(id)
		if heard && !ns.heard && ns.meta.ID != 0 {
			back = append(back, ns.meta)
		}
		ns.heard = heard
		online := d.onlineLocked(id)
		if ns.judged && online == ns.online {
			continue
		}
		was := ns.online && ns.judged
		ns.online, ns.judged = online, true
		d.epoch++
		if !online {
			for _, j := range append([]*job(nil), ns.queue...) {
				d.finishLocked(j, outcome{err: core.ErrNodeOffline})
			}
			if was {
				d.Log.Warn("node offline", "node_id", id, "node", ns.meta.Label(), "last_seen", ns.seen())
			}
		}
	}
	d.mu.Unlock()
	for _, n := range back {
		if err := d.Core.NodeOnline(ctx, n); err != nil && ctx.Err() == nil {
			d.Log.Error("node online", "node_id", n.ID, "err", err)
		}
		if d.OnOnline != nil {
			d.OnOnline(n.ID)
		}
	}
}

// expireJobs re-queues a leased job past its timeout once, then gives it
// up.
func (d *Dispatcher) expireJobs() {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	for _, j := range d.jobs {
		if j.leasedAt.IsZero() || now.Sub(j.leasedAt) < j.timeout {
			continue
		}
		ns := d.state(j.node)
		if j.attempts < 2 {
			ns.leased--
			j.leasedAt = time.Time{}
			ns.queue = append([]*job{j}, ns.queue...)
			signal(ns.wake)
			continue
		}
		d.finishLocked(j, outcome{err: core.ErrNodeNoResult})
	}
}

// findings opens or escalates node_offline on nodes offline for
// FindingAfter, and ends updates that did not come back in time.
func (d *Dispatcher) findings(ctx context.Context) {
	type offline struct {
		n    core.Node
		seen time.Time
	}
	var down []offline
	var stuck []core.Node
	d.mu.Lock()
	now := d.now()
	for id, ns := range d.nodes {
		n := ns.meta
		if !ns.known || n.ID == 0 {
			continue
		}
		if n.UpdateStarted > 0 && now.Sub(time.Unix(n.UpdateStarted, 0)) > UpdateWindow && n.Version != n.UpdateTo {
			stuck = append(stuck, n)
		}
		if n.State != core.NodeConfirmed || !n.Enabled || d.onlineLocked(id) || d.inGrace(FindingAfter) {
			continue
		}
		seen := ns.seen()
		if now.Sub(seen) >= FindingAfter {
			down = append(down, offline{n, seen})
		}
	}
	d.mu.Unlock()
	for _, o := range down {
		if err := d.Core.NodeOffline(ctx, o.n, o.seen); err != nil && ctx.Err() == nil {
			d.Log.Error("node offline finding", "node_id", o.n.ID, "err", err)
		}
	}
	for _, n := range stuck {
		d.endUpdate(ctx, n, "did not come back on "+n.UpdateTo+" within five minutes")
	}
}

func (d *Dispatcher) endUpdate(ctx context.Context, n core.Node, failure string) {
	if err := d.Core.EndNodeUpdate(ctx, n, failure); err != nil {
		d.Log.Error("node update", "node_id", n.ID, "err", err)
		return
	}
	if failure != "" {
		d.Log.Warn("node update failed", "node_id", n.ID, "node", n.Label(), "from", n.UpdateFrom, "to", n.UpdateTo, "reason", failure)
	} else {
		d.Log.Info("node updated", "node_id", n.ID, "node", n.Label(), "version", n.Version)
	}
	d.load(ctx, n.ID)
}

// releaseRE is a release tag, vX.Y.Z exactly. A development build
// (2026.10.15-5efacf7, v0.2.0-5-g5efacf7, anything -dirty, dev) is not one.
var releaseRE = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// IsRelease reports a release version, which nodes follow automatically
// and which has release assets for other platforms; other builds update
// nodes only by hand.
func IsRelease(v string) bool { return releaseRE.MatchString(v) }

// wantUpdate decides, at a node's poll, whether it gets an update job:
// when its version differs from the server's, it is not a container, and
// either an admin asked or "Keep nodes on the server's version" is on for a
// release. One node updates at a time. It also closes the node's running
// update: success when it reports the new version, failure when it reports
// a rollback or stayed away past UpdateWindow.
func (d *Dispatcher) wantUpdate(ctx context.Context, n core.Node, rollback string) bool {
	d.updMu.Lock()
	defer d.updMu.Unlock()
	if n.UpdateStarted > 0 {
		switch {
		case n.Version == n.UpdateTo:
			d.endUpdate(ctx, n, "")
		case rollback != "":
			d.endUpdate(ctx, n, rollback)
		case d.now().Sub(time.Unix(n.UpdateStarted, 0)) > UpdateWindow:
			d.endUpdate(ctx, n, "did not come back on "+n.UpdateTo+" within five minutes")
		}
		return false
	}
	if n.Version == d.Version || n.Facts.Container || n.State != core.NodeConfirmed || !n.Enabled {
		return false
	}
	if n.UpdateRequested == 0 {
		auto := d.Core.CurrentSettings(ctx).Nodes.AutoUpdate && IsRelease(d.Version)
		if !auto || n.UpdateFailed != "" {
			return false
		}
	}
	nodes, err := d.Core.Nodes(ctx)
	if err != nil {
		return false
	}
	for _, o := range nodes {
		if o.ID != n.ID && o.UpdateStarted > 0 && d.now().Sub(time.Unix(o.UpdateStarted, 0)) <= UpdateWindow {
			return false
		}
	}
	if err := d.Core.StartNodeUpdate(ctx, n, d.Version); err != nil {
		d.Log.Error("node update", "node_id", n.ID, "err", err)
		return false
	}
	d.Log.Info("updating node", "node_id", n.ID, "node", n.Label(), "from", n.Version, "to", d.Version)
	d.load(ctx, n.ID)
	return true
}

// Updating returns the progress of an update round: how many nodes are not
// on the server's version yet, and which place the running one has.
func (d *Dispatcher) Updating(nodes []core.Node) (n, of int) {
	for _, x := range nodes {
		if x.State != core.NodeConfirmed || x.Facts.Container {
			continue
		}
		if x.UpdateStarted > 0 {
			n = of + 1
		}
		if x.Version != d.Version || x.UpdateStarted > 0 {
			of++
		}
	}
	return n, of
}

// Stats are the per-node counters for /metrics.
type Stats struct {
	Node      core.Node
	Online    bool
	LastSeen  time.Time
	Completed int64
	Failed    int64
}

// Stats returns the counters of every confirmed node.
func (d *Dispatcher) Stats() []Stats {
	d.init()
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []Stats
	for id, ns := range d.nodes {
		if !ns.known || ns.meta.State != core.NodeConfirmed {
			continue
		}
		out = append(out, Stats{Node: ns.meta, Online: d.onlineLocked(id), LastSeen: ns.seen(), Completed: ns.completed, Failed: ns.failed})
	}
	return out
}
