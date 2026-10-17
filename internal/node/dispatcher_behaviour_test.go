package node

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// call sends one raw agent call to the test server.
func (e *env) call(t *testing.T, method, path, cred string, body []byte, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

type probeOutcome struct {
	res probe.Result
	err error
}

// probeAsync runs a dispatcher probe in the background.
func (e *env) probeAsync(ctx context.Context, id int64, req probe.Request) <-chan probeOutcome {
	ch := make(chan probeOutcome, 1)
	go func() {
		r, err := e.disp.Probe(ctx, id, req)
		ch <- probeOutcome{r, err}
	}()
	return ch
}

// waitLease leases the node's queued jobs, waiting for one to arrive.
func (e *env) waitLease(t *testing.T, id int64, pool int) []Job {
	t.Helper()
	for i := 0; i < 400; i++ {
		if jobs := e.disp.lease(id, pool); len(jobs) > 0 {
			return jobs
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no job to lease")
	return nil
}

// waitQueued waits until n jobs wait in the node's queue.
func (e *env) waitQueued(t *testing.T, id int64, n int) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if e.disp.Status(id).Queued == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("queue never reached %d: %+v", n, e.disp.Status(id))
}

func resultJSON(r Result) []byte {
	b, _ := json.Marshal(r)
	return b
}

func outcomeWithin(t *testing.T, ch <-chan probeOutcome, d time.Duration) (probeOutcome, bool) {
	t.Helper()
	select {
	case o := <-ch:
		return o, true
	case <-time.After(d):
		return probeOutcome{}, false
	}
}

var nodeReq = probe.Request{Host: "a.example", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem, Timeout: time.Second}

// The monitor reloads the nodes, deletes an enrolment nobody confirmed
// within the hour, and, when it ends (the server shuts down), answers the
// polls it holds at once instead of letting them run to the ceiling.
func TestRunExpiresEnrolmentsAndReleasesHeldPolls(t *testing.T) {
	e := setup(t)
	e.core.Now = e.clock.now
	ctx := context.Background()
	c := e.client(t, "v1.2.0")
	c.HTTP = &http.Client{Timeout: 30 * time.Second}
	e.enrolled(t, c)
	_, tok, err := e.core.CreateNode(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	pendingID, err := e.client(t, "v1.2.0").Enrol(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	e.clock.add(core.NodeTokenTTL + time.Minute)

	runCtx, stopRun := context.WithCancel(ctx)
	ran := make(chan struct{})
	go func() { e.disp.Run(runCtx); close(ran) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := e.core.Node(ctx, pendingID); errors.Is(err, core.ErrNotFound) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("an unconfirmed node outlived its hour")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e.disp.Online(pendingID) {
		t.Fatal("a deleted enrolment counts as online")
	}

	polled := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := c.poll(ctx, "")
		polled <- err
	}()
	time.Sleep(200 * time.Millisecond) // the poll is held now
	stopRun()
	<-ran
	select {
	case err := <-polled:
		if err != nil {
			t.Fatalf("held poll at shutdown: %v", err)
		}
		if time.Since(start) > 5*time.Second {
			t.Fatal("the held poll was not answered at shutdown")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the held poll was not answered when the monitor ended")
	}
}

// A server restart while a node polls: the new process knows the node by
// its stored credential hash, counts it online by the start grace, and the
// node's next poll takes the new process's jobs. A result for a job of the
// old process is acknowledged and discarded.
func TestServerRestartWhileNodePolls(t *testing.T) {
	e := setup(t)
	var cur atomic.Pointer[Dispatcher]
	cur.Store(e.disp)
	e.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { cur.Load().ServeHTTP(w, r) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cert := selfSigned(t, "portal.example.nl")
	c := e.client(t, "v1.2.0")
	c.Probe = func(_ context.Context, req probe.Request) probe.Result {
		return probe.Result{Host: req.Host, Port: req.Port, Addresses: []probe.Address{{IP: "10.0.3.5", OK: true, Chain: []*x509.Certificate{cert}}}}
	}
	n := e.enrolled(t, c)
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)

	// The old process has a job out when it stops.
	e.probeAsync(ctx, n.ID, nodeReq)
	oldRun, stopOld := context.WithCancel(ctx)
	go e.disp.Run(oldRun)
	time.Sleep(50 * time.Millisecond)

	d2 := &Dispatcher{Core: e.core, Version: "v1.2.0", Log: e.log, Now: e.clock.now, ReleaseKey: e.pub}
	cur.Store(d2)
	stopOld()
	e.srv.CloseClientConnections()

	if !d2.Online(n.ID) {
		t.Fatal("after a restart a node is not online during the start grace")
	}
	pctx, pcancel := context.WithTimeout(ctx, 10*time.Second)
	defer pcancel()
	r, err := d2.Probe(pctx, n.ID, nodeReq)
	if err != nil {
		t.Fatalf("probe through the new process: %v", err)
	}
	if len(r.Addresses) != 1 {
		t.Fatalf("result: %+v", r)
	}
	// A late result for a job the new process never issued.
	resp, _ := e.call(t, http.MethodPost, Prefix+"/jobs/0123456789abcdef01/result", c.cred, resultJSON(Result{Probe: &ProbeResult{}}), nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("result for an unknown job: %s", resp.Status)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Rotate credential revokes the node's credential at once; the machine's
// re-enrolment keeps the node's name and targets and waits for
// confirmation like a new node.
func TestRotatedCredentialRefusedAndReEnrolmentKeepsNode(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	c := e.client(t, "v1.2.0")
	n := e.enrolled(t, c)
	if _, err := e.core.SaveTarget(ctx, core.Target{Name: "t", Host: "a.example", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem,
		Enabled: true, AllChannels: true, NodeID: n.ID}, "admin"); err != nil {
		t.Fatal(err)
	}
	oldCred := c.cred
	tok, err := e.core.RenewNodeToken(ctx, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.disp.Refresh(ctx, n.ID)
	if _, err := c.poll(ctx, ""); !errors.Is(err, errUnauthorized) {
		t.Fatalf("poll with the rotated credential: %v", err)
	}
	if e.disp.Online(n.ID) {
		t.Fatal("a node without a credential takes jobs")
	}
	if _, err := e.disp.Probe(ctx, n.ID, nodeReq); !errors.Is(err, core.ErrNodeOffline) {
		t.Fatalf("probe on a rotated node: %v", err)
	}

	// The install command runs again on the same machine.
	again := &Client{Server: c.Server, Data: c.Data, Workers: 2, Version: "v1.2.0", Log: e.log, HTTP: c.HTTP}
	id, err := again.Enrol(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if id != n.ID {
		t.Fatalf("re-enrolment made node %d, want %d", id, n.ID)
	}
	got, _ := e.core.Node(ctx, id)
	if got.State != core.NodePending || got.Name != "dc1" || got.Targets != 1 {
		t.Fatalf("re-enrolled node: state %s name %q targets %d", got.State, got.Name, got.Targets)
	}
	e.disp.Refresh(ctx, id)
	if e.disp.Online(id) {
		t.Fatal("a re-enrolled node takes jobs before it is confirmed again")
	}
	if err := c.readCredential(); err != nil || c.cred == oldCred {
		t.Fatalf("the credential file was not replaced: %v", err)
	}
	if resp, _ := e.call(t, http.MethodGet, Prefix+"/jobs?wait=0s", oldCred, nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old credential after re-enrolment: %s", resp.Status)
	}
	if resp, _ := e.call(t, http.MethodGet, Prefix+"/jobs?wait=0s", c.cred, nil, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("new credential: %s", resp.Status)
	}
	if err := e.core.ConfirmNode(ctx, id, "dc1", "admin"); err != nil {
		t.Fatal(err)
	}
	e.disp.Refresh(ctx, id)
	if !e.disp.Online(id) {
		t.Fatal("confirmed again, but not online")
	}
}

// Rejecting a pending node or deleting a confirmed one revokes its
// credential; a job queued for a deleted node ends at once.
func TestRejectedAndDeletedNodesLoseAccess(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	_, tok, _ := e.core.CreateNode(ctx, "admin")
	p := e.client(t, "v1.2.0")
	pid, err := p.Enrol(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.core.RejectNode(ctx, pid); err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.call(t, http.MethodGet, Prefix+"/jobs?wait=0s", p.cred, nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("rejected node polls: %s", resp.Status)
	}

	c := e.client(t, "v1.2.0")
	n := e.enrolled(t, c)
	res := e.probeAsync(ctx, n.ID, nodeReq)
	e.waitQueued(t, n.ID, 1)
	if err := e.core.DeleteNode(ctx, n.ID, false); err != nil {
		t.Fatal(err)
	}
	e.disp.Refresh(ctx, n.ID)
	o, ok := outcomeWithin(t, res, 2*time.Second)
	if !ok {
		t.Fatal("a job queued for a deleted node still waits")
	}
	if !errors.Is(o.err, core.ErrNodeOffline) {
		t.Fatalf("job of a deleted node: %v", o.err)
	}
	if resp, _ := e.call(t, http.MethodGet, Prefix+"/jobs?wait=0s", c.cred, nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("deleted node polls: %s", resp.Status)
	}
}

// Disabling a node stops its jobs: what was queued ends, and its polls
// are answered without jobs.
func TestDisabledNodeQueuedJobsEnd(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	c := e.client(t, "v1.2.0")
	n := e.enrolled(t, c)
	res := e.probeAsync(ctx, n.ID, nodeReq)
	e.waitQueued(t, n.ID, 1)
	if err := e.core.SetNodeEnabled(ctx, n.ID, false); err != nil {
		t.Fatal(err)
	}
	e.disp.Refresh(ctx, n.ID)
	o, ok := outcomeWithin(t, res, 2*time.Second)
	if !ok || !errors.Is(o.err, core.ErrNodeOffline) {
		t.Fatalf("queued job on a disabled node: %v (ended %v)", o.err, ok)
	}
	resp, body := e.call(t, http.MethodGet, Prefix+"/jobs?wait=0s", c.cred, nil, nil)
	var pr PollResponse
	_ = json.Unmarshal(body, &pr)
	if resp.StatusCode != http.StatusOK || len(pr.Jobs) != 0 {
		t.Fatalf("disabled node's poll: %s %+v", resp.Status, pr)
	}
}

// A result counts once, only from the node the job went to, and only while
// the job is leased; the checked-at time is the server's lease time.
func TestResultReplayForeignNodeAndUnleasedJob(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca, cb := e.client(t, "v1.2.0"), e.client(t, "v1.2.0")
	a, b := e.enrolled(t, ca), e.enrolled(t, cb)
	res := e.probeAsync(ctx, a.ID, nodeReq)
	jobs := e.waitLease(t, a.ID, 4)
	leasedAt := e.clock.now()
	path := Prefix + "/jobs/" + jobs[0].ID + "/result"
	body := resultJSON(Result{Probe: &ProbeResult{Addresses: []Address{{IP: "10.0.0.1", ErrorKind: probe.ErrRefused, Error: "refused"}}}})

	if resp, _ := e.call(t, http.MethodPost, path, cb.cred, body, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("foreign result: %s", resp.Status)
	}
	if _, ok := outcomeWithin(t, res, 100*time.Millisecond); ok {
		t.Fatal("another node's result completed the job")
	}
	e.clock.add(time.Minute) // the node's answer arrives later
	if resp, _ := e.call(t, http.MethodPost, path, ca.cred, body, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("result: %s", resp.Status)
	}
	o, ok := outcomeWithin(t, res, 2*time.Second)
	if !ok || o.err != nil {
		t.Fatalf("result not taken: %v %v", o.err, ok)
	}
	if !o.res.StartedAt.Equal(leasedAt) || len(o.res.Addresses) != 1 {
		t.Fatalf("result: started %v (leased %v), %+v", o.res.StartedAt, leasedAt, o.res.Addresses)
	}
	// Replayed: acknowledged, not counted again.
	if resp, _ := e.call(t, http.MethodPost, path, ca.cred, body, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("replayed result: %s", resp.Status)
	}
	if st := e.disp.Status(a.ID); st.Completed != 1 || st.Running != 0 {
		t.Fatalf("after a replay: %+v", st)
	}
	if st := e.disp.Status(b.ID); st.Completed != 0 {
		t.Fatalf("foreign node credited: %+v", st)
	}
	// A job still queued (never leased) takes no result.
	res2 := e.probeAsync(ctx, a.ID, nodeReq)
	e.waitQueued(t, a.ID, 1)
	e.disp.mu.Lock()
	var queued string
	for id, j := range e.disp.jobs {
		if j.leasedAt.IsZero() {
			queued = id
		}
	}
	e.disp.mu.Unlock()
	e.call(t, http.MethodPost, Prefix+"/jobs/"+queued+"/result", ca.cred, body, nil)
	if _, ok := outcomeWithin(t, res2, 100*time.Millisecond); ok {
		t.Fatal("a result for a job the node never leased was taken")
	}
}

// Results that cannot be read are refused without ending the job; results
// the server cannot believe end it as a failure.
func TestMalformedAndOversizedResults(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := e.client(t, "v1.2.0")
	n := e.enrolled(t, c)
	res := e.probeAsync(ctx, n.ID, nodeReq)
	jobs := e.waitLease(t, n.ID, 4)
	path := Prefix + "/jobs/" + jobs[0].ID + "/result"

	for name, tc := range map[string]struct {
		body []byte
		hdr  map[string]string
	}{
		"not json":     {[]byte(`{"probe":`), nil},
		"oversized":    {append(append([]byte(`{"error":"`), bytes.Repeat([]byte("x"), maxBody)...), `"}`...), nil},
		"bad gzip":     {[]byte("plain"), map[string]string{"Content-Encoding": "gzip"}},
		"unknown enc.": {[]byte(`{}`), map[string]string{"Content-Encoding": "br"}},
	} {
		resp, _ := e.call(t, http.MethodPost, path, c.cred, tc.body, tc.hdr)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %s", name, resp.Status)
		}
	}
	if _, ok := outcomeWithin(t, res, 100*time.Millisecond); ok {
		t.Fatal("an unreadable result ended the job")
	}

	// Each of these ends its job with an error, counted as failed.
	bad := []Result{
		{Probe: &ProbeResult{Addresses: []Address{{IP: "10.0.0.1", OK: true, Chain: [][]byte{[]byte("not DER")}}}}},
		{Probe: &ProbeResult{Addresses: []Address{{IP: "10.0.0.1", OK: true}}}},
		{Error: strings.Repeat("e", 2000)},
		{},
	}
	results := []<-chan probeOutcome{res}
	for range bad[1:] {
		results = append(results, e.probeAsync(ctx, n.ID, nodeReq))
	}
	ids := []string{jobs[0].ID}
	for len(ids) < len(bad) {
		for _, j := range e.waitLease(t, n.ID, 8) {
			ids = append(ids, j.ID)
		}
	}
	for i, r := range bad {
		e.call(t, http.MethodPost, Prefix+"/jobs/"+ids[i]+"/result", c.cred, resultJSON(r), nil)
	}
	for i, ch := range results {
		o, ok := outcomeWithin(t, ch, 2*time.Second)
		if !ok || o.err == nil {
			t.Errorf("bad result %d: ended %v, err %v", i, ok, o.err)
		}
		if ok && len(o.err.Error()) > core.TextMax+20 {
			t.Errorf("bad result %d: error not clipped (%d bytes)", i, len(o.err.Error()))
		}
	}
	if st := e.disp.Status(n.ID); st.Failed != int64(len(bad)) || st.Completed != 0 || st.Running != 0 {
		t.Fatalf("status: %+v", st)
	}
}

// A cancelled check tells the node to stop the job, and the node's late
// answer to it is discarded.
func TestCancelledProbeSendsCancelJob(t *testing.T) {
	e := setup(t)
	c := e.client(t, "v1.2.0")
	n := e.enrolled(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	res := e.probeAsync(ctx, n.ID, nodeReq)
	jobs := e.waitLease(t, n.ID, 4)
	cancel()
	o, ok := outcomeWithin(t, res, 2*time.Second)
	if !ok || !errors.Is(o.err, context.Canceled) {
		t.Fatalf("cancelled probe: %v", o.err)
	}
	next := e.disp.lease(n.ID, 4)
	if len(next) != 1 || next[0].Kind != KindCancel || next[0].Cancel != jobs[0].ID {
		t.Fatalf("no cancel job for the node: %+v", next)
	}
	e.call(t, http.MethodPost, Prefix+"/jobs/"+jobs[0].ID+"/result", c.cred, resultJSON(Result{Probe: &ProbeResult{}}), nil)
	if st := e.disp.Status(n.ID); st.Completed != 0 || st.Failed != 0 || st.Running != 0 {
		t.Fatalf("status after a cancelled job: %+v", st)
	}
}

// A node that goes away mid-job: the leased job is re-queued once at its
// timeout and then given up, or, when the node is offline by then, ends
// at once; it is never held for a node that does not come back. The job
// timeout here (30 s × 4 attempts + the configuration test + slack) is
// longer than the offline window, so the node is judged offline before
// the job times out.
func TestJobOfNodeGoneMidJobIsNotHeldForever(t *testing.T) {
	e := setup(t)
	c := e.client(t, "v1.2.0")
	n := e.enrolled(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := nodeReq
	req.Timeout, req.Retries, req.Legacy = 30*time.Second, 3, true
	res := e.probeAsync(ctx, n.ID, req)
	jobs := e.waitLease(t, n.ID, 4)
	if timeout := jobs[0].Probe.Timeout(); timeout <= OfflineAfter {
		t.Fatalf("test needs a job timeout over the offline window, got %v", timeout)
	}
	// The start grace is over, and the node stops polling.
	e.clock.add(OfflineAfter + time.Second)
	e.disp.judge(ctx)
	if e.disp.Online(n.ID) {
		t.Fatal("node still online")
	}
	e.clock.add(jobs[0].Probe.Timeout())
	e.disp.expireJobs()
	e.disp.judge(ctx)
	o, ok := outcomeWithin(t, res, time.Second)
	if !ok {
		t.Fatalf("the timed-out job of an offline node was queued again and is held for it: %+v", e.disp.Status(n.ID))
	}
	if !errors.Is(o.err, core.ErrNodeOffline) && !errors.Is(o.err, core.ErrNodeNoResult) {
		t.Fatalf("job of a node gone mid-job: %v", o.err)
	}
}

// While a restore runs, leased jobs end, results are discarded and polls
// get no jobs; Resume starts from a clean slate.
func TestPauseDiscardsLeasedResultsAndResumeCleans(t *testing.T) {
	e := setup(t)
	c := e.client(t, "v1.2.0")
	n := e.enrolled(t, c)
	ctx := context.Background()
	res := e.probeAsync(ctx, n.ID, nodeReq)
	jobs := e.waitLease(t, n.ID, 4)
	e.disp.Pause()
	if o, ok := outcomeWithin(t, res, 2*time.Second); !ok || !errors.Is(o.err, core.ErrNodesPaused) {
		t.Fatalf("leased job at pause: %v", o.err)
	}
	if resp, _ := e.call(t, http.MethodPost, Prefix+"/jobs/"+jobs[0].ID+"/result", c.cred, resultJSON(Result{Probe: &ProbeResult{}}), nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("result during pause: %s", resp.Status)
	}
	e.disp.Resume()
	if st := e.disp.Status(n.ID); st.Running != 0 || st.Queued != 0 || st.Completed != 0 {
		t.Fatalf("after resume: %+v", st)
	}
	res = e.probeAsync(ctx, n.ID, nodeReq)
	jobs = e.waitLease(t, n.ID, 1)
	e.call(t, http.MethodPost, Prefix+"/jobs/"+jobs[0].ID+"/result", c.cred, resultJSON(Result{Probe: &ProbeResult{}}), nil)
	if o, ok := outcomeWithin(t, res, 2*time.Second); !ok || o.err != nil {
		t.Fatalf("probe after resume: %v", o.err)
	}
}

// Two machines running the same install command at once: one gets the
// credential, the other is refused.
func TestEnrolmentRaceSpendsTokenOnce(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	_, tok, err := e.core.CreateNode(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	const n = 8
	var wg sync.WaitGroup
	var ok atomic.Int32
	ids := make(chan int64, n)
	for i := 0; i < n; i++ {
		c := e.client(t, "v1.2.0")
		wg.Add(1)
		go func() {
			defer wg.Done()
			if id, err := c.Enrol(ctx, tok); err == nil {
				ok.Add(1)
				ids <- id
			}
		}()
	}
	wg.Wait()
	close(ids)
	if ok.Load() != 1 {
		t.Fatalf("%d enrolments with one token", ok.Load())
	}
	nodes, _ := e.core.Nodes(ctx)
	if len(nodes) != 1 || nodes[0].State != core.NodePending {
		t.Fatalf("nodes: %+v", nodes)
	}
}

// Failed credentials and tokens block an address after 20 in 15 minutes,
// but never a node or an install command with a valid one from it.
func TestFailedAttemptsBlockAddressButNotValidNodes(t *testing.T) {
	e := setup(t)
	e.disp.ClientIP = func(*http.Request) string { return "192.0.2.1" }
	ctx := context.Background()
	c := e.client(t, "v1.2.0")
	e.enrolled(t, c)
	for i := 0; i < limitFails-1; i++ {
		if resp, _ := e.call(t, http.MethodGet, Prefix+"/jobs?wait=0s", "wrong", nil, nil); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %s", i, resp.Status)
		}
	}
	bad, _ := json.Marshal(EnrolRequest{Token: "guess"})
	if resp, _ := e.call(t, http.MethodPost, Prefix+"/enrol", "", bad, nil); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("20th failure: %s", resp.Status)
	}
	if resp, _ := e.call(t, http.MethodGet, Prefix+"/jobs?wait=0s", "", nil, nil); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("blocked address without a credential: %s", resp.Status)
	}
	if resp, _ := e.call(t, http.MethodGet, Prefix+"/jobs?wait=0s", c.cred, nil, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("a valid node behind a blocked address: %s", resp.Status)
	}
	_, tok, _ := e.core.CreateNode(ctx, "admin")
	good, _ := json.Marshal(EnrolRequest{Token: tok, Pool: 2})
	if resp, _ := e.call(t, http.MethodPost, Prefix+"/enrol", "", good, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("a valid install token from a blocked address: %s", resp.Status)
	}
	e.clock.add(limitWindow + time.Second)
	if resp, _ := e.call(t, http.MethodGet, Prefix+"/jobs?wait=0s", "wrong", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after the window: %s", resp.Status)
	}
}

// The facts carry the node's clock, from which the server computes the
// offset; what a node reports is clipped, and a second report within five
// minutes is not stored.
func TestFactsClockOffsetClippingAndRate(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	c := e.client(t, "v1.2.0")
	n := e.enrolled(t, c)
	post := func(f Facts) int {
		b, _ := json.Marshal(f)
		resp, _ := e.call(t, http.MethodPost, Prefix+"/facts", c.cred, b, nil)
		return resp.StatusCode
	}
	f := Facts{NodeFacts: core.NodeFacts{Hostname: strings.Repeat("h", 500), Version: "v1.2.0"}, Time: e.clock.now().Add(time.Hour)}
	if code := post(f); code != http.StatusNoContent {
		t.Fatalf("facts: %d", code)
	}
	got, _ := e.core.Node(ctx, n.ID)
	if off := got.Facts.ClockOffsetMS; off < 3599000 || off > 3601000 {
		t.Fatalf("clock offset of a node an hour ahead: %d ms", off)
	}
	if len(got.Facts.Hostname) > core.ShortMax {
		t.Fatalf("hostname not clipped: %d bytes", len(got.Facts.Hostname))
	}
	f.Hostname, f.Time = "moved", e.clock.now()
	if code := post(f); code != http.StatusTooManyRequests {
		t.Fatalf("a second report within five minutes: %d, want 429 so the node sends it again", code)
	}
	if got, _ = e.core.Node(ctx, n.ID); got.Facts.Hostname == "moved" {
		t.Fatal("a second report within five minutes was stored")
	}
	e.clock.add(factsInterval)
	f.Time = e.clock.now()
	post(f)
	if got, _ = e.core.Node(ctx, n.ID); got.Facts.Hostname != "moved" || got.Facts.ClockOffsetMS != 0 {
		t.Fatalf("report after five minutes: %+v", got.Facts)
	}
}

// The version and update-error headers come from a machine the server does
// not control: they are clipped before they are stored.
func TestNodeHeadersClipped(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	c := e.client(t, "v1.1.0")
	n := e.enrolled(t, c)
	if !e.disp.wantUpdate(ctx, n, "") {
		t.Fatal("no update started")
	}
	e.call(t, http.MethodGet, Prefix+"/jobs?wait=0s", c.cred, nil, map[string]string{
		HeaderVersion: "v" + strings.Repeat("9", 1000), HeaderUpdateError: strings.Repeat("r", 5000)})
	got, _ := e.core.Node(ctx, n.ID)
	if len(got.Version) > core.ShortMax {
		t.Fatalf("version not clipped: %d bytes", len(got.Version))
	}
	if got.UpdateFailed == "" || len(got.UpdateFailed) > core.TextMax {
		t.Fatalf("update error: %d bytes", len(got.UpdateFailed))
	}
}

// The server holds a poll for the shorter of the node's wait and its own
// ceiling.
func TestPollWaitHonoured(t *testing.T) {
	e := setup(t)
	c := e.client(t, "v1.2.0")
	e.enrolled(t, c)
	start := time.Now()
	resp, _ := e.call(t, http.MethodGet, Prefix+"/jobs?wait=300ms", c.cred, nil, nil)
	if took := time.Since(start); resp.StatusCode != http.StatusOK || took < 250*time.Millisecond || took > 3*time.Second {
		t.Fatalf("poll with wait=300ms: %s after %v", resp.Status, took)
	}
	if resp.Header.Get("Accept-Encoding") != "gzip" {
		t.Fatal("the poll answer does not advertise gzip")
	}
}

// "Updating 2 of 5": the second node of a round of five is updating. The
// progress counts the round, not only the nodes still to go, and the
// place is the order of the round, not the order of the names.
func TestUpdatingReportsProgressThroughTheRound(t *testing.T) {
	d := &Dispatcher{Version: "v1.2.0"}
	mk := func(name, version string, started int64) core.Node {
		return core.Node{Name: name, State: core.NodeConfirmed, Enabled: true, Version: version, UpdateStarted: started, UpdateFrom: "v1.1.0", UpdateTo: "v1.2.0"}
	}
	// The first node of five to update sorts last by name.
	first := []core.Node{mk("a", "v1.1.0", 0), mk("b", "v1.1.0", 0), mk("c", "v1.1.0", 0), mk("d", "v1.1.0", 0), mk("e", "v1.1.0", 1)}
	if n, of := d.Updating(first); n != 1 || of != 5 {
		t.Errorf("first node of five updating: updating %d of %d, want 1 of 5", n, of)
	}
	// One is done, the second is updating.
	second := []core.Node{mk("a", "v1.2.0", 0), mk("b", "v1.1.0", 1), mk("c", "v1.1.0", 0), mk("d", "v1.1.0", 0), mk("e", "v1.1.0", 0)}
	if n, of := d.Updating(second); n != 2 || of != 5 {
		t.Errorf("second node of five updating: updating %d of %d, want 2 of 5", n, of)
	}
	// Nothing runs: no progress, whatever is outdated.
	if n, _ := d.Updating([]core.Node{mk("a", "v1.1.0", 0)}); n != 0 {
		t.Errorf("nothing updating: %d", n)
	}
}

// Containers and unconfirmed nodes are not part of an update round.
func TestUpdatingSkipsContainersAndPending(t *testing.T) {
	d := &Dispatcher{Version: "v1.2.0"}
	nodes := []core.Node{
		{State: core.NodeConfirmed, Version: "v1.1.0", UpdateStarted: 1},
		{State: core.NodeConfirmed, Version: "v1.1.0", Facts: core.NodeFacts{Container: true}},
		{State: core.NodePending, Version: "v1.1.0"},
	}
	if n, of := d.Updating(nodes); n != 1 || of != 1 {
		t.Fatalf("updating %d of %d, want 1 of 1", n, of)
	}
}

// /metrics counts per confirmed node.
func TestStatsCountConfirmedNodes(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	c := e.client(t, "v1.2.0")
	n := e.enrolled(t, c)
	_, tok, _ := e.core.CreateNode(ctx, "admin")
	if _, err := e.client(t, "v1.2.0").Enrol(ctx, tok); err != nil {
		t.Fatal(err)
	}
	res := e.probeAsync(ctx, n.ID, nodeReq)
	jobs := e.waitLease(t, n.ID, 4)
	e.call(t, http.MethodPost, Prefix+"/jobs/"+jobs[0].ID+"/result", c.cred, resultJSON(Result{Probe: &ProbeResult{}}), nil)
	<-res
	res = e.probeAsync(ctx, n.ID, nodeReq)
	jobs = e.waitLease(t, n.ID, 4)
	e.call(t, http.MethodPost, Prefix+"/jobs/"+jobs[0].ID+"/result", c.cred, resultJSON(Result{Error: "no resolver"}), nil)
	<-res
	stats := e.disp.Stats()
	if len(stats) != 1 {
		t.Fatalf("stats: %+v", stats)
	}
	if s := stats[0]; s.Node.ID != n.ID || !s.Online || s.Completed != 1 || s.Failed != 1 || s.LastSeen.IsZero() {
		t.Fatalf("stats: %+v", s)
	}
}

// The node verifies at the server's time, advanced by its own monotonic
// clock, whatever its wall clock says.
func TestProbeJobRunsOnServerClock(t *testing.T) {
	server := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	j := NewProbeJob(probe.Request{Host: "a.example", Port: 443, Timeout: 2 * time.Second, Retries: 1}, server)
	b, _ := json.Marshal(j)
	var wire ProbeJob
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	req := wire.Request(time.Now())
	if got := req.Now(); got.Before(server) || got.Sub(server) > time.Second {
		t.Fatalf("node clock: %v, server %v", got, server)
	}
	if req.Timeout != 2*time.Second || req.Retries != 1 || req.Host != "a.example" {
		t.Fatalf("request: %+v", req)
	}
	if got := wire.Timeout(); got != 2*2*time.Second+30*time.Second {
		t.Fatalf("job timeout: %v", got)
	}
}
