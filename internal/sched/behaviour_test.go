package sched

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

// fakeClock is shared by the scheduler, the core and the outbox.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type clocked struct {
	s     *Scheduler
	c     *core.Service
	clock *fakeClock
	calls *int64
	// sent counts deliveries per channel name.
	mu   sync.Mutex
	sent map[string][]notify.Message
}

// setupClocked is setup with one fake clock for every component and a
// recording sender, so time-based behaviour can be stepped through.
func setupClocked(t *testing.T, start time.Time) *clocked {
	t.Helper()
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	key, _ := secret.New(make([]byte, 32))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := &fakeClock{t: start}
	e := &clocked{clock: clock, sent: map[string][]notify.Message{}}
	chans := &notify.Channels{DB: d, Key: key, Now: clock.Now}
	disp := &notify.Dispatcher{DB: d, Channels: chans, Log: log, Now: clock.Now}
	disp.Senders = func(ch notify.Channel) notify.Sender {
		return senderFunc(func(m notify.Message) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.sent[ch.Name] = append(e.sent[ch.Name], m)
			return nil
		})
	}
	e.c = &core.Service{DB: d, Settings: config.NewStore(d, key), Channels: chans, Dispatcher: disp, Log: log, Now: clock.Now}
	var calls int64
	e.calls = &calls
	e.s = &Scheduler{Core: e.c, Log: log, Now: clock.Now, Probe: func(_ context.Context, req probe.Request) probe.Result {
		atomic.AddInt64(&calls, 1)
		return probe.Result{Host: req.Host, Port: req.Port, StartedAt: clock.Now(),
			Addresses: []probe.Address{{IP: "192.0.2.1", ErrorKind: probe.ErrConnect, Error: "refused"}}}
	}}
	return e
}

type senderFunc func(notify.Message) error

func (f senderFunc) Send(_ context.Context, m notify.Message) error { return f(m) }

func (e *clocked) take(name string) []notify.Message {
	e.mu.Lock()
	defer e.mu.Unlock()
	m := e.sent[name]
	delete(e.sent, name)
	return m
}

func (e *clocked) flush(t *testing.T) {
	t.Helper()
	e.clock.Add(notify.BatchDelay + time.Second)
	if err := e.c.Dispatcher.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (e *clocked) channel(t *testing.T, name, kind, floor string) int64 {
	t.Helper()
	c := notify.Channel{Name: name, Kind: kind, MinSeverity: floor, Enabled: true}
	switch kind {
	case notify.KindSMTP:
		c.SMTP = notify.SMTPSettings{Host: "smtp.example.nl", Port: 587, From: "tlswatch@example.nl", Recipients: []string{"ops@example.nl"}}
	case notify.KindWebhook:
		c.Webhook = notify.WebhookSettings{URL: "https://hooks.example.nl/tlswatch"}
	}
	id, err := e.c.Channels.Save(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *clocked) target(t *testing.T, port int) int64 {
	t.Helper()
	id, err := e.c.SaveTarget(context.Background(), core.Target{Name: "t", Host: "example.org", Port: port, Protocol: probe.TLS,
		Trust: probe.TrustSystem, AllAddresses: true, AllChannels: true, Enabled: true}, "test")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *clocked) digestRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.c.DB.R.QueryRow("SELECT COUNT(*) FROM alerts WHERE event = 'digest'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The weekly digest goes out once, in the configured hour of the configured
// day, in the configured time zone; not on other days or hours, not twice
// in the hour, and again a week later.
func TestDigestOncePerWeekInConfiguredHour(t *testing.T) {
	ams, err := time.LoadLocation("Europe/Amsterdam")
	if err != nil {
		t.Skip("no tzdata")
	}
	// Monday 19 October 2026, 08:10 in Amsterdam (06:10 UTC).
	start := time.Date(2026, 10, 19, 8, 10, 0, 0, ams)
	e := setupClocked(t, start)
	ctx := context.Background()
	e.channel(t, "mail", notify.KindSMTP, "warning")
	st := e.c.CurrentSettings(ctx)
	if err := e.c.Settings.SaveGeneral(ctx, config.General{TimeZone: "Europe/Amsterdam"}); err != nil {
		t.Fatal(err)
	}
	d := st.Defaults
	d.DigestEnabled, d.DigestWeekday, d.DigestHour = true, int(time.Monday), 8
	if err := e.c.Settings.SaveDefaults(ctx, d); err != nil {
		t.Fatal(err)
	}

	e.s.digest(ctx)
	if n := e.digestRows(t); n != 1 {
		t.Fatalf("digest in the configured hour: %d queued", n)
	}
	// The digest is sent right away, without the batch delay.
	if err := e.c.Dispatcher.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if m := e.take("mail"); len(m) != 1 || !strings.Contains(m[0].Subject, "weekly digest") || m[0].HTML == "" {
		t.Fatalf("digest delivered: %+v", m)
	}
	// Later in the same hour: not again.
	e.clock.Add(40 * time.Minute)
	e.s.digest(ctx)
	if n := e.digestRows(t); n != 1 {
		t.Fatalf("digest repeated within the hour: %d", n)
	}
	// The next hour and the next day: nothing.
	e.clock.Add(time.Hour)
	e.s.digest(ctx)
	e.clock.Add(23 * time.Hour)
	e.s.digest(ctx)
	if n := e.digestRows(t); n != 1 {
		t.Fatalf("digest outside the configured hour: %d", n)
	}
	// A week later, in the hour: once more.
	e.clock.Set(start.AddDate(0, 0, 7)) // across the end of summer time
	e.s.digest(ctx)
	if n := e.digestRows(t); n != 2 {
		t.Fatalf("second week: %d digests", n)
	}

	// 08:xx UTC is not 08:xx in Amsterdam.
	e.clock.Set(time.Date(2026, 11, 2, 8, 30, 0, 0, time.UTC))
	e.s.digest(ctx)
	if n := e.digestRows(t); n != 2 {
		t.Fatal("digest sent in the UTC hour instead of the configured time zone")
	}

	// Switched off: nothing.
	d.DigestEnabled = false
	if err := e.c.Settings.SaveDefaults(ctx, d); err != nil {
		t.Fatal(err)
	}
	e.clock.Set(start.AddDate(0, 0, 14))
	e.s.digest(ctx)
	if n := e.digestRows(t); n != 2 {
		t.Fatal("digest sent while switched off")
	}
}

func (c *fakeClock) Set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

// A digest that finds no channel is not marked as sent: once a channel is
// added later in the hour, it goes out.
func TestDigestWithoutChannelTriesAgainInTheHour(t *testing.T) {
	start := time.Date(2026, 10, 19, 8, 5, 0, 0, time.UTC)
	e := setupClocked(t, start)
	ctx := context.Background()
	if err := e.c.Settings.SaveGeneral(ctx, config.General{TimeZone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	d := e.c.CurrentSettings(ctx).Defaults
	d.DigestEnabled, d.DigestWeekday, d.DigestHour = true, int(time.Monday), 8
	if err := e.c.Settings.SaveDefaults(ctx, d); err != nil {
		t.Fatal(err)
	}
	// A webhook is no digest channel unless chosen.
	e.channel(t, "hook", notify.KindWebhook, "info")
	e.s.digest(ctx)
	if n := e.digestRows(t); n != 0 {
		t.Fatalf("digest queued to a non-SMTP channel: %d", n)
	}
	e.channel(t, "mail", notify.KindSMTP, "critical")
	e.clock.Add(time.Minute)
	e.s.digest(ctx)
	if n := e.digestRows(t); n != 1 {
		t.Fatalf("digest after a channel was added: %d", n)
	}
}

// Chosen digest channels replace the SMTP default; a disabled chosen channel
// is not used.
func TestDigestChosenChannels(t *testing.T) {
	e := setupClocked(t, time.Now())
	ctx := context.Background()
	mail := e.channel(t, "mail", notify.KindSMTP, "warning")
	hook := e.channel(t, "hook", notify.KindWebhook, "critical")
	d := e.c.CurrentSettings(ctx).Defaults
	d.DigestChannels = []int64{hook}
	if err := e.c.Settings.SaveDefaults(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := e.s.SendDigest(ctx); err != nil {
		t.Fatal(err)
	}
	var ch int64
	if err := e.c.DB.R.QueryRow("SELECT channel_id FROM alerts WHERE event = 'digest'").Scan(&ch); err != nil || ch != hook {
		t.Fatalf("digest went to channel %d (mail %d, hook %d): %v", ch, mail, hook, err)
	}
	c, _ := e.c.Channels.Get(ctx, hook)
	c.Enabled = false
	if _, err := e.c.Channels.Save(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := e.s.SendDigest(ctx); err == nil {
		t.Fatal("digest queued with its only chosen channel disabled")
	}
}

// A target that becomes due again while it is still being probed is not
// probed a second time: Check all, Check soon and Check now all join the
// running check.
func TestNoDoubleProbeWhileRunning(t *testing.T) {
	s, _, _ := setup(t, 1)
	var calls atomic.Int64
	started, release := make(chan struct{}), make(chan struct{})
	s.Probe = func(_ context.Context, req probe.Request) probe.Result {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return probe.Result{Host: req.Host, Port: req.Port, StartedAt: time.Now(),
			Addresses: []probe.Address{{IP: "192.0.2.1", ErrorKind: probe.ErrConnect, Error: "refused"}}}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	<-started
	s.CheckSoon(1)
	if _, err := s.CheckAll(ctx); err != nil {
		t.Fatal(err)
	}
	nowDone := make(chan core.Target, 1)
	go func() {
		tg, err := s.CheckNow(ctx, 1)
		if err != nil {
			t.Error(err)
		}
		nowDone <- tg
	}()
	time.Sleep(1500 * time.Millisecond) // a few dispatch rounds
	if n := calls.Load(); n != 1 {
		t.Fatalf("target probed %d times while its check was running", n)
	}
	close(release)
	tg := <-nowDone
	if tg.LastCheck == 0 {
		t.Fatal("Check now did not return the state of the check it waited for")
	}
	time.Sleep(1200 * time.Millisecond)
	if n := calls.Load(); n != 1 {
		t.Fatalf("probed %d times in all; the running check should have served every request", n)
	}
	if next := s.nextOf(1); next < time.Now().Add(11*time.Hour).Unix() {
		t.Fatalf("after the check the target is queued at %d, not at its next slot", next)
	}
}

// After downtime longer than the interval, an overdue target is checked
// once, spread over the first minutes, and not once per missed interval.
func TestOverdueAfterDowntimeCheckedOnce(t *testing.T) {
	start := time.Now()
	e := setupClocked(t, start)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		e.target(t, 2000+i)
	}
	// Checked three days ago, due two days ago, server down since.
	if _, err := e.c.DB.W.Exec("UPDATE targets SET last_check = ?, next_check = ?", start.Add(-72*time.Hour).Unix(), start.Add(-48*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go e.s.Run(ctx)
	time.Sleep(1200 * time.Millisecond)
	if n := atomic.LoadInt64(e.calls); n == 5 {
		t.Fatalf("restart fired every overdue probe at once")
	}
	e.clock.Add(301 * time.Second)
	waitFor(t, "the overdue targets", func() bool { return atomic.LoadInt64(e.calls) >= 5 })
	time.Sleep(1500 * time.Millisecond)
	if n := atomic.LoadInt64(e.calls); n != 5 {
		t.Fatalf("%d probes for 5 overdue targets", n)
	}
	ts, _ := e.c.Targets(context.Background())
	for _, tg := range ts {
		if tg.NextCheck < e.clock.Now().Add(12*time.Hour).Unix() {
			t.Fatalf("target %d next check %d is not a full slot ahead", tg.ID, tg.NextCheck)
		}
	}
}

// A disabled target is not probed, not by the schedule and not by Check
// all.
func TestDisabledTargetIsNotScheduled(t *testing.T) {
	s, c, calls := setup(t, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.SetEnabled(ctx, 2, false); err != nil {
		t.Fatal(err)
	}
	go s.Run(ctx)
	waitFor(t, "the enabled target", func() bool { tg, _ := c.Target(ctx, 1); return tg.LastCheck != 0 && s.Status().Running == 0 })
	if n, _ := s.CheckAll(ctx); n != 1 {
		t.Fatalf("Check all queued %d targets, one is enabled", n)
	}
	waitFor(t, "check all", func() bool { return atomic.LoadInt64(calls) >= 2 })
	time.Sleep(1200 * time.Millisecond)
	if n := atomic.LoadInt64(calls); n != 2 {
		t.Fatalf("%d probes, want 2 (the enabled target twice)", n)
	}
	if tg, _ := c.Target(ctx, 2); tg.LastCheck != 0 {
		t.Fatal("disabled target was checked")
	}
}

// confirmedNode creates, enrols and confirms a node.
func confirmedNode(t *testing.T, c *core.Service) core.Node {
	t.Helper()
	ctx := context.Background()
	id, tok, err := c.CreateNode(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.EnrolNode(ctx, tok, core.Enrolment{Facts: core.NodeFacts{Hostname: "probe1"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.ConfirmNode(ctx, id, "dc1", "admin"); err != nil {
		t.Fatal(err)
	}
	n, err := c.Node(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A node_offline finding is reminded at the global warning interval to the
// channels whose floor it meets, not while acknowledged, and recovers to the
// channels that had the alert.
func TestNodeOfflineReminders(t *testing.T) {
	e := setupClocked(t, time.Now())
	ctx := context.Background()
	e.channel(t, "mail", notify.KindSMTP, "warning")
	e.channel(t, "pager", notify.KindWebhook, "critical")
	n := confirmedNode(t, e.c)
	if err := e.c.NodeOffline(ctx, n, e.clock.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	e.flush(t)
	if m := e.take("mail"); len(m) != 1 || m[0].Subject[:9] != "[warning]" {
		t.Fatalf("open alert: %+v", m)
	}
	if m := e.take("pager"); len(m) != 0 {
		t.Fatal("warning sent to a critical-only channel")
	}
	// Seen as offline again: no repeat alert for the open finding.
	if err := e.c.NodeOffline(ctx, n, e.clock.Now().Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	e.flush(t)
	if m := e.take("mail"); len(m) != 0 {
		t.Fatalf("repeat alert for an open node finding: %+v", m)
	}

	e.clock.Add(6 * 24 * time.Hour)
	if q, err := e.c.Remind(ctx); err != nil || q != 0 {
		t.Fatalf("early reminder: %d %v", q, err)
	}
	e.clock.Add(25 * time.Hour)
	if q, err := e.c.Remind(ctx); err != nil || q != 1 {
		t.Fatalf("reminder after 7 days: %d %v", q, err)
	}
	e.flush(t)
	if m := e.take("mail"); len(m) != 1 || !strings.Contains(m[0].Subject, "still open since") {
		t.Fatalf("reminder: %+v", m)
	}
	if q, _ := e.c.Remind(ctx); q != 0 {
		t.Fatalf("reminded twice in a row: %d", q)
	}

	fs, _ := e.c.Findings(ctx, core.FindingFilter{})
	var fid int64
	for _, f := range fs {
		if f.NodeID == n.ID && f.Kind == check.NodeOffline {
			fid = f.ID
		}
	}
	if _, err := e.c.Acknowledge(ctx, fid, "Alex", time.Time{}, "moving racks"); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(8 * 24 * time.Hour)
	if q, _ := e.c.Remind(ctx); q != 0 {
		t.Fatalf("acknowledged node finding reminded: %d", q)
	}

	if err := e.c.NodeOnline(ctx, n); err != nil {
		t.Fatal(err)
	}
	e.flush(t)
	if m := e.take("mail"); len(m) != 1 || m[0].Subject[:10] != "[resolved]" {
		t.Fatalf("recovery: %+v", m)
	}
	if m := e.take("pager"); len(m) != 0 {
		t.Fatal("recovery sent to a channel that never had the alert")
	}
}

// A finding on a domain watch is reminded only to the watch's channels, and
// not while the watch is disabled.
func TestDomainFindingReminders(t *testing.T) {
	e := setupClocked(t, time.Now())
	ctx := context.Background()
	mail := e.channel(t, "mail", notify.KindSMTP, "warning")
	e.channel(t, "other", notify.KindWebhook, "info")
	did, err := e.c.SaveDomain(ctx, core.Domain{Name: "example.nl", Subdomains: true, Enabled: true, ChannelIDs: []int64{mail}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	opened := e.clock.Now().Unix()
	if _, err := e.c.DB.W.Exec(`INSERT INTO findings(domain_id, kind, severity, opened_at, details, fingerprint, last_alert_at)
		VALUES(?, 'unexpected_certificate', 'warning', ?, 'admin.example.nl by Sectigo', '1', ?)`, did, opened, opened); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(7*24*time.Hour + time.Minute)
	if q, err := e.c.Remind(ctx); err != nil || q != 1 {
		t.Fatalf("domain reminder: %d %v", q, err)
	}
	e.flush(t)
	if m := e.take("mail"); len(m) != 1 || !strings.Contains(m[0].Subject, "still open since") {
		t.Fatalf("mail: %+v", m)
	}
	if m := e.take("other"); len(m) != 0 {
		t.Fatal("domain reminder sent to a channel the watch does not use")
	}
	d, err := e.c.Domain(ctx, did)
	if err != nil {
		t.Fatal(err)
	}
	d.Enabled = false
	if _, err := e.c.SaveDomain(ctx, d, "admin"); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(8 * 24 * time.Hour)
	if q, _ := e.c.Remind(ctx); q != 0 {
		t.Fatalf("disabled watch reminded: %d", q)
	}
}

// "Never" as the reminder interval sends no reminders at all.
func TestReminderNever(t *testing.T) {
	e := setupClocked(t, time.Now())
	ctx := context.Background()
	e.channel(t, "mail", notify.KindSMTP, "info")
	d := e.c.CurrentSettings(ctx).Defaults
	d.RemindWarnS, d.RemindCritS = 0, 0
	if err := e.c.Settings.SaveDefaults(ctx, d); err != nil {
		t.Fatal(err)
	}
	n := confirmedNode(t, e.c)
	if err := e.c.NodeOffline(ctx, n, time.Time{}); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(365 * 24 * time.Hour)
	if q, _ := e.c.Remind(ctx); q != 0 {
		t.Fatalf("reminder with interval never: %d", q)
	}
}
