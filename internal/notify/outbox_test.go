package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// outbox is a dispatcher on an in-memory database with a fake clock and
// a sender per channel name that the test controls.
type outbox struct {
	t     *testing.T
	ctx   context.Context
	db    *db.DB
	key   *secret.Key
	clock *testClock
	chans *Channels
	d     *Dispatcher

	mu   sync.Mutex
	sent map[string][]Message
	fail map[string]error // per channel name: the error of every attempt
}

func newOutbox(t *testing.T) *outbox {
	t.Helper()
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	key, _ := secret.New(make([]byte, 32))
	o := &outbox{t: t, ctx: context.Background(), db: d, key: key, clock: &testClock{t: time.Now()},
		sent: map[string][]Message{}, fail: map[string]error{}}
	o.chans = &Channels{DB: d, Key: key, Now: o.clock.Now}
	o.d = o.dispatcher()
	return o
}

// dispatcher returns a new dispatcher on the same database, as after a
// restart.
func (o *outbox) dispatcher() *Dispatcher {
	return &Dispatcher{DB: o.db, Channels: o.chans, Now: o.clock.Now, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Senders: func(c Channel) Sender { return recorder{o, c.Name} }}
}

type recorder struct {
	o    *outbox
	name string
}

func (r recorder) Send(_ context.Context, m Message) error {
	r.o.mu.Lock()
	defer r.o.mu.Unlock()
	if err := r.o.fail[r.name]; err != nil {
		return err
	}
	r.o.sent[r.name] = append(r.o.sent[r.name], m)
	return nil
}

func (o *outbox) setFail(name string, err error) {
	o.mu.Lock()
	o.fail[name] = err
	o.mu.Unlock()
}

func (o *outbox) take(name string) []Message {
	o.mu.Lock()
	defer o.mu.Unlock()
	m := o.sent[name]
	delete(o.sent, name)
	return m
}

func (o *outbox) channel(name string) int64 {
	o.t.Helper()
	id, err := o.chans.Save(o.ctx, Channel{Name: name, Kind: KindWebhook, MinSeverity: "info", Enabled: true,
		Webhook: WebhookSettings{URL: "https://hooks.example.nl/" + name}})
	if err != nil {
		o.t.Fatal(err)
	}
	return id
}

// enqueue queues an alert without a finding, as core does inside its
// transaction.
func (o *outbox) enqueue(ch int64, event string, m Message) {
	o.t.Helper()
	tx, err := o.db.W.BeginTx(o.ctx, nil)
	if err != nil {
		o.t.Fatal(err)
	}
	if err := Enqueue(o.ctx, tx, 0, ch, event, m, o.clock.Now()); err != nil {
		tx.Rollback()
		o.t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		o.t.Fatal(err)
	}
}

func (o *outbox) flush() {
	o.t.Helper()
	if err := o.d.Flush(o.ctx); err != nil {
		o.t.Fatal(err)
	}
}

type alertRow struct {
	state    string
	attempts int
	next     int64
	err      string
}

func (o *outbox) rows(ch int64) []alertRow {
	o.t.Helper()
	rs, err := o.db.R.Query("SELECT state, attempts, next_attempt, error FROM alerts WHERE channel_id = ? ORDER BY id", ch)
	if err != nil {
		o.t.Fatal(err)
	}
	defer rs.Close()
	var out []alertRow
	for rs.Next() {
		var r alertRow
		if err := rs.Scan(&r.state, &r.attempts, &r.next, &r.err); err != nil {
			o.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func alertMsg(sev, text string) Message {
	return Message{Subject: "[" + sev + "] " + text, Body: text + "\n"}
}

// A new alert waits for the batch delay, so alerts of the same run are
// collapsed; it is not sent before.
func TestOutboxWaitsForBatchDelay(t *testing.T) {
	o := newOutbox(t)
	ch := o.channel("ops")
	o.enqueue(ch, EventOpen, alertMsg("warning", "a.example.nl:443 expires in 20 days"))
	o.clock.Add(BatchDelay - time.Second)
	o.flush()
	if m := o.take("ops"); len(m) != 0 {
		t.Fatalf("sent before the batch delay: %+v", m)
	}
	o.enqueue(ch, EventOpen, alertMsg("critical", "b.example.nl:443 certificate expired"))
	o.clock.Add(BatchDelay)
	o.flush()
	m := o.take("ops")
	if len(m) != 1 || !strings.HasPrefix(m[0].Subject, "[critical] 2 alerts") {
		t.Fatalf("collapsed message: %+v", m)
	}
	if strings.Index(m[0].Body, "b.example.nl") > strings.Index(m[0].Body, "a.example.nl") {
		t.Fatalf("worst severity not first:\n%s", m[0].Body)
	}
	if r := o.rows(ch); r[0].state != "sent" || r[1].state != "sent" {
		t.Fatalf("rows: %+v", r)
	}
	// A delivered alert is not sent again.
	o.clock.Add(time.Hour)
	o.flush()
	if m := o.take("ops"); len(m) != 0 {
		t.Fatalf("sent twice: %+v", m)
	}
}

// Retries follow 1 min, 5 min, 30 min, then hourly, and stop with the
// alert marked failed once retrying would pass 24 hours.
func TestOutboxBackoffScheduleAndGiveUp(t *testing.T) {
	o := newOutbox(t)
	ch := o.channel("ops")
	o.setFail("ops", errors.New("connection refused"))
	o.enqueue(ch, EventOpen, alertMsg("critical", "x"))
	created := o.clock.Now()
	o.clock.Add(BatchDelay)
	for i, want := range []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, time.Hour, time.Hour} {
		o.flush()
		r := o.rows(ch)[0]
		if r.state != "pending" || r.attempts != i+1 || r.next != o.clock.Now().Add(want).Unix() || r.err != "connection refused" {
			t.Fatalf("after attempt %d: %+v, want next in %v", i+1, r, want)
		}
		o.clock.Add(want)
	}
	for o.rows(ch)[0].state == "pending" {
		if o.clock.Now().Sub(created) > 25*time.Hour {
			t.Fatal("still retrying after 25 hours")
		}
		o.flush()
		o.clock.Add(time.Hour)
	}
	r := o.rows(ch)[0]
	if r.state != "failed" || o.clock.Now().Sub(created) < 23*time.Hour {
		t.Fatalf("given up at %v: %+v", o.clock.Now().Sub(created), r)
	}
	if r.attempts < 24 || r.attempts > 27 {
		t.Fatalf("%d attempts over 24 hours", r.attempts)
	}
}

// A refusal a retry cannot change (a recipient the relay does not know)
// fails the alert at once instead of retrying for a day.
func TestOutboxPermanentErrorFailsAtOnce(t *testing.T) {
	o := newOutbox(t)
	ch := o.channel("ops")
	o.setFail("ops", &PermanentError{Err: errors.New("RCPT TO gone@example.nl: 550 5.1.1 no such user")})
	o.enqueue(ch, EventOpen, alertMsg("critical", "x"))
	o.clock.Add(BatchDelay)
	o.flush()
	if r := o.rows(ch)[0]; r.state != "failed" || r.attempts != 1 || !strings.Contains(r.err, "550") {
		t.Fatalf("after a permanent refusal: %+v", r)
	}
}

// A recipient refused for good while another is retried stays named on
// the alert after the retry succeeds, and on the channel's last delivery.
func TestRefusalSurvivesSuccessfulRetry(t *testing.T) {
	o := newOutbox(t)
	ch := o.channel("ops")
	o.setFail("ops", &PartialRefusal{Refused: "RCPT TO gone@example.nl: 550 no such user",
		Err: errors.New("RCPT TO gone@example.nl: 550 no such user; RCPT TO ops@example.nl: 452 mailbox full")})
	o.enqueue(ch, EventOpen, alertMsg("critical", "x"))
	o.clock.Add(BatchDelay)
	o.flush()
	if r := o.rows(ch)[0]; r.state != "pending" {
		t.Fatalf("after the temporary failure: %+v", r)
	}
	o.setFail("ops", nil)
	o.clock.Add(time.Minute)
	o.flush()
	if r := o.rows(ch)[0]; r.state != "sent" || !strings.Contains(r.err, "not delivered to RCPT TO gone@example.nl: 550") {
		t.Fatalf("after the retry: %+v", r)
	}
	cs, _ := o.chans.List(o.ctx)
	if len(cs) != 1 || cs[0].LastState != "sent" || !strings.Contains(cs[0].LastError, "gone@example.nl") {
		t.Fatalf("channel's last delivery: %+v", cs)
	}
}

// A rate limit postpones the retry by at least the time asked, also when
// that is longer than the backoff.
func TestOutboxHonoursRetryAfter(t *testing.T) {
	o := newOutbox(t)
	ch := o.channel("ops")
	o.setFail("ops", &RetryAfterError{Err: errors.New("429 Too Many Requests"), After: 17 * time.Minute})
	o.enqueue(ch, EventOpen, alertMsg("warning", "x"))
	o.clock.Add(BatchDelay)
	o.flush()
	if r := o.rows(ch)[0]; r.state != "pending" || r.next < o.clock.Now().Add(17*time.Minute).Unix() {
		t.Fatalf("retry at %d, %d s from now: %+v", r.next, r.next-o.clock.Now().Unix(), r)
	}
	o.setFail("ops", nil)
	o.clock.Add(16 * time.Minute)
	o.flush()
	if m := o.take("ops"); len(m) != 0 {
		t.Fatal("retried before the time the transport asked for")
	}
	o.clock.Add(2 * time.Minute)
	o.flush()
	if m := o.take("ops"); len(m) != 1 {
		t.Fatalf("not delivered after the wait: %d", len(m))
	}
}

// The outbox is in the database: a restart with alerts pending delivers
// them once, keeping their attempt count.
func TestOutboxSurvivesRestart(t *testing.T) {
	o := newOutbox(t)
	ch := o.channel("ops")
	o.setFail("ops", errors.New("relay down"))
	o.enqueue(ch, EventOpen, alertMsg("critical", "x"))
	o.clock.Add(BatchDelay)
	o.flush()
	// Restart: a new dispatcher on the same database.
	o.setFail("ops", nil)
	o.d = o.dispatcher()
	o.flush()
	if m := o.take("ops"); len(m) != 0 {
		t.Fatal("restart ignored the backoff")
	}
	o.clock.Add(time.Minute)
	o.flush()
	if m := o.take("ops"); len(m) != 1 {
		t.Fatalf("pending alert after restart delivered %d times", len(m))
	}
	if r := o.rows(ch)[0]; r.state != "sent" || r.attempts != 2 {
		t.Fatalf("row: %+v", r)
	}
}

// A channel disabled while it has alerts queued gets nothing; the alerts
// end as failed with the reason, and other channels are served.
func TestOutboxDisabledChannel(t *testing.T) {
	o := newOutbox(t)
	ch := o.channel("ops")
	other := o.channel("other")
	o.enqueue(ch, EventOpen, alertMsg("critical", "x"))
	o.enqueue(other, EventOpen, alertMsg("critical", "x"))
	c, err := o.chans.Get(o.ctx, ch)
	if err != nil {
		t.Fatal(err)
	}
	c.Enabled = false
	if _, err := o.chans.Save(o.ctx, c); err != nil {
		t.Fatal(err)
	}
	o.clock.Add(BatchDelay)
	o.flush()
	if m := o.take("ops"); len(m) != 0 {
		t.Fatal("disabled channel was sent to")
	}
	if m := o.take("other"); len(m) != 1 {
		t.Fatal("the enabled channel was not served")
	}
	if r := o.rows(ch)[0]; r.state != "failed" || r.err != "channel disabled" {
		t.Fatalf("row: %+v", r)
	}
}

// Deleting a channel removes its queued alerts with its log: nothing is
// sent, and nothing is left retrying for a channel that no longer exists.
func TestOutboxDeletedChannel(t *testing.T) {
	o := newOutbox(t)
	ch := o.channel("ops")
	o.enqueue(ch, EventOpen, alertMsg("critical", "x"))
	if err := o.chans.Delete(o.ctx, ch); err != nil {
		t.Fatal(err)
	}
	o.clock.Add(BatchDelay)
	o.flush()
	if m := o.take("ops"); len(m) != 0 {
		t.Fatal("deleted channel was sent to")
	}
	var n int
	_ = o.db.R.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&n)
	if n != 0 {
		t.Fatalf("%d alerts left for a deleted channel", n)
	}
}

// A channel whose credentials cannot be decrypted is never sent through
// with empty settings; its alerts are retried with the reason, so they go
// out once an admin enters the credentials again.
func TestOutboxUnreadableChannel(t *testing.T) {
	o := newOutbox(t)
	ch := o.channel("ops")
	o.enqueue(ch, EventOpen, alertMsg("critical", "x"))
	other, _ := secret.New([]byte(strings.Repeat("k", 32)))
	if _, err := o.db.W.Exec("UPDATE channels SET settings = ? WHERE id = ?", other.Seal(sealContext, []byte(`{}`)), ch); err != nil {
		t.Fatal(err)
	}
	o.clock.Add(BatchDelay)
	o.flush()
	if m := o.take("ops"); len(m) != 0 {
		t.Fatal("sent through a channel whose settings cannot be read")
	}
	r := o.rows(ch)[0]
	if r.state != "pending" || !strings.Contains(r.err, "decrypt") {
		t.Fatalf("row: %+v", r)
	}
	// The admin enters the credentials again.
	c, _ := o.chans.Get(o.ctx, ch)
	c.Webhook = WebhookSettings{URL: "https://hooks.example.nl/ops"}
	if _, err := o.chans.Save(o.ctx, c); err != nil {
		t.Fatal(err)
	}
	o.clock.Add(time.Minute)
	o.flush()
	if m := o.take("ops"); len(m) != 1 {
		t.Fatalf("delivered %d after the credentials were entered again", len(m))
	}
}

// blockSender blocks until released, like a relay that does not answer.
type blockSender struct{ release chan struct{} }

func (b blockSender) Send(ctx context.Context, _ Message) error {
	select {
	case <-b.release:
		return errors.New("timeout")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// A channel that hangs does not hold up the delivery to another.
func TestOutboxHangingChannelDoesNotBlockOthers(t *testing.T) {
	o := newOutbox(t)
	slow := o.channel("slow")
	fast := o.channel("fast")
	release := make(chan struct{})
	delivered := make(chan struct{})
	o.d.Senders = func(c Channel) Sender {
		if c.Name == "slow" {
			return blockSender{release}
		}
		return senderFunc(func(Message) error { close(delivered); return nil })
	}
	o.enqueue(slow, EventOpen, alertMsg("critical", "x"))
	o.enqueue(fast, EventOpen, alertMsg("critical", "x"))
	o.clock.Add(BatchDelay)
	done := make(chan error, 1)
	go func() { done <- o.d.Flush(o.ctx) }()
	select {
	case <-delivered:
	case <-time.After(5 * time.Second):
		t.Fatal("the fast channel waited for the hanging one")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if r := o.rows(slow)[0]; r.state != "pending" || r.attempts != 1 {
		t.Fatalf("slow row: %+v", r)
	}
}

type senderFunc func(Message) error

func (f senderFunc) Send(_ context.Context, m Message) error { return f(m) }

// SendNow (the digest) is delivered by the running dispatcher at once, not
// after the batch delay or the next tick.
func TestSendNowWakesRun(t *testing.T) {
	o := newOutbox(t)
	ch := o.channel("ops")
	ctx, cancel := context.WithCancel(o.ctx)
	stopped := make(chan struct{})
	go func() { o.d.Run(ctx); close(stopped) }()
	defer func() { cancel(); <-stopped }()
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	if err := o.d.SendNow(o.ctx, []int64{ch}, EventDigest, Message{Subject: "[info] tlswatch weekly digest: 0 open", Body: "digest body"}); err != nil {
		t.Fatal(err)
	}
	for {
		o.mu.Lock()
		n := len(o.sent["ops"])
		o.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Since(start) > 3*time.Second {
			t.Fatal("SendNow did not wake the dispatcher")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// SendNow queues nothing when one of the channels does not exist: the
// digest goes to every channel or to none.
func TestSendNowIsAllOrNothing(t *testing.T) {
	o := newOutbox(t)
	ch := o.channel("ops")
	if err := o.d.SendNow(o.ctx, []int64{ch, 9999}, EventDigest, Message{Subject: "s"}); err == nil {
		t.Fatal("queued to a channel that does not exist")
	}
	var n int
	_ = o.db.R.QueryRow("SELECT COUNT(*) FROM alerts").Scan(&n)
	if n != 0 {
		t.Fatalf("%d rows left by a failed SendNow", n)
	}
}

// The weekly digest is its own message: an alert that happens to be due on
// the same channel at the same moment (a retry, or one past its batch
// delay) must not swallow it into a collapsed "2 alerts" list, which would
// leave only the digest's subject line and lose its content.
func TestDigestIsNotCollapsedWithAlerts(t *testing.T) {
	o := newOutbox(t)
	ch := o.channel("ops")
	o.enqueue(ch, EventOpen, alertMsg("warning", "a.example.nl:443 expires in 20 days"))
	o.clock.Add(BatchDelay)
	digest := Message{Subject: "[warning] tlswatch weekly digest: 1 open, 0 expiring within 30 days", Body: "Open findings (1)\n  [warning] a.example.nl:443 Expiring\n"}
	if err := o.d.SendNow(o.ctx, []int64{ch}, EventDigest, digest); err != nil {
		t.Fatal(err)
	}
	o.flush()
	var got *Message
	for _, m := range o.take("ops") {
		if m.Subject == digest.Subject {
			got = &m
		}
	}
	if got == nil || got.Body != digest.Body {
		t.Fatal("the digest was collapsed into an alert batch and its content lost")
	}
}

// A test message is sent at once, also through a disabled channel, and
// logged; a failure is logged with its error.
func TestSendTestLogsResult(t *testing.T) {
	o := newOutbox(t)
	ch := o.channel("ops")
	if err := o.d.SendTest(o.ctx, ch, "https://tlswatch.example.nl/"); err != nil {
		t.Fatal(err)
	}
	if m := o.take("ops"); len(m) != 1 || !strings.Contains(m[0].Body, `"ops"`) {
		t.Fatalf("test message: %+v", m)
	}
	o.setFail("ops", errors.New("403 Forbidden"))
	if err := o.d.SendTest(o.ctx, ch, ""); err == nil {
		t.Fatal("failure not reported")
	}
	r := o.rows(ch)
	if len(r) != 2 || r[0].state != "sent" || r[1].state != "failed" || r[1].err != "403 Forbidden" {
		t.Fatalf("log: %+v", r)
	}
	// A test is never picked up again by the outbox.
	o.setFail("ops", nil)
	o.clock.Add(time.Hour)
	o.flush()
	if m := o.take("ops"); len(m) != 0 {
		t.Fatal("a test message was re-sent by the outbox")
	}
}

// Channel.Sender picks the transport of the channel's kind.
func TestChannelSenderByKind(t *testing.T) {
	for kind, want := range map[string]string{
		KindSMTP: "*notify.SMTPSender", KindTelegram: "*notify.TelegramSender", KindSlack: "*notify.SlackSender",
		KindDiscord: "*notify.DiscordSender", KindNtfy: "*notify.NtfySender", KindWebhook: "*notify.WebhookSender",
	} {
		if got := typeName(Channel{Kind: kind}.Sender()); got != want {
			t.Errorf("%s: %s", kind, got)
		}
	}
	if _, ok := (Channel{Kind: KindTelegram}.Sender()).(PartialSender); !ok {
		t.Error("Telegram is not a PartialSender: a retry would repeat the message to chats that got it")
	}
	for _, k := range []string{KindDiscord, KindNtfy, KindWebhook} {
		if _, ok := (Channel{Kind: k}.Sender()).(RefSender); !ok {
			t.Errorf("%s does not report its reference", k)
		}
	}
}

func typeName(v any) string { return fmt.Sprintf("%T", v) }
