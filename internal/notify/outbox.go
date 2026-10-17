package notify

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/sjoerd305/tlswatch/internal/db"
)

// BatchDelay is how long a new alert waits so that alerts opened by the same
// run can be collapsed into one message per channel.
const BatchDelay = 15 * time.Second

// Enqueue adds an alert to the outbox within the caller's transaction.
func Enqueue(ctx context.Context, tx *sql.Tx, findingID, channelID int64, event string, m Message, now time.Time) error {
	var fid any
	if findingID != 0 {
		fid = findingID
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO alerts(finding_id, channel_id, event, created_at, next_attempt, subject, body, html)
		VALUES(?,?,?,?,?,?,?,?)`, fid, channelID, event, now.Unix(), now.Add(BatchDelay).Unix(), m.Subject, m.Body, m.HTML)
	return err
}

// backoff returns the delay before the next attempt after n failed attempts:
// 1 min, 5 min, 30 min, then hourly.
func backoff(n int) time.Duration {
	switch n {
	case 1:
		return time.Minute
	case 2:
		return 5 * time.Minute
	case 3:
		return 30 * time.Minute
	}
	return time.Hour
}

// GiveUpAfter is how long delivery is retried.
const GiveUpAfter = 24 * time.Hour

// Dispatcher delivers queued alerts.
type Dispatcher struct {
	DB       *db.DB
	Channels *Channels
	Now      func() time.Time
	Log      *slog.Logger
	// Link returns the URL of the findings page for collapsed messages.
	Link func(ctx context.Context) string
	// Senders overrides the transport per channel, for tests.
	Senders func(Channel) Sender

	wake chan struct{}
	once sync.Once
	mu   sync.Mutex // one flush at a time
}

func (d *Dispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Dispatcher) init() { d.once.Do(func() { d.wake = make(chan struct{}, 1) }) }

// Wake asks the dispatcher to look at the outbox soon.
func (d *Dispatcher) Wake() {
	d.init()
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Run delivers alerts until ctx ends; a flush under way finishes recording
// what it sent.
func (d *Dispatcher) Run(ctx context.Context) {
	d.init()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-d.wake:
		}
		if err := d.Flush(ctx); err != nil && ctx.Err() == nil {
			d.Log.Error("alert dispatch", "err", err)
		}
	}
}

type pending struct {
	id        int64
	createdAt int64
	attempts  int
	ref       string // references of the chats already reached
	msg       Message
}

// batchKey groups due alerts into one message: per channel, and per set of
// recipients already reached, so a retry skips exactly those. A digest is
// a message of its own (solo is its alert id), never a line in a batch.
type batchKey struct {
	channel   int64
	delivered string
	solo      int64
}

// Hold waits for a running flush and keeps the next one from starting until
// release is called, while a restore replaces the database.
func (d *Dispatcher) Hold() (release func()) {
	d.mu.Lock()
	return d.mu.Unlock
}

// Flush sends every due alert, collapsed per channel; channels are served
// in parallel so one that is down does not hold up another.
func (d *Dispatcher) Flush(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	rows, err := d.DB.R.QueryContext(ctx, `SELECT id, channel_id, delivered, ref, created_at, attempts, subject, body, html, event FROM alerts
		WHERE state = 'pending' AND next_attempt <= ? ORDER BY id`, now.Unix())
	if err != nil {
		return err
	}
	batches := map[batchKey][]pending{}
	var order []batchKey
	for rows.Next() {
		var p pending
		var k batchKey
		var event string
		if err := rows.Scan(&p.id, &k.channel, &k.delivered, &p.ref, &p.createdAt, &p.attempts, &p.msg.Subject, &p.msg.Body, &p.msg.HTML, &event); err != nil {
			rows.Close()
			return err
		}
		if event == EventDigest {
			k.solo = p.id
		}
		if _, ok := batches[k]; !ok {
			order = append(order, k)
		}
		batches[k] = append(batches[k], p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	// Channels are served in parallel; the batches of one channel in turn.
	byChannel := map[int64][]batchKey{}
	for _, k := range order {
		byChannel[k.channel] = append(byChannel[k.channel], k)
	}
	var wg sync.WaitGroup
	for ch, keys := range byChannel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, k := range keys {
				d.deliver(ctx, ch, k.delivered, batches[k])
			}
		}()
	}
	wg.Wait()
	return nil
}

// attempt is the outcome of sending one batch to one channel.
type attempt struct {
	err       error
	delivered string // recipients reached so far (multi-recipient channels)
	ref       string // the SMTP Message-ID, or "chat:message_id" per chat reached so far
	wait      time.Duration
}

// deliver sends one batch to one channel and records the outcome on its
// alerts.
func (d *Dispatcher) deliver(ctx context.Context, chID int64, delivered string, ps []pending) {
	c, err := d.Channels.Get(ctx, chID)
	var a attempt
	switch {
	case err != nil:
		a = attempt{err: err, delivered: delivered, ref: ps[0].ref}
	case !c.Enabled:
		a = attempt{err: errDisabled, delivered: delivered, ref: ps[0].ref}
	default:
		a = d.send(ctx, c, delivered, ps)
	}
	// Record the outcome even when shutdown cancelled ctx meanwhile, so a
	// message that went out is not sent again.
	ids, gaveUp := d.record(context.WithoutCancel(ctx), a, ps)
	log := d.Log.With("channel_id", chID, "channel", c.Name, "alerts", ids, "ref", a.ref)
	switch {
	case a.err == nil:
		log.Info("alert delivered")
	case len(gaveUp) > 0:
		log.Error("alert delivery given up", "failed", gaveUp, "err", a.err)
	default:
		log.Warn("alert delivery failed, will retry", "attempt", ps[0].attempts+1, "err", a.err)
	}
}

// send combines the batch into one message and sends it, skipping the
// recipients already reached when the transport tracks them.
func (d *Dispatcher) send(ctx context.Context, c Channel, delivered string, ps []pending) attempt {
	msgs := make([]Message, len(ps))
	for i, p := range ps {
		msgs[i] = p.msg
	}
	link := ""
	if d.Link != nil && len(ps) > 1 {
		link = d.Link(ctx)
	}
	m := Combine(msgs, link)
	m.Ref = NewRef()
	sctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	a := attempt{delivered: delivered}
	switch snd := d.sender(c).(type) {
	case PartialSender:
		var reached, refs []string
		reached, refs, a.err = snd.SendSkipping(sctx, m, splitList(delivered))
		a.delivered = joinList(append(splitList(delivered), reached...))
		a.ref = joinList(append(splitList(ps[0].ref), refs...))
	case RefSender:
		a.ref, a.err = snd.SendRef(sctx, m)
	default:
		if a.err = snd.Send(sctx, m); a.err == nil {
			a.ref = MessageID(m.Ref)
		}
	}
	if ra := (*RetryAfterError)(nil); errors.As(a.err, &ra) {
		a.wait = ra.After
	}
	return a
}

// record stores the attempt on every alert of the batch: sent, or pending
// with the next attempt after the backoff, or failed once retrying would
// pass GiveUpAfter or cannot help (a *PermanentError). It returns the alert IDs and those given up.
func (d *Dispatcher) record(ctx context.Context, a attempt, ps []pending) (ids, gaveUp []int64) {
	now := d.now()
	for _, p := range ps {
		ids = append(ids, p.id)
		var err error
		if a.err == nil {
			_, err = d.DB.W.ExecContext(ctx, "UPDATE alerts SET state='sent', sent_at=?, attempts=attempts+1, error='', ref=? WHERE id=?", now.Unix(), a.ref, p.id)
		} else {
			n := p.attempts + 1
			next := now.Add(max(backoff(n), a.wait))
			state := "pending"
			var perm *PermanentError
			if a.err == errDisabled || errors.As(a.err, &perm) || next.After(time.Unix(p.createdAt, 0).Add(GiveUpAfter)) {
				state = "failed"
				gaveUp = append(gaveUp, p.id)
			}
			_, err = d.DB.W.ExecContext(ctx, "UPDATE alerts SET state=?, attempts=?, next_attempt=?, error=?, delivered=?, ref=? WHERE id=?",
				state, n, next.Unix(), a.err.Error(), a.delivered, a.ref, p.id)
		}
		if err != nil {
			d.Log.Error("update alert", "id", p.id, "err", err)
		}
	}
	return ids, gaveUp
}

// sendTimeout bounds one delivery attempt.
const sendTimeout = 60 * time.Second

// sender is the transport for c. Transports redact their own credentials
// from the errors they return.
func (d *Dispatcher) sender(c Channel) Sender {
	if d.Senders != nil {
		return d.Senders(c)
	}
	return c.Sender()
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func joinList(l []string) string { return strings.Join(l, ",") }

type disabledError struct{}

func (disabledError) Error() string { return "channel disabled" }

var errDisabled error = disabledError{}

// SendTest sends a sample message right away and records it in the alert
// log.
func (d *Dispatcher) SendTest(ctx context.Context, chID int64, link string) error {
	c, err := d.Channels.Get(ctx, chID)
	if err != nil {
		return err
	}
	m := TestMessage(c.Name, link)
	m.Ref = NewRef()
	sctx, cancel := context.WithTimeout(ctx, sendTimeout)
	var refs []string
	var sendErr error
	switch snd := d.sender(c).(type) {
	case PartialSender:
		_, refs, sendErr = snd.SendSkipping(sctx, m, nil)
	case RefSender:
		var ref string
		if ref, sendErr = snd.SendRef(sctx, m); sendErr == nil && ref != "" {
			refs = []string{ref}
		}
	default:
		if sendErr = snd.Send(sctx, m); sendErr == nil {
			refs = []string{MessageID(m.Ref)}
		}
	}
	cancel()
	now := d.now().Unix()
	state, msg := "sent", ""
	if sendErr != nil {
		state, msg = "failed", sendErr.Error()
	}
	sent := int64(0)
	if state == "sent" {
		sent = now
	}
	ref := joinList(refs)
	_, err = d.DB.W.ExecContext(ctx, `INSERT INTO alerts(channel_id, event, created_at, state, attempts, next_attempt, sent_at, error, subject, body, ref)
		VALUES(?, 'test', ?, ?, 1, ?, ?, ?, ?, ?, ?)`, chID, now, state, now, sent, msg, m.Subject, m.Body, ref)
	if sendErr != nil {
		return sendErr
	}
	return err
}

// SendNow queues a message for every given channel and wakes the
// dispatcher; used by the digest.
func (d *Dispatcher) SendNow(ctx context.Context, chIDs []int64, event string, m Message) error {
	tx, err := d.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	now := d.now()
	for _, id := range chIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO alerts(channel_id, event, created_at, next_attempt, subject, body, html) VALUES(?,?,?,?,?,?,?)`,
			id, event, now.Unix(), now.Unix(), m.Subject, m.Body, m.HTML); err != nil {
			tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	d.Wake()
	return nil
}
