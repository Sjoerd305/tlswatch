package notify

import (
	"context"
	"database/sql"
	"log/slog"
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
	_, err := tx.ExecContext(ctx, `INSERT INTO alerts(finding_id, channel_id, event, created_at, next_attempt, subject, body)
		VALUES(?,?,?,?,?,?,?)`, fid, channelID, event, now.Unix(), now.Add(BatchDelay).Unix(), m.Subject, m.Body)
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

// Run delivers alerts until ctx ends.
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
	msg       Message
}

// Flush sends every due alert, collapsed per channel; channels are served
// in parallel so one that is down does not hold up another.
func (d *Dispatcher) Flush(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	rows, err := d.DB.R.QueryContext(ctx, `SELECT id, channel_id, created_at, attempts, subject, body FROM alerts
		WHERE state = 'pending' AND next_attempt <= ? ORDER BY id`, now.Unix())
	if err != nil {
		return err
	}
	byChannel := map[int64][]pending{}
	var order []int64
	for rows.Next() {
		var p pending
		var ch int64
		if err := rows.Scan(&p.id, &ch, &p.createdAt, &p.attempts, &p.msg.Subject, &p.msg.Body); err != nil {
			rows.Close()
			return err
		}
		if _, ok := byChannel[ch]; !ok {
			order = append(order, ch)
		}
		byChannel[ch] = append(byChannel[ch], p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var wg sync.WaitGroup
	for _, ch := range order {
		wg.Add(1)
		go func(ch int64, ps []pending) {
			defer wg.Done()
			d.deliver(ctx, ch, ps)
		}(ch, byChannel[ch])
	}
	wg.Wait()
	return nil
}

func (d *Dispatcher) deliver(ctx context.Context, chID int64, ps []pending) {
	c, err := d.Channels.Get(ctx, chID)
	var sendErr error
	switch {
	case err != nil:
		sendErr = err
	case !c.Enabled:
		sendErr = errDisabled
	default:
		msgs := make([]Message, len(ps))
		for i, p := range ps {
			msgs[i] = p.msg
		}
		link := ""
		if d.Link != nil && len(ps) > 1 {
			link = d.Link(ctx)
		}
		m := Combine(msgs, link)
		sender := c.Sender()
		if d.Senders != nil {
			sender = d.Senders(c)
		}
		sctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		sendErr = sender.Send(sctx, m)
		cancel()
		if sendErr != nil {
			sendErr = redactErr(sendErr, c.Secrets()...)
		}
	}
	now := d.now()
	var ids, gaveUp []int64
	for _, p := range ps {
		ids = append(ids, p.id)
		if sendErr == nil {
			_, err = d.DB.W.ExecContext(ctx, "UPDATE alerts SET state='sent', sent_at=?, attempts=attempts+1, error='' WHERE id=?", now.Unix(), p.id)
		} else {
			n := p.attempts + 1
			next := now.Add(backoff(n))
			state := "pending"
			if sendErr == errDisabled || next.After(time.Unix(p.createdAt, 0).Add(GiveUpAfter)) {
				state = "failed"
				gaveUp = append(gaveUp, p.id)
			}
			_, err = d.DB.W.ExecContext(ctx, "UPDATE alerts SET state=?, attempts=?, next_attempt=?, error=? WHERE id=?", state, n, next.Unix(), sendErr.Error(), p.id)
		}
		if err != nil {
			d.Log.Error("update alert", "id", p.id, "err", err)
		}
	}
	log := d.Log.With("channel_id", chID, "channel", c.Name, "alerts", ids)
	switch {
	case sendErr == nil:
		log.Info("alert delivered")
	case len(gaveUp) > 0:
		log.Error("alert delivery given up", "failed", gaveUp, "err", sendErr)
	default:
		log.Warn("alert delivery failed, will retry", "attempt", ps[0].attempts+1, "err", sendErr)
	}
}

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
	sender := c.Sender()
	if d.Senders != nil {
		sender = d.Senders(c)
	}
	sctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	sendErr := sender.Send(sctx, m)
	cancel()
	now := d.now().Unix()
	state, msg := "sent", ""
	if sendErr != nil {
		sendErr = redactErr(sendErr, c.Secrets()...)
		state, msg = "failed", sendErr.Error()
	}
	sent := int64(0)
	if state == "sent" {
		sent = now
	}
	_, err = d.DB.W.ExecContext(ctx, `INSERT INTO alerts(channel_id, event, created_at, state, attempts, next_attempt, sent_at, error, subject, body)
		VALUES(?, 'test', ?, ?, 1, ?, ?, ?, ?, ?)`, chID, now, state, now, sent, msg, m.Subject, m.Body)
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
		if _, err := tx.ExecContext(ctx, `INSERT INTO alerts(channel_id, event, created_at, next_attempt, subject, body) VALUES(?,?,?,?,?,?)`,
			id, event, now.Unix(), now.Unix(), m.Subject, m.Body); err != nil {
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
