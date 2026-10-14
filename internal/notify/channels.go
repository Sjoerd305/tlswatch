package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

// Channel kinds.
const (
	KindSMTP     = "smtp"
	KindTelegram = "telegram"
)

// Channel is a delivery route configured by an admin. The credentials are
// stored encrypted; SMTP or Telegram is set according to Kind.
type Channel struct {
	ID          int64
	Name        string
	Kind        string
	MinSeverity string
	Destination string
	Enabled     bool
	SMTP        SMTPSettings
	Telegram    TelegramSettings
	CreatedAt   int64
	UpdatedAt   int64
	// Delivery state, filled by List.
	LastState   string
	LastAt      int64
	LastError   string
	NextAttempt int64
	Sent30d     int
}

// KindLabel is the display name of the channel type.
func (c Channel) KindLabel() string {
	if c.Kind == KindTelegram {
		return "Telegram"
	}
	return "SMTP"
}

// Validate checks the channel and its settings.
func (c Channel) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("Name is required")
	}
	switch c.MinSeverity {
	case "info", "warning", "critical":
	default:
		return errors.New("Severity floor must be info, warning or critical")
	}
	switch c.Kind {
	case KindSMTP:
		return c.SMTP.Validate()
	case KindTelegram:
		return c.Telegram.Validate()
	}
	return errors.New("unknown channel type")
}

// Sender returns a transport for the channel.
func (c Channel) Sender() Sender {
	if c.Kind == KindTelegram {
		return &TelegramSender{S: c.Telegram}
	}
	return &SMTPSender{S: c.SMTP}
}

// Secrets lists the credential values to redact from logs.
func (c Channel) Secrets() []string { return []string{c.SMTP.Password, c.Telegram.Token} }

// Channels stores channels with their settings encrypted under the key.
type Channels struct {
	DB  *db.DB
	Key *secret.Key
	Now func() time.Time
}

func (s *Channels) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

type sealedSettings struct {
	SMTP     *SMTPSettings     `json:"smtp,omitempty"`
	Telegram *TelegramSettings `json:"telegram,omitempty"`
}

func (s *Channels) seal(c Channel) ([]byte, error) {
	var v sealedSettings
	if c.Kind == KindSMTP {
		v.SMTP = &c.SMTP
	} else {
		v.Telegram = &c.Telegram
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return s.Key.Seal(b), nil
}

func (s *Channels) unseal(c *Channel, blob []byte) error {
	pt, err := s.Key.Open(blob)
	if err != nil {
		return fmt.Errorf("channel %q: cannot decrypt settings (secret key changed?)", c.Name)
	}
	var v sealedSettings
	if err := json.Unmarshal(pt, &v); err != nil {
		return err
	}
	if v.SMTP != nil {
		c.SMTP = *v.SMTP
	}
	if v.Telegram != nil {
		c.Telegram = *v.Telegram
	}
	return nil
}

const channelCols = "id, name, kind, min_severity, settings, destination, enabled, created_at, updated_at"

func (s *Channels) scan(row interface{ Scan(...any) error }) (Channel, error) {
	var c Channel
	var blob []byte
	if err := row.Scan(&c.ID, &c.Name, &c.Kind, &c.MinSeverity, &blob, &c.Destination, &c.Enabled, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return c, err
	}
	if err := s.unseal(&c, blob); err != nil {
		return c, err
	}
	return c, nil
}

// List returns every channel with its last delivery state.
func (s *Channels) List(ctx context.Context) ([]Channel, error) {
	rows, err := s.DB.R.QueryContext(ctx, "SELECT "+channelCols+" FROM channels ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		c, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	since := s.now().Add(-30 * 24 * time.Hour).Unix()
	for i := range out {
		c := &out[i]
		_ = s.DB.R.QueryRowContext(ctx, `SELECT state, CASE WHEN sent_at > 0 THEN sent_at ELSE created_at END, error, next_attempt
			FROM alerts WHERE channel_id = ? AND state != 'pending'
			ORDER BY id DESC LIMIT 1`, c.ID).Scan(&c.LastState, &c.LastAt, &c.LastError, &c.NextAttempt)
		var pendingRetry int64
		if err := s.DB.R.QueryRowContext(ctx, "SELECT COALESCE(MIN(next_attempt),0) FROM alerts WHERE channel_id = ? AND state = 'pending' AND attempts > 0", c.ID).Scan(&pendingRetry); err == nil && pendingRetry > 0 {
			c.LastState = "retrying"
			c.NextAttempt = pendingRetry
		}
		_ = s.DB.R.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts WHERE channel_id = ? AND state = 'sent' AND sent_at >= ?", c.ID, since).Scan(&c.Sent30d)
	}
	return out, nil
}

// Enabled returns the enabled channels.
func (s *Channels) Enabled(ctx context.Context) ([]Channel, error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, c := range all {
		if c.Enabled {
			out = append(out, c)
		}
	}
	return out, nil
}

// Get returns one channel.
func (s *Channels) Get(ctx context.Context, id int64) (Channel, error) {
	return s.scan(s.DB.R.QueryRowContext(ctx, "SELECT "+channelCols+" FROM channels WHERE id = ?", id))
}

// Save creates (ID 0) or updates a channel. On update, an empty SMTP
// password or Telegram token keeps the stored value.
func (s *Channels) Save(ctx context.Context, c Channel) (int64, error) {
	if c.ID != 0 {
		old, err := s.Get(ctx, c.ID)
		if err != nil {
			return 0, err
		}
		c.Kind = old.Kind
		if c.SMTP.Password == "" {
			c.SMTP.Password = old.SMTP.Password
		}
		if c.Telegram.Token == "" {
			c.Telegram.Token = old.Telegram.Token
		}
	}
	if err := c.Validate(); err != nil {
		return 0, err
	}
	blob, err := s.seal(c)
	if err != nil {
		return 0, err
	}
	dest := c.SMTP.Destination()
	if c.Kind == KindTelegram {
		dest = c.Telegram.Destination()
	}
	now := s.now().Unix()
	if c.ID == 0 {
		res, err := s.DB.W.ExecContext(ctx, `INSERT INTO channels(name, kind, min_severity, settings, destination, enabled, created_at, updated_at)
			VALUES(?,?,?,?,?,?,?,?)`, strings.TrimSpace(c.Name), c.Kind, c.MinSeverity, blob, dest, c.Enabled, now, now)
		if err != nil {
			return 0, uniqueErr(err)
		}
		return res.LastInsertId()
	}
	_, err = s.DB.W.ExecContext(ctx, `UPDATE channels SET name=?, min_severity=?, settings=?, destination=?, enabled=?, updated_at=? WHERE id=?`,
		strings.TrimSpace(c.Name), c.MinSeverity, blob, dest, c.Enabled, now, c.ID)
	return c.ID, uniqueErr(err)
}

// Delete removes a channel and its alert log.
func (s *Channels) Delete(ctx context.Context, id int64) error {
	_, err := s.DB.W.ExecContext(ctx, "DELETE FROM channels WHERE id = ?", id)
	return err
}

func uniqueErr(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return errors.New("A channel with this name already exists")
	}
	return err
}
