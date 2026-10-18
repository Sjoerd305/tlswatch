package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/secret"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// Channel kinds.
const (
	KindSMTP      = "smtp"
	KindTelegram  = "telegram"
	KindSlack     = "slack"
	KindDiscord   = "discord"
	KindNtfy      = "ntfy"
	KindWebhook   = "webhook"
	KindTeams     = "teams"
	KindMatrix    = "matrix"
	KindPagerDuty = "pagerduty"
)

// Kinds lists the channel kinds in the order the UI offers them, with their
// display names.
var Kinds = []struct{ Kind, Label string }{
	{KindSMTP, "SMTP"}, {KindTelegram, "Telegram"}, {KindSlack, "Slack"}, {KindDiscord, "Discord"}, {KindTeams, "Microsoft Teams"},
	{KindMatrix, "Matrix"}, {KindNtfy, "ntfy"}, {KindPagerDuty, "PagerDuty"}, {KindWebhook, "Webhook"},
}

// KnownKind reports whether k is a channel kind.
func KnownKind(k string) bool {
	for _, x := range Kinds {
		if x.Kind == k {
			return true
		}
	}
	return false
}

// Channel is a delivery route configured by an admin. The credentials are
// stored encrypted; the settings struct matching Kind is set.
type Channel struct {
	ID          int64
	Name        string
	Kind        string
	MinSeverity string
	Destination string
	Enabled     bool
	SMTP        SMTPSettings
	Telegram    TelegramSettings
	Slack       SlackSettings
	Discord     DiscordSettings
	Ntfy        NtfySettings
	Webhook     WebhookSettings
	Teams       TeamsSettings
	Matrix      MatrixSettings
	PagerDuty   PagerDutySettings
	CreatedAt   int64
	UpdatedAt   int64
	// Unreadable is set when the stored settings cannot be decrypted, for
	// example after the secret key changed. Sending through the channel
	// fails until an admin enters its credentials again.
	Unreadable string
	// Delivery state, filled by List.
	LastState   string
	LastAt      int64
	LastError   string
	NextAttempt int64
	Sent30d     int
}

// KindLabel is the display name of the channel type.
func (c Channel) KindLabel() string {
	for _, k := range Kinds {
		if k.Kind == c.Kind {
			return k.Label
		}
	}
	return c.Kind
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
	case KindSlack:
		return c.Slack.Validate()
	case KindDiscord:
		return c.Discord.Validate()
	case KindNtfy:
		return c.Ntfy.Validate()
	case KindWebhook:
		return c.Webhook.Validate()
	case KindTeams:
		return c.Teams.Validate()
	case KindMatrix:
		return c.Matrix.Validate()
	case KindPagerDuty:
		return c.PagerDuty.Validate()
	}
	return errors.New("unknown channel type")
}

// Sender returns a transport for the channel.
func (c Channel) Sender() Sender {
	switch c.Kind {
	case KindTelegram:
		return &TelegramSender{S: c.Telegram}
	case KindSlack:
		return &SlackSender{S: c.Slack}
	case KindDiscord:
		return &DiscordSender{S: c.Discord}
	case KindNtfy:
		return &NtfySender{S: c.Ntfy}
	case KindWebhook:
		return &WebhookSender{S: c.Webhook}
	case KindTeams:
		return &TeamsSender{S: c.Teams}
	case KindMatrix:
		return &MatrixSender{S: c.Matrix}
	case KindPagerDuty:
		return &PagerDutySender{S: c.PagerDuty}
	}
	return &SMTPSender{S: c.SMTP}
}

// destination is the summary of the settings for the channel table.
func (c Channel) destination() string {
	switch c.Kind {
	case KindTelegram:
		return c.Telegram.Destination()
	case KindSlack:
		return c.Slack.Destination()
	case KindDiscord:
		return c.Discord.Destination()
	case KindNtfy:
		return c.Ntfy.Destination()
	case KindWebhook:
		return c.Webhook.Destination()
	case KindTeams:
		return c.Teams.Destination()
	case KindMatrix:
		return c.Matrix.Destination()
	case KindPagerDuty:
		return c.PagerDuty.Destination()
	}
	return c.SMTP.Destination()
}

// Secrets lists the credential values to redact from logs.
func (c Channel) Secrets() []string {
	return []string{c.SMTP.Password, c.Telegram.Token, c.Slack.WebhookURL, c.Discord.WebhookURL, c.Ntfy.Token, c.Webhook.Secret,
		c.Teams.WebhookURL, c.Matrix.Token, c.PagerDuty.RoutingKey}
}

// HasSecret reports whether a credential is set: a password, token, signing
// secret, or a webhook URL that is itself the credential.
func (c Channel) HasSecret() bool {
	for _, s := range c.Secrets() {
		if s != "" {
			return true
		}
	}
	return false
}

// ClearSecrets empties the credentials, for a form shown again after an
// error: a secret is never echoed back.
func (c *Channel) ClearSecrets() {
	c.SMTP.Password, c.Telegram.Token, c.Slack.WebhookURL, c.Discord.WebhookURL, c.Ntfy.Token, c.Webhook.Secret = "", "", "", "", "", ""
	c.Teams.WebhookURL, c.Matrix.Token, c.PagerDuty.RoutingKey = "", "", ""
}

// keepSecrets fills every empty credential of c from old, so that a form
// field left empty keeps the stored value.
func (c *Channel) keepSecrets(old Channel) {
	keep := func(dst *string, src string) {
		if *dst == "" {
			*dst = src
		}
	}
	keep(&c.SMTP.Password, old.SMTP.Password)
	keep(&c.Telegram.Token, old.Telegram.Token)
	keep(&c.Slack.WebhookURL, old.Slack.WebhookURL)
	keep(&c.Discord.WebhookURL, old.Discord.WebhookURL)
	keep(&c.Ntfy.Token, old.Ntfy.Token)
	keep(&c.Webhook.Secret, old.Webhook.Secret)
	keep(&c.Teams.WebhookURL, old.Teams.WebhookURL)
	keep(&c.Matrix.Token, old.Matrix.Token)
	keep(&c.PagerDuty.RoutingKey, old.PagerDuty.RoutingKey)
}

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
	SMTP      *SMTPSettings      `json:"smtp,omitempty"`
	Telegram  *TelegramSettings  `json:"telegram,omitempty"`
	Slack     *SlackSettings     `json:"slack,omitempty"`
	Discord   *DiscordSettings   `json:"discord,omitempty"`
	Ntfy      *NtfySettings      `json:"ntfy,omitempty"`
	Webhook   *WebhookSettings   `json:"webhook,omitempty"`
	Teams     *TeamsSettings     `json:"teams,omitempty"`
	Matrix    *MatrixSettings    `json:"matrix,omitempty"`
	PagerDuty *PagerDutySettings `json:"pagerduty,omitempty"`
}

func (s *Channels) seal(c Channel) ([]byte, error) {
	var v sealedSettings
	switch c.Kind {
	case KindTelegram:
		v.Telegram = &c.Telegram
	case KindSlack:
		v.Slack = &c.Slack
	case KindDiscord:
		v.Discord = &c.Discord
	case KindNtfy:
		v.Ntfy = &c.Ntfy
	case KindWebhook:
		v.Webhook = &c.Webhook
	case KindTeams:
		v.Teams = &c.Teams
	case KindMatrix:
		v.Matrix = &c.Matrix
	case KindPagerDuty:
		v.PagerDuty = &c.PagerDuty
	default:
		v.SMTP = &c.SMTP
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return s.Key.Seal(sealContext, b), nil
}

// sealContext names where channel settings live, for Seal.
const sealContext = "channels.settings"

// ErrUnreadable is wrapped by errors for a channel whose settings cannot be
// decrypted; the channel is still returned, with Unreadable set.
var ErrUnreadable = errors.New("cannot decrypt channel settings (secret key changed?)")

func (s *Channels) unseal(c *Channel, blob []byte) error {
	pt, err := s.Key.Open(sealContext, blob)
	if err != nil {
		c.Unreadable = ErrUnreadable.Error()
		return fmt.Errorf("channel %q: %w", c.Name, ErrUnreadable)
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
	if v.Slack != nil {
		c.Slack = *v.Slack
	}
	if v.Discord != nil {
		c.Discord = *v.Discord
	}
	if v.Ntfy != nil {
		c.Ntfy = *v.Ntfy
	}
	if v.Webhook != nil {
		c.Webhook = *v.Webhook
	}
	if v.Teams != nil {
		c.Teams = *v.Teams
	}
	if v.Matrix != nil {
		c.Matrix = *v.Matrix
	}
	if v.PagerDuty != nil {
		c.PagerDuty = *v.PagerDuty
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

// Reencrypt re-seals every channel's settings from old to new within tx,
// for a key rotation. It returns the names of channels that old cannot
// decrypt; those are left as they are.
func Reencrypt(ctx context.Context, tx *sql.Tx, old, new *secret.Key) (n int, unreadable []string, err error) {
	rows, err := tx.QueryContext(ctx, "SELECT id, name, settings FROM channels")
	if err != nil {
		return 0, nil, err
	}
	type row struct {
		id   int64
		name string
		blob []byte
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.name, &r.blob); err != nil {
			rows.Close()
			return 0, nil, err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	for _, r := range all {
		pt, err := old.Open(sealContext, r.blob)
		if err != nil {
			unreadable = append(unreadable, r.name)
			continue
		}
		if _, err := tx.ExecContext(ctx, "UPDATE channels SET settings = ? WHERE id = ?", new.Seal(sealContext, pt), r.id); err != nil {
			return n, unreadable, err
		}
		n++
	}
	return n, unreadable, nil
}

// List returns every channel with its last delivery state. A channel whose
// settings cannot be decrypted is listed with Unreadable set, so one bad
// channel does not hide the others or stop the checks that route alerts.
func (s *Channels) List(ctx context.Context) ([]Channel, error) {
	rows, err := s.DB.R.QueryContext(ctx, "SELECT "+channelCols+" FROM channels ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		c, err := s.scan(rows)
		if err != nil && !errors.Is(err, ErrUnreadable) {
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
		var retryAt int64
		var retryErr string
		if err := s.DB.R.QueryRowContext(ctx, `SELECT next_attempt, error FROM alerts WHERE channel_id = ? AND state = 'pending' AND attempts > 0
			ORDER BY next_attempt LIMIT 1`, c.ID).Scan(&retryAt, &retryErr); err == nil {
			c.LastState, c.NextAttempt, c.LastError = "retrying", retryAt, retryErr
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

// Get returns one channel. For a channel whose settings cannot be
// decrypted it returns the channel and an error wrapping ErrUnreadable.
func (s *Channels) Get(ctx context.Context, id int64) (Channel, error) {
	return s.scan(s.DB.R.QueryRowContext(ctx, "SELECT "+channelCols+" FROM channels WHERE id = ?", id))
}

// Save creates (ID 0) or updates a channel. On update, an empty credential
// (SMTP password, token, webhook URL or secret) keeps the stored value.
func (s *Channels) Save(ctx context.Context, c Channel) (int64, error) {
	if c.ID != 0 {
		// Unreadable settings are replaced by what the admin enters now.
		old, err := s.Get(ctx, c.ID)
		if err != nil && !errors.Is(err, ErrUnreadable) {
			return 0, err
		}
		c.Kind = old.Kind
		c.keepSecrets(old)
	}
	if err := c.Validate(); err != nil {
		return 0, usererr.Wrap(err)
	}
	blob, err := s.seal(c)
	if err != nil {
		return 0, err
	}
	dest := c.destination()
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
		return usererr.New("A channel with this name already exists")
	}
	return err
}
