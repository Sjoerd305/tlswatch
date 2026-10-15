package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// DiscordSettings configure a Discord channel through a webhook. The URL is
// the credential; it is stored encrypted and never shown back.
type DiscordSettings struct {
	WebhookURL string `json:"webhook_url"`
}

// Validate checks the settings before they are saved.
func (s DiscordSettings) Validate() error {
	_, err := validateURL("Webhook URL", s.WebhookURL)
	return err
}

// Destination is a summary for the channel table: the host only, since
// the path is the secret.
func (s DiscordSettings) Destination() string { return hostOf(s.WebhookURL) }

// DiscordSender posts messages to a webhook.
type DiscordSender struct {
	S      DiscordSettings
	Client *http.Client
}

// maxDiscordChars is Discord's limit on a message.
const maxDiscordChars = 2000

// Send posts m as one message.
func (d *DiscordSender) Send(ctx context.Context, m Message) error {
	_, err := d.SendRef(ctx, m)
	return err
}

// SendRef posts m and returns Discord's message ID.
func (d *DiscordSender) SendRef(ctx context.Context, m Message) (string, error) {
	text := truncateRunes(m.Subject+"\n\n"+strings.TrimRight(m.Body, "\n"), maxDiscordChars)
	body, err := json.Marshal(map[string]string{"content": text})
	if err != nil {
		return "", err
	}
	// wait=true makes Discord answer with the message it created.
	u, err := url.Parse(d.S.WebhookURL)
	if err != nil {
		return "", d.redact(fmt.Errorf("discord: %w", err))
	}
	q := u.Query()
	q.Set("wait", "true")
	u.RawQuery = q.Encode()
	status, resp, err := httpPost(ctx, d.Client, u.String(), "application/json", body, nil)
	if err != nil {
		return "", d.redact(fmt.Errorf("discord: %w", err))
	}
	if status/100 != 2 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(resp, &e)
		if e.Message != "" {
			return "", d.redact(fmt.Errorf("discord: %d %s", status, e.Message))
		}
		return "", d.redact(fmt.Errorf("discord: %w", statusError(strconv.Itoa(status)+" "+http.StatusText(status), resp)))
	}
	var r struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(resp, &r)
	return r.ID, nil
}

func (d *DiscordSender) redact(err error) error {
	return redactErr(err, d.S.WebhookURL, url.PathEscape(d.S.WebhookURL), secretPath(d.S.WebhookURL))
}
