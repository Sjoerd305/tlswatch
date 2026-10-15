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

// SlackSettings configure a Slack channel through an incoming webhook.
// Mattermost and Rocket.Chat incoming webhooks take the same message. The
// URL is the credential; it is stored encrypted and never shown back.
type SlackSettings struct {
	WebhookURL string `json:"webhook_url"`
}

// Validate checks the settings before they are saved.
func (s SlackSettings) Validate() error {
	_, err := validateURL("Webhook URL", s.WebhookURL)
	return err
}

// Destination is a summary for the channel table: the host only, since
// the path is the secret.
func (s SlackSettings) Destination() string { return hostOf(s.WebhookURL) }

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// SlackSender posts messages to an incoming webhook.
type SlackSender struct {
	S      SlackSettings
	Client *http.Client
}

// Send posts m as one text message: the subject, a blank line, the body.
func (s *SlackSender) Send(ctx context.Context, m Message) error {
	text := slackEscape(m.Subject + "\n\n" + strings.TrimRight(m.Body, "\n"))
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return err
	}
	status, resp, err := httpPost(ctx, s.Client, s.WebhookURL(), "application/json", body, nil)
	if err != nil {
		return s.redact(fmt.Errorf("slack: %w", err))
	}
	if status/100 != 2 {
		return s.redact(fmt.Errorf("slack: %w", statusError(strconv.Itoa(status)+" "+http.StatusText(status), resp)))
	}
	return nil
}

// WebhookURL is the URL posted to.
func (s *SlackSender) WebhookURL() string { return s.S.WebhookURL }

func (s *SlackSender) redact(err error) error {
	return redactErr(err, s.S.WebhookURL, url.PathEscape(s.S.WebhookURL), secretPath(s.S.WebhookURL))
}

// secretPath is the path of a webhook URL, the part that is the credential,
// so an error that quotes only the path is redacted too.
func secretPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || len(u.Path) < 8 {
		return ""
	}
	return u.Path
}

// slackEscape escapes the characters Slack's message format reserves.
func slackEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	return strings.ReplaceAll(s, ">", "&gt;")
}
