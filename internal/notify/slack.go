package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
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

// slackEscape escapes the characters Slack's message format reserves, and
// the mentions Mattermost and Rocket.Chat act on in plain text.
func slackEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	return noMentions(strings.ReplaceAll(s, ">", "&gt;"))
}

// mentionRe is an @ at the start of a word followed by a name: a mention
// in chat services that read plain text (@channel, @all, @here, @user).
// An e-mail address has a letter before its @ and is left alone.
var mentionRe = regexp.MustCompile(`(^|[^\pL\pN_.@-])@([\pL\pN_])`)

// noMentions puts a word joiner after every mention's @: the text reads
// the same, but no service pings anyone because a target is named
// "@channel".
func noMentions(s string) string {
	return mentionRe.ReplaceAllString(s, "${1}@\u2060${2}")
}
