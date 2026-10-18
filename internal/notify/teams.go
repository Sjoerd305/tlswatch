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

// TeamsSettings configure a Microsoft Teams channel through a Workflows
// (Power Automate) webhook, the "Post to a channel when a webhook request
// is received" template. The URL carries its signature, so it is the
// credential; it is stored encrypted and never shown back.
type TeamsSettings struct {
	WebhookURL string `json:"webhook_url"`
}

// Validate checks the settings before they are saved.
func (s TeamsSettings) Validate() error {
	_, err := validateURL("Workflow URL", s.WebhookURL)
	return err
}

// Destination is a summary for the channel table: the host only.
func (s TeamsSettings) Destination() string { return hostOf(s.WebhookURL) }

// teamsMaxText bounds the text of a card; Teams refuses a message of
// about 28 KB.
const teamsMaxText = 20000

// TeamsSender posts messages as an Adaptive Card.
type TeamsSender struct {
	S      TeamsSettings
	Client *http.Client
}

// Send posts m as a card: the subject as its title, coloured by severity,
// and the body one text block per line, since a card's text block folds
// single line breaks.
func (s *TeamsSender) Send(ctx context.Context, m Message) error {
	color := map[string]string{"critical": "Attention", "warning": "Warning", "resolved": "Good"}[subjectTag(m.Subject)]
	if color == "" {
		color = "Default"
	}
	blocks := []map[string]any{{"type": "TextBlock", "text": m.Subject, "weight": "Bolder", "size": "Medium", "wrap": true, "color": color}}
	text := strings.TrimRight(m.Body, "\n")
	if len(text) > teamsMaxText {
		text = text[:teamsMaxText] + "\n…"
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		blocks = append(blocks, map[string]any{"type": "TextBlock", "text": line, "wrap": true, "spacing": "None"})
	}
	card := map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]any{
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard", "version": "1.4", "body": blocks,
			},
		}},
	}
	body, err := json.Marshal(card)
	if err != nil {
		return err
	}
	status, resp, err := httpPost(ctx, s.Client, s.S.WebhookURL, "application/json", body, nil)
	if err != nil {
		return s.redact(fmt.Errorf("teams: %w", err))
	}
	if status/100 != 2 {
		return s.redact(failed(status, fmt.Errorf("teams: %w", statusError(strconv.Itoa(status)+" "+http.StatusText(status), resp))))
	}
	return nil
}

func (s *TeamsSender) redact(err error) error {
	u, _ := url.Parse(s.S.WebhookURL)
	q := ""
	if u != nil {
		q = u.RawQuery
	}
	return redactErr(err, s.S.WebhookURL, url.PathEscape(s.S.WebhookURL), secretPath(s.S.WebhookURL), q)
}
