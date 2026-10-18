package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

// PagerDutySettings configure a PagerDuty channel through the Events API
// v2: the integration (routing) key of a service, stored encrypted, and
// the region of the account.
type PagerDutySettings struct {
	RoutingKey string `json:"routing_key"`
	Region     string `json:"region"` // "us" (default) or "eu"
}

// Validate checks the settings before they are saved.
func (s PagerDutySettings) Validate() error {
	if len(strings.TrimSpace(s.RoutingKey)) != 32 {
		return errors.New("Integration key must be the 32 characters of an Events API v2 integration")
	}
	switch s.Region {
	case "", "us", "eu":
	default:
		return errors.New("Region must be US or EU")
	}
	return nil
}

// Destination is a summary for the channel table.
func (s PagerDutySettings) Destination() string { return s.endpoint() }

func (s PagerDutySettings) endpoint() string {
	if s.Region == "eu" {
		return "https://events.eu.pagerduty.com/v2/enqueue"
	}
	return "https://events.pagerduty.com/v2/enqueue"
}

// PagerDutySender sends one event per alert: open, escalate and remind
// trigger the incident of the finding, recover resolves it. The finding ID
// is the dedup key, so a finding is one incident however often it is
// alerted. Acknowledging in PagerDuty does not reach tlswatch.
type PagerDutySender struct {
	S      PagerDutySettings
	Client *http.Client
	// Endpoint overrides the Events API URL, for tests.
	Endpoint string
}

// DedupKey is the PagerDuty dedup key of a finding.
func DedupKey(findingID int64) string { return "tlswatch-finding-" + strconv.FormatInt(findingID, 10) }

// Send sends m.
func (s *PagerDutySender) Send(ctx context.Context, m Message) error {
	_, err := s.SendRef(ctx, m)
	return err
}

// SendRef sends the event m stands for and returns its dedup key. A test
// message triggers an incident of its own and resolves it at once.
func (s *PagerDutySender) SendRef(ctx context.Context, m Message) (string, error) {
	switch {
	case m.Event == EventDigest:
		return "", &PermanentError{Err: errors.New("pagerduty: a digest is not an incident; send the digest to another channel")}
	case m.FindingID != 0 && m.Event == EventRecover:
		return s.event(ctx, "resolve", DedupKey(m.FindingID), m)
	case m.FindingID != 0:
		return s.event(ctx, "trigger", DedupKey(m.FindingID), m)
	}
	key := "tlswatch-test-" + m.Ref
	if m.Ref == "" {
		key = "tlswatch-test-" + NewRef()
	}
	if _, err := s.event(ctx, "trigger", key, m); err != nil {
		return "", err
	}
	return s.event(ctx, "resolve", key, m)
}

func (s *PagerDutySender) event(ctx context.Context, action, key string, m Message) (string, error) {
	ev := map[string]any{"routing_key": s.S.RoutingKey, "event_action": action, "dedup_key": key}
	if action == "trigger" {
		sev := subjectTag(m.Subject)
		if sev != "critical" && sev != "warning" {
			sev = "info"
		}
		ev["client"] = "tlswatch"
		ev["payload"] = map[string]any{
			"summary": clipRunes(untagged(m.Subject), 1024), "source": "tlswatch", "severity": sev,
			"custom_details": map[string]string{"details": strings.TrimRight(m.Body, "\n")},
		}
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return "", err
	}
	u := s.Endpoint
	if u == "" {
		u = s.S.endpoint()
	}
	status, resp, err := httpPost(ctx, s.Client, u, "application/json", body, nil)
	if err != nil {
		return "", redactErr(fmt.Errorf("pagerduty: %w", err), s.S.RoutingKey)
	}
	if status/100 != 2 {
		return "", redactErr(failed(status, fmt.Errorf("pagerduty: %w", statusError(strconv.Itoa(status)+" "+http.StatusText(status), resp))), s.S.RoutingKey)
	}
	return key, nil
}

// clipRunes cuts s to at most n characters.
func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
