package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// NtfySettings configure an ntfy channel: a topic on ntfy.sh or on a
// self-hosted server. They are stored encrypted.
type NtfySettings struct {
	Server string `json:"server"` // default https://ntfy.sh
	Topic  string `json:"topic"`
	Token  string `json:"token"` // optional access token, sent as a bearer token
}

var ntfyTopicRe = regexp.MustCompile(`^[-_A-Za-z0-9]{1,64}$`)

// DefaultNtfyServer is used when no server is given.
const DefaultNtfyServer = "https://ntfy.sh"

func (s NtfySettings) server() string {
	srv := strings.TrimRight(strings.TrimSpace(s.Server), "/")
	if srv == "" {
		return DefaultNtfyServer
	}
	return srv
}

// Validate checks the settings before they are saved.
func (s NtfySettings) Validate() error {
	if _, err := validateURL("ntfy server", s.server()); err != nil {
		return err
	}
	if !ntfyTopicRe.MatchString(s.Topic) {
		return errors.New("topic must be 1 to 64 letters, digits, - or _")
	}
	return nil
}

// Destination is a summary for the channel table.
func (s NtfySettings) Destination() string { return s.server() + "/" + s.Topic }

// NtfySender publishes with ntfy's JSON endpoint.
type NtfySender struct {
	S      NtfySettings
	Client *http.Client
}

// ntfy priorities: 5 urgent, 4 high, 3 default.
var ntfyPriority = map[string]int{"critical": 5, "warning": 4, "info": 3, "resolved": 3}

var ntfyTags = map[string]string{"critical": "rotating_light", "warning": "warning", "info": "information_source", "resolved": "white_check_mark"}

// maxNtfyChars keeps a message under ntfy's default 4096-byte limit.
const maxNtfyChars = 4000

// Send publishes m to the topic.
func (n *NtfySender) Send(ctx context.Context, m Message) error {
	_, err := n.SendRef(ctx, m)
	return err
}

// SendRef publishes m and returns ntfy's message ID.
func (n *NtfySender) SendRef(ctx context.Context, m Message) (string, error) {
	sev := subjectTag(m.Subject)
	body, err := json.Marshal(map[string]any{
		"topic":    n.S.Topic,
		"title":    untagged(m.Subject),
		"message":  truncateRunes(m.Body, maxNtfyChars),
		"priority": ntfyPriority[sev],
		"tags":     []string{ntfyTags[sev]},
	})
	if err != nil {
		return "", err
	}
	headers := map[string]string{}
	if n.S.Token != "" {
		headers["Authorization"] = "Bearer " + n.S.Token
	}
	status, resp, err := httpPost(ctx, n.Client, n.S.server()+"/", "application/json", body, headers)
	if err != nil {
		return "", redactErr(fmt.Errorf("ntfy: %w", err), n.S.Token)
	}
	if status/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(resp, &e)
		if e.Error != "" {
			return "", redactErr(failed(status, fmt.Errorf("ntfy: %d %s", status, e.Error)), n.S.Token)
		}
		return "", redactErr(failed(status, fmt.Errorf("ntfy: %w", statusError(strconv.Itoa(status)+" "+http.StatusText(status), resp))), n.S.Token)
	}
	var r struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(resp, &r)
	return r.ID, nil
}

// truncateRunes cuts s to at most n runes, ending in an ellipsis when it
// had to.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}
