package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// MatrixSettings configure a Matrix channel through the client-server
// API: the homeserver, a room the account has joined, and the account's
// access token, which is stored encrypted and never shown back.
type MatrixSettings struct {
	Homeserver string `json:"homeserver"`
	RoomID     string `json:"room_id"`
	Token      string `json:"token"`
}

// Validate checks the settings before they are saved.
func (s MatrixSettings) Validate() error {
	if _, err := validateURL("Homeserver", s.Homeserver); err != nil {
		return err
	}
	if !strings.HasPrefix(s.RoomID, "!") || !strings.Contains(s.RoomID, ":") {
		return errors.New("Room ID must look like !abc123:example.org (Room settings › Advanced); an alias (#room:server) will not do")
	}
	if strings.TrimSpace(s.Token) == "" {
		return errors.New("Access token is required")
	}
	return nil
}

// Destination is a summary for the channel table: the room on its server.
func (s MatrixSettings) Destination() string { return s.RoomID }

// MatrixSender sends messages as notices into a room.
type MatrixSender struct {
	S      MatrixSettings
	Client *http.Client
}

// Send sends m.
func (s *MatrixSender) Send(ctx context.Context, m Message) error {
	_, err := s.SendRef(ctx, m)
	return err
}

// SendRef sends m as an m.notice, which clients show without a sound and
// bots do not answer, and returns the event ID. The transaction ID is the
// message's reference, so a retry of a send whose answer was lost is the
// same event, not a second one.
func (s *MatrixSender) SendRef(ctx context.Context, m Message) (string, error) {
	text := noMentions(m.Subject + "\n\n" + strings.TrimRight(m.Body, "\n"))
	formatted := "<strong>" + html.EscapeString(noMentions(m.Subject)) + "</strong><br><br>" +
		strings.ReplaceAll(html.EscapeString(noMentions(strings.TrimRight(m.Body, "\n"))), "\n", "<br>")
	body, err := json.Marshal(map[string]string{"msgtype": "m.notice", "body": text, "format": "org.matrix.custom.html", "formatted_body": formatted})
	if err != nil {
		return "", err
	}
	txn := m.Ref
	if txn == "" {
		txn = NewRef()
	}
	u := strings.TrimRight(s.S.Homeserver, "/") + "/_matrix/client/v3/rooms/" + url.PathEscape(s.S.RoomID) + "/send/m.room.message/" + url.PathEscape(txn)
	status, resp, err := httpSend(ctx, s.Client, http.MethodPut, u, "application/json", body, map[string]string{"Authorization": "Bearer " + s.S.Token})
	if err != nil {
		return "", redactErr(fmt.Errorf("matrix: %w", err), s.S.Token)
	}
	if status/100 != 2 {
		return "", redactErr(failed(status, fmt.Errorf("matrix: %w", statusError(strconv.Itoa(status)+" "+http.StatusText(status), resp))), s.S.Token)
	}
	var out struct {
		EventID string `json:"event_id"`
	}
	_ = json.Unmarshal(resp, &out)
	return out.EventID, nil
}
