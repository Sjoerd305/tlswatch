package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// WebhookSettings configure a generic webhook channel: tlswatch posts a
// JSON document to the URL. They are stored encrypted.
type WebhookSettings struct {
	URL string `json:"url"`
	// Secret, when set, signs every request: X-TLSWatch-Signature carries
	// "sha256=" and the hex HMAC-SHA256 of the body under it.
	Secret string `json:"secret"`
}

// Validate checks the settings before they are saved.
func (s WebhookSettings) Validate() error {
	_, err := validateURL("Webhook URL", s.URL)
	return err
}

// Destination is a summary for the channel table: the URL without its
// query, which may carry a token.
func (s WebhookSettings) Destination() string {
	u, err := url.Parse(s.URL)
	if err != nil {
		return ""
	}
	u.RawQuery, u.Fragment, u.User = "", "", nil
	return u.String()
}

// WebhookPayload is the JSON document a webhook channel posts.
type WebhookPayload struct {
	Source   string `json:"source"`   // "tlswatch"
	Ref      string `json:"ref"`      // the delivery reference in the alert log
	Severity string `json:"severity"` // critical, warning, info or resolved
	Subject  string `json:"subject"`  // without the severity tag
	Text     string `json:"text"`     // the plain-text body
	SentAt   string `json:"sent_at"`  // RFC 3339
}

// WebhookSender posts messages as JSON.
type WebhookSender struct {
	S      WebhookSettings
	Client *http.Client
	Now    func() time.Time
}

// Send posts m to the URL.
func (w *WebhookSender) Send(ctx context.Context, m Message) error {
	_, err := w.SendRef(ctx, m)
	return err
}

// SendRef posts m and returns the reference the payload carried.
func (w *WebhookSender) SendRef(ctx context.Context, m Message) (string, error) {
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	ref := m.Ref
	if ref == "" {
		ref = NewRef()
	}
	body, err := json.Marshal(WebhookPayload{Source: "tlswatch", Ref: ref, Severity: subjectTag(m.Subject), Subject: untagged(m.Subject), Text: m.Body, SentAt: now().UTC().Format(time.RFC3339)})
	if err != nil {
		return "", err
	}
	headers := map[string]string{"X-TLSWatch-Ref": ref, "X-TLSWatch-Severity": subjectTag(m.Subject)}
	if w.S.Secret != "" {
		headers["X-TLSWatch-Signature"] = "sha256=" + Sign(w.S.Secret, body)
	}
	status, resp, err := httpPost(ctx, w.Client, w.S.URL, "application/json", body, headers)
	if err != nil {
		return "", redactErr(fmt.Errorf("webhook: %w", err), w.S.Secret)
	}
	if status/100 != 2 {
		return "", redactErr(failed(status, fmt.Errorf("webhook: %w", statusError(strconv.Itoa(status)+" "+http.StatusText(status), resp))), w.S.Secret)
	}
	return ref, nil
}

// Sign returns the hex HMAC-SHA256 of body under secret, as the signature
// header carries it.
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks a signature header against body, for receivers
// written in Go and for the tests.
func VerifySignature(secret string, body []byte, header string) error {
	want := "sha256=" + Sign(secret, body)
	if !hmac.Equal([]byte(want), []byte(header)) {
		return errors.New("signature mismatch")
	}
	return nil
}
