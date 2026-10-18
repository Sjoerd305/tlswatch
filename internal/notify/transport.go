package notify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"
)

// Message is one notification: a subject line and a plain-text body.
type Message struct {
	Subject string
	Body    string // plain text, for every transport
	HTML    string // HTML part for mail; empty sends plain text only
	// Ref identifies this delivery; SMTP sends it as the Message-ID so
	// the relay's logs can be matched with the alert log. Empty: random.
	Ref string
	// Event and FindingID are the alert event (open, escalate, remind,
	// recover, digest, test) and its finding, set when the message is one
	// alert and not a batch: PagerDuty turns them into incident actions.
	Event     string
	FindingID int64
}

// NewRef returns a random delivery reference.
func NewRef() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Sender delivers a message over one transport.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// PartialSender is a Sender with several recipients that are reached one
// by one (Telegram chats). SendSkipping leaves out the recipients in done
// and returns the ones it reached, also when others failed, so a retry
// does not repeat the message to them, with the transport's reference for
// each delivery (for Telegram "chat:message_id").
type PartialSender interface {
	Sender
	SendSkipping(ctx context.Context, m Message, done []string) (reached, refs []string, err error)
}

// RefSender is a Sender that returns the transport's reference for a
// delivery (Discord's or ntfy's message ID, the reference a webhook payload
// carried), to show in the alert log. A plain Sender is logged under the
// SMTP Message-ID form of the message's Ref.
type RefSender interface {
	Sender
	SendRef(ctx context.Context, m Message) (ref string, err error)
}

// RetryAfterError is a delivery error from a transport that asked to wait
// before the next attempt (a rate limit).
type RetryAfterError struct {
	Err   error
	After time.Duration
}

func (e *RetryAfterError) Error() string { return e.Err.Error() }
func (e *RetryAfterError) Unwrap() error { return e.Err }

// PermanentError is a delivery error that a retry will not change, such
// as a recipient the relay refuses for good or a webhook that is gone: the
// alert fails at once.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// PartialRefusal is a temporary failure of a delivery in which some
// recipients were also refused for good. Refused names those with the
// answer, so the alert still says so once a retry reaches the others.
type PartialRefusal struct {
	Refused string
	Err     error
}

func (e *PartialRefusal) Error() string { return e.Err.Error() }
func (e *PartialRefusal) Unwrap() error { return e.Err }

// Redact replaces every non-empty secret in s with "[redacted]".
func Redact(s string, secrets ...string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	return s
}

// redactedError wraps an error so that its message never shows secrets.
type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }

func redactErr(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	return &redactedError{msg: Redact(err.Error(), secrets...), err: err}
}
