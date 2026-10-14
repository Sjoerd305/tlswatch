package notify

import (
	"context"
	"strings"
	"time"
)

// Message is one notification: a subject line and a plain-text body.
type Message struct {
	Subject string
	Body    string
}

// Sender delivers a message over one transport.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// PartialSender is a Sender with several recipients that are reached one
// by one (Telegram chats). SendSkipping leaves out the recipients in done
// and returns the ones it reached, also when others failed, so a retry
// does not repeat the message to them.
type PartialSender interface {
	Sender
	SendSkipping(ctx context.Context, m Message, done []string) (reached []string, err error)
}

// RetryAfterError is a delivery error from a transport that asked to wait
// before the next attempt (a rate limit).
type RetryAfterError struct {
	Err   error
	After time.Duration
}

func (e *RetryAfterError) Error() string { return e.Err.Error() }
func (e *RetryAfterError) Unwrap() error { return e.Err }

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
