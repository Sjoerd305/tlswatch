package notify

import (
	"context"
	"strings"
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
