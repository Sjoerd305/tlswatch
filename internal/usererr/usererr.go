// Package usererr marks errors whose message is meant for the user: a rule
// the input broke, not a fault. The web layer shows their message and logs
// every other error as a server error.
package usererr

import (
	"errors"
	"unicode"
	"unicode/utf8"
)

// Error is an error for the user.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// New returns an error for the user.
func New(msg string) error { return &Error{msg} }

// Wrap turns err into an error for the user, its message starting with a
// capital; nil stays nil.
func Wrap(err error) error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return err
	}
	msg := err.Error()
	r, n := utf8.DecodeRuneInString(msg)
	return &Error{string(unicode.ToUpper(r)) + msg[n:]}
}

// Message returns the message of an error for the user anywhere in err's
// chain.
func Message(err error) (string, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Msg, true
	}
	return "", false
}
