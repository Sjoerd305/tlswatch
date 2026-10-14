package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// SMTPSettings configure an SMTP channel. They are stored encrypted.
type SMTPSettings struct {
	Host               string   `json:"host"`
	Port               int      `json:"port"`
	Encryption         string   `json:"encryption"` // "starttls" (default), "tls" (implicit), "none"
	Username           string   `json:"username"`
	Password           string   `json:"password"`
	From               string   `json:"from"`
	Recipients         []string `json:"recipients"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify"`
}

func (s SMTPSettings) encryption() string {
	if s.Encryption == "" {
		return "starttls"
	}
	return s.Encryption
}

// Validate checks the settings before they are saved.
func (s SMTPSettings) Validate() error {
	if strings.TrimSpace(s.Host) == "" {
		return errors.New("SMTP host is required")
	}
	if s.Port < 1 || s.Port > 65535 {
		return errors.New("SMTP port must be between 1 and 65535")
	}
	switch s.encryption() {
	case "starttls", "tls", "none":
	default:
		return fmt.Errorf("unknown encryption %q", s.Encryption)
	}
	if _, err := mail.ParseAddress(s.From); err != nil {
		return fmt.Errorf("from address: %v", err)
	}
	if len(s.Recipients) == 0 {
		return errors.New("at least one recipient is required")
	}
	for _, r := range s.Recipients {
		if _, err := mail.ParseAddress(r); err != nil {
			return fmt.Errorf("recipient %q: %v", r, err)
		}
	}
	if s.Username != "" && s.encryption() == "none" && !isLocalhost(s.Host) {
		return errors.New("authentication without encryption is only allowed to localhost")
	}
	return nil
}

// Destination is a human-readable summary for the channel table.
func (s SMTPSettings) Destination() string {
	return strings.Join(s.Recipients, ", ")
}

func isLocalhost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// SMTPSender delivers messages through an SMTP relay.
type SMTPSender struct {
	S        SMTPSettings
	Timeout  time.Duration
	Hostname string         // EHLO name, default "tlswatch"
	RootCAs  *x509.CertPool // nil: system roots
}

// Send delivers m to every recipient in one transaction.
func (s *SMTPSender) Send(ctx context.Context, m Message) error {
	return redactErr(s.send(ctx, m), s.S.Password)
}

func (s *SMTPSender) send(ctx context.Context, m Message) error {
	if err := s.S.Validate(); err != nil {
		return err
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()

	addr := net.JoinHostPort(s.S.Host, strconv.Itoa(s.S.Port))
	tlsConf := &tls.Config{ServerName: s.S.Host, MinVersion: tls.VersionTLS12, RootCAs: s.RootCAs, InsecureSkipVerify: s.S.InsecureSkipVerify} //nolint:gosec // opt-in per channel

	var conn net.Conn
	var err error
	d := &net.Dialer{}
	if s.S.encryption() == "tls" {
		conn, err = (&tls.Dialer{NetDialer: d, Config: tlsConf}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect to %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	c, err := smtp.NewClient(conn, s.S.Host)
	if err != nil {
		return fmt.Errorf("smtp greeting: %w", err)
	}
	defer c.Close()
	hostname := s.Hostname
	if hostname == "" {
		hostname = "tlswatch"
	}
	if err := c.Hello(hostname); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}
	secure := s.S.encryption() == "tls"
	if s.S.encryption() == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("server does not offer STARTTLS")
		}
		if err := c.StartTLS(tlsConf); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
		secure = true
	}
	if s.S.Username != "" {
		if !secure && !isLocalhost(s.S.Host) {
			return errors.New("refusing to send credentials over an unencrypted connection")
		}
		ok, mechs := c.Extension("AUTH")
		if !ok {
			return errors.New("server does not offer AUTH")
		}
		var a smtp.Auth
		upper := " " + strings.ToUpper(mechs) + " "
		switch {
		case strings.Contains(upper, " PLAIN "):
			a = &plainAuth{user: s.S.Username, pass: s.S.Password}
		case strings.Contains(upper, " LOGIN "):
			a = &loginAuth{user: s.S.Username, pass: s.S.Password}
		default:
			return fmt.Errorf("no supported AUTH mechanism (server offers %s)", mechs)
		}
		if err := c.Auth(a); err != nil {
			return fmt.Errorf("authentication: %w", err)
		}
	}
	from, _ := mail.ParseAddress(s.S.From)
	if err := c.Mail(from.Address); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	var to []string
	for _, r := range s.S.Recipients {
		a, _ := mail.ParseAddress(r)
		if err := c.Rcpt(a.Address); err != nil {
			return fmt.Errorf("RCPT TO %s: %w", a.Address, err)
		}
		to = append(to, a.String())
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(buildMessage(from.String(), to, m, time.Now())); err != nil {
		return fmt.Errorf("write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("end of data: %w", err)
	}
	return c.Quit()
}

// MessageID is the Message-ID header value for a delivery reference.
func MessageID(ref string) string { return "<" + ref + "@tlswatch>" }

func buildMessage(from string, to []string, m Message, now time.Time) []byte {
	ref := m.Ref
	if ref == "" {
		ref = NewRef()
	}
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", from)
	h("To", strings.Join(to, ", "))
	h("Subject", mime.QEncoding.Encode("utf-8", strings.NewReplacer("\r", " ", "\n", " ").Replace(m.Subject)))
	h("Date", now.Format(time.RFC1123Z))
	h("Message-ID", MessageID(ref))
	h("MIME-Version", "1.0")
	h("Content-Type", "text/plain; charset=utf-8")
	h("Content-Transfer-Encoding", "quoted-printable")
	h("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	body := strings.ReplaceAll(strings.ReplaceAll(m.Body, "\r\n", "\n"), "\n", "\r\n")
	_, _ = qp.Write([]byte(body))
	_ = qp.Close()
	return b.Bytes()
}

// plainAuth is PLAIN without net/smtp's TLS check; Send only uses it on an
// encrypted connection or to localhost.
type plainAuth struct{ user, pass string }

func (a *plainAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.pass), nil
}

func (a *plainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}

type loginAuth struct{ user, pass string }

func (a *loginAuth) Start(*smtp.ServerInfo) (string, []byte, error) { return "LOGIN", nil, nil }

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(fromServer))) {
	case "username:", "user name", "username":
		return []byte(a.user), nil
	case "password:", "password":
		return []byte(a.pass), nil
	}
	return nil, fmt.Errorf("unexpected LOGIN challenge %q", fromServer)
}
