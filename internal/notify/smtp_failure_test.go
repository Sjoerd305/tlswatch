package notify

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptedSMTP is a relay whose replies a test chooses. reply maps a
// command prefix (upper case: "EHLO", "AUTH", "MAIL", "RCPT", "DATA",
// "END" for the end of data, "QUIT") to the reply; "" leaves the default.
// "RCPT " plus an upper-case address answers for that recipient only.
// For "QUIT" the reply "close" hangs up without answering. greet is the
// greeting ("" for 220). afterTLS lists the EHLO lines offered once the
// session is encrypted, before is the list offered before.
type scriptedSMTP struct {
	greet          string
	before, after  []string
	reply          map[string]string
	silent         bool // accept and never say a word
	mu             sync.Mutex
	commands       []string
	data           string
	sawAuthInClear bool
}

func (s *scriptedSMTP) serve(t *testing.T, cert tls.Certificate) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	conf := &tls.Config{Certificates: []tls.Certificate{cert}}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if s.silent {
			_, _ = conn.Read(make([]byte, 1))
			return
		}
		secure := false
		r := bufio.NewReader(conn)
		w := func(l string) { _, _ = conn.Write([]byte(l + "\r\n")) }
		rep := func(cmd, def string) string {
			if v, ok := s.reply[cmd]; ok && v != "" {
				return v
			}
			return def
		}
		greet := s.greet
		if greet == "" {
			greet = "220 relay ESMTP"
		}
		w(greet)
		if !strings.HasPrefix(greet, "220") {
			return
		}
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			cmd := strings.ToUpper(line)
			s.mu.Lock()
			s.commands = append(s.commands, line)
			if strings.HasPrefix(cmd, "AUTH") && !secure {
				s.sawAuthInClear = true
			}
			s.mu.Unlock()
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				ext := s.before
				if secure {
					ext = s.after
				}
				w("250-relay")
				for _, e := range ext {
					w("250-" + e)
				}
				w("250 8BITMIME")
			case cmd == "STARTTLS":
				w("220 go ahead")
				tc := tls.Server(conn, conf)
				if err := tc.Handshake(); err != nil {
					return
				}
				conn, r, secure = tc, bufio.NewReader(tc), true
			case strings.HasPrefix(cmd, "AUTH PLAIN"):
				w(rep("AUTH", "235 ok"))
			case strings.HasPrefix(cmd, "MAIL FROM:"):
				w(rep("MAIL", "250 ok"))
			case strings.HasPrefix(cmd, "RCPT TO:"):
				addr := strings.Trim(strings.TrimPrefix(cmd, "RCPT TO:"), "<> ")
				w(rep("RCPT "+strings.ToUpper(addr), rep("RCPT", "250 ok")))
			case cmd == "DATA":
				d := rep("DATA", "354 go")
				w(d)
				if !strings.HasPrefix(d, "354") {
					continue
				}
				var b strings.Builder
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					b.WriteString(l)
				}
				s.mu.Lock()
				s.data = b.String()
				s.mu.Unlock()
				w(rep("END", "250 queued as 4711"))
			case cmd == "RSET":
				w("250 ok")
			case cmd == "QUIT":
				if rep("QUIT", "") == "close" {
					return
				}
				w("221 bye")
				return
			default:
				w("502 unknown")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func (s *scriptedSMTP) sent(cmd string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.commands {
		if strings.HasPrefix(strings.ToUpper(c), cmd) {
			return true
		}
	}
	return false
}

// STARTTLS is required: a relay that does not offer it never sees the
// credentials, not even an AUTH command.
func TestSMTPStartTLSMissingNeverSendsCredentials(t *testing.T) {
	cert, _ := testCert(t)
	srv := &scriptedSMTP{before: []string{"AUTH PLAIN LOGIN"}}
	s := settings(srv.serve(t, cert), "starttls")
	s.Username, s.Password = "user", "hunter2-secret"
	err := (&SMTPSender{S: s, Timeout: 5 * time.Second}).Send(context.Background(), Message{Subject: "s", Body: "b"})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("got %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if srv.sent("AUTH") || srv.sent("MAIL") {
		t.Fatalf("commands sent without STARTTLS: %q", srv.commands)
	}
}

// Relays commonly offer AUTH only after STARTTLS; the sender reads the
// extensions again on the encrypted session.
func TestSMTPAuthOfferedOnlyAfterStartTLS(t *testing.T) {
	cert, pool := testCert(t)
	srv := &scriptedSMTP{before: []string{"STARTTLS"}, after: []string{"AUTH PLAIN"}}
	s := settings(srv.serve(t, cert), "starttls")
	s.Username, s.Password = "user", "pw"
	if err := (&SMTPSender{S: s, RootCAs: pool, Timeout: 5 * time.Second}).Send(context.Background(), Message{Subject: "s", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	if srv.sawAuthInClear || !srv.sent("AUTH PLAIN") {
		t.Fatalf("auth in clear %v, commands %q", srv.sawAuthInClear, srv.commands)
	}
}

// A rejected login is a failed delivery that names the cause and does not
// carry the password; nothing is submitted.
func TestSMTPAuthFailure(t *testing.T) {
	cert, pool := testCert(t)
	srv := &scriptedSMTP{before: []string{"STARTTLS"}, after: []string{"AUTH PLAIN"},
		reply: map[string]string{"AUTH": "535 5.7.8 Authentication credentials invalid"}}
	s := settings(srv.serve(t, cert), "starttls")
	s.Username, s.Password = "user", "Credentials-Pw"
	err := (&SMTPSender{S: s, RootCAs: pool, Timeout: 5 * time.Second}).Send(context.Background(), Message{Subject: "s", Body: "b"})
	if err == nil || !strings.Contains(err.Error(), "535") || !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "Credentials-Pw") {
		t.Fatalf("password in the error: %v", err)
	}
	if srv.sent("MAIL") {
		t.Fatal("submitted after a failed login")
	}
}

// Temporary (4xx) and permanent (5xx) refusals at every step are errors
// that keep the relay's reply, so the alert log says why.
func TestSMTPRefusals(t *testing.T) {
	cert, _ := testCert(t)
	cases := map[string]struct {
		srv  *scriptedSMTP
		want string
	}{
		"greeting":    {&scriptedSMTP{greet: "554 5.7.1 no thanks"}, "554"},
		"mail from":   {&scriptedSMTP{reply: map[string]string{"MAIL": "451 4.3.0 try later"}}, "451"},
		"rcpt":        {&scriptedSMTP{reply: map[string]string{"RCPT": "550 5.1.1 no such user"}}, "550"},
		"data":        {&scriptedSMTP{reply: map[string]string{"DATA": "452 4.3.1 insufficient storage"}}, "452"},
		"end of data": {&scriptedSMTP{reply: map[string]string{"END": "554 5.7.1 spam"}}, "554"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			snd := &SMTPSender{S: settings(c.srv.serve(t, cert), "none"), Timeout: 5 * time.Second}
			err := snd.Send(context.Background(), Message{Subject: "s", Body: "b"})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want the %s reply", err, c.want)
			}
		})
	}
}

// A relay that accepts the connection and never answers does not hold the
// delivery longer than the timeout.
func TestSMTPSilentRelayTimesOut(t *testing.T) {
	cert, _ := testCert(t)
	srv := &scriptedSMTP{silent: true}
	snd := &SMTPSender{S: settings(srv.serve(t, cert), "none"), Timeout: 300 * time.Millisecond}
	start := time.Now()
	if err := snd.Send(context.Background(), Message{Subject: "s"}); err == nil {
		t.Fatal("no error from a silent relay")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %v with a 300 ms timeout", d)
	}
}

// Once the relay has accepted the message (250 after the data), the
// delivery succeeded: a relay that then drops the connection instead of
// answering QUIT must not make the outbox send the mail again.
func TestSMTPAcceptedThenDroppedIsDelivered(t *testing.T) {
	cert, _ := testCert(t)
	srv := &scriptedSMTP{reply: map[string]string{"QUIT": "close"}}
	snd := &SMTPSender{S: settings(srv.serve(t, cert), "none"), Timeout: 5 * time.Second}
	if err := snd.Send(context.Background(), Message{Subject: "s", Body: "b"}); err != nil {
		t.Fatalf("message accepted by the relay reported as failed (it would be sent again): %v", err)
	}
}

// A body line that is a lone dot does not end the message early.
func TestSMTPDotStuffing(t *testing.T) {
	cert, _ := testCert(t)
	srv := &scriptedSMTP{}
	snd := &SMTPSender{S: settings(srv.serve(t, cert), "none"), Timeout: 5 * time.Second}
	if err := snd.Send(context.Background(), Message{Subject: "s", Body: "before\n.\nafter the dot"}); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !strings.Contains(srv.data, "after the dot") {
		t.Fatalf("message cut at a lone dot:\n%s", srv.data)
	}
}

// A subject cannot add header lines, and the longest non-ASCII subject a
// node name allows (80 bytes) is encoded in words of at most 75 characters
// on lines a relay accepts.
func TestBuildMessageHeaders(t *testing.T) {
	m := Message{Subject: "[critical] evil.example:443\r\nBcc: victim@example.org\nX-Injected: 1", Body: "b"}
	raw := string(buildMessage("a@example.nl", []string{"b@example.nl"}, m, time.Now()))
	head := raw[:strings.Index(raw, "\r\n\r\n")]
	for _, l := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(l, "Bcc:") || strings.HasPrefix(l, "X-Injected:") {
			t.Fatalf("header injected through the subject: %q", l)
		}
	}

	long := "[critical] node " + strings.Repeat("ü", 40) + " offline, still open since 19 Oct"
	raw = string(buildMessage("a@example.nl", []string{"b@example.nl"}, Message{Subject: long, Body: "b"}, time.Now()))
	head = raw[:strings.Index(raw, "\r\n\r\n")]
	var subject string
	for _, l := range strings.Split(head, "\r\n") {
		if len(l) > 998 {
			t.Fatalf("header line of %d characters", len(l))
		}
		if strings.HasPrefix(l, "Subject: ") || strings.HasPrefix(l, " ") && subject != "" {
			subject += strings.TrimPrefix(l, "Subject: ")
		}
	}
	for _, w := range strings.Fields(subject) {
		if strings.HasPrefix(w, "=?") && len(w) > 75 {
			t.Fatalf("encoded word of %d characters", len(w))
		}
	}
}

// The relay judges each recipient: the mail goes to the ones it accepts,
// a 5xx refusal is permanent and a 4xx one is retried for that recipient
// alone.
func TestSMTPPerRecipient(t *testing.T) {
	cert, _ := testCert(t)
	two := func(port int) SMTPSettings {
		st := settings(port, "none")
		st.Recipients = []string{"ops@example.nl", "gone@example.nl"}
		return st
	}

	srv := &scriptedSMTP{reply: map[string]string{"RCPT GONE@EXAMPLE.NL": "550 5.1.1 no such user"}}
	snd := &SMTPSender{S: two(srv.serve(t, cert)), Timeout: 5 * time.Second}
	reached, _, err := snd.SendSkipping(context.Background(), Message{Subject: "s", Body: "b"}, nil)
	var perm *PermanentError
	if !errors.As(err, &perm) || !strings.Contains(err.Error(), "gone@example.nl") {
		t.Fatalf("permanent refusal: %v", err)
	}
	srv.mu.Lock()
	data := srv.data
	srv.mu.Unlock()
	if !strings.Contains(data, "Subject: s") || len(reached) != 2 {
		t.Fatalf("mail to the accepted recipient: reached %v, data %q", reached, data)
	}

	srv = &scriptedSMTP{reply: map[string]string{"RCPT GONE@EXAMPLE.NL": "452 4.2.2 mailbox full"}}
	snd = &SMTPSender{S: two(srv.serve(t, cert)), Timeout: 5 * time.Second}
	reached, _, err = snd.SendSkipping(context.Background(), Message{Subject: "s", Body: "b"}, nil)
	if err == nil || errors.As(err, &perm) || !slices.Equal(reached, []string{"ops@example.nl"}) {
		t.Fatalf("temporary refusal: reached %v, %v", reached, err)
	}

	// One refused for good, one for now: the permanent one is named apart.
	srv = &scriptedSMTP{reply: map[string]string{"RCPT GONE@EXAMPLE.NL": "550 5.1.1 no such user", "RCPT FULL@EXAMPLE.NL": "452 4.2.2 mailbox full"}}
	three := two(srv.serve(t, cert))
	three.Recipients = append(three.Recipients, "full@example.nl")
	_, _, err = (&SMTPSender{S: three, Timeout: 5 * time.Second}).SendSkipping(context.Background(), Message{Subject: "s", Body: "b"}, nil)
	var pr *PartialRefusal
	if !errors.As(err, &pr) || errors.As(err, &perm) || !strings.Contains(pr.Refused, "gone@example.nl") || strings.Contains(pr.Refused, "full@") {
		t.Fatalf("mixed refusals: %v", err)
	}
	srv = &scriptedSMTP{}
	snd = &SMTPSender{S: two(srv.serve(t, cert)), Timeout: 5 * time.Second}
	if _, _, err := snd.SendSkipping(context.Background(), Message{Subject: "s", Body: "b"}, reached); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if strings.Contains(strings.Join(srv.commands, "\n"), "ops@example.nl") {
		t.Fatalf("retry repeated the recipient already reached: %v", srv.commands)
	}
}

// Permanent refusals of the whole message, and authentication, are not
// retried.
func TestSMTPPermanentReplies(t *testing.T) {
	cert, _ := testCert(t)
	for name, c := range map[string]struct {
		srv       *scriptedSMTP
		permanent bool
	}{
		"mail from 550":   {&scriptedSMTP{reply: map[string]string{"MAIL": "550 5.7.1 sender refused"}}, true},
		"mail from 451":   {&scriptedSMTP{reply: map[string]string{"MAIL": "451 4.3.0 try later"}}, false},
		"end of data 554": {&scriptedSMTP{reply: map[string]string{"END": "554 5.7.1 spam"}}, true},
		"data 452":        {&scriptedSMTP{reply: map[string]string{"DATA": "452 4.3.1 insufficient storage"}}, false},
	} {
		snd := &SMTPSender{S: settings(c.srv.serve(t, cert), "none"), Timeout: 5 * time.Second}
		err := snd.Send(context.Background(), Message{Subject: "s", Body: "b"})
		var perm *PermanentError
		if err == nil || errors.As(err, &perm) != c.permanent {
			t.Errorf("%s: %v, permanent %v", name, err, errors.As(err, &perm))
		}
	}
}
