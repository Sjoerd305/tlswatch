package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"mime"
	"net"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

type captured struct {
	from, auth string
	rcpt       []string
	data       string
	tls        bool
}

// fakeSMTP serves one session. mode: "starttls", "tls" or "none"; mechs is
// the AUTH line ("" for none).
func fakeSMTP(t *testing.T, mode, mechs string, cert tls.Certificate) (int, <-chan captured) {
	t.Helper()
	conf := &tls.Config{Certificates: []tls.Certificate{cert}}
	var ln net.Listener
	var err error
	if mode == "tls" {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", conf)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	out := make(chan captured, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var c captured
		c.tls = mode == "tls"
		r := bufio.NewReader(conn)
		w := func(s string) { conn.Write([]byte(s + "\r\n")) }
		w("220 fake ESMTP")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				out <- c
				return
			}
			line = strings.TrimRight(line, "\r\n")
			cmd := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				w("250-fake")
				if mode == "starttls" && !c.tls {
					w("250-STARTTLS")
				}
				if mechs != "" {
					w("250-AUTH " + mechs)
				}
				w("250 8BITMIME")
			case cmd == "STARTTLS":
				w("220 go ahead")
				tc := tls.Server(conn, conf)
				if err := tc.Handshake(); err != nil {
					out <- c
					return
				}
				conn = tc
				r = bufio.NewReader(tc)
				c.tls = true
			case strings.HasPrefix(cmd, "AUTH PLAIN"):
				raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("AUTH PLAIN"):]))
				c.auth = "PLAIN:" + string(raw)
				w("235 ok")
			case strings.HasPrefix(cmd, "AUTH LOGIN"):
				w("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
				u, _ := r.ReadString('\n')
				w("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
				p, _ := r.ReadString('\n')
				ub, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(u))
				pb, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
				c.auth = "LOGIN:" + string(ub) + ":" + string(pb)
				w("235 ok")
			case strings.HasPrefix(cmd, "MAIL FROM:"):
				c.from = line[10:]
				w("250 ok")
			case strings.HasPrefix(cmd, "RCPT TO:"):
				c.rcpt = append(c.rcpt, line[8:])
				w("250 ok")
			case cmd == "DATA":
				w("354 go")
				var b strings.Builder
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					b.WriteString(l)
				}
				c.data = b.String()
				w("250 queued")
			case cmd == "QUIT":
				w("221 bye")
				out <- c
				return
			default:
				w("502 unknown")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, out
}

func settings(port int, enc string) SMTPSettings {
	return SMTPSettings{
		Host: "127.0.0.1", Port: port, Encryption: enc,
		From: "tlswatch <tlswatch@example.nl>", Recipients: []string{"ops@example.nl", "Noc <noc@example.nl>"},
	}
}

func TestSMTPStartTLSPlainAuth(t *testing.T) {
	cert, pool := testCert(t)
	port, got := fakeSMTP(t, "starttls", "PLAIN LOGIN", cert)
	s := settings(port, "starttls")
	s.Username, s.Password = "user", "s3cret"
	snd := &SMTPSender{S: s, RootCAs: pool, Timeout: 5 * time.Second}
	err := snd.Send(context.Background(), Message{Subject: "[critical] portal.example.nl:443 expires in 6 days", Body: "line one\nline two", Ref: "0a1b2c"})
	if err != nil {
		t.Fatal(err)
	}
	c := <-got
	if !c.tls || c.auth != "PLAIN:\x00user\x00s3cret" {
		t.Fatalf("tls=%v auth=%q", c.tls, c.auth)
	}
	if !strings.HasPrefix(c.from, "<tlswatch@example.nl>") || len(c.rcpt) != 2 || c.rcpt[1] != "<noc@example.nl>" {
		t.Fatalf("envelope %q %q", c.from, c.rcpt)
	}
	for _, want := range []string{"Subject: [critical] portal.example.nl:443 expires in 6 days\r\n", "Auto-Submitted: auto-generated", "Content-Transfer-Encoding: quoted-printable", "line one\r\nline two", "Message-ID: <0a1b2c@tlswatch>"} {
		if !strings.Contains(c.data, want) {
			t.Errorf("message lacks %q:\n%s", want, c.data)
		}
	}
}

func TestSMTPImplicitTLSLoginAuth(t *testing.T) {
	cert, pool := testCert(t)
	port, got := fakeSMTP(t, "tls", "LOGIN", cert)
	s := settings(port, "tls")
	s.Username, s.Password = "user", "pw"
	snd := &SMTPSender{S: s, RootCAs: pool, Timeout: 5 * time.Second}
	if err := snd.Send(context.Background(), Message{Subject: "s", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	if c := <-got; c.auth != "LOGIN:user:pw" {
		t.Fatalf("auth %q", c.auth)
	}
}

func TestSMTPNone(t *testing.T) {
	cert, _ := testCert(t)
	port, got := fakeSMTP(t, "none", "", cert)
	snd := &SMTPSender{S: settings(port, "none"), Timeout: 5 * time.Second}
	if err := snd.Send(context.Background(), Message{Subject: "Kritiek: café verloopt", Body: "é"}); err != nil {
		t.Fatal(err)
	}
	c := <-got
	if c.tls || c.auth != "" {
		t.Fatalf("tls=%v auth=%q", c.tls, c.auth)
	}
	subj := ""
	for _, l := range strings.Split(c.data, "\r\n") {
		if strings.HasPrefix(l, "Subject: ") {
			subj = l[9:]
		}
	}
	if !strings.HasPrefix(subj, "=?utf-8?q?") {
		t.Fatalf("subject not encoded: %q", subj)
	}
	dec, _ := new(mime.WordDecoder).DecodeHeader(subj)
	if dec != "Kritiek: café verloopt" {
		t.Fatalf("decoded %q", dec)
	}
}

func TestSMTPUntrustedCertAndRedaction(t *testing.T) {
	cert, _ := testCert(t)
	port, _ := fakeSMTP(t, "starttls", "PLAIN", cert)
	s := settings(port, "starttls")
	s.Username, s.Password = "user", "127.0.0.1" // password that would appear in the error
	snd := &SMTPSender{S: s, Timeout: 5 * time.Second}
	err := snd.Send(context.Background(), Message{Subject: "s", Body: "b"})
	if err == nil {
		t.Fatal("expected certificate error")
	}
	if strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("password leaked: %v", err)
	}
}

func TestSMTPNoStartTLSOffered(t *testing.T) {
	cert, _ := testCert(t)
	port, _ := fakeSMTP(t, "none", "", cert)
	snd := &SMTPSender{S: settings(port, "starttls"), Timeout: 5 * time.Second}
	if err := snd.Send(context.Background(), Message{}); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("got %v", err)
	}
}

func TestSMTPValidate(t *testing.T) {
	ok := settings(587, "")
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*SMTPSettings){
		"no host":    func(s *SMTPSettings) { s.Host = "" },
		"port":       func(s *SMTPSettings) { s.Port = 70000 },
		"enc":        func(s *SMTPSettings) { s.Encryption = "ssl3" },
		"from":       func(s *SMTPSettings) { s.From = "nope" },
		"no rcpt":    func(s *SMTPSettings) { s.Recipients = nil },
		"bad rcpt":   func(s *SMTPSettings) { s.Recipients = []string{"x@"} },
		"plain auth": func(s *SMTPSettings) { s.Host, s.Encryption, s.Username = "smtp.example.nl", "none", "u" },
	}
	for name, mut := range cases {
		s := settings(587, "starttls")
		mut(&s)
		if s.Validate() == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if d := ok.Destination(); d != "ops@example.nl, Noc <noc@example.nl>" {
		t.Errorf("destination %q", d)
	}
}
