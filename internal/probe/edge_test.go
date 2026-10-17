package probe

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestIsUnreachable(t *testing.T) {
	op := func(errno error) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
	}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"network unreachable", op(syscall.ENETUNREACH), true},
		{"host unreachable", op(syscall.EHOSTUNREACH), true},
		{"address not available", op(syscall.EADDRNOTAVAIL), true},
		{"wrapped", fmt.Errorf("probe: %w", op(syscall.ENETUNREACH)), true},
		{"text only", errors.New("dial tcp [2001:db8::1]:443: connect: network is unreachable"), true},
		{"no route text", errors.New("connect: no route to host"), true},
		{"connection refused", op(syscall.ECONNREFUSED), false},
		{"timeout", os.ErrDeadlineExceeded, false},
		{"DNS", &net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true}, false},
	}
	for _, c := range cases {
		if got := isUnreachable(c.err); got != c.want {
			t.Errorf("%s: isUnreachable(%v) = %v, want %v", c.name, c.err, got, c.want)
		}
	}
}

func TestCleanError(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	if got := cleanError(refused, time.Second); got != "connect: connection refused" {
		t.Errorf("refused: %q", got)
	}
	if got := cleanError(fmt.Errorf("read: %w", os.ErrDeadlineExceeded), 7*time.Second); got != "timed out after 7s" {
		t.Errorf("deadline: %q", got)
	}
}

func TestCheckHostname(t *testing.T) {
	p := newPKI(t)
	wild := newLeaf(t, p.inter, "*.example.com")
	both := newLeaf(t, p.inter, "example.com", "*.example.com")
	puny := newLeaf(t, p.inter, "xn--bcher-kva.example")
	ipLeaf := newCert(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "10.0.0.5"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("2001:db8::5")},
	}, p.inter, nil)
	cases := []struct {
		name       string
		leaf       *testCert
		serverName string
		checked    bool
		ok         bool
	}{
		{"exact", p.leaf, "good.example", true, true},
		{"second SAN", p.leaf, "www.good.example", true, true},
		{"uppercase server name", p.leaf, "GOOD.Example", true, true},
		{"trailing dot", p.leaf, "good.example.", true, true},
		{"other name", p.leaf, "bad.example", true, false},
		{"sub of an exact name", p.leaf, "a.good.example", true, false},
		{"empty server name skips", p.leaf, "", false, false},
		{"wildcard covers one label", wild, "a.example.com", true, true},
		{"wildcard uppercase", wild, "A.EXAMPLE.COM", true, true},
		{"wildcard does not cover the apex", wild, "example.com", true, false},
		{"wildcard does not cover two labels", wild, "a.b.example.com", true, false},
		{"apex and wildcard", both, "example.com", true, true},
		{"punycode IDN", puny, "xn--bcher-kva.example", true, true},
		{"IPv4 SAN", ipLeaf, "10.0.0.5", true, true},
		{"IPv6 SAN", ipLeaf, "2001:db8::5", true, true},
		{"other IP", ipLeaf, "10.0.0.6", true, false},
		{"IP SAN does not cover a name", ipLeaf, "good.example", true, false},
	}
	for _, c := range cases {
		checked, ok := CheckHostname(c.leaf.cert, c.serverName)
		if checked != c.checked || ok != c.ok {
			t.Errorf("%s: checked %v ok %v, want %v %v", c.name, checked, ok, c.checked, c.ok)
		}
	}
}

func TestVerifyChains(t *testing.T) {
	p := newPKI(t)
	oldRoot := newCert(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Old Root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-1000 * 24 * time.Hour), NotAfter: time.Now().Add(1000 * 24 * time.Hour),
	}, nil, nil)
	p.pool.AddCert(oldRoot.cert)
	expiredInter := newCert(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Old Intermediate"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-400 * 24 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour),
	}, oldRoot, nil)
	behindExpired := newCert(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "x.example"}, DNSNames: []string{"x.example"},
		NotBefore: time.Now().Add(-300 * 24 * time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour),
	}, expiredInter, nil)
	selfSigned := newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "self.example"}, DNSNames: []string{"self.example"}}, nil, nil)

	cases := []struct {
		name  string
		chain []*testCert
		trust TrustMode
		roots *x509.CertPool
		want  bool
	}{
		{"complete chain", []*testCert{p.leaf, p.inter}, TrustBundle, p.pool, true},
		{"root presented too", []*testCert{p.leaf, p.inter, p.root}, TrustBundle, p.pool, true},
		{"misordered chain", []*testCert{p.leaf, p.root, p.inter}, TrustBundle, p.pool, true},
		{"missing intermediate", []*testCert{p.leaf}, TrustBundle, p.pool, false},
		{"bundle trust without a bundle", []*testCert{p.leaf, p.inter}, TrustBundle, nil, false},
		{"system trust, private root", []*testCert{p.leaf, p.inter}, TrustSystem, nil, false},
		{"expired intermediate judged apart from expiry", []*testCert{behindExpired, expiredInter}, TrustBundle, p.pool, true},
		{"self-signed under bundle trust", []*testCert{selfSigned}, TrustBundle, p.pool, false},
	}
	for _, c := range cases {
		a := Address{IP: "192.0.2.1", OK: true}
		for _, tc := range c.chain {
			a.Chain = append(a.Chain, tc.cert)
		}
		Verify(&a, Request{Trust: c.trust, Roots: c.roots})
		if a.Verified != c.want {
			t.Errorf("%s: verified %v (%s), want %v", c.name, a.Verified, a.VerifyError, c.want)
		}
		if c.want && (len(a.VerifiedChain) == 0 || !a.VerifiedChain[len(a.VerifiedChain)-1].IsCA) {
			t.Errorf("%s: verified chain does not end at the root", c.name)
		}
		if !c.want && a.VerifyError == "" {
			t.Errorf("%s: no verify error", c.name)
		}
	}

	// Self-signed trust: nothing is verified, the hostname still is.
	a := Address{IP: "192.0.2.1", OK: true, Chain: []*x509.Certificate{selfSigned.cert}}
	Verify(&a, Request{Trust: TrustSelfSigned, ServerName: "other.example"})
	if a.Verified || a.VerifyError != "" || !a.HostnameChecked || a.HostnameOK {
		t.Fatalf("self-signed trust: %+v", a)
	}
}

func TestDescribeKeys(t *testing.T) {
	p := newPKI(t)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name string
		c    *testCert
		desc string
		bits int
		weak bool
	}{
		{"P-384", newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "p384"}}, p.inter, ec384), "ECDSA P-384", 384, false},
		{"Ed25519", newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "ed"}}, p.inter, ed), "Ed25519", 256, false},
		{"SHA-1 with ECDSA", newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "sha1"}, SignatureAlgorithm: x509.ECDSAWithSHA1}, p.inter, nil), "ECDSA P-256", 256, true},
	}
	for _, c := range cases {
		ci := Describe(c.c.cert)
		if ci.KeyDesc != c.desc || ci.KeyBits != c.bits || ci.WeakSignature != c.weak {
			t.Errorf("%s: %s %d weak %v, want %s %d %v", c.name, ci.KeyDesc, ci.KeyBits, ci.WeakSignature, c.desc, c.bits, c.weak)
		}
	}
	// No CN: the first DNS SAN stands in.
	noCN := newCert(t, &x509.Certificate{DNSNames: []string{"san.example"}}, p.inter, nil)
	if ci := Describe(noCN.cert); ci.SubjectCN != "san.example" {
		t.Errorf("SubjectCN %q", ci.SubjectCN)
	}
}

func TestReadReply(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		code  int
		lines []string
		err   bool
	}{
		{"single line", "250 ok\r\n", 250, []string{"ok"}, false},
		{"bare code", "250\r\n", 250, []string{""}, false},
		{"multiline", "250-mail.example\r\n250-STARTTLS\r\n250 SIZE 10\r\n", 250, []string{"mail.example", "STARTTLS", "SIZE 10"}, false},
		{"LF only", "250-a\n250 b\n", 250, []string{"a", "b"}, false},
		{"not a number", "abc def\r\n", 0, nil, true},
		{"closed mid-reply", "250-a\r\n", 0, nil, true},
		{"empty", "", 0, nil, true},
	}
	for _, c := range cases {
		code, lines, err := readReply(bufio.NewReader(strings.NewReader(c.in)))
		if (err != nil) != c.err {
			t.Errorf("%s: err %v, want error %v", c.name, err, c.err)
			continue
		}
		if c.err {
			continue
		}
		if code != c.code || strings.Join(lines, "|") != strings.Join(c.lines, "|") {
			t.Errorf("%s: %d %q, want %d %q", c.name, code, lines, c.code, c.lines)
		}
	}
}

// script is a plain-text preamble: it writes greet, then for each step
// reads one line, checks it starts with the expected command and writes the
// answer. It returns ok (start TLS) after the last step.
type step struct{ expect, answer string }

func script(greet string, ok bool, steps ...step) func(net.Conn, *bufio.Reader) bool {
	return func(c net.Conn, r *bufio.Reader) bool {
		if greet != "" {
			io.WriteString(c, greet)
		}
		for _, s := range steps {
			if l := line(r); !strings.HasPrefix(l, s.expect) {
				return false
			}
			io.WriteString(c, s.answer)
		}
		return ok
	}
}

func TestSTARTTLSDialects(t *testing.T) {
	p := newPKI(t)
	cfg := serverConfig(p.leaf, p.inter)
	cases := []struct {
		name  string
		proto Protocol
		pre   func(net.Conn, *bufio.Reader) bool
		kind  ErrorKind // ErrNone: the handshake completes
	}{
		{"smtp lowercase starttls", SMTP, script("220 hi\r\n", true, step{"EHLO", "250-mx\r\n250-starttls\r\n250 OK\r\n"}, step{"STARTTLS", "220 go\r\n"}), ErrNone},
		{"smtp starttls on the last line", SMTP, script("220 hi\r\n", true, step{"EHLO", "250-mx\r\n250 STARTTLS\r\n"}, step{"STARTTLS", "220 go\r\n"}), ErrNone},
		{"smtp STARTTLS refused with 454", SMTP, script("220 hi\r\n", false, step{"EHLO", "250-mx\r\n250 STARTTLS\r\n"}, step{"STARTTLS", "454 TLS not available\r\n"}), ErrStartTLS},
		{"smtp EHLO refused", SMTP, script("220 hi\r\n", false, step{"EHLO", "502 unknown\r\n"}), ErrStartTLS},
		{"smtp STARTTLS only as a word in a line", SMTP, script("220 hi\r\n", false, step{"EHLO", "250-mx says no STARTTLS\r\n250 OK\r\n"}), ErrStartTLS},
		{"smtp rejecting greeting", SMTP, script("554 go away\r\n", false), ErrHandshake},
		{"smtp garbage greeting", SMTP, script("HTTP/1.1 400 Bad Request\r\n\r\n", false), ErrHandshake},
		{"imap lowercase capability", IMAP, script("* OK ready\r\n", true, step{"a1 CAPABILITY", "* capability imap4rev1 starttls\r\na1 OK\r\n"}, step{"a2 STARTTLS", "a2 OK go\r\n"}), ErrNone},
		{"imap STARTTLS answered NO", IMAP, script("* OK ready\r\n", false, step{"a1 CAPABILITY", "* CAPABILITY IMAP4rev1 STARTTLS\r\na1 OK\r\n"}, step{"a2 STARTTLS", "a2 NO not now\r\n"}), ErrStartTLS},
		{"imap STARTTLS answered BAD", IMAP, script("* OK ready\r\n", false, step{"a1 CAPABILITY", "* CAPABILITY IMAP4rev1 STARTTLS\r\na1 OK\r\n"}, step{"a2 STARTTLS", "a2 BAD\r\n"}), ErrStartTLS},
		{"imap BYE greeting", IMAP, script("* BYE overloaded\r\n", false), ErrHandshake},
		{"pop3 STLS refused", POP3, script("+OK ready\r\n", false, step{"CAPA", "+OK\r\nSTLS\r\n.\r\n"}, step{"STLS", "-ERR no\r\n"}), ErrStartTLS},
		{"pop3 error greeting", POP3, script("-ERR busy\r\n", false), ErrHandshake},
		{"ftp multiline greeting with code lines", FTP, script("220-one\r\n220-two\r\n220 ready\r\n", true, step{"AUTH TLS", "234 go\r\n"}), ErrNone},
		{"ftp error greeting", FTP, script("421 too many\r\n", false), ErrHandshake},
		{"postgres unexpected reply", Postgres, func(c net.Conn, r *bufio.Reader) bool {
			var msg [8]byte
			if _, err := io.ReadFull(r, msg[:]); err != nil {
				return false
			}
			c.Write([]byte("E"))
			return false
		}, ErrHandshake},
	}
	for _, c := range cases {
		a := single(t, Probe(context.Background(), req(serve(t, cfg, c.pre), c.proto)))
		if c.kind == ErrNone && !a.OK {
			t.Errorf("%s: %s %s, want a handshake", c.name, a.ErrorKind, a.Error)
		}
		if c.kind != ErrNone && (a.OK || a.ErrorKind != c.kind) {
			t.Errorf("%s: ok %v kind %q (%s), want %q", c.name, a.OK, a.ErrorKind, a.Error, c.kind)
		}
	}
}

// A server that accepts the connection and never speaks is a timeout, not
// a missing STARTTLS, and the probe gives up after its timeout.
func TestSilentServerTimesOut(t *testing.T) {
	for _, proto := range []Protocol{TLS, SMTP, IMAP, POP3, FTP, Postgres} {
		port := serve(t, nil, func(c net.Conn, r *bufio.Reader) bool {
			_, _ = io.Copy(io.Discard, r)
			return false
		})
		rq := req(port, proto)
		rq.Timeout = 300 * time.Millisecond
		start := time.Now()
		a := single(t, Probe(context.Background(), rq))
		if a.OK || a.ErrorKind != ErrHandshake || !strings.Contains(a.Error, "timed out") {
			t.Errorf("%s: %+v", proto, a)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: took %s with a 300ms timeout", proto, d)
		}
	}
}

// A cancelled context stops a probe that is waiting on a slow server.
func TestCancelStopsProbe(t *testing.T) {
	port := serve(t, nil, func(c net.Conn, r *bufio.Reader) bool {
		_, _ = io.Copy(io.Discard, r)
		return false
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	rq := req(port, SMTP)
	rq.Timeout = 10 * time.Second
	rq.Retries = 3
	start := time.Now()
	a := single(t, Probe(ctx, rq))
	if a.OK || time.Since(start) > 2*time.Second {
		t.Fatalf("cancelled probe: %+v after %s", a, time.Since(start))
	}
}

func TestIPv6Literal(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	p := newPKI(t)
	cfg := serverConfig(p.leaf, p.inter)
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := tls.Server(c, cfg)
				if tc.Handshake() == nil {
					_, _ = io.Copy(io.Discard, tc)
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	for _, host := range []string{"::1", "[::1]"} {
		rq := req(port, TLS)
		rq.Host, rq.ServerName, rq.Trust, rq.Roots = host, "good.example", TrustBundle, p.pool
		a := single(t, Probe(context.Background(), rq))
		if !a.OK || a.IP != "::1" || !a.Verified || !a.HostnameOK {
			t.Errorf("%s: %+v", host, a)
		}
	}
}

func TestTrailingDotHost(t *testing.T) {
	p := newPKI(t)
	port := serve(t, serverConfig(p.leaf, p.inter), nil)
	rq := req(port, TLS)
	rq.Host, rq.ServerName = "127.0.0.1.", "good.example."
	rq.Trust, rq.Roots = TrustBundle, p.pool
	a := single(t, Probe(context.Background(), rq))
	if !a.OK || !a.Verified || !a.HostnameOK {
		t.Fatalf("%+v", a)
	}
}
