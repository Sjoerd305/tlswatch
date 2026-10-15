package probe

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

type testCert struct {
	cert *x509.Certificate
	key  crypto.Signer
}

var serial int64 = 100

func newCert(t *testing.T, tmpl *x509.Certificate, parent *testCert, key crypto.Signer) *testCert {
	t.Helper()
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	serial++
	tmpl.SerialNumber = big.NewInt(serial)
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	signer, parentCert := key, tmpl
	if parent != nil {
		signer, parentCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{cert: c, key: key}
}

func newCA(t *testing.T, name string, parent *testCert) *testCert {
	return newCert(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: name, Organization: []string{"Test Org"}},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
	}, parent, nil)
}

func newLeaf(t *testing.T, parent *testCert, dns ...string) *testCert {
	return newCert(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: dns[0]},
		DNSNames:    dns,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}, parent, nil)
}

type pki struct {
	root, inter, leaf *testCert
	pool              *x509.CertPool
}

func newPKI(t *testing.T) pki {
	root := newCA(t, "Test Root", nil)
	inter := newCA(t, "Test Intermediate", root)
	leaf := newLeaf(t, inter, "good.example", "www.good.example")
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	return pki{root, inter, leaf, pool}
}

func serverConfig(chain ...*testCert) *tls.Config {
	c := tls.Certificate{PrivateKey: chain[0].key}
	for _, tc := range chain {
		c.Certificate = append(c.Certificate, tc.cert.Raw)
	}
	return &tls.Config{Certificates: []tls.Certificate{c}}
}

// serve accepts connections, runs preamble on the plain connection, then a
// TLS handshake when preamble returns true.
func serve(t *testing.T, cfg *tls.Config, preamble func(net.Conn, *bufio.Reader) bool) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if preamble != nil && !preamble(conn, bufio.NewReader(conn)) {
					return
				}
				tc := tls.Server(conn, cfg)
				if tc.Handshake() == nil {
					_, _ = io.Copy(io.Discard, tc)
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func req(port int, p Protocol) Request {
	return Request{Host: "127.0.0.1", Port: port, Protocol: p, AllowLocal: true, Timeout: 3 * time.Second}
}

func single(t *testing.T, r Result) Address {
	t.Helper()
	if r.DNSError != "" || len(r.Addresses) != 1 {
		t.Fatalf("want one address, got %+v", r)
	}
	return r.Addresses[0]
}

func TestImplicitTLSBundleTrust(t *testing.T) {
	p := newPKI(t)
	port := serve(t, serverConfig(p.leaf, p.inter), nil)
	r := req(port, TLS)
	r.ServerName, r.Trust, r.Roots = "good.example", TrustBundle, p.pool
	a := single(t, Probe(context.Background(), r))
	if !a.OK || a.ErrorKind != ErrNone {
		t.Fatalf("not ok: %+v", a)
	}
	if !a.Verified || len(a.VerifiedChain) != 3 || a.VerifiedChain[2].Subject.CommonName != "Test Root" {
		t.Fatalf("verification: %v %q chain=%d", a.Verified, a.VerifyError, len(a.VerifiedChain))
	}
	if len(a.Chain) != 2 || Fingerprint(a.Chain[0]) != Fingerprint(p.leaf.cert) {
		t.Fatalf("chain as presented: %d", len(a.Chain))
	}
	if !a.HostnameChecked || !a.HostnameOK {
		t.Fatalf("hostname: %v %v", a.HostnameChecked, a.HostnameOK)
	}
	if a.TLSVersion != "TLS 1.3" || a.Cipher == "" {
		t.Fatalf("version %q cipher %q", a.TLSVersion, a.Cipher)
	}
}

func TestHostnameMismatch(t *testing.T) {
	p := newPKI(t)
	port := serve(t, serverConfig(p.leaf, p.inter), nil)
	r := req(port, TLS)
	r.ServerName, r.Trust, r.Roots = "other.example", TrustBundle, p.pool
	a := single(t, Probe(context.Background(), r))
	if !a.OK || !a.HostnameChecked || a.HostnameOK {
		t.Fatalf("want mismatch: %+v", a)
	}
	if !a.Verified {
		t.Fatalf("chain should still verify: %s", a.VerifyError)
	}
}

func TestUntrustedChain(t *testing.T) {
	p := newPKI(t)
	port := serve(t, serverConfig(p.leaf, p.inter), nil)
	r := req(port, TLS)
	r.ServerName, r.Trust = "good.example", TrustSystem
	a := single(t, Probe(context.Background(), r))
	if !a.OK || a.Verified || a.VerifyError == "" {
		t.Fatalf("private CA should not verify against the system store: %+v", a)
	}
	// Missing intermediate under bundle trust.
	port = serve(t, serverConfig(p.leaf), nil)
	r = req(port, TLS)
	r.ServerName, r.Trust, r.Roots = "good.example", TrustBundle, p.pool
	a = single(t, Probe(context.Background(), r))
	if a.Verified {
		t.Fatal("chain without intermediate verified")
	}
}

func TestClientOnlyCertificateNotTrusted(t *testing.T) {
	p := newPKI(t)
	client := newCert(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "good.example"},
		DNSNames:    []string{"good.example"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}, p.inter, nil)
	port := serve(t, serverConfig(client, p.inter), nil)
	r := req(port, TLS)
	r.ServerName, r.Trust, r.Roots = "good.example", TrustBundle, p.pool
	a := single(t, Probe(context.Background(), r))
	if !a.OK || a.Verified || !strings.Contains(a.VerifyError, "usage") {
		t.Fatalf("client-only certificate verified as a server certificate: %+v", a.VerifyError)
	}
}

func TestExpiredLeafStillTrusted(t *testing.T) {
	longAgo := time.Now().Add(-400 * 24 * time.Hour)
	root := newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Old Root"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: longAgo, NotAfter: time.Now().Add(time.Hour * 24 * 365)}, nil, nil)
	inter := newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "Old Intermediate"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: longAgo, NotAfter: time.Now().Add(time.Hour * 24 * 365)}, root, nil)
	p := pki{root: root, inter: inter, pool: x509.NewCertPool()}
	p.pool.AddCert(root.cert)
	expired := newCert(t, &x509.Certificate{
		Subject:   pkix.Name{CommonName: "old.example"},
		DNSNames:  []string{"old.example"},
		NotBefore: time.Now().Add(-100 * 24 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour),
	}, p.inter, nil)
	port := serve(t, serverConfig(expired, p.inter), nil)
	r := req(port, TLS)
	r.ServerName, r.Trust, r.Roots = "old.example", TrustBundle, p.pool
	a := single(t, Probe(context.Background(), r))
	if !a.OK || !a.Verified {
		t.Fatalf("expired leaf: trust judged apart from expiry, got %q", a.VerifyError)
	}
}

func TestSelfSignedIPTarget(t *testing.T) {
	ss := newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "appliance"}}, nil, nil)
	port := serve(t, serverConfig(ss), nil)
	r := req(port, TLS)
	r.Trust = TrustSelfSigned
	a := single(t, Probe(context.Background(), r))
	if !a.OK || a.HostnameChecked || a.Verified || a.VerifyError != "" {
		t.Fatalf("self-signed IP target: %+v", a)
	}
	if !Describe(a.Chain[0]).SelfSigned {
		t.Fatal("not recognised as self-signed")
	}
}

func TestLocalRefused(t *testing.T) {
	r := req(1, TLS)
	r.AllowLocal = false
	a := single(t, Probe(context.Background(), r))
	if a.ErrorKind != ErrRefused || a.OK {
		t.Fatalf("got %+v", a)
	}
}

func TestConnectFailureWithRetries(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	r := req(port, TLS)
	r.Retries = 2
	res := Probe(context.Background(), r)
	a := single(t, res)
	if a.ErrorKind != ErrConnect || a.Error == "" {
		t.Fatalf("got %+v", a)
	}
	if res.Duration < 2*retryBackoff {
		t.Fatalf("expected two retries with backoff, took %s", res.Duration)
	}
}

func TestHandshakeFailure(t *testing.T) {
	port := serve(t, nil, func(c net.Conn, _ *bufio.Reader) bool {
		_, _ = c.Write([]byte("HTTP/1.0 400 Bad Request\r\n\r\n"))
		return false
	})
	a := single(t, Probe(context.Background(), req(port, TLS)))
	if a.ErrorKind != ErrHandshake {
		t.Fatalf("got %+v", a)
	}
}

func line(r *bufio.Reader) string {
	s, _ := r.ReadString('\n')
	return strings.TrimRight(s, "\r\n")
}

func smtpServer(offer bool) func(net.Conn, *bufio.Reader) bool {
	return func(c net.Conn, r *bufio.Reader) bool {
		io.WriteString(c, "220-mail.example ESMTP\r\n220 ready\r\n")
		if !strings.HasPrefix(line(r), "EHLO") {
			return false
		}
		io.WriteString(c, "250-mail.example\r\n250-PIPELINING\r\n")
		if offer {
			io.WriteString(c, "250-STARTTLS\r\n")
		}
		io.WriteString(c, "250 8BITMIME\r\n")
		if line(r) != "STARTTLS" {
			return false
		}
		io.WriteString(c, "220 go ahead\r\n")
		return true
	}
}

func TestSMTP(t *testing.T) {
	p := newPKI(t)
	cfg := serverConfig(p.leaf, p.inter)
	a := single(t, Probe(context.Background(), req(serve(t, cfg, smtpServer(true)), SMTP)))
	if !a.OK {
		t.Fatalf("smtp: %+v", a)
	}
	r := req(serve(t, cfg, smtpServer(false)), SMTP)
	r.Retries = 2
	start := time.Now()
	a = single(t, Probe(context.Background(), r))
	if a.ErrorKind != ErrStartTLS {
		t.Fatalf("smtp without STARTTLS: %+v", a)
	}
	if time.Since(start) > retryBackoff {
		t.Fatal("missing STARTTLS must not be retried")
	}
}

func TestIMAP(t *testing.T) {
	p := newPKI(t)
	cfg := serverConfig(p.leaf, p.inter)
	imap := func(offer bool) func(net.Conn, *bufio.Reader) bool {
		return func(c net.Conn, r *bufio.Reader) bool {
			io.WriteString(c, "* OK IMAP4rev1 ready\r\n")
			if line(r) != "a1 CAPABILITY" {
				return false
			}
			caps := "* CAPABILITY IMAP4rev1 LOGINDISABLED"
			if offer {
				caps += " STARTTLS"
			}
			io.WriteString(c, caps+"\r\na1 OK done\r\n")
			if line(r) != "a2 STARTTLS" {
				return false
			}
			io.WriteString(c, "a2 OK begin TLS\r\n")
			return true
		}
	}
	if a := single(t, Probe(context.Background(), req(serve(t, cfg, imap(true)), IMAP))); !a.OK {
		t.Fatalf("imap: %+v", a)
	}
	if a := single(t, Probe(context.Background(), req(serve(t, cfg, imap(false)), IMAP))); a.ErrorKind != ErrStartTLS {
		t.Fatalf("imap without STARTTLS: %+v", a)
	}
}

func TestPOP3(t *testing.T) {
	p := newPKI(t)
	cfg := serverConfig(p.leaf, p.inter)
	pop := func(capa string) func(net.Conn, *bufio.Reader) bool {
		return func(c net.Conn, r *bufio.Reader) bool {
			io.WriteString(c, "+OK POP3 ready\r\n")
			if line(r) != "CAPA" {
				return false
			}
			if capa == "" {
				io.WriteString(c, "-ERR unknown command\r\n")
			} else {
				io.WriteString(c, "+OK\r\nUSER\r\n"+capa+".\r\n")
			}
			if line(r) != "STLS" {
				return false
			}
			io.WriteString(c, "+OK begin TLS\r\n")
			return true
		}
	}
	if a := single(t, Probe(context.Background(), req(serve(t, cfg, pop("STLS\r\n")), POP3))); !a.OK {
		t.Fatalf("pop3: %+v", a)
	}
	if a := single(t, Probe(context.Background(), req(serve(t, cfg, pop("")), POP3))); !a.OK {
		t.Fatalf("pop3 without CAPA: %+v", a)
	}
	if a := single(t, Probe(context.Background(), req(serve(t, cfg, pop("SASL PLAIN\r\n")), POP3))); a.ErrorKind != ErrStartTLS {
		t.Fatalf("pop3 without STLS: %+v", a)
	}
}

func TestFTP(t *testing.T) {
	p := newPKI(t)
	cfg := serverConfig(p.leaf, p.inter)
	ftp := func(code string) func(net.Conn, *bufio.Reader) bool {
		return func(c net.Conn, r *bufio.Reader) bool {
			io.WriteString(c, "220-Welcome\r\n banner text\r\n220 FTP ready\r\n")
			if line(r) != "AUTH TLS" {
				return false
			}
			io.WriteString(c, code+" reply\r\n")
			return code == "234"
		}
	}
	if a := single(t, Probe(context.Background(), req(serve(t, cfg, ftp("234")), FTP))); !a.OK {
		t.Fatalf("ftp: %+v", a)
	}
	if a := single(t, Probe(context.Background(), req(serve(t, cfg, ftp("502")), FTP))); a.ErrorKind != ErrStartTLS {
		t.Fatalf("ftp refused: %+v", a)
	}
}

func TestPostgres(t *testing.T) {
	p := newPKI(t)
	cfg := serverConfig(p.leaf, p.inter)
	pg := func(reply byte) func(net.Conn, *bufio.Reader) bool {
		return func(c net.Conn, r *bufio.Reader) bool {
			var msg [8]byte
			if _, err := io.ReadFull(r, msg[:]); err != nil {
				return false
			}
			c.Write([]byte{reply})
			return reply == 'S'
		}
	}
	if a := single(t, Probe(context.Background(), req(serve(t, cfg, pg('S')), Postgres))); !a.OK {
		t.Fatalf("postgres: %+v", a)
	}
	if a := single(t, Probe(context.Background(), req(serve(t, cfg, pg('N')), Postgres))); a.ErrorKind != ErrStartTLS {
		t.Fatalf("postgres without SSL: %+v", a)
	}
}

func TestDNSFailure(t *testing.T) {
	r := Request{
		Host: "nonexistent.invalid", Port: 443, Timeout: time.Second,
		Resolver: &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("no DNS in tests")
		}},
	}
	res := Probe(context.Background(), r)
	if res.DNSError == "" || len(res.Addresses) != 0 {
		t.Fatalf("got %+v", res)
	}
}

func TestDescribe(t *testing.T) {
	p := newPKI(t)
	ci := Describe(p.leaf.cert)
	if ci.KeyDesc != "ECDSA P-256" || ci.KeyBits != 256 || ci.SigAlg != "SHA-256 with ECDSA" {
		t.Fatalf("key: %+v", ci)
	}
	if ci.SubjectCN != "good.example" || ci.IssuerCN != "Test Intermediate" || ci.IssuerOrg != "Test Org" {
		t.Fatalf("names: %+v", ci)
	}
	if len(ci.SANs) != 2 || ci.SelfSigned || ci.IsCA || ci.WeakSignature {
		t.Fatalf("flags: %+v", ci)
	}
	if ci.Serial != strings.ToUpper(p.leaf.cert.SerialNumber.Text(16)) || len(ci.Fingerprint) != 64 {
		t.Fatalf("ids: %q %q", ci.Serial, ci.Fingerprint)
	}
	if !strings.HasPrefix(ci.PEM, "-----BEGIN CERTIFICATE-----") {
		t.Fatal("pem")
	}
	if root := Describe(p.root.cert); !root.SelfSigned || !root.IsCA {
		t.Fatalf("root: %+v", root)
	}

	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weak := newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "weak"}}, nil, weakKey)
	if ci := Describe(weak.cert); !ci.WeakSignature || ci.KeyDesc != "RSA 1024" {
		t.Fatalf("RSA 1024: %+v", ci)
	}

	strongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sha1"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), SignatureAlgorithm: x509.SHA1WithRSA}
	if der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &strongKey.PublicKey, strongKey); err == nil {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if ci := Describe(c); !ci.WeakSignature || ci.SigAlg != "SHA-1 with RSA" || !ci.SelfSigned {
			t.Fatalf("SHA-1: %+v", ci)
		}
	} else {
		t.Logf("SHA-1 certificate not created (%v); covered by RSA 1024", err)
	}
}

func TestValidateHost(t *testing.T) {
	for _, ok := range []string{"example.nl", "portal.example.nl.", "a-b.c", "10.0.0.5", "2001:db8:c0::17", "localhost"} {
		if err := ValidateHost(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	long := strings.Repeat("a", 64) + ".example"
	for _, bad := range []string{"", ".", "-a.example", "a-.example", "a..b", "exa mple.nl", "host:443", "*.example.nl", long, "under_score.nl"} {
		if ValidateHost(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestProtocols(t *testing.T) {
	for _, p := range Protocols {
		if DefaultPort(p) == 0 {
			t.Errorf("%s has no default port", p)
		}
	}
	if p, err := ParseProtocol(" SMTP "); err != nil || p != SMTP {
		t.Fatalf("%v %v", p, err)
	}
	if _, err := ParseProtocol("http"); err == nil {
		t.Fatal("http accepted")
	}
	if !IsLocalIP(net.ParseIP("127.0.0.1")) || !IsLocalIP(net.ParseIP("fe80::1")) || IsLocalIP(net.ParseIP("10.0.0.1")) {
		t.Fatal("IsLocalIP")
	}
}

func TestReadLineLimits(t *testing.T) {
	long := strings.Repeat("x", maxLineBytes+1) + "\r\n"
	if _, err := readLine(bufio.NewReader(strings.NewReader(long))); err == nil {
		t.Fatal("over-long line accepted")
	}
	if l, err := readLine(bufio.NewReader(strings.NewReader(strings.Repeat("y", 5000)[:4000] + "\r\n"))); err != nil || len(l) != 4000 {
		t.Fatalf("line longer than the reader buffer: %d %v", len(l), err)
	}
	endless := strings.Repeat("250-EXTENSION\r\n", maxReplyLines+1)
	if _, _, err := readReply(bufio.NewReader(strings.NewReader(endless))); !errors.Is(err, errTooManyLines) {
		t.Fatalf("endless reply: %v", err)
	}
}

func TestLegacyVersions(t *testing.T) {
	p := newPKI(t)
	cases := []struct {
		name     string
		min, max uint16
		want     []string
	}{
		{"modern server refuses both", tls.VersionTLS12, 0, nil},
		{"permissive server accepts both", tls.VersionTLS10, 0, []string{"TLS 1.0", "TLS 1.1"}},
		{"TLS 1.1 only", tls.VersionTLS11, tls.VersionTLS11, []string{"TLS 1.1"}},
		{"TLS 1.0 only, settled by the negotiated version", tls.VersionTLS10, tls.VersionTLS10, []string{"TLS 1.0"}},
	}
	for _, c := range cases {
		cfg := serverConfig(p.leaf, p.inter)
		cfg.MinVersion, cfg.MaxVersion = c.min, c.max
		r := req(serve(t, cfg, nil), TLS)
		r.Legacy = true
		a := single(t, Probe(context.Background(), r))
		if !a.OK || !a.LegacyChecked || strings.Join(a.Legacy, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: ok %v checked %v legacy %v, want %v", c.name, a.OK, a.LegacyChecked, a.Legacy, c.want)
		}
	}
}

func TestLegacyNotTestedUnlessAsked(t *testing.T) {
	p := newPKI(t)
	cfg := serverConfig(p.leaf, p.inter)
	cfg.MinVersion = tls.VersionTLS10
	a := single(t, Probe(context.Background(), req(serve(t, cfg, nil), TLS)))
	if !a.OK || a.LegacyChecked || a.Legacy != nil {
		t.Fatalf("legacy tested without Request.Legacy: %+v", a)
	}
}
