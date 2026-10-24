package probe

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// The probe reads bytes a server controls before any certificate is
// trusted: STARTTLS dialogues, the replies to the hand-built hellos, and
// the stapled OCSP response. These fuzz targets hold each parser to not
// panicking, not looping and not reading past its bounds. The seeds run
// as ordinary tests; go test -fuzz=FuzzName runs one for longer.

func FuzzHandshakeReader(f *testing.F) {
	sh := serverHelloMsg(tls.VersionTLS12, 0x0033)
	f.Add(record(sh))
	f.Add(append(record(append(sh, dheKeyExchange(1024)...)), record(handshakeMsg(msgServerHelloDone, nil))...))
	f.Add(record(append(sh[:10:10], 0)))
	f.Add([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28})
	f.Add([]byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x0c, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		rd := &handshakeReader{r: bytes.NewReader(data)}
		for range 64 {
			typ, body, err := rd.next()
			if err != nil {
				return
			}
			if rd.total > maxHandshake {
				t.Fatalf("read %d bytes, over the bound", rd.total)
			}
			if typ == msgServerHello {
				parseServerHello(body)
			}
			if bits, ok := dhGroupBits(body); ok && bits > 8*len(body) {
				t.Fatalf("a %d-bit group from %d bytes", bits, len(body))
			}
		}
	})
}

func FuzzSSL3ServerHello(f *testing.F) {
	f.Add(record(serverHelloMsg(VersionSSL30, 0x000A)))
	f.Add([]byte{0x15, 0x03, 0x00, 0x00, 0x02, 0x02, 0x46})
	f.Add([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		ok, err := ssl3ServerHello(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("a refusal from a byte stream became no verdict: %v", err)
		}
		if ok && (len(data) < 5+4+35 || data[5] != msgServerHello) {
			t.Fatalf("accepted %x", data)
		}
	})
}

func FuzzReadReply(f *testing.F) {
	f.Add([]byte("250-mx.example\r\n250-PIPELINING\r\n250 STARTTLS\r\n"))
	f.Add([]byte("220 ready\n"))
	f.Add([]byte("250-x\r\n"))
	f.Add([]byte("abc\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, lines, err := readReply(bufio.NewReader(bytes.NewReader(data)))
		if err != nil {
			return
		}
		if len(lines) > maxReplyLines {
			t.Fatalf("%d lines", len(lines))
		}
		for _, l := range lines {
			if len(l) > maxLineBytes {
				t.Fatalf("a line of %d bytes", len(l))
			}
		}
	})
}

// FuzzStartTLS plays a server that sends data and hangs up, for each
// protocol with a STARTTLS dialogue.
func FuzzStartTLS(f *testing.F) {
	protocols := []Protocol{SMTP, IMAP, POP3, FTP, Postgres}
	f.Add(byte(0), []byte("220 mx ESMTP\r\n250-mx\r\n250 STARTTLS\r\n220 go ahead\r\n"))
	f.Add(byte(1), []byte("* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\na1 OK begin TLS\r\n"))
	f.Add(byte(2), []byte("+OK ready\r\n+OK\r\nSTLS\r\n.\r\n+OK begin\r\n"))
	f.Add(byte(3), []byte("220 ftp\r\n234 AUTH TLS ok\r\n"))
	f.Add(byte(4), []byte("S"))
	f.Add(byte(4), []byte("E"))
	f.Fuzz(func(t *testing.T, which byte, data []byte) {
		client, server := net.Pipe()
		defer client.Close()
		go func() {
			go func() { _, _ = io.Copy(io.Discard, server) }()
			_, _ = server.Write(data)
			_ = server.Close()
		}()
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		start := time.Now()
		_ = startTLS(client, protocols[int(which)%len(protocols)])
		if time.Since(start) > time.Second {
			t.Fatalf("STARTTLS hung on a closed connection for %v", time.Since(start))
		}
	})
}

func FuzzMustStaple(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x05})
	f.Add([]byte{0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x11})
	f.Add([]byte{0x02, 0x01, 0x05})
	f.Fuzz(func(t *testing.T, value []byte) {
		MustStaple(&x509.Certificate{Extensions: []pkix.Extension{{Id: oidTLSFeature, Value: value}}})
	})
}

// FuzzStapleOf feeds the stapled response, the one untrusted input of the
// revocation check, against a fixed leaf and issuer.
func FuzzStapleOf(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x0a, 0x01, 0x06})
	f.Add([]byte{0x30, 0x00})
	var once sync.Once
	var chain []*x509.Certificate
	f.Fuzz(func(t *testing.T, data []byte) {
		once.Do(func() {
			p := newPKI(t)
			chain = []*x509.Certificate{p.leaf.cert, p.inter.cert}
		})
		s := StapleOf(Address{OK: true, Chain: chain, OCSP: data})
		if len(data) > 0 && s.Status == "" {
			t.Fatal("a stapled response with no status")
		}
	})
}
