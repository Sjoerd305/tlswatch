package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// ssl3ServerHelloRecord is what a server with SSL 3.0 on answers: a
// handshake record carrying a ServerHello at version 3.0 that picks suite.
func ssl3ServerHelloRecord(version uint16, suite uint16) []byte {
	body := binary.BigEndian.AppendUint16(nil, version)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // no session ID
	body = binary.BigEndian.AppendUint16(body, suite)
	body = append(body, 0) // null compression
	hs := []byte{0x02, 0, 0, byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x00}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func TestSSL3ClientHelloShape(t *testing.T) {
	h := ssl3ClientHello()
	if h[0] != 0x16 || h[1] != 0x03 || h[2] != 0x00 {
		t.Fatalf("record header %x", h[:3])
	}
	if int(binary.BigEndian.Uint16(h[3:])) != len(h)-5 {
		t.Fatalf("record length %d for %d bytes", binary.BigEndian.Uint16(h[3:]), len(h)-5)
	}
	hs := h[5:]
	if hs[0] != 0x01 || int(hs[1])<<16|int(hs[2])<<8|int(hs[3]) != len(hs)-4 {
		t.Fatalf("handshake header %x for %d bytes", hs[:4], len(hs)-4)
	}
	if hs[4] != 0x03 || hs[5] != 0x00 {
		t.Fatalf("client version %x, want 3.0", hs[4:6])
	}
	if n := binary.BigEndian.Uint16(hs[39:]); int(n) != 2*len(ssl3Suites) {
		t.Fatalf("suites length %d, want %d", n, 2*len(ssl3Suites))
	}
	if !bytes.HasSuffix(h, []byte{1, 0}) {
		t.Fatal("no null compression at the end: SSL 3.0 has no extensions")
	}
}

func TestSSL3ServerHelloJudged(t *testing.T) {
	alert := []byte{0x15, 0x03, 0x00, 0x00, 0x02, 0x02, 0x46} // fatal protocol_version
	cases := []struct {
		name  string
		reply []byte
		want  bool
	}{
		{"ServerHello 3.0", ssl3ServerHelloRecord(0x0300, 0x000A), true},
		{"ServerHello at TLS 1.0 is not SSL 3.0", ssl3ServerHelloRecord(0x0301, 0x000A), false},
		{"alert", alert, false},
		{"connection closed at once", nil, false},
		{"closed inside the header", []byte{0x16, 0x03}, false},
		{"closed inside the body", ssl3ServerHelloRecord(0x0300, 0x000A)[:20], false},
		{"plaintext banner", []byte("HTTP/1.1 400 Bad Request\r\n\r\n"), false},
		{"handshake record too short for a ServerHello", []byte{0x16, 0x03, 0x00, 0x00, 0x02, 0x02, 0x00}, false},
		{"record longer than any ServerHello", []byte{0x16, 0x03, 0x00, 0xff, 0xff}, false},
	}
	for _, c := range cases {
		ok, err := ssl3ServerHello(bytes.NewReader(c.reply))
		if err != nil || ok != c.want {
			t.Errorf("%s: accepted %v err %v, want %v", c.name, ok, err, c.want)
		}
	}
}

// rawServer answers every connection with reply (nil: close at once) and
// hangs instead when reply is hang.
func rawServer(t *testing.T, reply []byte, hang bool) int {
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
				var hdr [5]byte
				if _, err := io.ReadFull(conn, hdr[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(hdr[3:]))
				if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil {
					return
				}
				if hang {
					time.Sleep(4 * time.Second)
					return
				}
				_, _ = conn.Write(reply)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestSSL3Accepts(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	alert := []byte{0x15, 0x03, 0x00, 0x00, 0x02, 0x02, 0x46}
	for _, c := range []struct {
		name  string
		port  int
		want  bool
		noVer bool
	}{
		{"server with SSL 3.0 on", rawServer(t, ssl3ServerHelloRecord(0x0300, 0x0035), false), true, false},
		{"server answering with an alert", rawServer(t, alert, false), false, false},
		{"server closing the connection", rawServer(t, nil, false), false, false},
		{"server that hangs: no verdict", rawServer(t, nil, true), false, true},
	} {
		r := req(c.port, TLS)
		r.Timeout = time.Second
		ok, err := ssl3Accepts(context.Background(), r, ip)
		if ok != c.want || (err != nil) != c.noVer {
			t.Errorf("%s: accepted %v err %v, want %v (no verdict %v)", c.name, ok, err, c.want, c.noVer)
		}
	}
}

// A Go TLS server has no SSL 3.0 and refuses the hello with an alert.
func TestSSL3RefusedByModernServer(t *testing.T) {
	p := newPKI(t)
	cfg := serverConfig(p.leaf, p.inter)
	cfg.MinVersion = tls.VersionTLS10
	ok, err := ssl3Accepts(context.Background(), req(serve(t, cfg, nil), TLS), net.ParseIP("127.0.0.1"))
	if ok || err != nil {
		t.Fatalf("accepted %v err %v, want refused", ok, err)
	}
}

// replayConn hands the bytes already read from conn back to the TLS server.
type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// serveWithSSL3 is a server on modern TLS for the normal probe that also
// answers an SSL 3.0 ClientHello with a ServerHello at 3.0, the way an
// appliance with the version still on would.
func serveWithSSL3(t *testing.T, cfg *tls.Config) int {
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
				var hdr [5]byte
				if _, err := io.ReadFull(conn, hdr[:]); err != nil {
					return
				}
				if hdr[0] == 0x16 && hdr[1] == 0x03 && hdr[2] == 0x00 {
					n := int(binary.BigEndian.Uint16(hdr[3:]))
					if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil {
						return
					}
					_, _ = conn.Write(ssl3ServerHelloRecord(0x0300, 0x0035))
					return
				}
				tc := tls.Server(&replayConn{Conn: conn, r: io.MultiReader(bytes.NewReader(hdr[:]), conn)}, cfg)
				if tc.Handshake() == nil {
					_, _ = io.Copy(io.Discard, tc)
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestLegacyVersionsIncludeSSL3(t *testing.T) {
	p := newPKI(t)
	cfg := serverConfig(p.leaf, p.inter)
	cfg.MinVersion = tls.VersionTLS12
	r := req(serveWithSSL3(t, cfg), TLS)
	r.Legacy = true
	a := single(t, Probe(context.Background(), r))
	if !a.OK || !a.LegacyChecked || strings.Join(a.Legacy, ",") != "SSL 3.0" {
		t.Fatalf("ok %v checked %v legacy %v, want SSL 3.0 alone", a.OK, a.LegacyChecked, a.Legacy)
	}
	if a.TLSVersion != "TLS 1.3" {
		t.Fatalf("normal probe negotiated %s", a.TLSVersion)
	}
}

func TestVersionName(t *testing.T) {
	if VersionName(VersionSSL30) != "SSL 3.0" || VersionName(tls.VersionTLS10) != "TLS 1.0" {
		t.Fatalf("%q %q", VersionName(VersionSSL30), VersionName(tls.VersionTLS10))
	}
}
