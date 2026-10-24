package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// offeredSuites reads the cipher suites out of a ClientHello body.
func offeredSuites(body []byte) []uint16 {
	sid := int(body[34])
	p := body[35+sid:]
	n := int(binary.BigEndian.Uint16(p))
	var out []uint16
	for i := 0; i < n; i += 2 {
		out = append(out, binary.BigEndian.Uint16(p[2+i:]))
	}
	return out
}

// handshakeMsg frames one handshake message.
func handshakeMsg(typ byte, body []byte) []byte {
	hs := []byte{typ, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

// record frames handshake bytes in one TLS 1.2 record.
func record(hs []byte) []byte {
	rec := []byte{0x16, 0x03, 0x03}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

// serverHelloMsg is a ServerHello at version picking suite.
func serverHelloMsg(version, suite uint16) []byte {
	body := binary.BigEndian.AppendUint16(nil, version)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, suite)
	return handshakeMsg(msgServerHello, append(body, 0))
}

// dheKeyExchange is a ServerKeyExchange with a group of bits bits.
func dheKeyExchange(bits int) []byte {
	p := new(big.Int).Lsh(big.NewInt(1), uint(bits-1)).Bytes() // exactly bits bits
	body := binary.BigEndian.AppendUint16(nil, uint16(len(p)))
	body = append(body, p...)
	body = append(body, 0, 1, 2)          // g
	body = append(body, 0, 1, 3)          // Ys
	body = append(body, 0x04, 0x01, 0, 0) // signature: rsa_pkcs1_sha256, empty
	return handshakeMsg(msgServerKeyExchange, body)
}

// fakeServer serves the normal probe with a Go TLS server and answers a
// hand-built hello itself: pick sees the suites offered and returns the
// reply bytes, or nil to hand the hello to Go (which refuses what it does
// not know).
func fakeServer(t *testing.T, cfg *tls.Config, pick func(offered []uint16) []byte) int {
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
				body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
				if _, err := io.ReadFull(conn, body); err != nil {
					return
				}
				if reply := pick(offeredSuites(body[4:])); reply != nil {
					_, _ = conn.Write(reply)
					return
				}
				tc := tls.Server(&replayConn{Conn: conn, r: io.MultiReader(bytes.NewReader(hdr[:]), bytes.NewReader(body), conn)}, cfg)
				if tc.Handshake() == nil {
					_, _ = io.Copy(io.Discard, tc)
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// accepting picks the first offered suite that is in accept, at TLS 1.2.
func accepting(accept ...uint16) func([]uint16) []byte {
	return func(offered []uint16) []byte {
		for _, s := range offered {
			if contains(accept, s) {
				return record(serverHelloMsg(tls.VersionTLS12, s))
			}
		}
		return nil
	}
}

func TestClientHelloExtensions(t *testing.T) {
	h := clientHello(helloOptions{version: tls.VersionTLS12, suites: []uint16{0x0003}, serverName: "www.example.", extensions: true})
	if h[0] != 0x16 || h[1] != 0x03 || h[2] != 0x01 {
		t.Fatalf("record header %x, want handshake at 3.1", h[:3])
	}
	if h[9] != 0x03 || h[10] != 0x03 {
		t.Fatalf("client version %x, want 3.3", h[9:11])
	}
	if !bytes.Contains(h, []byte("www.example")) || bytes.Contains(h, []byte("www.example.")) {
		t.Fatal("server name missing or not trimmed")
	}
	if !bytes.Contains(h, []byte{0x00, 0x0d}) || !bytes.Contains(h, []byte{0x00, 0x0a}) {
		t.Fatal("signature_algorithms or supported_groups missing")
	}
	ip := clientHello(helloOptions{version: tls.VersionTLS12, suites: []uint16{0x0003}, serverName: "192.0.2.1", extensions: true})
	if bytes.Contains(ip, []byte("192.0.2.1")) {
		t.Fatal("an IP literal was sent as the server name")
	}
	if got := offeredSuites(h[9:]); len(got) != 1 || got[0] != 0x0003 {
		t.Fatalf("offered %x", got)
	}
}

func TestHandshakeReaderAcrossRecords(t *testing.T) {
	sh := serverHelloMsg(tls.VersionTLS12, 0x0033)
	kx := dheKeyExchange(1024)
	all := append(append([]byte{}, sh...), kx...)
	// Split in the middle of the second message.
	cut := len(sh) + 7
	stream := append(record(all[:cut]), record(all[cut:])...)
	rd := &handshakeReader{r: bytes.NewReader(stream)}
	typ, body, err := rd.next()
	if err != nil || typ != msgServerHello {
		t.Fatalf("first: %d %v", typ, err)
	}
	if h, ok := parseServerHello(body); !ok || h.suite != 0x0033 || h.version != tls.VersionTLS12 {
		t.Fatalf("server hello %+v %v", h, ok)
	}
	typ, body, err = rd.next()
	if err != nil || typ != msgServerKeyExchange {
		t.Fatalf("second: %d %v", typ, err)
	}
	if bits, ok := dhGroupBits(body); !ok || bits != 1024 {
		t.Fatalf("group %d %v, want 1024", bits, ok)
	}
	if _, _, err = rd.next(); err != errRefused {
		t.Fatalf("end of stream: %v, want refused", err)
	}
	alert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}
	if _, _, err := (&handshakeReader{r: bytes.NewReader(alert)}).next(); err != errRefused {
		t.Fatalf("alert: %v", err)
	}
	huge := []byte{0x16, 0x03, 0x03, 0xff, 0xff}
	if _, _, err := (&handshakeReader{r: bytes.NewReader(huge)}).next(); err != errRefused {
		t.Fatalf("oversized record: %v", err)
	}
}

func TestDHGroupBitsBounds(t *testing.T) {
	for _, bad := range [][]byte{nil, {0x00}, {0x00, 0x00}, {0x00, 0x04, 0x01}} {
		if _, ok := dhGroupBits(bad); ok {
			t.Errorf("%x parsed", bad)
		}
	}
	if bits, ok := dhGroupBits([]byte{0x00, 0x02, 0x00, 0xff}); !ok || bits != 8 {
		t.Fatalf("leading zero byte: %d %v", bits, ok)
	}
}

func TestRawClassesDetected(t *testing.T) {
	p := newPKI(t)
	leaf := rsaLeaf(t, p.inter)
	cases := []struct {
		name   string
		accept []uint16
		want   string
		suites string
	}{
		{"export suite", []uint16{0x0003}, "export", "TLS_RSA_EXPORT_WITH_RC4_40_MD5"},
		{"NULL and anonymous: the hello repeats without the class picked", []uint16{0xC010, 0x0034}, "null,anon", "TLS_ECDHE_RSA_WITH_NULL_SHA,TLS_DH_anon_WITH_AES_128_CBC_SHA"},
		{"DES", []uint16{0x0009}, "des", "TLS_RSA_WITH_DES_CBC_SHA"},
		{"a suite not offered is a refusal", nil, "", ""},
	}
	for _, c := range cases {
		cfg := serverConfig(leaf, p.inter)
		cfg.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
		cfg.MinVersion = tls.VersionTLS12
		accept := c.accept
		pick := func(offered []uint16) []byte {
			for _, s := range offered {
				if contains(accept, s) {
					return record(serverHelloMsg(tls.VersionTLS12, s))
				}
			}
			if c.want == "" && contains(offered, 0x0003) {
				// Answer the raw hello with a suite the client never offered.
				return record(serverHelloMsg(tls.VersionTLS12, 0xC02F))
			}
			return nil
		}
		r := req(fakeServer(t, cfg, pick), TLS)
		r.Legacy = true
		a := single(t, Probe(context.Background(), r))
		if !a.OK || !a.SuitesChecked || classes(a.Suites) != c.want || strings.Join(a.SuiteNames, ",") != c.suites || a.DHBits != 0 {
			t.Errorf("%s: ok %v checked %v classes %q names %v dh %d, want %q %q", c.name, a.OK, a.SuitesChecked, classes(a.Suites), a.SuiteNames, a.DHBits, c.want, c.suites)
		}
	}
}

func TestDHEGroupRead(t *testing.T) {
	p := newPKI(t)
	leaf := rsaLeaf(t, p.inter)
	for _, bits := range []int{1024, 2048} {
		cfg := serverConfig(leaf, p.inter)
		cfg.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
		cfg.MinVersion = tls.VersionTLS12
		pick := func(offered []uint16) []byte {
			if !contains(offered, 0x0033) {
				return nil
			}
			// ServerHello and an (empty) Certificate in one record, the
			// key exchange and ServerHelloDone in another.
			first := append(serverHelloMsg(tls.VersionTLS12, 0x0033), handshakeMsg(11, []byte{0, 0, 0})...)
			second := append(dheKeyExchange(bits), handshakeMsg(msgServerHelloDone, nil)...)
			return append(record(first), record(second)...)
		}
		r := req(fakeServer(t, cfg, pick), TLS)
		r.Legacy = true
		a := single(t, Probe(context.Background(), r))
		if !a.OK || !a.SuitesChecked || a.DHBits != bits || len(a.Suites) != 0 {
			t.Errorf("%d bits: ok %v checked %v dh %d classes %v", bits, a.OK, a.SuitesChecked, a.DHBits, a.Suites)
		}
	}
}

// A server that accepts a DHE suite but closes before the key exchange
// still counts as accepting it, with the group unknown.
func TestDHEWithoutKeyExchange(t *testing.T) {
	p := newPKI(t)
	cfg := serverConfig(rsaLeaf(t, p.inter), p.inter)
	cfg.MinVersion = tls.VersionTLS12
	port := fakeServer(t, cfg, accepting(0x0039))
	reply, err := rawHandshake(context.Background(), req(port, TLS), net.ParseIP("127.0.0.1"), helloOptions{version: tls.VersionTLS12, suites: dheSuites, extensions: true}, true)
	if err != nil || reply == nil || reply.hello.suite != 0x0039 || reply.dhBits != 0 {
		t.Fatalf("reply %+v err %v", reply, err)
	}
}

func TestSuiteNames(t *testing.T) {
	if suiteName(0x0003) != "TLS_RSA_EXPORT_WITH_RC4_40_MD5" || suiteName(tls.TLS_RSA_WITH_RC4_128_SHA) != "TLS_RSA_WITH_RC4_128_SHA" || suiteName(0xFFFF) != "0xFFFF" {
		t.Fatalf("%q %q %q", suiteName(0x0003), suiteName(tls.TLS_RSA_WITH_RC4_128_SHA), suiteName(0xFFFF))
	}
	for _, c := range RawClasses {
		for _, s := range c.Suites() {
			if _, ok := rawSuiteNames[s]; !ok {
				t.Errorf("%s: suite %04X has no name", c, s)
			}
			if got, _ := classOf(s); got != c {
				t.Errorf("suite %04X in %s classified as %s", s, c, got)
			}
		}
	}
	for _, s := range dheSuites {
		if _, ok := rawSuiteNames[s]; !ok {
			t.Errorf("DHE suite %04X has no name", s)
		}
	}
}
