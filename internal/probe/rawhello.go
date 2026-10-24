package probe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"slices"
	"strings"
)

// Go's client offers only the cipher suites it implements, so whether a
// server accepts an export, NULL, anonymous or DES suite, or what size of
// Diffie-Hellman group it uses for DHE, cannot be learnt from a Go
// handshake. This file speaks just enough of the record layer to send a
// hand-built ClientHello and read the server's first handshake messages:
// the ServerHello names the suite the server picked, and for a DHE suite
// the ServerKeyExchange carries the group. The handshake is never
// finished. SSL 3.0 (ssl3.go) uses the same builder and reader.

// Lengths the reader accepts: one record, and the handshake messages read
// in all (a chain in a Certificate message is a few tens of KiB).
const (
	maxRecord    = 1<<14 + 2048
	maxHandshake = 256 << 10
)

// Handshake message types.
const (
	msgClientHello       = 1
	msgServerHello       = 2
	msgServerKeyExchange = 12
	msgServerHelloDone   = 14
)

// errRefused is the reader's verdict when the server answered with an
// alert, closed the connection, or sent something that is not a handshake.
var errRefused = errors.New("refused")

// helloOptions shape a ClientHello.
type helloOptions struct {
	version    uint16   // the client version offered
	suites     []uint16 // in preference order
	serverName string   // the SNI name; "" sends none
	extensions bool     // signature_algorithms, supported_groups, SNI; off for SSL 3.0
}

// clientHello builds one ClientHello record. The record header carries
// version 3.1 for a TLS hello, as every client does, and 3.0 for SSL 3.0.
func clientHello(o helloOptions) []byte {
	var random [32]byte
	_, _ = rand.Read(random[:])
	body := binary.BigEndian.AppendUint16(nil, o.version)
	body = append(body, random[:]...)
	body = append(body, 0) // no session ID
	body = binary.BigEndian.AppendUint16(body, u16(2*len(o.suites)))
	for _, s := range o.suites {
		body = binary.BigEndian.AppendUint16(body, s)
	}
	body = append(body, 1, 0) // one compression method: null
	if o.extensions {
		body = append(body, helloExtensions(o.serverName)...)
	}
	hs := append([]byte{msgClientHello, 0}, binary.BigEndian.AppendUint16(nil, u16(len(body)))...)
	hs = append(hs, body...)
	recVersion := uint16(0x0301)
	if o.version < 0x0301 {
		recVersion = o.version
	}
	rec := binary.BigEndian.AppendUint16([]byte{0x16}, recVersion)
	rec = binary.BigEndian.AppendUint16(rec, u16(len(hs)))
	return append(rec, hs...)
}

// helloExtensions are the extensions a TLS 1.2 server needs to pick any of
// the offered suites: the server name for virtual hosting, the signature
// algorithms it may sign the key exchange with (RSA, ECDSA and DSA, SHA-1
// included for old servers), the curves and finite-field groups, and the
// uncompressed point format.
func helloExtensions(serverName string) []byte {
	var ext []byte
	add := func(typ uint16, data []byte) {
		ext = binary.BigEndian.AppendUint16(ext, typ)
		ext = binary.BigEndian.AppendUint16(ext, u16(len(data)))
		ext = append(ext, data...)
	}
	if name := strings.TrimSuffix(serverName, "."); name != "" && net.ParseIP(name) == nil {
		entry := append([]byte{0}, binary.BigEndian.AppendUint16(nil, u16(len(name)))...)
		entry = append(entry, name...)
		add(0, append(binary.BigEndian.AppendUint16(nil, u16(len(entry))), entry...))
	}
	groups := []uint16{29, 23, 24, 25, 256, 257} // x25519, P-256, P-384, P-521, ffdhe2048, ffdhe3072
	var g []byte
	for _, id := range groups {
		g = binary.BigEndian.AppendUint16(g, id)
	}
	add(10, append(binary.BigEndian.AppendUint16(nil, u16(len(g))), g...))
	add(11, []byte{1, 0}) // ec_point_formats: uncompressed
	sigs := []uint16{0x0804, 0x0401, 0x0501, 0x0601, 0x0201, 0x0403, 0x0503, 0x0603, 0x0203, 0x0402, 0x0202}
	var s []byte
	for _, id := range sigs {
		s = binary.BigEndian.AppendUint16(s, id)
	}
	add(13, append(binary.BigEndian.AppendUint16(nil, u16(len(s))), s...))
	return append(binary.BigEndian.AppendUint16(nil, u16(len(ext))), ext...)
}

// u16 is a length as a 16-bit field. Every length in a hello comes from
// the fixed suite and extension lists and a host name, a few hundred bytes;
// one that did not fit would be a programming error, hence the panic.
func u16(n int) uint16 {
	if n < 0 || n > 0xFFFF {
		panic("hello: length does not fit a 16-bit field")
	}
	return uint16(n)
}

// handshakeReader reads handshake messages off the record layer, across
// record boundaries.
type handshakeReader struct {
	r     io.Reader
	hs    []byte // handshake bytes received and not yet consumed
	total int
}

// next returns the next handshake message. errRefused means the server
// did not go on with a handshake: an alert, a close, a non-handshake
// record, or more bytes than any server hello flight needs. Any other
// error is a timeout, and so no verdict.
func (h *handshakeReader) next() (typ byte, body []byte, err error) {
	for {
		if len(h.hs) >= 4 {
			n := int(h.hs[1])<<16 | int(h.hs[2])<<8 | int(h.hs[3])
			if len(h.hs) >= 4+n {
				typ, body = h.hs[0], h.hs[4:4+n]
				h.hs = h.hs[4+n:]
				return typ, body, nil
			}
		}
		var hdr [5]byte
		if _, err := io.ReadFull(h.r, hdr[:]); err != nil {
			return 0, nil, refusedUnlessTimeout(err)
		}
		// 0x16 is a handshake record; 0x15 is an alert, and anything else
		// (a plaintext banner, an HTTP reply) is not TLS at all.
		if hdr[0] != 0x16 || hdr[1] != 0x03 {
			return 0, nil, errRefused
		}
		n := int(binary.BigEndian.Uint16(hdr[3:]))
		h.total += n
		if n > maxRecord || h.total > maxHandshake {
			return 0, nil, errRefused
		}
		rec := make([]byte, n)
		if _, err := io.ReadFull(h.r, rec); err != nil {
			return 0, nil, refusedUnlessTimeout(err)
		}
		h.hs = append(h.hs, rec...)
	}
}

// refusedUnlessTimeout keeps a timeout as it is and makes every other read
// or write error a refusal: the server closed or reset the connection.
func refusedUnlessTimeout(err error) error {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return errRefused
}

// serverHello is what the ServerHello says.
type serverHello struct {
	version uint16
	suite   uint16
}

// parseServerHello reads version and suite out of a ServerHello body.
func parseServerHello(body []byte) (serverHello, bool) {
	// version(2) random(32) session_id<0..32> suite(2) compression(1)
	if len(body) < 35 {
		return serverHello{}, false
	}
	sid := int(body[34])
	if len(body) < 35+sid+3 {
		return serverHello{}, false
	}
	return serverHello{version: binary.BigEndian.Uint16(body), suite: binary.BigEndian.Uint16(body[35+sid:])}, true
}

// dhGroupBits reads the size of the prime out of a DHE ServerKeyExchange:
// dh_p<1..2^16-1> comes first.
func dhGroupBits(body []byte) (int, bool) {
	if len(body) < 2 {
		return 0, false
	}
	n := int(binary.BigEndian.Uint16(body))
	if n == 0 || len(body) < 2+n {
		return 0, false
	}
	return new(big.Int).SetBytes(body[2 : 2+n]).BitLen(), true
}

// rawReply is what a raw hello learnt: the suite the server picked, and
// for a DHE suite the group size, 0 when it was not read.
type rawReply struct {
	hello  serverHello
	dhBits int
}

// rawHandshake sends a hello built from o and reads the server's answer.
// A nil reply means refused: the server did not pick one of the offered
// suites. With readKX it goes on to the ServerKeyExchange for the group
// size. err is set when no verdict was reached: connect, STARTTLS, a
// timeout.
func rawHandshake(ctx context.Context, req Request, ip net.IP, o helloOptions, readKX bool) (*rawReply, error) {
	conn, done, err := connect(ctx, req, ip)
	if err != nil {
		return nil, err
	}
	defer done()
	if _, err := conn.Write(clientHello(o)); err != nil {
		return nil, verdict(ctx, refusedUnlessTimeout(err))
	}
	rd := &handshakeReader{r: conn}
	typ, body, err := rd.next()
	if err != nil {
		return nil, verdict(ctx, err)
	}
	sh, ok := parseServerHello(body)
	if typ != msgServerHello || !ok || !contains(o.suites, sh.suite) {
		return nil, nil
	}
	reply := &rawReply{hello: sh}
	if !readKX {
		return reply, nil
	}
	// The flight is ServerHello, Certificate, ServerKeyExchange, maybe a
	// CertificateRequest, ServerHelloDone. Stop at the exchange or the
	// end; a server that closes after the hello still accepted the suite.
	for range 8 {
		typ, body, err = rd.next()
		if err != nil {
			if errors.Is(err, errRefused) {
				return reply, nil
			}
			return nil, verdict(ctx, err)
		}
		if typ == msgServerKeyExchange {
			reply.dhBits, _ = dhGroupBits(body)
			return reply, nil
		}
		if typ == msgServerHelloDone {
			return reply, nil
		}
	}
	return reply, nil
}

// verdict turns a reader error into the caller's: a refusal is (nil, nil)
// there, so it becomes nil; a timeout or the context's cancellation stays
// an error.
func verdict(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, errRefused) {
		return nil
	}
	return err
}

func contains(ids []uint16, id uint16) bool { return slices.Contains(ids, id) }

// suiteName names a cipher suite by its IANA name: the raw hellos' own
// table first, then Go's, which shows an unknown one as its number.
func suiteName(id uint16) string {
	if n, ok := rawSuiteNames[id]; ok {
		return n
	}
	return tls.CipherSuiteName(id)
}
