package probe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
)

// SSL 3.0 has no client in Go (removed in Go 1.14), so whether a server
// still accepts it is decided from its first reply to a hand-built
// ClientHello, as sslscan and testssl.sh do: a ServerHello at version
// 3.0 means accepted, an alert or a closed connection means refused. The
// handshake is never finished; the question is whether the version is on.

// VersionSSL30 is SSL 3.0 on the wire. Go's own constant is deprecated
// along with its client, so the probe names it itself.
const VersionSSL30 uint16 = 0x0300

// ssl3Suites are the cipher suites the SSL 3.0 ClientHello offers: every
// RSA and DHE suite of the era, export suites included, and the ECDHE
// suites OpenSSL accepted under SSL 3.0 even though RFC 4492 ties them to
// extensions. A server with SSL 3.0 on accepts at least one of them.
var ssl3Suites = []uint16{
	0xC014, 0xC013, 0xC00A, 0xC009, 0xC011, 0xC012, // ECDHE AES, RC4, 3DES
	0x0039, 0x0033, 0x0016, 0x0038, 0x0032, 0x0013, // DHE AES, 3DES
	0x0035, 0x002F, 0x000A, 0x0005, 0x0004, // RSA AES, 3DES, RC4
	0x0015, 0x0009, 0x0012, 0x0065, 0x0064, 0x0062, // DES, export 1024
	0x0003, 0x0006, 0x0008, 0x0014, 0x0011, // export 40-bit
	0x00FF, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
}

// ssl3MaxRecord bounds the server's first record: a ServerHello is a few
// hundred bytes, and the record layer caps at 16 KiB plus overhead.
const ssl3MaxRecord = 1<<14 + 2048

// ssl3ClientHello builds a ClientHello record at version 3.0 without
// extensions, which SSL 3.0 does not have.
func ssl3ClientHello() []byte {
	var random [32]byte
	_, _ = rand.Read(random[:])
	body := []byte{0x03, 0x00}
	body = append(body, random[:]...)
	body = append(body, 0) // no session ID
	body = binary.BigEndian.AppendUint16(body, u16(2*len(ssl3Suites)))
	for _, s := range ssl3Suites {
		body = binary.BigEndian.AppendUint16(body, s)
	}
	body = append(body, 1, 0) // one compression method: null
	hs := append([]byte{0x01, 0}, binary.BigEndian.AppendUint16(nil, u16(len(body)))...)
	hs = append(hs, body...)
	rec := binary.BigEndian.AppendUint16([]byte{0x16, 0x03, 0x00}, u16(len(hs)))
	return append(rec, hs...)
}

// u16 is a length as a 16-bit field. Every length in the hello comes from
// the fixed suite list and is a few hundred bytes; a change that pushed it
// over the field would be a programming error, hence the panic.
func u16(n int) uint16 {
	if n < 0 || n > 0xFFFF {
		panic("ssl3: length does not fit a 16-bit field")
	}
	return uint16(n)
}

// ssl3Accepts reports whether the address answers an SSL 3.0 ClientHello
// with a ServerHello at that version. A refused hello (an alert, a closed
// connection, anything that is not a 3.0 ServerHello) is (false, nil); err
// is set when no verdict was reached: connect, STARTTLS or a timeout.
func ssl3Accepts(ctx context.Context, req Request, ip net.IP) (bool, error) {
	conn, done, err := connect(ctx, req, ip)
	if err != nil {
		return false, err
	}
	defer done()
	if _, err := conn.Write(ssl3ClientHello()); err != nil {
		return false, noVerdict(ctx, err)
	}
	ok, err := ssl3ServerHello(conn)
	if err != nil {
		return false, noVerdict(ctx, err)
	}
	return ok, nil
}

// ssl3ServerHello reads the server's first record and reports whether it
// is a ServerHello at version 3.0. A read error other than a timeout is a
// refusal: the server closed or reset the connection. Only a timeout is
// returned.
func ssl3ServerHello(r io.Reader) (bool, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return false, timeoutOnly(err)
	}
	// 0x16 is a handshake record; 0x15 is an alert, and anything else
	// (a plaintext banner, an HTTP reply) is not SSL at all.
	if hdr[0] != 0x16 || hdr[1] != 0x03 {
		return false, nil
	}
	n := int(binary.BigEndian.Uint16(hdr[3:]))
	if n < 6 || n > ssl3MaxRecord {
		return false, nil
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return false, timeoutOnly(err)
	}
	// Handshake type 2 is ServerHello; its version follows the 3-byte
	// length. The record header's version is not judged: some servers put
	// the negotiated version there, others the highest they speak.
	return body[0] == 0x02 && body[4] == 0x03 && body[5] == 0x00, nil
}

// timeoutOnly keeps a timeout as an error and turns every other read or
// write error into a verdict of refused.
func timeoutOnly(err error) error {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return nil
}

// noVerdict is timeoutOnly with the context's cancellation counted as a
// timeout too.
func noVerdict(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return err
	}
	return timeoutOnly(err)
}

// VersionName names a TLS version the way the UI, the finding details
// and the stored results spell it: "SSL 3.0", "TLS 1.0". Go's own name
// for 3.0 is "SSLv3".
func VersionName(v uint16) string {
	if v == VersionSSL30 {
		return "SSL 3.0"
	}
	return tls.VersionName(v)
}
