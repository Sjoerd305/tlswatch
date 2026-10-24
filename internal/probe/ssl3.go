package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
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

// ssl3ClientHello builds a ClientHello record at version 3.0 without
// extensions, which SSL 3.0 does not have.
func ssl3ClientHello() []byte {
	return clientHello(helloOptions{version: VersionSSL30, suites: ssl3Suites})
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
		return false, verdict(ctx, refusedUnlessTimeout(err))
	}
	ok, err := ssl3ServerHello(conn)
	if err != nil {
		return false, verdict(ctx, err)
	}
	return ok, nil
}

// ssl3ServerHello reads the server's first handshake message and reports
// whether it is a ServerHello at version 3.0. The record header's version
// is not judged: some servers put the negotiated version there, others
// the highest they speak. A refusal is (false, nil).
func ssl3ServerHello(r io.Reader) (bool, error) {
	typ, body, err := (&handshakeReader{r: r}).next()
	if err != nil {
		return false, verdict(context.Background(), err)
	}
	sh, ok := parseServerHello(body)
	return typ == msgServerHello && ok && sh.version == VersionSSL30, nil
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
