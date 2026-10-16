package probe

import (
	"context"
	"crypto/tls"
	"net"
)

// SuiteClass is one class of cipher suites the configuration test offers
// on its own, so that a completed handshake proves the server accepts it.
type SuiteClass string

// The classes, in the order they are tested and reported. See the
// specification, "TLS configuration grade".
const (
	ClassRC4   SuiteClass = "rc4"      // broken cipher, RFC 7465
	Class3DES  SuiteClass = "3des"     // 64-bit blocks, Sweet32
	ClassNoPFS SuiteClass = "no_pfs"   // RSA key exchange: no forward secrecy
	ClassCBC   SuiteClass = "cbc_sha1" // ECDHE with CBC and a SHA-1 MAC: not AEAD
)

// SuiteClasses lists every class, in test order.
var SuiteClasses = []SuiteClass{ClassRC4, Class3DES, ClassNoPFS, ClassCBC}

// Label is the class as shown to people.
func (c SuiteClass) Label() string {
	switch c {
	case ClassRC4:
		return "RC4"
	case Class3DES:
		return "3DES"
	case ClassNoPFS:
		return "no forward secrecy"
	case ClassCBC:
		return "CBC with SHA-1"
	}
	return string(c)
}

// Suites are the cipher suites offered for a class, all TLS 1.2 or older.
// Go's client offers no export, NULL, anonymous or DES suites, so those
// cannot be tested for.
func (c SuiteClass) Suites() []uint16 {
	switch c {
	case ClassRC4:
		return []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA}
	case Class3DES:
		return []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA}
	case ClassNoPFS:
		return []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA, tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384}
	case ClassCBC:
		return []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}
	}
	return nil
}

// ParseSuiteClass returns the class named s, or false.
func ParseSuiteClass(s string) (SuiteClass, bool) {
	for _, c := range SuiteClasses {
		if string(c) == s {
			return c, true
		}
	}
	return "", false
}

// probeSuites tests each suite class with one handshake pinned to TLS 1.2
// that offers only that class. A completed handshake means accepted and
// names the suite; a refused one means not accepted; a handshake that
// could not be attempted (connect, STARTTLS or a timeout) leaves the test
// unchecked, and it is repeated on the next check. A server that only
// speaks TLS 1.3 refuses every pinned 1.2 handshake and is judged on that.
func probeSuites(ctx context.Context, req Request, ip net.IP) ([]SuiteClass, []string, bool) {
	var accepted []SuiteClass
	var suites []string
	checked := true
	for _, c := range SuiteClasses {
		suite, ok, err := handshakeSuites(ctx, req, ip, c.Suites())
		switch {
		case ok:
			accepted = append(accepted, c)
			suites = append(suites, suite)
		case err != nil:
			checked = false
		}
	}
	return accepted, suites, checked
}

// handshakeSuites reports whether the address completes a TLS 1.2 handshake
// offering only ids, and the suite it picked. A refused handshake is
// (false, nil); err is set when no verdict was reached.
func handshakeSuites(ctx context.Context, req Request, ip net.IP, ids []uint16) (string, bool, error) {
	cfg := clientConfig(req.ServerName)
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	cfg.CipherSuites = ids
	st, err := handshakeWith(ctx, req, ip, cfg)
	if err != nil || st == nil {
		return "", false, err
	}
	return tls.CipherSuiteName(st.CipherSuite), true, nil
}
