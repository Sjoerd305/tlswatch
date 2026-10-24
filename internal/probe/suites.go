package probe

import (
	"context"
	"crypto/tls"
	"net"
)

// SuiteClass is one class of cipher suites the configuration test offers
// on its own, so that a completed handshake proves the server accepts it.
type SuiteClass string

// The classes, in the order they are reported. The first four are suites
// Go's client does not implement, tested with a hand-built hello
// (rawhello.go); the other four with a Go handshake offering only that
// class. See the specification, "TLS configuration grade".
const (
	ClassExport SuiteClass = "export"   // 40- and 56-bit export suites (FREAK)
	ClassNull   SuiteClass = "null"     // no encryption at all
	ClassAnon   SuiteClass = "anon"     // anonymous DH or ECDH: no authentication
	ClassDES    SuiteClass = "des"      // single DES, 56-bit
	ClassRC4    SuiteClass = "rc4"      // broken cipher, RFC 7465
	Class3DES   SuiteClass = "3des"     // 64-bit blocks, Sweet32
	ClassNoPFS  SuiteClass = "no_pfs"   // RSA key exchange: no forward secrecy
	ClassCBC    SuiteClass = "cbc_sha1" // ECDHE with CBC and a SHA-1 MAC: not AEAD
)

// SuiteClasses lists every class, in report order.
var SuiteClasses = []SuiteClass{ClassExport, ClassNull, ClassAnon, ClassDES, ClassRC4, Class3DES, ClassNoPFS, ClassCBC}

// RawClasses are the classes tested with a hand-built hello, in the order
// their suites are offered; GoClasses the ones a Go handshake tests.
var (
	RawClasses = []SuiteClass{ClassExport, ClassNull, ClassAnon, ClassDES}
	GoClasses  = []SuiteClass{ClassRC4, Class3DES, ClassNoPFS, ClassCBC}
)

// Label is the class as shown to people.
func (c SuiteClass) Label() string {
	switch c {
	case ClassExport:
		return "export-grade"
	case ClassNull:
		return "NULL encryption"
	case ClassAnon:
		return "anonymous key exchange"
	case ClassDES:
		return "DES"
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
func (c SuiteClass) Suites() []uint16 {
	switch c {
	case ClassExport:
		return []uint16{0x0003, 0x0006, 0x0008, 0x000B, 0x000E, 0x0011, 0x0014, 0x0017, 0x0019, 0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065}
	case ClassNull:
		return []uint16{0x0001, 0x0002, 0x003B, 0xC001, 0xC006, 0xC00B, 0xC010, 0xC015}
	case ClassAnon:
		return []uint16{0x0018, 0x001B, 0x0034, 0x003A, 0x006C, 0x006D, 0x00A6, 0x00A7, 0xC016, 0xC017, 0xC018, 0xC019}
	case ClassDES:
		return []uint16{0x0009, 0x000C, 0x000F, 0x0012, 0x0015}
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

// dheSuites are the DHE suites the group test offers, RSA- and DSS-signed,
// AES, ChaCha20 and 3DES. Go has none of them, so the group size a server
// uses for DHE can only be read from a raw ServerKeyExchange.
var dheSuites = []uint16{0x009F, 0x009E, 0xCCAA, 0x006B, 0x0067, 0x0039, 0x0033, 0x0016, 0x00A3, 0x00A2, 0x006A, 0x0040, 0x0038, 0x0032, 0x0013}

// rawSuiteNames are the IANA names of the suites the raw hellos offer.
var rawSuiteNames = map[uint16]string{
	0x0001: "TLS_RSA_WITH_NULL_MD5", 0x0002: "TLS_RSA_WITH_NULL_SHA", 0x003B: "TLS_RSA_WITH_NULL_SHA256",
	0xC001: "TLS_ECDH_ECDSA_WITH_NULL_SHA", 0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA", 0xC00B: "TLS_ECDH_RSA_WITH_NULL_SHA",
	0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA", 0xC015: "TLS_ECDH_anon_WITH_NULL_SHA",
	0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", 0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", 0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x000B: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", 0x000E: "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0011: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", 0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
	0x0017: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", 0x0019: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
	0x0060: "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5", 0x0061: "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5",
	0x0062: "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", 0x0063: "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
	0x0064: "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", 0x0065: "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
	0x0018: "TLS_DH_anon_WITH_RC4_128_MD5", 0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", 0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
	0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA", 0x006C: "TLS_DH_anon_WITH_AES_128_CBC_SHA256", 0x006D: "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
	0x00A6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256", 0x00A7: "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
	0xC016: "TLS_ECDH_anon_WITH_RC4_128_SHA", 0xC017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
	0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", 0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
	0x0009: "TLS_RSA_WITH_DES_CBC_SHA", 0x000C: "TLS_DH_DSS_WITH_DES_CBC_SHA", 0x000F: "TLS_DH_RSA_WITH_DES_CBC_SHA",
	0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA", 0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
	0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", 0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
	0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	0x00A3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", 0x00A2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
	0x006A: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", 0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
	0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", 0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", 0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
}

// classOf names the raw class a suite belongs to.
func classOf(id uint16) (SuiteClass, bool) {
	for _, c := range RawClasses {
		if contains(c.Suites(), id) {
			return c, true
		}
	}
	return "", false
}

// probeSuites runs the cipher suite part of the configuration test. The
// raw classes are offered together in one hello at TLS 1.2: a server that
// picks one of them accepts that class, and the hello is repeated without
// that class until the server refuses, so a clean server pays one hello
// and a bad one pays one per class it accepts. Each Go class then gets one
// handshake pinned to TLS 1.2 offering only that class; a completed one
// names the suite. Last, one hello offering only DHE suites reads the
// Diffie-Hellman group size from the ServerKeyExchange, 0 when the server
// does not do DHE. A refused handshake means not accepted; one that could
// not be attempted (connect, STARTTLS or a timeout) leaves the test
// unchecked, and it is repeated on the next check. A server that only
// speaks TLS 1.3 refuses every pinned 1.2 handshake and is judged on that.
func probeSuites(ctx context.Context, req Request, ip net.IP) (accepted []SuiteClass, suites []string, dhBits int, checked bool) {
	checked = true
	remaining := append([]SuiteClass{}, RawClasses...)
	for len(remaining) > 0 {
		var offer []uint16
		for _, c := range remaining {
			offer = append(offer, c.Suites()...)
		}
		reply, err := rawHandshake(ctx, req, ip, helloOptions{version: tls.VersionTLS12, suites: offer, serverName: req.ServerName, extensions: true}, false)
		if err != nil {
			checked = false
			break
		}
		if reply == nil {
			break
		}
		c, _ := classOf(reply.hello.suite)
		accepted = append(accepted, c)
		suites = append(suites, suiteName(reply.hello.suite))
		remaining = without(remaining, c)
	}
	for _, c := range GoClasses {
		suite, ok, err := handshakeSuites(ctx, req, ip, c.Suites())
		switch {
		case ok:
			accepted = append(accepted, c)
			suites = append(suites, suite)
		case err != nil:
			checked = false
		}
	}
	reply, err := rawHandshake(ctx, req, ip, helloOptions{version: tls.VersionTLS12, suites: dheSuites, serverName: req.ServerName, extensions: true}, true)
	switch {
	case err != nil:
		checked = false
	case reply != nil:
		dhBits = reply.dhBits
	}
	return accepted, suites, dhBits, checked
}

func without(cs []SuiteClass, drop SuiteClass) []SuiteClass {
	var out []SuiteClass
	for _, c := range cs {
		if c != drop {
			out = append(out, c)
		}
	}
	return out
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
