package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"net"
	"slices"
	"time"
)

// A server can hold more than one certificate for a name and pick by what
// the client offers, so the normal probe sees only one of them. The
// configuration test asks for the others in two ways:
//
//   - by key type: a server with an RSA and an ECDSA certificate picks by
//     the client's suites and signature algorithms, so a TLS 1.2 handshake
//     offering only the suites of the other key type gets the other
//     certificate, the one clients without ECDSA (or without RSA) see;
//   - without SNI: the certificate a client gets when it sends no server
//     name, the default of the virtual host setup.
//
// Every TLS 1.3 client supports both RSA and ECDSA (RFC 8446, 9.1), so the
// key type that matters is chosen at TLS 1.2; a server that speaks only
// TLS 1.3 refuses the pinned handshake and has no other certificate a
// client could get by key type.

// How an other chain was obtained.
const (
	ViaOtherKey = "other_key"
	ViaNoSNI    = "no_sni"
)

// OtherChain is a chain the address serves besides the one the normal
// probe got, verified and hostname-checked like it.
type OtherChain struct {
	Via             string
	Chain           []*x509.Certificate // as presented, leaf first
	Verified        bool
	VerifyError     string
	VerifiedChain   []*x509.Certificate
	HostnameChecked bool
	HostnameOK      bool
}

// Address is the other chain as an answered address at ip, for the
// certificate checks that judge addresses.
func (o OtherChain) Address(ip string) Address {
	return Address{IP: ip, OK: true, Chain: o.Chain, Verified: o.Verified, VerifyError: o.VerifyError,
		VerifiedChain: o.VerifiedChain, HostnameChecked: o.HostnameChecked, HostnameOK: o.HostnameOK}
}

// Judge sets the verdict fields of the other chain from the address judge
// leaves in a: the server calls it with its own verification, so a node
// reports chains but not trust.
func (o *OtherChain) Judge(judge func(*Address), ip string) {
	a := Address{IP: ip, OK: true, Chain: o.Chain}
	judge(&a)
	o.Verified, o.VerifyError, o.VerifiedChain = a.Verified, a.VerifyError, a.VerifiedChain
	o.HostnameChecked, o.HostnameOK = a.HostnameChecked, a.HostnameOK
}

// The TLS 1.2 suites that need an RSA certificate, and those that need an
// ECDSA (or Ed25519) one, among the suites Go implements.
var (
	rsaKeySuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	}
	ecdsaKeySuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	}
)

// probeOthers asks the address for its other certificates and returns the
// chains whose leaf differs from leaf. checked is false when a handshake
// could not be attempted (connect, STARTTLS or a timeout); a refused one
// means the server has no such certificate.
func probeOthers(ctx context.Context, req Request, ip net.IP, leaf *x509.Certificate) ([]OtherChain, bool) {
	var out []OtherChain
	checked := true
	fp := Fingerprint(leaf)
	try := func(via string, cfg *tls.Config) {
		st, err := handshakeWith(ctx, req, ip, cfg)
		switch {
		case err != nil:
			checked = false
		case st != nil && len(st.PeerCertificates) > 0 && Fingerprint(st.PeerCertificates[0]) != fp:
			o := OtherChain{Via: via, Chain: st.PeerCertificates}
			o.Judge(func(a *Address) { verify(a, req) }, ip.String())
			out = append(out, o)
		}
	}

	cfg := clientConfig(req.ServerName)
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	cfg.CipherSuites = ecdsaKeySuites
	if Describe(leaf).KeyType == "ECDSA" {
		cfg.CipherSuites = rsaKeySuites
	}
	try(ViaOtherKey, cfg)

	if NamedServer(req.ServerName) {
		try(ViaNoSNI, clientConfig(""))
	}
	return out, checked
}

// NamedServer reports whether name is sent in SNI: a DNS name, not empty
// and not an IP literal, which TLS does not send.
func NamedServer(name string) bool {
	return name != "" && net.ParseIP(name) == nil
}

// oidTLSFeature is the TLS feature extension (RFC 7633); status_request,
// feature 5, in it is OCSP must-staple.
var oidTLSFeature = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

// MustStaple reports whether the certificate requires a stapled OCSP
// response (RFC 7633 status_request).
func MustStaple(c *x509.Certificate) bool {
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidTLSFeature) {
			continue
		}
		var features []int
		if rest, err := asn1.Unmarshal(ext.Value, &features); err == nil && len(rest) == 0 && slices.Contains(features, 5) {
			return true
		}
	}
	return false
}

// stapleRetryDelay is how long the probe waits before asking again for the
// staple of a must-staple leaf that came without one. nginx and others
// fetch the response on the first handshake that needs it and staple from
// the next one on, so a server just restarted would otherwise report a
// missing staple it is about to send.
var stapleRetryDelay = 2 * time.Second

// restaple asks once more for the staple of a must-staple leaf the address
// served without one, and takes it when the same leaf comes back.
func restaple(ctx context.Context, req Request, ip net.IP, a *Address) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(stapleRetryDelay):
	}
	st, err := handshakeWith(ctx, req, ip, clientConfig(req.ServerName))
	if err != nil || st == nil || len(st.PeerCertificates) == 0 || !st.PeerCertificates[0].Equal(a.Chain[0]) {
		return
	}
	a.OCSP = st.OCSPResponse
}
