// Package probe connects to TLS endpoints, captures the presented chain and
// verifies it. It has no database access, so a node (internal/node) runs it
// unchanged inside another network.
package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Protocol is how the TLS session is started on a connection.
type Protocol string

const (
	TLS      Protocol = "tls"
	SMTP     Protocol = "smtp"
	IMAP     Protocol = "imap"
	POP3     Protocol = "pop3"
	FTP      Protocol = "ftp"
	Postgres Protocol = "postgres"
)

// Protocols lists every supported protocol in display order.
var Protocols = []Protocol{TLS, SMTP, IMAP, POP3, FTP, Postgres}

// DefaultPort returns the conventional port for p, 0 when unknown.
func DefaultPort(p Protocol) int {
	switch p {
	case TLS:
		return 443
	case SMTP:
		return 587
	case IMAP:
		return 143
	case POP3:
		return 110
	case FTP:
		return 21
	case Postgres:
		return 5432
	}
	return 0
}

// ParseProtocol accepts a protocol name, case-insensitively.
func ParseProtocol(s string) (Protocol, error) {
	p := Protocol(strings.ToLower(strings.TrimSpace(s)))
	if DefaultPort(p) == 0 {
		return "", fmt.Errorf("unknown protocol %q", s)
	}
	return p, nil
}

// TrustMode says what the chain is verified against.
type TrustMode string

const (
	TrustSystem     TrustMode = "system"
	TrustBundle     TrustMode = "bundle"
	TrustSelfSigned TrustMode = "self-signed"
)

// Request describes one probe of one target.
type Request struct {
	Host     string
	Port     int
	Protocol Protocol
	// ServerName is sent in SNI and checked against the certificate; empty
	// means no SNI and no hostname check.
	ServerName string
	Trust      TrustMode
	Roots      *x509.CertPool // for TrustBundle; nil means the system pool for TrustSystem
	FirstOnly  bool
	Timeout    time.Duration // per attempt, connect plus handshake; default 10 s
	Retries    int           // extra attempts per address after a connect or handshake error
	AllowLocal bool          // allow loopback, link-local and unspecified addresses
	// Allow, when set, refuses an address it returns an error for; a node
	// uses it for its own allowlist.
	Allow func(net.IP) error
	// Legacy runs the configuration test on every answering address: one
	// handshake per legacy version (TLS 1.0 and 1.1) pinned to it, then one
	// pinned to TLS 1.2 per cipher suite class (see SuiteClasses).
	Legacy   bool
	Resolver *net.Resolver
	Now      func() time.Time
}

// ErrorKind classifies a failed address.
type ErrorKind string

const (
	ErrNone      ErrorKind = ""
	ErrConnect   ErrorKind = "connect"
	ErrHandshake ErrorKind = "handshake"
	ErrStartTLS  ErrorKind = "starttls_unavailable"
	ErrRefused   ErrorKind = "refused" // address not allowed as a target
)

// Address is the result for one resolved address.
type Address struct {
	IP         string
	OK         bool
	ErrorKind  ErrorKind
	Error      string
	TLSVersion string
	Cipher     string
	// Group is the key exchange group the handshake negotiated
	// ("X25519MLKEM768", "X25519"), "" when the connection state names none.
	Group string
	Chain []*x509.Certificate // as presented, leaf first
	// Verified reports whether the chain is trusted under the trust mode,
	// independent of expiry (expiry is reported separately by the checker).
	// Not attempted for TrustSelfSigned.
	Verified        bool
	VerifyError     string
	VerifiedChain   []*x509.Certificate // includes the root when Verified
	HostnameChecked bool
	HostnameOK      bool
	Duration        time.Duration
	// LegacyChecked reports whether every version in LegacyVersions got a
	// verdict; Legacy lists the ones the address accepted.
	LegacyChecked bool
	Legacy        []string
	// SuitesChecked reports whether every class in SuiteClasses got a
	// verdict; Suites lists the classes the address accepted, and
	// SuiteNames the suite it picked for each, in the same order.
	SuitesChecked bool
	Suites        []SuiteClass
	SuiteNames    []string
	// PQChecked reports whether the post-quantum handshake of the
	// configuration test got a verdict; PQ whether it completed.
	PQChecked bool
	PQ        bool
	// OCSP is the OCSP response the server stapled, DER; nil when none.
	// StapleOf judges it.
	OCSP []byte
}

// LegacyVersions are the deprecated TLS versions Request.Legacy tests for,
// oldest first (RFC 8996). Go has no SSL 3.0 client, so that is not tested.
var LegacyVersions = []uint16{tls.VersionTLS10, tls.VersionTLS11}

// Result is the outcome of one probe of one target.
type Result struct {
	Host        string
	Port        int
	Protocol    Protocol
	ServerName  string
	StartedAt   time.Time
	Duration    time.Duration
	DNSError    string // set when the name did not resolve
	Addresses   []Address
	SkippedIPv6 []string // AAAA records skipped: this host has no IPv6 route
}

const (
	maxAddresses   = 8
	defaultTimeout = 10 * time.Second
	retryBackoff   = 500 * time.Millisecond
)

// Probe resolves the host and probes each address in parallel.
func Probe(ctx context.Context, req Request) Result {
	start := time.Now()
	if req.Timeout <= 0 {
		req.Timeout = defaultTimeout
	}
	if req.Protocol == "" {
		req.Protocol = TLS
	}
	if req.Now == nil {
		req.Now = time.Now
	}
	res := Result{Host: req.Host, Port: req.Port, Protocol: req.Protocol, ServerName: req.ServerName, StartedAt: start}

	ips, err := resolve(ctx, req)
	if err != nil {
		res.DNSError = err.Error()
		res.Duration = time.Since(start)
		return res
	}
	if req.FirstOnly && len(ips) > 1 {
		ips = ips[:1]
	}
	if len(ips) > maxAddresses {
		ips = ips[:maxAddresses]
	}

	addrs := make([]Address, len(ips))
	skipped := make([]bool, len(ips))
	var wg sync.WaitGroup
	for i, ip := range ips {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs[i], skipped[i] = probeAddress(ctx, req, ip)
		}()
	}
	wg.Wait()
	for i, a := range addrs {
		if skipped[i] {
			res.SkippedIPv6 = append(res.SkippedIPv6, a.IP)
			continue
		}
		res.Addresses = append(res.Addresses, a)
	}
	res.Duration = time.Since(start)
	return res
}

func resolve(ctx context.Context, req Request) ([]net.IP, error) {
	host := strings.TrimSuffix(req.Host, ".")
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return []net.IP{ip}, nil
	}
	r := req.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	lctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	found, err := r.LookupIPAddr(lctx, host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			if dnsErr.IsNotFound {
				return nil, fmt.Errorf("%s: no such host", host)
			}
			if dnsErr.IsTimeout {
				return nil, fmt.Errorf("%s: DNS lookup timed out", host)
			}
		}
		return nil, err
	}
	var v4, v6 []net.IP
	seen := map[string]bool{}
	for _, a := range found {
		if seen[a.IP.String()] {
			continue
		}
		seen[a.IP.String()] = true
		if a.IP.To4() != nil {
			v4 = append(v4, a.IP)
		} else {
			v6 = append(v6, a.IP)
		}
	}
	ips := append(v4, v6...)
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s: no addresses", host)
	}
	return ips, nil
}

func probeAddress(ctx context.Context, req Request, ip net.IP) (Address, bool) {
	if !req.AllowLocal && IsLocalIP(ip) {
		return Address{IP: ip.String(), ErrorKind: ErrRefused, Error: "loopback and link-local addresses are not allowed as targets"}, false
	}
	if req.Allow != nil {
		if err := req.Allow(ip); err != nil {
			return Address{IP: ip.String(), ErrorKind: ErrRefused, Error: err.Error()}, false
		}
	}
	var a Address
	for attempt := 0; attempt <= max(req.Retries, 0); attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return a, false
			case <-time.After(retryBackoff):
			}
		}
		var err error
		a, err = probeOnce(ctx, req, ip)
		if a.OK || (a.ErrorKind != ErrConnect && a.ErrorKind != ErrHandshake) {
			break
		}
		if attempt == 0 && a.ErrorKind == ErrConnect && ip.To4() == nil && isUnreachable(err) && !HasIPv6Route() {
			return a, true
		}
	}
	if a.OK && req.Legacy {
		a.Legacy, a.LegacyChecked = probeLegacy(ctx, req, ip, a.TLSVersion)
		a.Suites, a.SuiteNames, a.SuitesChecked = probeSuites(ctx, req, ip)
		a.PQ, a.PQChecked = probePQ(ctx, req, ip, a.Group)
	}
	return a, false
}

// probeLegacy tests each legacy version with a handshake pinned to it. The
// negotiated version settles some without a handshake: the server picked the
// highest version it shares with a client offering all of them. A version
// whose handshake could not be attempted (connect, STARTTLS or a timeout)
// leaves the result unchecked.
func probeLegacy(ctx context.Context, req Request, ip net.IP, negotiated string) ([]string, bool) {
	var neg uint16
	for _, w := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
		if tls.VersionName(w) == negotiated {
			neg = w
		}
	}
	var accepted []string
	checked := true
	for _, v := range LegacyVersions {
		name := tls.VersionName(v)
		switch {
		case neg == v:
			accepted = append(accepted, name)
			continue
		case neg != 0 && neg < v:
			continue
		}
		ok, err := handshakeVersion(ctx, req, ip, v)
		switch {
		case ok:
			accepted = append(accepted, name)
		case err != nil:
			checked = false
		}
	}
	return accepted, checked
}

// PQGroup is the post-quantum hybrid key exchange the configuration test
// offers on its own.
const PQGroup = tls.X25519MLKEM768

// probePQ tests whether the address negotiates post-quantum key exchange:
// one handshake at TLS 1.3 offering X25519MLKEM768 and nothing else. The
// normal probe settles it when it already negotiated that group. A
// handshake that could not be attempted leaves it unchecked.
func probePQ(ctx context.Context, req Request, ip net.IP, negotiated string) (pq, checked bool) {
	if negotiated == groupName(PQGroup) {
		return true, true
	}
	cfg := clientConfig(req.ServerName)
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	cfg.CurvePreferences = []tls.CurveID{PQGroup}
	st, err := handshakeWith(ctx, req, ip, cfg)
	if err != nil {
		return false, false
	}
	return st != nil, true
}

// groupName names a key exchange group, "" for none.
func groupName(id tls.CurveID) string {
	if id == 0 {
		return ""
	}
	return id.String()
}

// handshakeVersion reports whether the address completes a handshake at
// exactly version v. A refused handshake is (false, nil); err is set when
// no verdict was reached.
func handshakeVersion(ctx context.Context, req Request, ip net.IP, v uint16) (bool, error) {
	cfg := clientConfig(req.ServerName)
	cfg.MinVersion, cfg.MaxVersion = v, v
	st, err := handshakeWith(ctx, req, ip, cfg)
	return st != nil, err
}

// handshakeWith connects, runs the protocol's STARTTLS and a handshake with
// cfg, and returns the connection state when it completed. A refused
// handshake (an alert, a closed connection) is (nil, nil); err is set when
// no verdict was reached: connect, STARTTLS or a timeout.
func handshakeWith(ctx context.Context, req Request, ip net.IP, cfg *tls.Config) (*tls.ConnectionState, error) {
	start := time.Now()
	d := net.Dialer{Timeout: req.Timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(req.Port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(start.Add(req.Timeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if err := startTLS(conn, req.Protocol); err != nil {
		return nil, err
	}
	tc := tls.Client(conn, cfg)
	err = tc.HandshakeContext(ctx)
	if err == nil {
		st := tc.ConnectionState()
		return &st, nil
	}
	var ne net.Error
	if ctx.Err() != nil || errors.As(err, &ne) && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, err
	}
	return nil, nil
}

func probeOnce(ctx context.Context, req Request, ip net.IP) (Address, error) {
	start := time.Now()
	a := Address{IP: ip.String()}
	fail := func(kind ErrorKind, err error) (Address, error) {
		a.ErrorKind, a.Error, a.Duration = kind, cleanError(err, req.Timeout), time.Since(start)
		return a, err
	}

	d := net.Dialer{Timeout: req.Timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(req.Port)))
	if err != nil {
		return fail(ErrConnect, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(start.Add(req.Timeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if err := startTLS(conn, req.Protocol); err != nil {
		var nf *notOffered
		if errors.As(err, &nf) {
			return fail(ErrStartTLS, err)
		}
		return fail(ErrHandshake, err)
	}

	tc := tls.Client(conn, clientConfig(req.ServerName))
	if err := tc.HandshakeContext(ctx); err != nil {
		return fail(ErrHandshake, err)
	}
	st := tc.ConnectionState()
	a.Duration = time.Since(start)
	if len(st.PeerCertificates) == 0 {
		return fail(ErrHandshake, errors.New("server presented no certificate"))
	}
	a.OK = true
	a.TLSVersion = tls.VersionName(st.Version)
	a.Cipher = tls.CipherSuiteName(st.CipherSuite)
	a.Group = groupName(st.CurveID)
	a.Chain = st.PeerCertificates
	a.OCSP = st.OCSPResponse
	verify(&a, req)
	return a, nil
}

var cipherSuites = func() []uint16 {
	var ids []uint16
	for _, list := range [][]*tls.CipherSuite{tls.CipherSuites(), tls.InsecureCipherSuites()} {
		for _, s := range list {
			for _, v := range s.SupportedVersions {
				if v <= tls.VersionTLS12 {
					ids = append(ids, s.ID)
					break
				}
			}
		}
	}
	return ids
}()

// clientConfig accepts TLS 1.0 and every cipher suite Go still implements so
// that old appliances can be monitored; verification is done afterwards.
func clientConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName:         strings.TrimSuffix(serverName, "."),
		InsecureSkipVerify: true, // #nosec G402 -- the chain is verified explicitly in verify()
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       cipherSuites,
	}
}

// Verify recomputes the hostname check and the chain verification of an
// address that answered, from its chain and the request. The server runs it
// on a chain a node captured, so bundle trust and the hostname are judged
// in one place.
func Verify(a *Address, req Request) {
	if !a.OK || len(a.Chain) == 0 {
		return
	}
	if req.Now == nil {
		req.Now = time.Now
	}
	a.HostnameChecked, a.HostnameOK = false, false
	a.Verified, a.VerifyError, a.VerifiedChain = false, "", nil
	verify(a, req)
}

// CheckHostname reports whether the hostname is checked (a server name is
// set) and whether the leaf covers it.
func CheckHostname(leaf *x509.Certificate, serverName string) (checked, ok bool) {
	if serverName == "" {
		return false, false
	}
	return true, leaf.VerifyHostname(strings.TrimSuffix(serverName, ".")) == nil
}

func verify(a *Address, req Request) {
	leaf := a.Chain[0]
	a.HostnameChecked, a.HostnameOK = CheckHostname(leaf, req.ServerName)
	if req.Trust == TrustSelfSigned {
		return
	}
	roots := req.Roots
	if req.Trust == TrustBundle && roots == nil {
		roots = x509.NewCertPool()
	}
	inter := x509.NewCertPool()
	for _, c := range a.Chain[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   req.Now(),
		// A leaf (or chain) restricted to client authentication is not a
		// valid server certificate, as a browser would also refuse it. A
		// leaf without the extension is valid for any use.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	chains, err := leaf.Verify(opts)
	var inv x509.CertificateInvalidError
	if err != nil && errors.As(err, &inv) && inv.Reason == x509.Expired {
		// Judge trust apart from expiry: verify at a moment inside the
		// validity window of every presented certificate. A root from the
		// store may have expired before that moment: then try its last
		// second too, so the verdict is about trust, and check reports the
		// expiry.
		for _, t := range validMoments(a.Chain) {
			opts.CurrentTime = t
			for range 3 {
				if chains, err = leaf.Verify(opts); err == nil || !errors.As(err, &inv) || inv.Reason != x509.Expired ||
					inv.Cert == nil || !inv.Cert.NotAfter.Before(opts.CurrentTime) || inv.Cert.NotAfter.Before(leaf.NotBefore) {
					break
				}
				opts.CurrentTime = inv.Cert.NotAfter.Add(-time.Second)
			}
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		a.VerifyError = err.Error()
		return
	}
	best := chains[0]
	for _, c := range chains[1:] {
		if len(c) < len(best) {
			best = c
		}
	}
	a.Verified = true
	a.VerifiedChain = best
}

// validMoments returns candidate verification times: the last second at
// which every presented certificate was valid, and the leaf's last second.
func validMoments(chain []*x509.Certificate) []time.Time {
	var from, to time.Time
	for i, c := range chain {
		if i == 0 || c.NotBefore.After(from) {
			from = c.NotBefore
		}
		if i == 0 || c.NotAfter.Before(to) {
			to = c.NotAfter
		}
	}
	var ts []time.Time
	if t := to.Add(-time.Second); !t.Before(from) {
		ts = append(ts, t)
	}
	return append(ts, chain[0].NotAfter.Add(-time.Second))
}

func cleanError(err error, timeout time.Duration) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Sprintf("timed out after %s", timeout)
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return err.Error()
}

func isUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.EADDRNOTAVAIL) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "network is unreachable") || strings.Contains(s, "no route to host")
}

var v6route struct {
	sync.Mutex
	checked time.Time
	ok      bool
}

// HasIPv6Route reports whether this host has a global IPv6 route, cached
// for a minute. A UDP "dial" sends nothing; it only asks the kernel for a
// route.
func HasIPv6Route() bool {
	v6route.Lock()
	defer v6route.Unlock()
	if time.Since(v6route.checked) < time.Minute {
		return v6route.ok
	}
	c, err := net.Dial("udp6", "[2001:4860:4860::8888]:53")
	v6route.ok = err == nil
	if c != nil {
		_ = c.Close()
	}
	v6route.checked = time.Now()
	return v6route.ok
}

// Fingerprint returns the lowercase hex SHA-256 of the certificate's DER.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// IsLocalIP reports loopback, link-local and unspecified addresses.
func IsLocalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// ValidateHost accepts an IP literal or a DNS name (RFC 1123 labels, an
// optional trailing dot, at most 253 characters).
func ValidateHost(h string) error {
	if h == "" {
		return errors.New("host is empty")
	}
	if net.ParseIP(h) != nil {
		return nil
	}
	name := strings.TrimSuffix(h, ".")
	if name == "" || len(name) > 253 {
		return fmt.Errorf("%q is not a valid host name", h)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%q is not a valid host name", h)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("%q is not a valid host name", h)
			}
		}
	}
	return nil
}
