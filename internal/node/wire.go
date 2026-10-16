// Package node lets tlswatch probe from inside a network the server cannot
// reach. A node is the same binary started as "tlswatch node": it holds no
// database and no schedule, long-polls the server over outbound HTTPS for
// jobs, runs them with internal/probe and posts the results back. This
// package holds both ends: the messages of protocol v1, the server-side
// dispatcher with the /agent/v1 handlers, and the node's client loop with
// its enrolment, system facts and self-update.
package node

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// Protocol is the version of the agent protocol, in the path of every call.
const Protocol = 1

// Prefix is the path of the protocol's calls.
const Prefix = "/agent/v1"

// Headers on the node's requests.
const (
	HeaderVersion     = "X-Tlswatch-Version"      // the node's tlswatch version, on every call
	HeaderUpdateError = "X-Tlswatch-Update-Error" // why the last self-update was rolled back
	HeaderSHA256      = "X-Tlswatch-Sha256"       // on a binary download: its SHA-256, hex
)

// Job kinds.
const (
	KindProbe  = "probe"
	KindCancel = "cancel"
	KindUpdate = "update"
)

// Timing of the protocol (see the specification's table).
const (
	PollCeiling   = 55 * time.Second  // the server answers a held poll by then
	ClientTimeout = 70 * time.Second  // the node gives up on a request after this
	OfflineAfter  = 165 * time.Second // no request for this long: offline
	FindingAfter  = 10 * time.Minute  // offline this long: node_offline opens
	FactsEvery    = time.Hour
	UpdateWindow  = 5 * time.Minute // an updated node must poll again within this
)

// Facts is what a node reports about its machine, with its clock.
type Facts struct {
	core.NodeFacts
	Time time.Time `json:"time"`
}

// EnrolRequest exchanges an install token for a credential.
type EnrolRequest struct {
	Token string `json:"token"`
	Pool  int    `json:"pool"`
	Facts Facts  `json:"facts"`
}

// EnrolResponse carries the credential, which the server shows nobody else.
type EnrolResponse struct {
	NodeID        int64  `json:"node_id"`
	Credential    string `json:"credential"`
	ServerVersion string `json:"server_version"`
}

// PollResponse answers a poll: zero or more jobs. Update without jobs is
// the fixed reply to a protocol version the server does not speak; every
// node version understands it and updates itself over the download route.
type PollResponse struct {
	ServerVersion string `json:"server_version"`
	Update        bool   `json:"update,omitempty"`
	Jobs          []Job  `json:"jobs,omitempty"`
}

// Job is one command for a node. The envelope leaves room for later kinds
// without a new transport.
type Job struct {
	ID     string     `json:"id"`
	Kind   string     `json:"kind"`
	Probe  *ProbeJob  `json:"probe,omitempty"`
	Cancel string     `json:"cancel,omitempty"` // KindCancel: the job to stop
	Update *UpdateJob `json:"update,omitempty"`
}

// UpdateJob asks the node to replace its binary with the server's.
type UpdateJob struct {
	Version string `json:"version"`
}

// ProbeJob is a probe request without its Go-only fields. The node resolves
// the host itself and verifies at the server's time.
type ProbeJob struct {
	Host       string          `json:"host"`
	Port       int             `json:"port"`
	Protocol   probe.Protocol  `json:"protocol"`
	ServerName string          `json:"server_name,omitempty"`
	Trust      probe.TrustMode `json:"trust"`
	FirstOnly  bool            `json:"first_only,omitempty"`
	TimeoutMS  int64           `json:"timeout_ms"`
	Retries    int             `json:"retries"`
	AllowLocal bool            `json:"allow_local,omitempty"`
	Legacy     bool            `json:"legacy,omitempty"`
	ServerTime time.Time       `json:"server_time"`
}

// NewProbeJob converts a probe request for the wire.
func NewProbeJob(req probe.Request, now time.Time) *ProbeJob {
	return &ProbeJob{Host: req.Host, Port: req.Port, Protocol: req.Protocol, ServerName: req.ServerName, Trust: req.Trust,
		FirstOnly: req.FirstOnly, TimeoutMS: req.Timeout.Milliseconds(), Retries: req.Retries, AllowLocal: req.AllowLocal,
		Legacy: req.Legacy, ServerTime: now}
}

// Request is the probe request a node runs for the job, received at
// received. The clock is the server's, advanced by the node's own
// monotonic clock, so a node with a wrong clock gives no false verdicts.
func (j ProbeJob) Request(received time.Time) probe.Request {
	base := j.ServerTime
	return probe.Request{Host: j.Host, Port: j.Port, Protocol: j.Protocol, ServerName: j.ServerName, Trust: j.Trust,
		FirstOnly: j.FirstOnly, Timeout: time.Duration(j.TimeoutMS) * time.Millisecond, Retries: j.Retries,
		AllowLocal: j.AllowLocal, Legacy: j.Legacy,
		Now: func() time.Time { return base.Add(time.Since(received)) }}
}

// Timeout is how long the server waits for a leased job: the target's
// timeout for every attempt, plus one timeout per handshake of the
// configuration test (two legacy versions, four suite classes) and slack
// for the round trip.
func (j ProbeJob) Timeout() time.Duration {
	d := time.Duration(j.TimeoutMS) * time.Millisecond
	t := d*time.Duration(j.Retries+1) + 30*time.Second
	if j.Legacy {
		t += 6 * d
	}
	return t
}

// Result is a node's answer to one job.
type Result struct {
	Error string       `json:"error,omitempty"` // the job could not run at all
	Probe *ProbeResult `json:"probe,omitempty"`
}

// ProbeResult is a probe result with the chains as DER (base64 in JSON).
type ProbeResult struct {
	DurationMS  int64     `json:"duration_ms"`
	DNSError    string    `json:"dns_error,omitempty"`
	Addresses   []Address `json:"addresses"`
	SkippedIPv6 []string  `json:"skipped_ipv6,omitempty"`
}

// Address is the result for one resolved address.
type Address struct {
	IP              string          `json:"ip"`
	OK              bool            `json:"ok"`
	ErrorKind       probe.ErrorKind `json:"error_kind,omitempty"`
	Error           string          `json:"error,omitempty"`
	TLSVersion      string          `json:"tls_version,omitempty"`
	Cipher          string          `json:"cipher,omitempty"`
	Chain           [][]byte        `json:"chain,omitempty"`
	Verified        bool            `json:"verified,omitempty"`
	VerifyError     string          `json:"verify_error,omitempty"`
	VerifiedChain   [][]byte        `json:"verified_chain,omitempty"`
	HostnameChecked bool            `json:"hostname_checked,omitempty"`
	HostnameOK      bool            `json:"hostname_ok,omitempty"`
	DurationMS      int64           `json:"duration_ms"`
	LegacyChecked   bool            `json:"legacy_checked,omitempty"`
	Legacy          []string        `json:"legacy,omitempty"`
	SuitesChecked   bool            `json:"suites_checked,omitempty"`
	Suites          []string        `json:"suites,omitempty"`
	SuiteNames      []string        `json:"suite_names,omitempty"`
}

// EncodeResult converts a probe result for the wire.
func EncodeResult(r probe.Result) *ProbeResult {
	out := &ProbeResult{DurationMS: r.Duration.Milliseconds(), DNSError: r.DNSError, SkippedIPv6: r.SkippedIPv6, Addresses: []Address{}}
	for _, a := range r.Addresses {
		out.Addresses = append(out.Addresses, Address{
			IP: a.IP, OK: a.OK, ErrorKind: a.ErrorKind, Error: a.Error, TLSVersion: a.TLSVersion, Cipher: a.Cipher,
			Chain: der(a.Chain), Verified: a.Verified, VerifyError: a.VerifyError, VerifiedChain: der(a.VerifiedChain),
			HostnameChecked: a.HostnameChecked, HostnameOK: a.HostnameOK, DurationMS: a.Duration.Milliseconds(),
			LegacyChecked: a.LegacyChecked, Legacy: a.Legacy,
			SuitesChecked: a.SuitesChecked, Suites: classNames(a.Suites), SuiteNames: a.SuiteNames,
		})
	}
	return out
}

// classNames and parseClasses carry the suite classes as strings; a class
// a server of another version does not know is dropped, not refused.
func classNames(cs []probe.SuiteClass) []string {
	var out []string
	for _, c := range cs {
		out = append(out, string(c))
	}
	return out
}

func parseClasses(names []string) []probe.SuiteClass {
	var out []probe.SuiteClass
	for _, n := range names {
		if c, ok := probe.ParseSuiteClass(n); ok {
			out = append(out, c)
		}
	}
	return out
}

func der(chain []*x509.Certificate) [][]byte {
	if len(chain) == 0 {
		return nil
	}
	out := make([][]byte, len(chain))
	for i, c := range chain {
		out[i] = c.Raw
	}
	return out
}

func parseChain(ders [][]byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, d := range ders {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// Decode turns a wire result back into the probe result for req, judged on
// the server: the hostname is checked here, and for trust mode bundle the
// chain is verified here against the bundle, which never leaves the server.
// For trust mode system the node's verdict against its own store stands.
func (p ProbeResult) Decode(req probe.Request, started time.Time) (probe.Result, error) {
	r := probe.Result{Host: req.Host, Port: req.Port, Protocol: req.Protocol, ServerName: req.ServerName, StartedAt: started,
		Duration: time.Duration(p.DurationMS) * time.Millisecond, DNSError: p.DNSError, SkippedIPv6: p.SkippedIPv6}
	for _, w := range p.Addresses {
		a := probe.Address{IP: w.IP, OK: w.OK, ErrorKind: w.ErrorKind, Error: w.Error, TLSVersion: w.TLSVersion, Cipher: w.Cipher,
			Verified: w.Verified, VerifyError: w.VerifyError, Duration: time.Duration(w.DurationMS) * time.Millisecond,
			LegacyChecked: w.LegacyChecked, Legacy: w.Legacy,
			SuitesChecked: w.SuitesChecked, Suites: parseClasses(w.Suites), SuiteNames: w.SuiteNames}
		var err error
		if a.Chain, err = parseChain(w.Chain); err != nil {
			return r, fmt.Errorf("address %s: chain: %w", w.IP, err)
		}
		if a.VerifiedChain, err = parseChain(w.VerifiedChain); err != nil {
			return r, fmt.Errorf("address %s: verified chain: %w", w.IP, err)
		}
		if a.OK && len(a.Chain) == 0 {
			return r, fmt.Errorf("address %s answered without a certificate", w.IP)
		}
		if a.OK {
			judge(&a, req)
		}
		r.Addresses = append(r.Addresses, a)
	}
	return r, nil
}

// judge redoes on the server what is decided there.
func judge(a *probe.Address, req probe.Request) {
	switch req.Trust {
	case probe.TrustBundle:
		probe.Verify(a, req) // the hostname too
	case probe.TrustSelfSigned:
		a.Verified, a.VerifyError, a.VerifiedChain = false, "", nil
		fallthrough
	default:
		a.HostnameChecked, a.HostnameOK = probe.CheckHostname(a.Chain[0], req.ServerName)
	}
}
