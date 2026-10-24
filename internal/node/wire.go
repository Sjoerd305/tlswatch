// Package node lets tlswatch probe from inside a network the server cannot
// reach. A node is the same binary started as "tlswatch node": it holds no
// database and no schedule, long-polls the server over outbound HTTPS for
// jobs, runs them with internal/probe and posts the results back. This
// package holds both ends: the messages of protocol v1, the server-side
// dispatcher with the /agent/v1 handlers, and the node's client loop with
// its enrolment, system facts and self-update.
package node

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/crl"
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
	KindScan   = core.KindScan
	KindCRL    = core.KindCRL
)

// Kinds are the job kinds this version runs, reported in the facts so the
// server sends a node nothing it cannot do. Every node runs the first
// three; an older node, whose facts list none, runs no others.
var Kinds = []string{KindProbe, KindCancel, KindUpdate, KindScan, KindCRL}

// ErrUnsupported is the answer of a node to a job kind it does not know.
const ErrUnsupported = "unsupported kind"

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
	Scan   *ScanJob   `json:"scan,omitempty"`
	CRL    *CRLJob    `json:"crl,omitempty"`
}

// CRLJob asks a node to fetch the CRL at URL and return its bytes; the
// server verifies them.
type CRLJob struct {
	URL        string `json:"url"`
	AllowLocal bool   `json:"allow_local,omitempty"`
}

// Timeout is how long the server waits for a leased CRL fetch: the fetch's
// own limit, and slack for the round trip of up to 50 MB.
func (CRLJob) Timeout() time.Duration { return crl.Timeout + 60*time.Second }

// ScanJob is one chunk of a discovery scan.
type ScanJob struct {
	Addresses  []string `json:"addresses"`
	Ports      []int    `json:"ports"`
	Rate       int      `json:"rate"`
	TimeoutMS  int64    `json:"timeout_ms"`
	AllowLocal bool     `json:"allow_local,omitempty"`
}

// NewScanJob converts a scan request for the wire.
func NewScanJob(req probe.ScanRequest) *ScanJob {
	j := &ScanJob{Ports: req.Ports, Rate: req.Rate, TimeoutMS: req.Timeout.Milliseconds(), AllowLocal: req.AllowLocal}
	for _, a := range req.Addresses {
		j.Addresses = append(j.Addresses, a.String())
	}
	return j
}

// Request is the scan request a node runs for the job; an address that
// does not parse is refused.
func (j ScanJob) Request() (probe.ScanRequest, error) {
	req := probe.ScanRequest{Ports: j.Ports, Rate: j.Rate, Timeout: time.Duration(j.TimeoutMS) * time.Millisecond, AllowLocal: j.AllowLocal}
	for _, s := range j.Addresses {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return req, fmt.Errorf("address %q: %w", s, err)
		}
		req.Addresses = append(req.Addresses, a)
	}
	return req, nil
}

// Timeout is how long the server waits for a leased scan chunk: its
// connects at the rate, the last one's timeout, and slack.
func (j ScanJob) Timeout() time.Duration {
	rate := max(j.Rate, 1)
	n := len(j.Addresses) * len(j.Ports)
	return time.Duration(n)*time.Second/time.Duration(rate) + time.Duration(j.TimeoutMS)*time.Millisecond + 30*time.Second
}

// ScanResult is a node's answer to a scan chunk, the chains as DER.
type ScanResult struct {
	Hits    []ScanHit `json:"hits"`
	Probed  int       `json:"probed"`
	Refused int       `json:"refused"`
}

// ScanHit is one endpoint that answered with TLS.
type ScanHit struct {
	IP         string         `json:"ip"`
	Port       int            `json:"port"`
	Protocol   probe.Protocol `json:"protocol"`
	TLSVersion string         `json:"tls_version"`
	Chain      [][]byte       `json:"chain"`
}

// EncodeScan converts a scan result for the wire.
func EncodeScan(r probe.ScanResult) *ScanResult {
	out := &ScanResult{Probed: r.Probed, Refused: r.Refused, Hits: []ScanHit{}}
	for _, h := range r.Hits {
		out.Hits = append(out.Hits, ScanHit{IP: h.IP, Port: h.Port, Protocol: h.Protocol, TLSVersion: h.TLSVersion, Chain: der(h.Chain)})
	}
	return out
}

// Decode turns a wire scan result back, refusing a hit without a
// certificate or on an address or port the chunk did not ask for.
func (s ScanResult) Decode(j ScanJob) (probe.ScanResult, error) {
	out := probe.ScanResult{Probed: s.Probed, Refused: s.Refused}
	for _, h := range s.Hits {
		if !slices.Contains(j.Addresses, h.IP) || !slices.Contains(j.Ports, h.Port) {
			return out, fmt.Errorf("hit %s:%d was not asked for", h.IP, h.Port)
		}
		chain, err := parseChain(h.Chain)
		if err != nil || len(chain) == 0 {
			return out, fmt.Errorf("hit %s:%d: no usable chain", h.IP, h.Port)
		}
		out.Hits = append(out.Hits, probe.ScanHit{IP: h.IP, Port: h.Port, Protocol: probe.ScanProtocol(h.Port), TLSVersion: core.Clip(h.TLSVersion, core.ShortMax), Chain: chain})
	}
	return out, nil
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
// configuration test (three legacy versions, up to five hellos for the
// raw suite classes, four Go suite classes, the DHE group, the
// post-quantum handshake, the other certificates by key type and without
// SNI) and slack for the round trip, which also covers the staple retry
// of a must-staple leaf.
func (j ProbeJob) Timeout() time.Duration {
	d := time.Duration(j.TimeoutMS) * time.Millisecond
	t := d*time.Duration(j.Retries+1) + 30*time.Second
	if j.Legacy {
		t += 16 * d
	}
	return t
}

// Result is a node's answer to one job.
type Result struct {
	Error string       `json:"error,omitempty"` // the job could not run at all
	Probe *ProbeResult `json:"probe,omitempty"`
	Scan  *ScanResult  `json:"scan,omitempty"`
	CRL   []byte       `json:"crl,omitempty"` // KindCRL: the CRL as fetched
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
	Group           string          `json:"group,omitempty"`
	Chain           [][]byte        `json:"chain,omitempty"`
	Verified        bool            `json:"verified,omitempty"`
	VerifyError     string          `json:"verify_error,omitempty"`
	VerifiedChain   [][]byte        `json:"verified_chain,omitempty"`
	HostnameChecked bool            `json:"hostname_checked,omitempty"`
	HostnameOK      bool            `json:"hostname_ok,omitempty"`
	DurationMS      int64           `json:"duration_ms"`
	LegacyChecked   bool            `json:"legacy_checked,omitempty"`
	Legacy          []string        `json:"legacy,omitempty"`
	// LegacyVersions names the versions the node's configuration test
	// covers (probe.LegacyVersions of its build). A node from before SSL
	// 3.0 was tested sends none, meaning TLS 1.0 and 1.1 only.
	LegacyVersions []string `json:"legacy_versions,omitempty"`
	SuitesChecked  bool     `json:"suites_checked,omitempty"`
	Suites         []string `json:"suites,omitempty"`
	SuiteNames     []string `json:"suite_names,omitempty"`
	// SuiteClasses names the classes the node's suites test covers plus
	// dhGroupTest for the DHE group; a node from before them sends none,
	// meaning the four Go classes only. DHBits is the group size found.
	SuiteClasses []string `json:"suite_classes,omitempty"`
	DHBits       int      `json:"dh_bits,omitempty"`
	// OthersChecked and Others are the other certificates the address
	// serves (by key type, without SNI); a node from before them sends
	// neither, so the test has no verdict. The server judges the chains.
	OthersChecked bool         `json:"others_checked,omitempty"`
	Others        []OtherChain `json:"others,omitempty"`
	OCSP          []byte       `json:"ocsp,omitempty"` // the stapled OCSP response
	PQChecked     bool         `json:"pq_checked,omitempty"`
	PQ            bool         `json:"pq,omitempty"`
}

// EncodeResult converts a probe result for the wire.
func EncodeResult(r probe.Result) *ProbeResult {
	out := &ProbeResult{DurationMS: r.Duration.Milliseconds(), DNSError: r.DNSError, SkippedIPv6: r.SkippedIPv6, Addresses: []Address{}}
	for _, a := range r.Addresses {
		out.Addresses = append(out.Addresses, Address{
			IP: a.IP, OK: a.OK, ErrorKind: a.ErrorKind, Error: a.Error, TLSVersion: a.TLSVersion, Cipher: a.Cipher, Group: a.Group,
			Chain: der(a.Chain), Verified: a.Verified, VerifyError: a.VerifyError, VerifiedChain: der(a.VerifiedChain),
			HostnameChecked: a.HostnameChecked, HostnameOK: a.HostnameOK, DurationMS: a.Duration.Milliseconds(),
			LegacyChecked: a.LegacyChecked, Legacy: a.Legacy, LegacyVersions: legacyNames(a.LegacyChecked),
			SuitesChecked: a.SuitesChecked, Suites: classNames(a.Suites), SuiteNames: a.SuiteNames, SuiteClasses: suiteTests(a.SuitesChecked), DHBits: a.DHBits,
			OthersChecked: a.OthersChecked, Others: encodeOthers(a.Others),
			OCSP: a.OCSP, PQChecked: a.PQChecked, PQ: a.PQ,
		})
	}
	return out
}

// legacyNames lists the versions this build's configuration test covers,
// sent with a checked result so the server knows what "checked" spans.
func legacyNames(checked bool) []string {
	if !checked {
		return nil
	}
	var out []string
	for _, v := range probe.LegacyVersions {
		out = append(out, probe.VersionName(v))
	}
	return out
}

// legacyCovered reports whether a node that tested the named versions
// (none: the TLS 1.0 and 1.1 of older nodes) covered every version this
// server tests. A result that does not is still "checked" for what it
// accepted, but not a full verdict: the finding and the grade wait for the
// node to update.
func legacyCovered(names []string) bool {
	if names == nil {
		names = []string{tls.VersionName(tls.VersionTLS10), tls.VersionName(tls.VersionTLS11)}
	}
	for _, v := range probe.LegacyVersions {
		if !slices.Contains(names, probe.VersionName(v)) {
			return false
		}
	}
	return true
}

// OtherChain is an other certificate chain as DER, with how it was got.
type OtherChain struct {
	Via   string   `json:"via"`
	Chain [][]byte `json:"chain"`
}

func encodeOthers(os []probe.OtherChain) []OtherChain {
	var out []OtherChain
	for _, o := range os {
		out = append(out, OtherChain{Via: o.Via, Chain: der(o.Chain)})
	}
	return out
}

// decodeOthers parses the other chains and judges them as the main chain
// is judged; a via this server does not know is dropped.
func decodeOthers(ws []OtherChain, ip string, req probe.Request) ([]probe.OtherChain, error) {
	var out []probe.OtherChain
	for _, w := range ws {
		if w.Via != probe.ViaOtherKey && w.Via != probe.ViaNoSNI {
			continue
		}
		chain, err := parseChain(w.Chain)
		if err != nil {
			return nil, fmt.Errorf("other chain: %w", err)
		}
		if len(chain) == 0 {
			return nil, fmt.Errorf("other chain without a certificate")
		}
		o := probe.OtherChain{Via: w.Via, Chain: chain}
		o.Judge(func(a *probe.Address) { judge(a, req) }, ip)
		out = append(out, o)
	}
	return out, nil
}

// dhGroupTest is the entry in SuiteClasses that marks the DHE group test.
const dhGroupTest = "dh_group"

// suiteTests lists what this build's suites test covers, sent with a
// checked result so the server knows what "checked" spans.
func suiteTests(checked bool) []string {
	if !checked {
		return nil
	}
	return append(classNames(probe.SuiteClasses), dhGroupTest)
}

// suitesCovered reports whether a node that ran the named tests (none: the
// four Go classes of older nodes) covered every test this server expects.
// A result that does not is still "checked" for what it accepted, but not a
// full verdict: the finding and the grade wait for the node to update.
func suitesCovered(names []string) bool {
	if names == nil {
		names = classNames(probe.GoClasses)
	}
	for _, want := range suiteTests(true) {
		if !slices.Contains(names, want) {
			return false
		}
	}
	return true
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
		a := probe.Address{IP: w.IP, OK: w.OK, ErrorKind: w.ErrorKind, Error: w.Error, TLSVersion: w.TLSVersion, Cipher: w.Cipher, Group: core.Clip(w.Group, core.ShortMax),
			Verified: w.Verified, VerifyError: w.VerifyError, Duration: time.Duration(w.DurationMS) * time.Millisecond,
			LegacyChecked: w.LegacyChecked && legacyCovered(w.LegacyVersions), Legacy: w.Legacy,
			SuitesChecked: w.SuitesChecked && suitesCovered(w.SuiteClasses), Suites: parseClasses(w.Suites), SuiteNames: w.SuiteNames, DHBits: w.DHBits,
			OCSP: w.OCSP, PQChecked: w.PQChecked, PQ: w.PQ}
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
			a.OthersChecked = w.OthersChecked
			if a.Others, err = decodeOthers(w.Others, w.IP, req); err != nil {
				return r, fmt.Errorf("address %s: %w", w.IP, err)
			}
		}
		r.Addresses = append(r.Addresses, a)
	}
	return r, nil
}

// judge redoes on the server what is decided there: the chain is verified
// against the server's roots or bundle and the hostname checked, whatever
// the node reported, so a node can say what it saw but not what to trust.
func judge(a *probe.Address, req probe.Request) {
	switch req.Trust {
	case probe.TrustSelfSigned:
		a.Verified, a.VerifyError, a.VerifiedChain = false, "", nil
		a.HostnameChecked, a.HostnameOK = probe.CheckHostname(a.Chain[0], req.ServerName)
	default:
		probe.Verify(a, req) // system roots or the bundle; the hostname too
	}
}
