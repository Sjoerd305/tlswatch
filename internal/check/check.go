// Package check turns a probe result into findings: expiry thresholds, chain
// and hostname verification, change detection and debouncing of
// network-shaped failures. It is pure; the caller persists the outcome.
package check

import (
	"crypto/x509"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

// Kind is the type of a finding.
type Kind string

// The finding kinds from the specification.
const (
	Expiring           Kind = "expiring"
	RenewalOverdue     Kind = "renewal_overdue"
	DistrustedCA       Kind = "distrusted_ca"
	Revoked            Kind = "revoked"
	Expired            Kind = "expired"
	NotYetValid        Kind = "not_yet_valid"
	ChainUntrusted     Kind = "chain_untrusted"
	SelfSigned         Kind = "self_signed"
	HostnameMismatch   Kind = "hostname_mismatch"
	WeakSignature      Kind = "weak_signature"
	LegacyProtocol     Kind = "legacy_protocol"
	WeakConfiguration  Kind = "weak_configuration"
	CertificateChanged Kind = "certificate_changed"
	IssuerChanged      Kind = "issuer_changed"
	Inconsistent       Kind = "inconsistent"
	TLSUnavailable     Kind = "tls_unavailable"
	Unreachable        Kind = "unreachable"
	DNSFailed          Kind = "dns_failed"
	// RevocationUnknown is info and never alerted: the CRL of a served leaf
	// could not be fetched or verified for days.
	RevocationUnknown Kind = "revocation_unknown"
	// MustStaple: the leaf requires a stapled OCSP response and the server
	// sent none, or one a client refuses.
	MustStaple Kind = "must_staple"
	// AlternateCertificate: the certificate the address serves to clients
	// of the other key type fails a certificate check; DefaultCertificate
	// (info, never alerted): the one it serves without SNI does.
	AlternateCertificate Kind = "alternate_certificate"
	DefaultCertificate   Kind = "default_certificate"
	// GradeChanged is an event (info, recorded as resolved): the target's
	// configuration grade moved since the last test.
	GradeChanged Kind = "grade_changed"
	// NodeOffline is opened on a node, not on a target, by the node
	// dispatcher; Evaluate never returns it.
	NodeOffline Kind = "node_offline"
	// UnexpectedCertificate and CTSourceFailed are opened on a domain watch
	// by the Certificate Transparency poller; Evaluate never returns them.
	UnexpectedCertificate Kind = "unexpected_certificate"
	CTSourceFailed        Kind = "ct_source_failed"
	// CertificateIssued is an event (info, recorded as resolved) on a
	// domain watch: an expected issuance is now served by a target.
	CertificateIssued Kind = "certificate_issued"
	// CAAViolation is opened on a domain watch for an issuance its CAA
	// record does not permit; CAAChanged is an event (info, recorded as
	// resolved) when the watch's CAA record set changed.
	CAAViolation Kind = "caa_violation"
	CAAChanged   Kind = "caa_changed"
	// UnknownEndpoint is opened on a scan schedule by a scheduled discovery
	// run: a TLS endpoint it found that no target covers. Fingerprint holds
	// the endpoint as address:port. Acknowledging it resolves it, and the
	// endpoint is not reported again by that schedule.
	UnknownEndpoint Kind = "unknown_endpoint"
)

// Kinds lists every kind, for filters.
var Kinds = []Kind{Expiring, RenewalOverdue, DistrustedCA, Revoked, RevocationUnknown, MustStaple, Expired, NotYetValid, ChainUntrusted, SelfSigned, HostnameMismatch, AlternateCertificate, DefaultCertificate, WeakSignature, LegacyProtocol, WeakConfiguration, CertificateChanged, IssuerChanged, GradeChanged, Inconsistent, TLSUnavailable, Unreachable, DNSFailed, NodeOffline, UnexpectedCertificate, CTSourceFailed, CertificateIssued, CAAViolation, CAAChanged, UnknownEndpoint}

// Label is the human name of a kind.
func (k Kind) Label() string {
	switch k {
	case RenewalOverdue:
		return "Renewal overdue"
	case DistrustedCA:
		return "Distrusted CA"
	case RevocationUnknown:
		return "Revocation unknown"
	case MustStaple:
		return "Must-staple without staple"
	case AlternateCertificate:
		return "Alternate certificate"
	case DefaultCertificate:
		return "Default certificate"
	case NotYetValid:
		return "Not yet valid"
	case ChainUntrusted:
		return "Chain untrusted"
	case SelfSigned:
		return "Self-signed"
	case HostnameMismatch:
		return "Hostname mismatch"
	case WeakSignature:
		return "Weak signature"
	case LegacyProtocol:
		return "Legacy protocol"
	case WeakConfiguration:
		return "Weak configuration"
	case GradeChanged:
		return "Grade changed"
	case CertificateChanged:
		return "Certificate changed"
	case IssuerChanged:
		return "Issuer changed"
	case TLSUnavailable:
		return "STARTTLS unavailable"
	case DNSFailed:
		return "DNS failed"
	case NodeOffline:
		return "Node offline"
	case UnexpectedCertificate:
		return "Unexpected certificate"
	case CTSourceFailed:
		return "CT source failed"
	case CertificateIssued:
		return "Certificate issued"
	case CAAViolation:
		return "CAA violation"
	case CAAChanged:
		return "CAA changed"
	case UnknownEndpoint:
		return "Endpoint not in inventory"
	}
	s := string(k)
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// Short is the compact label used in chips.
func (k Kind) Short() string {
	switch k {
	case CertificateChanged:
		return "changed"
	case IssuerChanged:
		return "issuer"
	case RenewalOverdue:
		return "renewal"
	case DistrustedCA:
		return "distrusted"
	case RevocationUnknown:
		return "revocation"
	case MustStaple:
		return "staple"
	case AlternateCertificate:
		return "alternate"
	case DefaultCertificate:
		return "no sni"
	case NotYetValid:
		return "not yet valid"
	case ChainUntrusted:
		return "untrusted"
	case HostnameMismatch:
		return "hostname"
	case WeakSignature:
		return "weak"
	case LegacyProtocol:
		return "legacy"
	case WeakConfiguration:
		return "ciphers"
	case GradeChanged:
		return "grade"
	case TLSUnavailable:
		return "starttls"
	case DNSFailed:
		return "dns"
	case SelfSigned:
		return "self-signed"
	case NodeOffline:
		return "node"
	case UnexpectedCertificate:
		return "issued"
	case CTSourceFailed:
		return "ct source"
	case CertificateIssued:
		return "issued"
	case CAAViolation, CAAChanged:
		return "caa"
	case UnknownEndpoint:
		return "not listed"
	}
	return string(k)
}

// AckResolves reports whether acknowledging a finding of this kind resolves it.
func (k Kind) AckResolves() bool {
	return k == CertificateChanged || k == IssuerChanged || k == UnexpectedCertificate || k == CAAViolation || k == UnknownEndpoint
}

// Silent reports whether a finding of the kind is never alerted, whatever
// a channel's floor.
func (k Kind) Silent() bool { return k == RevocationUnknown || k == DefaultCertificate }

// Network reports whether the kind is network-shaped (debounced).
func (k Kind) Network() bool { return k == Unreachable || k == DNSFailed }

// Severity of a finding.
type Severity string

// The three severities.
const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Critical Severity = "critical"
)

// Rank orders severities; higher is worse.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 3
	case Warning:
		return 2
	case Info:
		return 1
	}
	return 0
}

// Short is the pill text.
func (s Severity) Short() string {
	switch s {
	case Critical:
		return "crit"
	case Warning:
		return "warn"
	}
	return "info"
}

// Class is the CSS status class.
func (s Severity) Class() string {
	switch s {
	case Critical:
		return "crit"
	case Warning:
		return "warn"
	}
	return "info"
}

// Worst returns the highest severity among fs, or "" when fs is empty.
func Worst(fs []Finding) Severity {
	var w Severity
	for _, f := range fs {
		if f.Severity.Rank() > w.Rank() {
			w = f.Severity
		}
	}
	return w
}

// Meets reports whether s is at or above floor.
func (s Severity) Meets(floor Severity) bool { return s.Rank() >= floor.Rank() }

// ParseSeverity parses a severity name.
func ParseSeverity(v string) (Severity, bool) {
	switch Severity(v) {
	case Info, Warning, Critical:
		return Severity(v), true
	}
	return "", false
}

// ACMEIssuers are issuer organisations whose certificates are normally
// renewed automatically.
var ACMEIssuers = []string{"Let's Encrypt", "ZeroSSL", "Google Trust Services", "Buypass"}

// IsACMEIssuer reports whether an issuer organisation or CN belongs to a
// known ACME CA.
func IsACMEIssuer(org, cn string) bool {
	for _, a := range ACMEIssuers {
		if strings.EqualFold(org, a) || strings.Contains(strings.ToLower(org), strings.ToLower(a)) {
			return true
		}
	}
	return strings.HasPrefix(cn, "ZeroSSL")
}

// Thresholds are warning and critical days, and the same as a share of
// the leaf's lifetime remaining in percent (0: days only). The one that
// fires later wins: days keep a long-lived certificate from warning months
// ahead, the share keeps a short-lived one from warning at issuance.
type Thresholds struct{ Warn, Crit, WarnPct, CritPct int }

// DefaultRenewalPoint is the share of its lifetime, in percent, after
// which a renewal-managed leaf is overdue: past the two-thirds where ACME
// clients renew, with margin.
const DefaultRenewalPoint = 75

// Target is the configuration the checks need.
type Target struct {
	Trust      probe.TrustMode
	ServerName string
	// Explicit per-target values; nil follows the default, a percentage
	// of 0 means days only.
	Warn, Crit       *int
	WarnPct, CritPct *int
	Manual           Thresholds
	Managed          Thresholds
	// RenewalPoint is the share of the lifetime after which renewal_overdue
	// opens on a renewal-managed target; 0 is DefaultRenewalPoint.
	RenewalPoint   int
	RenewalManaged bool
	RenewalSet     bool // false: derive RenewalManaged from the issuer
	ExpectedIssuer string
	Debounce       int
	PinnedFP       string
	SkipLegacy     bool // the configuration test (SSL 3.0, TLS 1.0 and 1.1, cipher suites, other certificates) is off
}

// Previous is the state left by the last check.
type Previous struct {
	LeafFP string
	// Recent holds the leaves served at any address of the target lately:
	// one of them becoming current again is not a new certificate.
	Recent    map[string]bool
	IssuerOrg string
	IssuerCN  string
	SANs      []string
	// Leaf describes the previous leaf in full and Inter the certificate
	// that issued it, for the diff of a change; nil and zero when unknown.
	Leaf       *probe.CertInfo
	Inter      Intermediate
	FailStreak int
	OkStreak   int
	DNSFail    int
	DNSOk      int
	Open       map[Kind]bool
	Grade      string // the stored configuration grade, "" for none yet
	// CRL is what the cached CRLs say of the served leaves, by
	// fingerprint; a leaf without a usable CRL is absent.
	CRL map[string]CRLStatus
	// RevokedFP is the leaf the open revoked finding is about.
	RevokedFP string
}

// CRLStatus is what the cached CRL of a leaf says of it.
type CRLStatus struct {
	URL       string
	Revoked   bool
	RevokedAt time.Time
	Reason    string
	// Unknown is why the CRL could not be fetched or verified, set once
	// that failed on UnknownAfter days in a row.
	Unknown string
}

// Finding is a desired open finding (or an event).
type Finding struct {
	Kind        Kind
	Severity    Severity
	Details     string
	Fingerprint string
	DaysLeft    *int
}

// AddressOutcome is the per-address verdict stored on the observation.
type AddressOutcome struct {
	Status string // ok, warning, critical, error, skipped
	LeafFP string
}

// Outcome is everything the caller needs to persist.
type Outcome struct {
	Open   []Finding // findings that should be open now (opened or updated)
	Keep   []Kind    // open findings to leave untouched
	Events []Finding // informational events, recorded as already resolved
	// Current certificate, when any address answered.
	Leaf           *x509.Certificate
	LeafFP         string
	NotAfter       time.Time // earliest NotAfter in the presented chain
	TLSVersion     string
	RenewalManaged bool
	Thresholds     Thresholds
	PinFP          string // non-empty: pin this fingerprint (self-signed trust)
	// LegacyChecked reports that this check tested the legacy versions;
	// Legacy lists those any address accepted.
	LegacyChecked bool
	Legacy        []string
	// GradeChecked reports that every answering address got a full
	// configuration verdict this check; Grade, GradeReasons and
	// AddressGrades then hold the result under GradeRules.
	GradeChecked  bool
	Grade         string
	GradeReasons  []string
	GradeRules    int
	AddressGrades []AddressGrade
	// PQ is whether the target negotiates post-quantum key exchange, when
	// GradeChecked: PQYes when every address does, PQNo when one does
	// not, PQUntested when an address got no verdict.
	PQ         string
	Answered   bool // at least one address completed a handshake
	FailStreak int
	OkStreak   int
	DNSFail    int
	DNSOk      int
	Addresses  map[string]AddressOutcome
	Error      string // the addresses that failed, when any did
	// Waiting lists network kinds that failed this check but are not open
	// yet: the debounce wants more consecutive failures.
	Waiting []Kind
}

// DaysLeft counts whole days remaining; a certificate expiring in 29 days
// and 23 hours has 29 days left. Negative once expired.
func DaysLeft(notAfter, now time.Time) int {
	d := notAfter.Sub(now)
	if d < 0 {
		return -int((-d + 24*time.Hour - 1) / (24 * time.Hour))
	}
	return int(d / (24 * time.Hour))
}

// HoursUnder is the number of days below which time left is shown in
// hours.
const HoursUnder = 7

// Span is a duration as the UI and alerts show it: whole days ("12 days",
// "1 day"), or whole hours under HoursUnder days ("31 h"), truncated like
// DaysLeft. A negative span is shown as its absolute value.
func Span(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	if d < HoursUnder*24*time.Hour {
		return fmt.Sprintf("%d h", int(d/time.Hour))
	}
	if days := int(d / (24 * time.Hour)); days != 1 {
		return fmt.Sprintf("%d days", days)
	}
	return "1 day"
}

// ShareLeft is the share of the lifetime from notBefore to notAfter that
// remains at now, in percent, 0 to 100.
func ShareLeft(notBefore, notAfter, now time.Time) float64 {
	life := notAfter.Sub(notBefore)
	if life <= 0 {
		return 0
	}
	return min(max(float64(notAfter.Sub(now))*100/float64(life), 0), 100)
}

// Due reports which threshold th sets off with days whole days and share
// percent of the leaf's lifetime left: Critical, Warning or "". A
// threshold fires once both its days and its share have passed.
func (th Thresholds) Due(days int, share float64) Severity {
	passed := func(d, pct int) bool { return days < d && (pct == 0 || share < float64(pct)) }
	switch {
	case passed(th.Crit, th.CritPct):
		return Critical
	case passed(th.Warn, th.WarnPct):
		return Warning
	}
	return ""
}

// ShareDecides reports whether, for a leaf of lifetime life, the share
// rather than the days is the later of the two at severity sev.
func (th Thresholds) ShareDecides(sev Severity, life time.Duration) bool {
	d, pct := th.Warn, th.WarnPct
	if sev == Critical {
		d, pct = th.Crit, th.CritPct
	}
	return pct > 0 && life*time.Duration(pct)/100 < time.Duration(d)*24*time.Hour
}

// Evaluate applies every check to one probe result. The caller resolves
// every open finding the outcome neither opens nor keeps.
func Evaluate(t Target, prev Previous, r probe.Result, now time.Time) Outcome {
	e := &evaluation{t: t, prev: prev, now: now, debounce: max(t.Debounce, 1)}
	e.out.Addresses = map[string]AddressOutcome{}

	if r.DNSError != "" && len(r.Addresses) == 0 {
		e.dnsFailed(r.DNSError)
		return e.out
	}
	e.out.DNSOk, e.out.DNSFail = prev.DNSOk+1, 0
	e.recovering(DNSFailed, e.out.DNSOk)

	ok := e.sortAddresses(r.Addresses)
	if len(ok) == 0 {
		e.nothingAnswered(r)
		return e.out
	}
	e.out.Answered = true
	e.out.Error = partialError(r.Addresses)
	e.out.OkStreak, e.out.FailStreak = prev.OkStreak+1, 0
	e.recovering(Unreachable, e.out.OkStreak)

	cur := pickLeaf(ok)
	info := probe.Describe(cur.Chain[0])
	e.out.Leaf, e.out.LeafFP, e.out.TLSVersion = cur.Chain[0], info.Fingerprint, cur.TLSVersion
	e.out.RenewalManaged, e.out.Thresholds = thresholds(t, info)

	e.inconsistent(ok)
	e.facts(ok)
	e.renewal()
	e.revocation(ok)
	e.legacy(ok)
	e.others(ok)
	e.grade(ok)
	e.expectedIssuer(info)
	e.changes(info, cur)
	return e.out
}

// evaluation is the state of one Evaluate call.
type evaluation struct {
	t        Target
	prev     Previous
	now      time.Time
	debounce int
	out      Outcome
	// otherCerts are the other certificates of each address, for the
	// configuration test's result.
	otherCerts map[string][]OtherCert
}

func (e *evaluation) open(f Finding) { e.out.Open = append(e.out.Open, f) }

// keep leaves k untouched if it is open.
func (e *evaluation) keep(k Kind) {
	if e.prev.Open[k] {
		e.out.Keep = append(e.out.Keep, k)
	}
}

// keepAllBut keeps every open kind except the given ones.
func (e *evaluation) keepAllBut(except ...Kind) {
	for _, k := range Kinds {
		if !slices.Contains(except, k) {
			e.keep(k)
		}
	}
}

// failing opens a debounced finding once streak consecutive checks failed;
// an open one stays open on every further failure.
func (e *evaluation) failing(k Kind, streak int, details string) {
	if e.prev.Open[k] || streak >= e.debounce {
		e.open(Finding{Kind: k, Severity: Critical, Details: details})
		return
	}
	e.out.Waiting = append(e.out.Waiting, k)
}

// recovering keeps a debounced finding open until streak consecutive checks
// passed.
func (e *evaluation) recovering(k Kind, streak int) {
	if streak < e.debounce {
		e.keep(k)
	}
}

// dnsFailed handles a name that did not resolve: nothing else was tested,
// so every other finding and the network streaks stand.
func (e *evaluation) dnsFailed(err string) {
	e.out.DNSFail, e.out.DNSOk = e.prev.DNSFail+1, 0
	e.out.FailStreak, e.out.OkStreak = e.prev.FailStreak, e.prev.OkStreak
	e.out.Error = err
	e.failing(DNSFailed, e.out.DNSFail, "the name did not resolve: "+err)
	e.keepAllBut(DNSFailed)
}

// sortAddresses records the failed addresses, opens tls_unavailable for those
// that refused STARTTLS, and returns the ones that answered.
func (e *evaluation) sortAddresses(addrs []probe.Address) []probe.Address {
	var ok []probe.Address
	var starttls []string
	for _, a := range addrs {
		switch {
		case a.OK:
			ok = append(ok, a)
		case a.ErrorKind == probe.ErrStartTLS:
			starttls = append(starttls, a.IP)
			e.out.Addresses[a.IP] = AddressOutcome{Status: "critical"}
		default:
			e.out.Addresses[a.IP] = AddressOutcome{Status: "error"}
		}
	}
	if len(starttls) > 0 {
		e.open(Finding{Kind: TLSUnavailable, Severity: Critical, Details: "STARTTLS not offered on " + strings.Join(starttls, ", ")})
	}
	return ok
}

// nothingAnswered handles a check where no address completed a handshake.
// The target is unreachable unless an address refused STARTTLS: that one
// answered, so the network streaks stand. No certificate was read, so the
// certificate findings stand.
func (e *evaluation) nothingAnswered(r probe.Result) {
	var failures []string
	starttls := false
	for _, a := range r.Addresses {
		if a.ErrorKind == probe.ErrStartTLS {
			starttls = true
		} else {
			failures = append(failures, a.IP+": "+a.Error)
		}
	}
	if starttls {
		e.out.FailStreak, e.out.OkStreak = e.prev.FailStreak, e.prev.OkStreak
		e.keep(Unreachable)
	} else {
		e.out.FailStreak, e.out.OkStreak = e.prev.FailStreak+1, 0
		e.out.Error = strings.Join(failures, "; ")
		details := summarise(failures)
		if len(r.Addresses) == 0 && len(r.SkippedIPv6) > 0 {
			e.out.Error = NoIPv6Route(r.Host, r.SkippedIPv6)
			details = e.out.Error
		}
		if hint := PortHint(r.Protocol, r.Port); hint != "" {
			e.out.Error += ". " + hint
			details += ". " + hint
		}
		e.failing(Unreachable, e.out.FailStreak, details)
	}
	e.keepAllBut(Unreachable, DNSFailed, TLSUnavailable)
}

// partialError names the addresses that could not be reached in a check
// where others answered; a STARTTLS refusal has its own finding.
func partialError(addrs []probe.Address) string {
	var failures []string
	for _, a := range addrs {
		if !a.OK && a.ErrorKind != probe.ErrStartTLS {
			failures = append(failures, a.IP+": "+a.Error)
		}
	}
	return strings.Join(failures, "; ")
}

// pickLeaf returns the address serving the current leaf: the one most
// addresses serve, ties going to the latest expiry so a stale node does not
// become current.
func pickLeaf(ok []probe.Address) probe.Address {
	counts := map[string]int{}
	for _, a := range ok {
		counts[probe.Fingerprint(a.Chain[0])]++
	}
	best := ok[0]
	for _, a := range ok[1:] {
		ca, cb := counts[probe.Fingerprint(a.Chain[0])], counts[probe.Fingerprint(best.Chain[0])]
		if ca > cb || ca == cb && a.Chain[0].NotAfter.After(best.Chain[0].NotAfter) {
			best = a
		}
	}
	return best
}

// thresholds decides whether the certificate is renewal managed and which
// thresholds apply to it.
func thresholds(t Target, info probe.CertInfo) (bool, Thresholds) {
	managed := t.RenewalManaged
	if !t.RenewalSet {
		managed = IsACMEIssuer(info.IssuerOrg, info.IssuerCN)
	}
	th := t.Manual
	if managed {
		th = t.Managed
	}
	if t.Warn != nil {
		th.Warn = *t.Warn
	}
	if t.Crit != nil {
		th.Crit = *t.Crit
	}
	if t.WarnPct != nil {
		th.WarnPct = *t.WarnPct
	}
	if t.CritPct != nil {
		th.CritPct = *t.CritPct
	}
	return managed, th
}

// renewal opens renewal_overdue on a renewal-managed target whose current
// leaf has used more than the renewal point of its lifetime: the ACME
// client should have replaced it by now. An expired leaf has its own
// finding.
func (e *evaluation) renewal() {
	leaf := e.out.Leaf
	if !e.out.RenewalManaged || !e.now.Before(leaf.NotAfter) {
		return
	}
	point := e.t.RenewalPoint
	if point == 0 {
		point = DefaultRenewalPoint
	}
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	due := leaf.NotBefore.Add(life * time.Duration(point) / 100)
	if life <= 0 || !e.now.After(due) {
		return
	}
	days := DaysLeft(leaf.NotAfter, e.now)
	e.open(Finding{Kind: RenewalOverdue, Severity: Warning, Fingerprint: e.out.LeafFP, DaysLeft: &days,
		Details: fmt.Sprintf("renewal was due %s ago; the certificate expires in %s", Span(e.now.Sub(due)), Span(leaf.NotAfter.Sub(e.now)))})
}

// inconsistent opens a finding when the addresses serve different leaves.
func (e *evaluation) inconsistent(ok []probe.Address) {
	if !slices.ContainsFunc(ok, func(a probe.Address) bool { return probe.Fingerprint(a.Chain[0]) != e.out.LeafFP }) {
		return
	}
	var parts []string
	for _, a := range ok {
		parts = append(parts, fmt.Sprintf("%s serves %s (%d d)", a.IP, probe.Fingerprint(a.Chain[0])[:8], DaysLeft(a.Chain[0].NotAfter, e.now)))
	}
	e.open(Finding{Kind: Inconsistent, Severity: Warning, Details: strings.Join(parts, ", ")})
}

// facts runs the certificate checks on every answered address, records each
// address's status and opens each kind at its worst across the addresses.
func (e *evaluation) facts(ok []probe.Address) {
	worst := map[Kind]Finding{}
	for _, a := range ok {
		fs, notAfter := addressFacts(e.t, a, e.out.Thresholds, e.now)
		if e.out.NotAfter.IsZero() || notAfter.Before(e.out.NotAfter) {
			e.out.NotAfter = notAfter
		}
		status := "ok"
		var sev Severity
		for _, f := range fs {
			if old, seen := worst[f.Kind]; !seen || worse(f, old) {
				worst[f.Kind] = f
			}
			if f.Severity.Rank() > sev.Rank() {
				sev = f.Severity
			}
		}
		if sev.Rank() >= Warning.Rank() {
			status = string(sev)
		}
		e.out.Addresses[a.IP] = AddressOutcome{Status: status, LeafFP: probe.Fingerprint(a.Chain[0])}
	}
	for _, k := range Kinds {
		if f, found := worst[k]; found {
			e.open(f)
		}
	}
}

// legacy opens legacy_protocol while an address accepts SSL 3.0, TLS 1.0
// or 1.1. The versions are tested about once a day, so a check that did not
// test them leaves the finding as it is; so does a test that found nothing
// but could not reach every address.
func (e *evaluation) legacy(ok []probe.Address) {
	if e.t.SkipLegacy {
		return
	}
	on := map[string][]string{}
	tested, all := false, true
	for _, a := range ok {
		tested = tested || a.LegacyChecked || len(a.Legacy) > 0
		all = all && a.LegacyChecked
		for _, v := range a.Legacy {
			on[v] = append(on[v], a.IP)
		}
	}
	if !tested || len(on) == 0 && !all {
		e.keep(LegacyProtocol)
		return
	}
	e.out.LegacyChecked = true
	// Versions accepted by the same addresses share one part of the text:
	// "SSL 3.0, TLS 1.0 accepted", or "… accepted on 192.0.2.1".
	var where []string
	versions := map[string][]string{}
	for _, v := range probe.LegacyVersions {
		name := probe.VersionName(v)
		ips, found := on[name]
		if !found {
			continue
		}
		e.out.Legacy = append(e.out.Legacy, name)
		w := ""
		if len(ips) < len(ok) {
			w = " on " + strings.Join(ips, ", ")
		}
		if versions[w] == nil {
			where = append(where, w)
		}
		versions[w] = append(versions[w], name)
	}
	if len(where) == 0 {
		return
	}
	var parts []string
	for _, w := range where {
		parts = append(parts, strings.Join(versions[w], ", ")+" accepted"+w)
	}
	e.open(Finding{Kind: LegacyProtocol, Severity: Warning, Details: strings.Join(parts, "; ")})
}

// worse reports whether f is worse than old, a finding of the same kind:
// higher severity, or as severe with fewer days left.
func worse(f, old Finding) bool {
	if f.Severity.Rank() != old.Severity.Rank() {
		return f.Severity.Rank() > old.Severity.Rank()
	}
	return f.DaysLeft != nil && old.DaysLeft != nil && *f.DaysLeft < *old.DaysLeft
}

// expectedIssuer opens issuer_changed while the leaf is not from the
// configured issuer. It is a state check: it resolves once the issuer
// matches again.
func (e *evaluation) expectedIssuer(info probe.CertInfo) {
	if e.t.ExpectedIssuer == "" {
		return
	}
	exp := strings.ToLower(e.t.ExpectedIssuer)
	for _, s := range []string{info.IssuerCN, info.IssuerOrg, info.Issuer} {
		if strings.Contains(strings.ToLower(s), exp) {
			return
		}
	}
	e.open(Finding{Kind: IssuerChanged, Severity: Warning, Fingerprint: e.out.LeafFP,
		Details: fmt.Sprintf("issued by %s, expected %s", issuerName(info), e.t.ExpectedIssuer)})
}

// changes compares the leaf with the pinned one (self-signed trust) or with
// the previous leaf. Change findings stay open until acknowledged or until
// an automatic renewal confirms the certificate is back on its normal cycle.
// The details carry a diff of the two leaves.
func (e *evaluation) changes(info probe.CertInfo, cur probe.Address) {
	fp, prev := e.out.LeafFP, e.prev
	renewed := false
	switch {
	case e.t.Trust == probe.TrustSelfSigned:
		if e.t.PinnedFP == "" {
			e.out.PinFP = fp
		} else if fp != e.t.PinnedFP {
			what := describeChange(prev, info)
			if prev.Leaf != nil && prev.Leaf.Fingerprint == e.t.PinnedFP {
				what = Diff(*prev.Leaf, info, Intermediate{}, Intermediate{})
			}
			e.open(Finding{Kind: CertificateChanged, Severity: Warning, Fingerprint: fp,
				Details: fmt.Sprintf("pinned %s replaced by %s: %s", e.t.PinnedFP[:8], fp[:8], what)})
		}
	case prev.LeafFP != "" && fp != prev.LeafFP && !prev.Recent[fp]:
		sameIssuer := prev.IssuerOrg != "" && strings.EqualFold(prev.IssuerOrg, info.IssuerOrg)
		// An expected renewal keeps every name and still covers the
		// server name; dropping one is worth a look even from the ACME CA.
		covers := true
		if checked, ok := probe.CheckHostname(e.out.Leaf, e.t.ServerName); checked {
			covers = ok
		}
		what := describeChange(prev, info)
		if prev.Leaf != nil {
			what = Diff(*prev.Leaf, info, prev.Inter, servedIntermediate(cur))
		}
		if e.out.RenewalManaged && sameIssuer && superset(info.SANs, prev.SANs) && covers {
			renewed = true
			e.out.Events = append(e.out.Events, Finding{Kind: CertificateChanged, Severity: Info, Fingerprint: fp,
				Details: fmt.Sprintf("renewed by %s: %s", issuerName(info), what)})
		} else {
			e.open(Finding{Kind: CertificateChanged, Severity: Warning, Fingerprint: fp,
				Details: fmt.Sprintf("new leaf %s from %s: %s", fp[:8], issuerName(info), what)})
		}
		if e.t.ExpectedIssuer == "" && prev.IssuerOrg != "" && !sameIssuer {
			e.open(Finding{Kind: IssuerChanged, Severity: Warning, Fingerprint: fp,
				Details: fmt.Sprintf("issuer changed from %s to %s", prev.IssuerOrg, issuerName(info))})
		}
	}
	if renewed {
		return
	}
	e.keepUnlessOpened(CertificateChanged)
	if e.t.ExpectedIssuer == "" {
		e.keepUnlessOpened(IssuerChanged)
	}
}

// servedIntermediate is the certificate the address served after its leaf.
func servedIntermediate(a probe.Address) Intermediate {
	if len(a.Chain) < 2 {
		return Intermediate{}
	}
	return Intermediate{FP: probe.Fingerprint(a.Chain[1]), CN: nameOf(a.Chain[1])}
}

// keepUnlessOpened keeps k when this evaluation did not open it again.
func (e *evaluation) keepUnlessOpened(k Kind) {
	if !slices.ContainsFunc(e.out.Open, func(f Finding) bool { return f.Kind == k }) {
		e.keep(k)
	}
}

// addressFacts runs the certificate checks on one answered address and
// returns the findings and the earliest NotAfter in the presented chain.
func addressFacts(t Target, a probe.Address, th Thresholds, now time.Time) ([]Finding, time.Time) {
	var fs []Finding
	leaf := a.Chain[0]
	fp := probe.Fingerprint(leaf)
	earliest := leaf.NotAfter
	var expired, early []string
	var weak []string
	latestStart := leaf.NotBefore
	for _, c := range a.Chain {
		d := probe.Describe(c)
		root := d.SelfSigned && d.IsCA && c != leaf
		// A stale root the server still sends after a valid chain is not
		// used by clients, so its dates are not judged; only the root a
		// verified chain ends in is.
		if root && !anchors(a, c) {
			if d.KeyType == "RSA" && d.KeyBits < 2048 {
				weak = append(weak, nameOf(c))
			}
			continue
		}
		if c.NotAfter.Before(earliest) {
			earliest = c.NotAfter
		}
		if now.After(c.NotAfter) {
			expired = append(expired, nameOf(c))
		}
		// Clients refuse a certificate before its NotBefore just as after
		// its NotAfter; Verify judges trust apart from both.
		if now.Before(c.NotBefore) {
			early = append(early, nameOf(c))
			if c.NotBefore.After(latestStart) {
				latestStart = c.NotBefore
			}
		}
		// A root's own signature is never checked, so a SHA-1 root is fine;
		// its key signs the next certificate and is judged like any other.
		if d.WeakSignature && !root || root && d.KeyType == "RSA" && d.KeyBits < 2048 {
			weak = append(weak, nameOf(c))
		}
	}
	// The root a verified chain ends in, when it came from the store or
	// bundle rather than the server, is judged for expiry too.
	if n := len(a.VerifiedChain); n > 0 {
		if r := a.VerifiedChain[n-1]; !slices.ContainsFunc(a.Chain, r.Equal) && now.After(r.NotAfter) {
			expired = append(expired, nameOf(r)+" (root in the trust store)")
			if r.NotAfter.Before(earliest) {
				earliest = r.NotAfter
			}
		}
	}
	days := DaysLeft(earliest, now)
	// The share is what remains until the earliest expiry, against the
	// leaf's own lifetime.
	share, life := 100.0, leaf.NotAfter.Sub(leaf.NotBefore)
	if life > 0 {
		share = float64(earliest.Sub(now)) * 100 / float64(life)
	}
	if len(expired) > 0 {
		d := days
		fs = append(fs, Finding{Kind: Expired, Severity: Critical, Fingerprint: fp, DaysLeft: &d,
			Details: fmt.Sprintf("%s expired %s", strings.Join(expired, ", "), earliest.UTC().Format("2006-01-02"))})
	} else if sev := th.Due(days, share); sev != "" {
		left := Span(earliest.Sub(now)) + " left"
		// Name the share when it, not the days, decided.
		if th.ShareDecides(sev, life) {
			left += fmt.Sprintf(", %d %% of its lifetime", int(share))
		}
		d := days
		fs = append(fs, Finding{Kind: Expiring, Severity: sev, Fingerprint: fp, DaysLeft: &d,
			Details: fmt.Sprintf("%s · %s", left, earliest.UTC().Format("2006-01-02"))})
	}
	if len(early) > 0 {
		fs = append(fs, Finding{Kind: NotYetValid, Severity: Critical, Fingerprint: fp,
			Details: fmt.Sprintf("%s not valid until %s", strings.Join(early, ", "), latestStart.UTC().Format("2006-01-02 15:04 MST"))})
	}
	selfSigned := probe.Describe(leaf).SelfSigned
	if t.Trust != probe.TrustSelfSigned {
		// A self-signed leaf that verifies is itself in the bundle or store.
		if selfSigned && !a.Verified {
			fs = append(fs, Finding{Kind: SelfSigned, Severity: Critical, Fingerprint: fp, Details: "self-signed certificate on a target verified against the " + trustLabel(t.Trust)})
		} else if !a.Verified {
			fs = append(fs, Finding{Kind: ChainUntrusted, Severity: Critical, Fingerprint: fp, Details: a.VerifyError})
		}
	}
	if a.HostnameChecked && !a.HostnameOK {
		fs = append(fs, Finding{Kind: HostnameMismatch, Severity: Critical, Fingerprint: fp,
			Details: fmt.Sprintf("%s is not covered by %s", t.ServerName, strings.Join(probe.Describe(leaf).SANs, ", "))})
	}
	if len(weak) > 0 {
		fs = append(fs, Finding{Kind: WeakSignature, Severity: Warning, Fingerprint: fp, Details: "weak signature or key: " + strings.Join(weak, ", ")})
	}
	if f, bad := mustStaple(a, now); bad {
		f.Fingerprint = fp
		fs = append(fs, f)
	}
	// A private PKI is in no root program.
	if t.Trust == probe.TrustSystem || t.Trust == "" {
		if hits := Distrusted(a.Chain, a.VerifiedChain); len(hits) > 0 {
			fs = append(fs, distrustFinding(hits, leaf, fp, now))
		}
	}
	return fs, earliest
}

// anchors reports whether c is the root a verified chain of a ends in.
func anchors(a probe.Address, c *x509.Certificate) bool {
	n := len(a.VerifiedChain)
	return n > 0 && a.VerifiedChain[n-1].Equal(c)
}

func trustLabel(m probe.TrustMode) string {
	if m == probe.TrustBundle {
		return "CA bundle"
	}
	return "system store"
}

func nameOf(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

func issuerName(i probe.CertInfo) string {
	if i.IssuerOrg != "" {
		return i.IssuerOrg
	}
	return i.IssuerCN
}

func shortCN(cn string) string {
	if cn == "" {
		return "?"
	}
	return cn
}

func describeChange(prev Previous, info probe.CertInfo) string {
	switch {
	case len(prev.SANs) == 0:
		return "SANs " + strings.Join(info.SANs, ", ")
	case sameSet(prev.SANs, info.SANs):
		return "same SANs"
	case superset(info.SANs, prev.SANs):
		return "SANs added"
	}
	return "SANs changed"
}

func superset(have, want []string) bool {
	m := map[string]bool{}
	for _, s := range have {
		m[strings.ToLower(s)] = true
	}
	for _, s := range want {
		if !m[strings.ToLower(s)] {
			return false
		}
	}
	return true
}

func sameSet(a, b []string) bool { return superset(a, b) && superset(b, a) }

// implicitPorts are well-known ports that speak TLS from the first byte,
// and the protocol to use there.
var implicitPorts = map[int]string{465: "smtp", 993: "imap", 995: "pop3", 990: "ftp", 636: "ldap", 5061: "sip"}

// starttlsPorts are well-known ports that start in plain text.
var starttlsPorts = map[int]probe.Protocol{25: probe.SMTP, 587: probe.SMTP, 143: probe.IMAP, 110: probe.POP3, 21: probe.FTP, 5432: probe.Postgres}

// PortHint explains a protocol that does not fit a well-known port, the
// usual cause of a timeout or a failed handshake. It returns "" when the
// combination looks right.
func PortHint(p probe.Protocol, port int) string {
	if p != probe.TLS && p != "" {
		if name, ok := implicitPorts[port]; ok {
			return fmt.Sprintf("Port %d normally uses implicit TLS (%ss); choose protocol tls, or the STARTTLS port of %s", port, name, p)
		}
		return ""
	}
	if want, ok := starttlsPorts[port]; ok {
		return fmt.Sprintf("Port %d normally starts in plain text; choose protocol %s", port, want)
	}
	return ""
}

// NoIPv6Route explains a name with only IPv6 addresses, or an IPv6
// address, probed from a host that has no IPv6 route: nothing was tried.
func NoIPv6Route(host string, skipped []string) string {
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return "this address is IPv6 and there is no IPv6 route from here; probe it from a node with IPv6"
	}
	return fmt.Sprintf("the name has only IPv6 addresses (%s) and there is no IPv6 route from here; probe it from a node with IPv6",
		summarise(skipped))
}

func summarise(failures []string) string {
	if len(failures) == 0 {
		return "no address answered"
	}
	if len(failures) > 3 {
		return strings.Join(failures[:3], "; ") + fmt.Sprintf("; and %d more", len(failures)-3)
	}
	return strings.Join(failures, "; ")
}
