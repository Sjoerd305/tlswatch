// Package check turns a probe result into findings: expiry thresholds, chain
// and hostname verification, change detection and debouncing of
// network-shaped failures. It is pure; the caller persists the outcome.
package check

import (
	"crypto/x509"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

// Kind is the type of a finding.
type Kind string

// The finding kinds from the specification.
const (
	Expiring           Kind = "expiring"
	Expired            Kind = "expired"
	ChainUntrusted     Kind = "chain_untrusted"
	SelfSigned         Kind = "self_signed"
	HostnameMismatch   Kind = "hostname_mismatch"
	WeakSignature      Kind = "weak_signature"
	CertificateChanged Kind = "certificate_changed"
	IssuerChanged      Kind = "issuer_changed"
	Inconsistent       Kind = "inconsistent"
	TLSUnavailable     Kind = "tls_unavailable"
	Unreachable        Kind = "unreachable"
	DNSFailed          Kind = "dns_failed"
)

// Kinds lists every kind, for filters.
var Kinds = []Kind{Expiring, Expired, ChainUntrusted, SelfSigned, HostnameMismatch, WeakSignature, CertificateChanged, IssuerChanged, Inconsistent, TLSUnavailable, Unreachable, DNSFailed}

// Label is the human name of a kind.
func (k Kind) Label() string {
	switch k {
	case ChainUntrusted:
		return "Chain untrusted"
	case SelfSigned:
		return "Self-signed"
	case HostnameMismatch:
		return "Hostname mismatch"
	case WeakSignature:
		return "Weak signature"
	case CertificateChanged:
		return "Certificate changed"
	case IssuerChanged:
		return "Issuer changed"
	case TLSUnavailable:
		return "STARTTLS unavailable"
	case DNSFailed:
		return "DNS failed"
	}
	s := string(k)
	return strings.ToUpper(s[:1]) + s[1:]
}

// Short is the compact label used in chips.
func (k Kind) Short() string {
	switch k {
	case CertificateChanged:
		return "changed"
	case IssuerChanged:
		return "issuer"
	case ChainUntrusted:
		return "untrusted"
	case HostnameMismatch:
		return "hostname"
	case WeakSignature:
		return "weak"
	case TLSUnavailable:
		return "starttls"
	case DNSFailed:
		return "dns"
	case SelfSigned:
		return "self-signed"
	}
	return string(k)
}

// AckResolves reports whether acknowledging a finding of this kind resolves it.
func (k Kind) AckResolves() bool { return k == CertificateChanged || k == IssuerChanged }

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

// Thresholds are warning and critical days.
type Thresholds struct{ Warn, Crit int }

// Target is the configuration the checks need.
type Target struct {
	Trust          probe.TrustMode
	ServerName     string
	Warn, Crit     *int // explicit per-target values; nil follows the default
	Manual         Thresholds
	Managed        Thresholds
	RenewalManaged bool
	RenewalSet     bool // false: derive RenewalManaged from the issuer
	ExpectedIssuer string
	Debounce       int
	PinnedFP       string
}

// Previous is the state left by the last check.
type Previous struct {
	LeafFP     string
	IssuerOrg  string
	IssuerCN   string
	SANs       []string
	FailStreak int
	OkStreak   int
	DNSFail    int
	DNSOk      int
	Open       map[Kind]bool
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
	Answered       bool   // at least one address completed a handshake
	FailStreak     int
	OkStreak       int
	DNSFail        int
	DNSOk          int
	Addresses      map[string]AddressOutcome
	Error          string // summary error when nothing answered
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

// Evaluate applies every check to one probe result.
func Evaluate(t Target, prev Previous, r probe.Result, now time.Time) Outcome {
	out := Outcome{Addresses: map[string]AddressOutcome{}}
	debounce := t.Debounce
	if debounce < 1 {
		debounce = 1
	}
	keep := func(k Kind) {
		if prev.Open[k] {
			out.Keep = append(out.Keep, k)
		}
	}

	// DNS.
	if r.DNSError != "" && len(r.Addresses) == 0 {
		out.DNSFail = prev.DNSFail + 1
		out.Error = r.DNSError
		if prev.Open[DNSFailed] || out.DNSFail >= debounce {
			out.Open = append(out.Open, Finding{Kind: DNSFailed, Severity: Critical, Details: "the name did not resolve: " + r.DNSError})
		}
		out.FailStreak, out.OkStreak = prev.FailStreak, prev.OkStreak
		for _, k := range Kinds {
			if k != DNSFailed {
				keep(k)
			}
		}
		return out
	}
	out.DNSOk = prev.DNSOk + 1
	if prev.Open[DNSFailed] && out.DNSOk < debounce {
		keep(DNSFailed)
	}

	var ok []probe.Address
	var starttls []string
	var failures []string
	for _, a := range r.Addresses {
		switch {
		case a.OK:
			ok = append(ok, a)
		case a.ErrorKind == probe.ErrStartTLS:
			starttls = append(starttls, a.IP)
			out.Addresses[a.IP] = AddressOutcome{Status: "critical"}
		default:
			failures = append(failures, a.IP+": "+a.Error)
			out.Addresses[a.IP] = AddressOutcome{Status: "error"}
		}
	}

	if len(starttls) > 0 {
		out.Open = append(out.Open, Finding{Kind: TLSUnavailable, Severity: Critical, Details: "STARTTLS not offered on " + strings.Join(starttls, ", ")})
	}

	// Unreachable on every address that did not refuse STARTTLS.
	if len(ok) == 0 {
		if len(starttls) == 0 {
			out.FailStreak = prev.FailStreak + 1
			out.Error = strings.Join(failures, "; ")
			details := summarise(failures)
			if hint := PortHint(r.Protocol, r.Port); hint != "" {
				out.Error += ". " + hint
				details += ". " + hint
			}
			if prev.Open[Unreachable] || out.FailStreak >= debounce {
				out.Open = append(out.Open, Finding{Kind: Unreachable, Severity: Critical, Details: details})
			}
		} else {
			out.FailStreak, out.OkStreak = prev.FailStreak, prev.OkStreak
			keep(Unreachable)
		}
		// Nothing was read: certificate findings stay as they are.
		for _, k := range Kinds {
			if !k.Network() && k != TLSUnavailable {
				keep(k)
			}
		}
		return out
	}
	out.Answered = true
	out.OkStreak = prev.OkStreak + 1
	if prev.Open[Unreachable] && out.OkStreak < debounce {
		keep(Unreachable)
	}

	// Pick the current leaf: the one most addresses serve; ties go to the
	// latest expiry so a stale node does not become "current".
	counts := map[string]int{}
	leafOf := map[string]probe.Address{}
	for _, a := range ok {
		fp := probe.Fingerprint(a.Chain[0])
		counts[fp]++
		leafOf[fp] = a
	}
	fps := make([]string, 0, len(counts))
	for fp := range counts {
		fps = append(fps, fp)
	}
	sort.Slice(fps, func(i, j int) bool {
		if counts[fps[i]] != counts[fps[j]] {
			return counts[fps[i]] > counts[fps[j]]
		}
		return leafOf[fps[i]].Chain[0].NotAfter.After(leafOf[fps[j]].Chain[0].NotAfter)
	})
	cur := leafOf[fps[0]]
	leaf := cur.Chain[0]
	out.Leaf = leaf
	out.LeafFP = fps[0]
	out.TLSVersion = cur.TLSVersion
	info := probe.Describe(leaf)

	out.RenewalManaged = t.RenewalManaged
	if !t.RenewalSet {
		out.RenewalManaged = IsACMEIssuer(info.IssuerOrg, info.IssuerCN)
	}
	th := t.Manual
	if out.RenewalManaged {
		th = t.Managed
	}
	if t.Warn != nil {
		th.Warn = *t.Warn
	}
	if t.Crit != nil {
		th.Crit = *t.Crit
	}
	out.Thresholds = th

	if len(fps) > 1 {
		var parts []string
		for _, a := range ok {
			fp := probe.Fingerprint(a.Chain[0])
			parts = append(parts, fmt.Sprintf("%s serves %s (%d d)", a.IP, fp[:8], DaysLeft(a.Chain[0].NotAfter, now)))
		}
		out.Open = append(out.Open, Finding{Kind: Inconsistent, Severity: Warning, Details: strings.Join(parts, ", ")})
	}

	// Fact findings, per address, merged to the worst.
	facts := map[Kind]Finding{}
	merge := func(f Finding) {
		if old, ok := facts[f.Kind]; !ok || f.Severity.Rank() > old.Severity.Rank() ||
			(f.DaysLeft != nil && old.DaysLeft != nil && *f.DaysLeft < *old.DaysLeft) {
			facts[f.Kind] = f
		}
	}
	earliest := time.Time{}
	for _, a := range ok {
		fs, na := addressFacts(t, a, th, now)
		if earliest.IsZero() || na.Before(earliest) {
			earliest = na
		}
		worst := "ok"
		for _, f := range fs {
			merge(f)
			if f.Severity == Critical {
				worst = "critical"
			} else if f.Severity == Warning && worst != "critical" {
				worst = "warning"
			}
		}
		out.Addresses[a.IP] = AddressOutcome{Status: worst, LeafFP: probe.Fingerprint(a.Chain[0])}
	}
	out.NotAfter = earliest
	for _, k := range Kinds {
		if f, ok := facts[k]; ok {
			out.Open = append(out.Open, f)
		}
	}

	// Expected issuer is a state check.
	if t.ExpectedIssuer != "" {
		exp := strings.ToLower(t.ExpectedIssuer)
		if !strings.Contains(strings.ToLower(info.IssuerCN), exp) && !strings.Contains(strings.ToLower(info.IssuerOrg), exp) && !strings.Contains(strings.ToLower(info.Issuer), exp) {
			out.Open = append(out.Open, Finding{Kind: IssuerChanged, Severity: Warning, Fingerprint: out.LeafFP,
				Details: fmt.Sprintf("issued by %s, expected %s", issuerName(info), t.ExpectedIssuer)})
		}
	}

	// Change detection.
	changed := false
	switch {
	case t.Trust == probe.TrustSelfSigned:
		if t.PinnedFP == "" {
			out.PinFP = out.LeafFP
		} else if out.LeafFP != t.PinnedFP {
			changed = true
			out.Open = append(out.Open, Finding{Kind: CertificateChanged, Severity: Warning, Fingerprint: out.LeafFP,
				Details: fmt.Sprintf("pinned %s replaced by %s, %s", t.PinnedFP[:8], out.LeafFP[:8], describeChange(prev, info))})
		}
	case prev.LeafFP != "" && out.LeafFP != prev.LeafFP:
		changed = true
		sameIssuer := prev.IssuerOrg != "" && strings.EqualFold(prev.IssuerOrg, info.IssuerOrg)
		if out.RenewalManaged && sameIssuer && superset(info.SANs, prev.SANs) {
			out.Events = append(out.Events, Finding{Kind: CertificateChanged, Severity: Info, Fingerprint: out.LeafFP,
				Details: fmt.Sprintf("renewed by %s, %s → %s", issuerName(info), shortCN(prev.IssuerCN), shortCN(info.IssuerCN))})
		} else {
			out.Open = append(out.Open, Finding{Kind: CertificateChanged, Severity: Warning, Fingerprint: out.LeafFP,
				Details: fmt.Sprintf("new leaf %s from %s, %s", out.LeafFP[:8], issuerName(info), describeChange(prev, info))})
		}
		if t.ExpectedIssuer == "" && prev.IssuerOrg != "" && !sameIssuer {
			out.Open = append(out.Open, Finding{Kind: IssuerChanged, Severity: Warning, Fingerprint: out.LeafFP,
				Details: fmt.Sprintf("issuer changed from %s to %s", prev.IssuerOrg, issuerName(info))})
		}
	}
	// Change findings stay open until acknowledged.
	if !changed {
		keep(CertificateChanged)
		if t.ExpectedIssuer == "" {
			keep(IssuerChanged)
		}
	}
	return out
}

// addressFacts runs the certificate checks on one answered address and
// returns the findings and the earliest NotAfter in the presented chain.
func addressFacts(t Target, a probe.Address, th Thresholds, now time.Time) ([]Finding, time.Time) {
	var fs []Finding
	leaf := a.Chain[0]
	fp := probe.Fingerprint(leaf)
	earliest := leaf.NotAfter
	var expired []string
	var weak []string
	for _, c := range a.Chain {
		if c.NotAfter.Before(earliest) {
			earliest = c.NotAfter
		}
		if now.After(c.NotAfter) {
			expired = append(expired, nameOf(c))
		}
		// A root's own signature is never checked, so a SHA-1 root is fine.
		if d := probe.Describe(c); d.WeakSignature && !(d.SelfSigned && d.IsCA && c != leaf) {
			weak = append(weak, nameOf(c))
		}
	}
	days := DaysLeft(earliest, now)
	if len(expired) > 0 {
		d := days
		fs = append(fs, Finding{Kind: Expired, Severity: Critical, Fingerprint: fp, DaysLeft: &d,
			Details: fmt.Sprintf("%s expired %s", strings.Join(expired, ", "), earliest.UTC().Format("2006-01-02"))})
	} else if days < th.Warn {
		sev := Warning
		if days < th.Crit {
			sev = Critical
		}
		d := days
		fs = append(fs, Finding{Kind: Expiring, Severity: sev, Fingerprint: fp, DaysLeft: &d,
			Details: fmt.Sprintf("%d days left · %s", days, earliest.UTC().Format("2006-01-02"))})
	}
	selfSigned := probe.Describe(leaf).SelfSigned
	if t.Trust != probe.TrustSelfSigned {
		if selfSigned {
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
	return fs, earliest
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

func summarise(failures []string) string {
	if len(failures) == 0 {
		return "no address answered"
	}
	if len(failures) > 3 {
		return strings.Join(failures[:3], "; ") + fmt.Sprintf("; and %d more", len(failures)-3)
	}
	return strings.Join(failures, "; ")
}
