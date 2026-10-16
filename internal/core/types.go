// Package core is the domain: targets, certificates, findings and their
// state transitions, acknowledgements, CA bundles, retention and the audit
// log. Every component reads and writes through it.
package core

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/secret"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// ErrNotFound is returned for unknown IDs.
var ErrNotFound = errors.New("not found")

// ErrTargetExists is returned when a target with the same endpoint exists.
var ErrTargetExists = usererr.New("A target with this host, port, protocol and server name already exists")

// ErrStale is returned by Apply when the target was disabled, or its
// endpoint or trust changed, while it was being probed; the result is
// discarded.
var ErrStale = errors.New("target changed during the check")

// Target statuses.
const (
	StatusPending     = "pending"
	StatusHealthy     = "healthy"
	StatusWarning     = "warning"
	StatusChanged     = "changed"
	StatusCritical    = "critical"
	StatusUnreachable = "unreachable"
	StatusDisabled    = "disabled"
)

// StatusClass maps a status to its colour class.
func StatusClass(s string) string {
	switch s {
	case StatusHealthy:
		return "ok"
	case StatusWarning, StatusChanged:
		return "warn"
	case StatusCritical:
		return "crit"
	}
	return "off"
}

// StatusLabel is the word shown next to the status dot.
func StatusLabel(s string) string {
	switch s {
	case StatusPending:
		return "Pending"
	case StatusHealthy:
		return "Healthy"
	case StatusWarning:
		return "Warning"
	case StatusChanged:
		return "Changed"
	case StatusCritical:
		return "Critical"
	case StatusUnreachable:
		return "Unreachable"
	case StatusDisabled:
		return "Disabled"
	}
	return s
}

// Target is one endpoint to probe plus its current state.
type Target struct {
	ID             int64
	Name           string
	Host           string
	Port           int
	Protocol       probe.Protocol
	ServerName     string
	Trust          probe.TrustMode
	BundleID       int64
	BundleName     string
	RenewalManaged bool
	RenewalSet     bool
	ExpectedIssuer string
	// Optional overrides; nil follows Settings › Defaults.
	WarnDays    *int
	CritDays    *int
	IntervalS   *int
	TimeoutS    *int
	Retries     *int
	Debounce    *int
	RemindWarnS *int
	RemindCritS *int

	AllAddresses bool
	SkipLegacy   bool // the configuration test (TLS 1.0 and 1.1, cipher suites) is off
	AllChannels  bool
	ChannelIDs   []int64
	Tags         []string
	Notes        string
	Enabled      bool
	CreatedAt    int64
	CreatedBy    string
	UpdatedAt    int64

	// NodeID is the node the target is probed from, 0 for this server.
	NodeID   int64
	NodeName string

	// Current state.
	Status       string
	PinnedFP     string
	CurrentFP    string
	NotAfter     int64
	TLSVersion   string
	AddressCount int
	LastCheck    int64
	LastError    string
	FailStreak   int
	OkStreak     int
	DNSFail      int
	DNSOk        int
	NextCheck    int64
	// LegacyChecked is when TLS 1.0 and 1.1 were last tested, 0 for never;
	// LegacyAccepted lists the versions an address accepted then.
	LegacyChecked  int64
	LegacyAccepted []string
	// Grade is the configuration grade (A, B, C, F; "" before the first
	// full test) with its reasons, the rules version it was given under,
	// and the per-address verdicts of the last full test.
	Grade        string
	GradeReasons []string
	GradeRules   int
	ConfigTest   []check.AddressGrade

	// Joined for display.
	Cert *Certificate
}

// GradeClass is the status colour of the target's grade.
func (t Target) GradeClass() string { return check.GradeClass(t.Grade) }

// HostPort is host:port with IPv6 literals bracketed.
func (t Target) HostPort() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// Effective holds the values in force for a target after defaults.
type Effective struct {
	Warn, Crit      int
	IntervalS       int
	TimeoutS        int
	Retries         int
	Debounce        int
	RemindWarnS     int
	RemindCritS     int
	WarnDefault     bool // warning/critical follow the default
	IntervalDefault bool
	RemindDefault   bool
}

func or(p *int, def int) int {
	if p != nil {
		return *p
	}
	return def
}

// Effective resolves the target's settings against the defaults.
func (t Target) Effective(d config.Defaults) Effective {
	th := d.Manual
	if t.RenewalManaged {
		th = d.Managed
	}
	return Effective{
		Warn:            or(t.WarnDays, th.WarnDays),
		Crit:            or(t.CritDays, th.CritDays),
		IntervalS:       or(t.IntervalS, d.IntervalS),
		TimeoutS:        or(t.TimeoutS, d.TimeoutS),
		Retries:         or(t.Retries, d.Retries),
		Debounce:        or(t.Debounce, d.Debounce),
		RemindWarnS:     or(t.RemindWarnS, d.RemindWarnS),
		RemindCritS:     or(t.RemindCritS, d.RemindCritS),
		WarnDefault:     t.WarnDays == nil && t.CritDays == nil,
		IntervalDefault: t.IntervalS == nil,
		RemindDefault:   t.RemindWarnS == nil && t.RemindCritS == nil,
	}
}

// DaysLeft returns whole days until the earliest expiry, or nil when unknown.
func (t Target) DaysLeft(now time.Time) *int {
	if t.NotAfter == 0 {
		return nil
	}
	d := check.DaysLeft(time.Unix(t.NotAfter, 0), now)
	return &d
}

// Certificate is one X.509 certificate, keyed by fingerprint.
type Certificate struct {
	Fingerprint string
	Subject     string
	SubjectCN   string
	Issuer      string
	IssuerCN    string
	IssuerOrg   string
	Serial      string
	NotBefore   int64
	NotAfter    int64
	SANs        []string
	KeyType     string
	KeyBits     int
	SigAlg      string
	IsCA        bool
	SelfSigned  bool
	PEM         string
	FirstSeen   int64
	LastSeen    int64
}

// KeyDesc is "RSA 2048", "ECDSA P-256" or "Ed25519".
func (c Certificate) KeyDesc() string {
	switch c.KeyType {
	case "ECDSA":
		switch c.KeyBits {
		case 256:
			return "ECDSA P-256"
		case 384:
			return "ECDSA P-384"
		case 521:
			return "ECDSA P-521"
		}
	case "Ed25519":
		return "Ed25519"
	}
	return c.KeyType + " " + strconv.Itoa(c.KeyBits)
}

// IssuerName is the organisation, or the CN when there is none.
func (c Certificate) IssuerName() string {
	if c.SelfSigned {
		return "self-signed"
	}
	if c.IssuerOrg != "" {
		return c.IssuerOrg
	}
	return c.IssuerCN
}

// LifetimeUsed is the share of the validity period already used, 0 to 100.
func (c Certificate) LifetimeUsed(now time.Time) int {
	return LifetimeUsed(c.NotBefore, c.NotAfter, now)
}

// LifetimeUsed computes the used share of a validity period.
func LifetimeUsed(nb, na int64, now time.Time) int {
	total := na - nb
	if total <= 0 {
		return 100
	}
	p := (now.Unix() - nb) * 100 / total
	switch {
	case p < 0:
		return 0
	case p > 100:
		return 100
	}
	return int(p)
}

// LifetimeDays is the total validity in days.
func (c Certificate) LifetimeDays() int { return int((c.NotAfter - c.NotBefore + 43200) / 86400) }

// Finding is a problem on a target, open until it resolves.
type Finding struct {
	ID          int64
	TargetID    int64
	Kind        check.Kind
	Severity    check.Severity
	OpenedAt    int64
	ResolvedAt  int64
	Details     string
	Fingerprint string
	DaysLeft    *int
	AckBy       string
	AckAt       int64
	AckUntil    int64
	AckComment  string
	LastAlertAt int64
	// NodeID is set, and TargetID 0, for a finding on a node (node_offline).
	NodeID int64

	// Joined for display. For a node finding TargetName is the node's
	// name and TargetHost its hostname.
	TargetName     string
	TargetHost     string
	TargetPort     int
	TargetProtocol string
	LastAlertVia   string
}

// Open reports whether the finding is unresolved.
func (f Finding) Open() bool { return f.ResolvedAt == 0 }

// Acked reports whether an acknowledgement is in force at now.
func (f Finding) Acked(now time.Time) bool {
	return f.AckAt > 0 && (f.AckUntil == 0 || f.AckUntil > now.Unix())
}

// HostPort of the finding's target, or the hostname of its node.
func (f Finding) HostPort() string {
	if f.NodeID != 0 {
		return f.TargetHost
	}
	return net.JoinHostPort(f.TargetHost, strconv.Itoa(f.TargetPort))
}

// Service is the domain service.
type Service struct {
	DB         *db.DB
	Settings   *config.Store
	Channels   *notify.Channels
	Dispatcher *notify.Dispatcher
	// Key seals a node's install token while it is unspent, so the Add
	// node screen can show its command again; nil keeps no copy.
	Key *secret.Key
	Now func() time.Time
	Log *slog.Logger

	bundles bundleCache
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) wake() {
	if s.Dispatcher != nil {
		s.Dispatcher.Wake()
	}
}

// ParseTags splits a tag field on commas and whitespace, lowercases,
// de-duplicates and drops tags over 40 characters.
func ParseTags(v string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' }) {
		t := strings.ToLower(strings.TrimSpace(f))
		if t == "" || seen[t] {
			continue
		}
		if len([]rune(t)) > 40 {
			return nil, usererr.New("Tags are limited to 40 characters: " + t)
		}
		seen[t] = true
		out = append(out, t)
	}
	return out, nil
}

func nullInt(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func intPtr(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}

// Audit records a change in the tool itself.
func (s *Service) Audit(ctx context.Context, user, action, object, details string) {
	if _, err := s.DB.W.ExecContext(ctx, "INSERT INTO audit(at, user_email, action, object, details) VALUES(?,?,?,?,?)",
		s.now().Unix(), user, action, object, details); err != nil && s.Log != nil {
		s.Log.Error("audit", "err", err)
	}
}

// CurrentSettings returns the current settings; a load error is logged and
// the defaults are used.
func (s *Service) CurrentSettings(ctx context.Context) config.Settings {
	st, err := s.Settings.Get(ctx)
	if err != nil && s.Log != nil {
		s.Log.Error("load settings", "err", err)
	}
	return st
}

// ExpiryClass colours a days-left value by the target's thresholds: "crit",
// "warn" or "" when nothing is due.
func (t Target) ExpiryClass(d config.Defaults, now time.Time) string {
	if t.NotAfter == 0 {
		return ""
	}
	days := check.DaysLeft(time.Unix(t.NotAfter, 0), now)
	eff := t.Effective(d)
	switch {
	case days < eff.Crit:
		return "crit"
	case days < eff.Warn:
		return "warn"
	}
	return ""
}

// BarClass is the lifetime bar colour.
func (t Target) BarClass(d config.Defaults, now time.Time) string {
	if c := t.ExpiryClass(d, now); c != "" {
		return c
	}
	if !t.Enabled {
		return "off"
	}
	return "ok"
}
