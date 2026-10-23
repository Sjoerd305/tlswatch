package check

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

// Anchor is a CA certificate a distrust event covers. It is matched by the
// SHA-256 of its public key rather than of the certificate, so a re-issued
// or cross-signed copy of the same root matches too, and by its subject key
// ID, so a chain whose server leaves the root out still matches through the
// authority key ID of the intermediate below it.
type Anchor struct {
	Name string
	SPKI string // hex SHA-256 of the SubjectPublicKeyInfo
	SKI  string // hex subject key identifier
}

// DistrustEvent is one root program's distrust of one CA: from Effective
// on, the program no longer trusts certificates under Anchors that were
// issued after IssuedAfter, or any of them when IssuedAfter is zero.
type DistrustEvent struct {
	CA      string
	Program string // Chrome, Mozilla, Apple or Microsoft
	Anchors []Anchor
	// IssuedAfter is the cutoff; BySCT judges it by the earliest embedded
	// SCT (Chrome's rule), falling back to NotBefore, which the other
	// programs use.
	IssuedAfter time.Time
	BySCT       bool
	Effective   time.Time
	Description string
	Link        string
}

// Phrase is the event in words as of now: "Chrome distrusts certificates
// from it issued after 11 Nov 2024", "Mozilla stops trusting it on 15 Apr
// 2026".
func (ev DistrustEvent) Phrase(now time.Time) string {
	day := func(t time.Time) string { return t.UTC().Format("2 Jan 2006") }
	ahead := now.Before(ev.Effective)
	switch {
	case ev.IssuedAfter.IsZero() && ahead:
		return fmt.Sprintf("%s stops trusting it on %s", ev.Program, day(ev.Effective))
	case ev.IssuedAfter.IsZero():
		return fmt.Sprintf("%s stopped trusting it on %s", ev.Program, day(ev.Effective))
	case ahead:
		return fmt.Sprintf("%s will distrust certificates from it issued after %s, from %s", ev.Program, day(ev.IssuedAfter), day(ev.Effective))
	}
	return fmt.Sprintf("%s distrusts certificates from it issued after %s", ev.Program, day(ev.IssuedAfter))
}

// covers returns the anchor of ev that c is, or that issued c.
func (ev DistrustEvent) covers(c *x509.Certificate) (Anchor, bool) {
	spki := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	key, aki := hex.EncodeToString(spki[:]), hex.EncodeToString(c.AuthorityKeyId)
	for _, a := range ev.Anchors {
		if a.SPKI == key || aki != "" && a.SKI == aki {
			return a, true
		}
	}
	return Anchor{}, false
}

// issued is when leaf counts as issued under ev's rule.
func (ev DistrustEvent) issued(leaf *x509.Certificate) time.Time {
	if ev.BySCT {
		if t, ok := EarliestSCT(leaf); ok {
			return t
		}
	}
	return leaf.NotBefore
}

// DistrustTable versions Distrusts: a release that adds or changes events
// raises it. Every check evaluates the table in the binary, so a new table
// applies to every target at its next check, on the server, without a node
// update.
const DistrustTable = 2

// DistrustsOf returns the events whose anchors include c itself, or with
// issuer set, c's issuer.
func DistrustsOf(c *x509.Certificate, issuer bool) []DistrustEvent {
	spki := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	key, aki := hex.EncodeToString(spki[:]), hex.EncodeToString(c.AuthorityKeyId)
	var out []DistrustEvent
	for _, ev := range Distrusts {
		if slices.ContainsFunc(ev.Anchors, func(a Anchor) bool { return !issuer && a.SPKI == key || issuer && aki != "" && a.SKI == aki }) {
			out = append(out, ev)
		}
	}
	return out
}

// DistrustHit is an event that applies to a served chain.
type DistrustHit struct {
	Event  DistrustEvent
	Anchor Anchor
}

// Distrusted returns the events that apply to the chain under leaf:
// chain is what the server sent (leaf first) and verified the chain that
// verification built. An event applies when it covers the root the chain
// ends in, the leaf falls under its rule, and the leaf does not expire
// before the event takes effect. Only the anchor counts, not every
// certificate sent: a server that sends an old root's cross-sign next to a
// path to a newer root is anchored in the newer one. The anchor is the
// root verification chose, or when it failed, the top of the served chain
// (that certificate itself, or its issuer through the authority key ID).
// An event of a program that still trusts another root the chain leads to,
// through a cross-sign, does not apply.
func Distrusted(chain, verified []*x509.Certificate) []DistrustHit {
	if len(chain) == 0 {
		return nil
	}
	leaf, top := chain[0], chain[len(chain)-1]
	if len(verified) > 0 {
		top = verified[len(verified)-1]
	}
	if top == leaf {
		return nil
	}
	var hits []DistrustHit
	for _, ev := range Distrusts {
		if leaf.NotAfter.Before(ev.Effective) {
			continue
		}
		if !ev.IssuedAfter.IsZero() && !ev.issued(leaf).After(ev.IssuedAfter) {
			continue
		}
		a, ok := ev.covers(top)
		if ok && !anchoredElsewhere(ev, slices.Concat(chain[1:], verified)) {
			hits = append(hits, DistrustHit{Event: ev, Anchor: a})
		}
	}
	return hits
}

// anchoredElsewhere reports whether ev's program can anchor the chain in a
// root it still trusts: a certificate of the chain, other than one ev
// covers, carries the key of such a root, as a cross-signed newer root
// does.
func anchoredElsewhere(ev DistrustEvent, certs []*x509.Certificate) bool {
	roots := programRoots[ev.Program]
	for _, c := range certs {
		spki := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		key := hex.EncodeToString(spki[:])
		if roots[key] && !slices.ContainsFunc(ev.Anchors, func(a Anchor) bool { return a.SPKI == key }) {
			return true
		}
	}
	return false
}

// distrustFinding is the distrusted_ca finding for hits: a warning while
// every event is still ahead, critical once one is in effect.
func distrustFinding(hits []DistrustHit, leaf *x509.Certificate, fp string, now time.Time) Finding {
	sev := Warning
	var parts []string
	roots := map[string]bool{}
	var names []string
	byIssue := false
	for _, h := range hits {
		if !now.Before(h.Event.Effective) {
			sev = Critical
		}
		if !roots[h.Anchor.Name] {
			roots[h.Anchor.Name] = true
			names = append(names, h.Anchor.Name)
		}
		parts = append(parts, h.Event.Phrase(now))
		byIssue = byIssue || !h.Event.IssuedAfter.IsZero()
	}
	details := "chain roots in " + strings.Join(names, ", ") + "; " + strings.Join(parts, "; ")
	if byIssue {
		details += "; this one was issued " + leaf.NotBefore.UTC().Format("2 Jan 2006")
	}
	return Finding{Kind: DistrustedCA, Severity: sev, Fingerprint: fp, Details: details}
}

// sctOID is the embedded SCT list extension (RFC 6962, section 3.3).
var sctOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// EarliestSCT returns the earliest timestamp of the SCTs embedded in c.
func EarliestSCT(c *x509.Certificate) (time.Time, bool) {
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(sctOID) {
			continue
		}
		var list []byte
		if _, err := asn1.Unmarshal(ext.Value, &list); err != nil || len(list) < 2 {
			return time.Time{}, false
		}
		// A TLS vector of SCTs, each a vector of version (1 byte), log ID
		// (32 bytes), timestamp (8 bytes, milliseconds) and more.
		b := list[2:]
		var earliest time.Time
		for len(b) >= 2 {
			n := int(binary.BigEndian.Uint16(b))
			if len(b) < 2+n {
				break
			}
			if sct := b[2 : 2+n]; len(sct) >= 41 && sct[0] == 0 {
				// A timestamp with the top bit set is no timestamp.
				if ms := binary.BigEndian.Uint64(sct[33:41]); ms <= math.MaxInt64 {
					t := time.UnixMilli(int64(ms)).UTC()
					if earliest.IsZero() || t.Before(earliest) {
						earliest = t
					}
				}
			}
			b = b[2+n:]
		}
		return earliest, !earliest.IsZero()
	}
	return time.Time{}, false
}
