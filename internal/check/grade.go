package check

import (
	"crypto/tls"
	"fmt"
	"slices"
	"strings"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

// GradeRules is the version of the rules table below. It is stored next to
// every grade, so a tightened rule set re-grades on the next test and the
// history shows which rules a grade was given under.
const GradeRules = 1

// Grades, best first. There is no A+ and no D: four grades sort a list and
// settle a discussion with a vendor; finer steps invite disputes about
// scoring instead of fixes.
const (
	GradeA = "A"
	GradeB = "B"
	GradeC = "C"
	GradeF = "F"
)

// Grades lists every grade, best first.
var Grades = []string{GradeA, GradeB, GradeC, GradeF}

// GradeRank orders grades; higher is better, 0 for no grade.
func GradeRank(g string) int {
	switch g {
	case GradeA:
		return 4
	case GradeB:
		return 3
	case GradeC:
		return 2
	case GradeF:
		return 1
	}
	return 0
}

// GradeClass is the status colour of a grade: ok, warn, crit.
func GradeClass(g string) string {
	switch g {
	case GradeA:
		return "ok"
	case GradeB:
		return "info"
	case GradeC:
		return "warn"
	case GradeF:
		return "crit"
	}
	return "off"
}

// AddressGrade is the configuration verdict of one address.
type AddressGrade struct {
	IP      string
	Grade   string
	Reasons []string
	// What the test found: the legacy versions and the suite classes the
	// address accepted, and the suite it picked per class.
	Versions   []string
	Classes    []probe.SuiteClass
	SuiteNames []string
}

// gradeAddress applies the rules to one address whose configuration test
// reached a full verdict. Every rule that fires is a reason; the grade is
// the lowest any rule gives. Certificate validity (expiry, trust, the
// hostname) stays out: it has findings of its own.
func gradeAddress(a probe.Address) AddressGrade {
	g := AddressGrade{IP: a.IP, Grade: GradeA, Versions: a.Legacy, Classes: a.Suites, SuiteNames: a.SuiteNames}
	lower := func(grade, reason string) {
		if GradeRank(grade) < GradeRank(g.Grade) {
			g.Grade = grade
		}
		g.Reasons = append(g.Reasons, reason)
	}
	suite := func(c probe.SuiteClass) string {
		for i, have := range a.Suites {
			if have == c && i < len(a.SuiteNames) {
				return have.Label() + " (" + a.SuiteNames[i] + ")"
			}
		}
		return c.Label()
	}
	accepts := func(c probe.SuiteClass) bool {
		for _, have := range a.Suites {
			if have == c {
				return true
			}
		}
		return false
	}

	// Versions. The normal probe offers everything up to TLS 1.3, so the
	// negotiated version is the highest the server speaks.
	switch a.TLSVersion {
	case tls.VersionName(tls.VersionTLS10), tls.VersionName(tls.VersionTLS11):
		lower(GradeF, "speaks "+a.TLSVersion+" at most")
	case tls.VersionName(tls.VersionTLS12):
		if len(a.Legacy) > 0 {
			lower(GradeC, "accepts "+strings.Join(a.Legacy, " and "))
		}
		lower(GradeB, "no TLS 1.3")
	default:
		if len(a.Legacy) > 0 {
			lower(GradeC, "accepts "+strings.Join(a.Legacy, " and "))
		}
	}

	// Cipher suite classes.
	if accepts(probe.ClassRC4) {
		lower(GradeF, "accepts "+suite(probe.ClassRC4))
	}
	if accepts(probe.Class3DES) {
		lower(GradeC, "accepts "+suite(probe.Class3DES))
	}
	if accepts(probe.ClassNoPFS) {
		lower(GradeB, "accepts "+suite(probe.ClassNoPFS))
	}
	if accepts(probe.ClassCBC) {
		lower(GradeB, "accepts "+suite(probe.ClassCBC))
	}

	// Keys and signatures in the chain. A root's own signature is never
	// checked, so it does not count, as for weak_signature.
	for i, c := range a.Chain {
		d := probe.Describe(c)
		switch d.KeyType {
		case "RSA", "DSA":
			if d.KeyBits > 0 && d.KeyBits < 1024 {
				lower(GradeF, fmt.Sprintf("%s key of %d bits on %s", d.KeyType, d.KeyBits, nameOf(c)))
			} else if d.KeyBits > 0 && d.KeyBits < 2048 {
				lower(GradeC, fmt.Sprintf("%s key of %d bits on %s", d.KeyType, d.KeyBits, nameOf(c)))
			}
		case "ECDSA":
			if d.KeyBits > 0 && d.KeyBits < 256 {
				lower(GradeC, fmt.Sprintf("ECDSA key of %d bits on %s", d.KeyBits, nameOf(c)))
			}
		}
		if weakSig(c.SignatureAlgorithm) && !(d.SelfSigned && d.IsCA && i > 0) {
			lower(GradeC, d.SigAlg+" signature on "+nameOf(c))
		}
	}
	if probe.StapleOf(a).Status == probe.StapleGood {
		g.Reasons = append(g.Reasons, StapledReason)
	}
	return g
}

func weakSig(alg interface{ String() string }) bool {
	s := alg.String()
	return strings.Contains(s, "SHA1") || strings.Contains(s, "MD5") || strings.Contains(s, "MD2")
}

// grade grades the answering addresses when their configuration test
// reached a full verdict, opens weak_configuration for the weak suite
// classes, and records a changed grade as an event. A check that did not
// test, or one where an address got no verdict, leaves the finding and the
// stored grade as they are.
func (e *evaluation) grade(ok []probe.Address) {
	if e.t.SkipLegacy {
		return
	}
	tested, all := false, true
	for _, a := range ok {
		tested = tested || a.SuitesChecked || len(a.Suites) > 0
		all = all && a.SuitesChecked && a.LegacyChecked
	}
	if !tested {
		e.keep(WeakConfiguration)
		return
	}
	on := map[probe.SuiteClass][]string{}
	named := map[probe.SuiteClass]string{}
	for _, a := range ok {
		for i, c := range a.Suites {
			on[c] = append(on[c], a.IP)
			if i < len(a.SuiteNames) && named[c] == "" {
				named[c] = a.SuiteNames[i]
			}
		}
	}
	weak := []probe.SuiteClass{probe.ClassRC4, probe.Class3DES, probe.ClassNoPFS}
	found := false
	for _, c := range weak {
		found = found || len(on[c]) > 0
	}
	if !found && !all {
		e.keep(WeakConfiguration)
	} else if found {
		var where []string
		byWhere := map[string][]string{}
		for _, c := range weak {
			ips, hit := on[c]
			if !hit {
				continue
			}
			w := ""
			if len(ips) < len(ok) {
				w = " on " + strings.Join(ips, ", ")
			}
			if byWhere[w] == nil {
				where = append(where, w)
			}
			byWhere[w] = append(byWhere[w], c.Label()+" ("+named[c]+")")
		}
		var parts []string
		for _, w := range where {
			parts = append(parts, strings.Join(byWhere[w], ", ")+" accepted"+w)
		}
		e.open(Finding{Kind: WeakConfiguration, Severity: Warning, Details: strings.Join(parts, "; ")})
	}
	if !all {
		return
	}

	// The grade: every address, the lowest counts for the target.
	e.out.GradeChecked, e.out.GradeRules = true, GradeRules
	for _, a := range ok {
		g := gradeAddress(a)
		e.out.AddressGrades = append(e.out.AddressGrades, g)
		if e.out.Grade == "" || GradeRank(g.Grade) < GradeRank(e.out.Grade) {
			e.out.Grade = g.Grade
		}
	}
	// The target's reasons: those of its lowest-graded addresses, without
	// repeats.
	seen := map[string]bool{}
	for _, g := range e.out.AddressGrades {
		if g.Grade != e.out.Grade {
			continue
		}
		for _, r := range g.Reasons {
			if !seen[r] {
				seen[r] = true
				e.out.GradeReasons = append(e.out.GradeReasons, r)
			}
		}
	}
	if e.prev.Grade != "" && e.prev.Grade != e.out.Grade {
		why := ""
		lowering := slices.DeleteFunc(slices.Clone(e.out.GradeReasons), func(r string) bool { return r == StapledReason })
		if GradeRank(e.out.Grade) < GradeRank(e.prev.Grade) && len(lowering) > 0 {
			why = ": " + strings.Join(lowering, ", ")
		}
		e.out.Events = append(e.out.Events, Finding{Kind: GradeChanged, Severity: Info,
			Details: fmt.Sprintf("grade %s → %s%s", e.prev.Grade, e.out.Grade, why)})
	}
}
