package check

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

// Intermediate is the certificate that issued a leaf, as served: its
// fingerprint and name. A zero value is unknown.
type Intermediate struct {
	FP string
	CN string
}

// Diff says in one line what changed from the old leaf to the new one:
// issuer, the intermediate, subject, SANs added and removed, key,
// signature algorithm and validity. Unchanged fields are left out:
// "SANs +api.example.nl −old.example.nl; key RSA 2048 → ECDSA P-256;
// lifetime 90 → 47 days".
func Diff(old, cur probe.CertInfo, oldInter, curInter Intermediate) string {
	var parts []string
	if old.Issuer != cur.Issuer {
		parts = append(parts, fmt.Sprintf("issuer %s → %s", issuerLabel(old, cur.IssuerOrg), issuerLabel(cur, old.IssuerOrg)))
	} else if oldInter.FP != "" && curInter.FP != "" && oldInter.FP != curInter.FP {
		// Same issuer name, another certificate: a re-issued or
		// cross-signed intermediate.
		parts = append(parts, fmt.Sprintf("intermediate %s replaced (%s → %s)", shortCN(curInter.CN), oldInter.FP[:8], curInter.FP[:8]))
	}
	if old.Subject != cur.Subject {
		parts = append(parts, fmt.Sprintf("subject %s → %s", old.Subject, cur.Subject))
	}
	if added, removed := sanDiff(old.SANs, cur.SANs); len(added)+len(removed) > 0 {
		var s []string
		for _, n := range added {
			s = append(s, "+"+n)
		}
		for _, n := range removed {
			s = append(s, "−"+n)
		}
		parts = append(parts, "SANs "+strings.Join(s, " "))
	}
	if old.KeyDesc != cur.KeyDesc {
		parts = append(parts, fmt.Sprintf("key %s → %s", old.KeyDesc, cur.KeyDesc))
	}
	if old.SigAlg != cur.SigAlg {
		parts = append(parts, fmt.Sprintf("signature %s → %s", old.SigAlg, cur.SigAlg))
	}
	if !old.NotAfter.Equal(cur.NotAfter) {
		parts = append(parts, fmt.Sprintf("expires %s → %s", old.NotAfter.UTC().Format(time.DateOnly), cur.NotAfter.UTC().Format(time.DateOnly)))
	}
	if lo, lc := lifetimeDays(old), lifetimeDays(cur); lo != lc {
		parts = append(parts, fmt.Sprintf("lifetime %d → %d days", lo, lc))
	}
	if len(parts) == 0 {
		return "re-issued with the same fields"
	}
	return strings.Join(parts, "; ")
}

// issuerLabel names an issuer by its CN, with the organisation in front
// when the other side's organisation differs: "R10 → R11", but
// "Let's Encrypt R11 → Sectigo Limited Sectigo RSA DV".
func issuerLabel(c probe.CertInfo, otherOrg string) string {
	cn := shortCN(c.IssuerCN)
	if c.IssuerOrg != "" && c.IssuerOrg != otherOrg && c.IssuerOrg != c.IssuerCN {
		return c.IssuerOrg + " " + cn
	}
	return cn
}

// sanDiff lists the names cur adds to old and the ones it drops, in
// order, without regard to case.
func sanDiff(old, cur []string) (added, removed []string) {
	in := func(list []string, n string) bool {
		return slices.ContainsFunc(list, func(s string) bool { return strings.EqualFold(s, n) })
	}
	for _, n := range cur {
		if !in(old, n) {
			added = append(added, n)
		}
	}
	for _, n := range old {
		if !in(cur, n) {
			removed = append(removed, n)
		}
	}
	return added, removed
}

// lifetimeDays is a certificate's lifetime in whole days, rounded: a
// 90-day certificate runs to the second before its 90th day.
func lifetimeDays(c probe.CertInfo) int {
	return int((c.NotAfter.Sub(c.NotBefore) + 12*time.Hour) / (24 * time.Hour))
}
