package check

import (
	"cmp"
	"fmt"
	"strings"

	"github.com/sjoerd305/tlswatch/internal/crl"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// UnknownAfter is how many daily fetches of a CRL must fail in a row
// before revocation_unknown is recorded.
const UnknownAfter = 3

// StapledReason is the grade reason of an address that staples a good
// OCSP response. It is shown but never lowers the grade.
const StapledReason = "OCSP stapled"

// revocation opens revoked while a served leaf is listed in its CRL or
// stapled a response saying so, and revocation_unknown while the CRL of a
// served leaf could not be checked for UnknownAfter days. A revocation is
// a fact about the leaf: once open it stays until a different leaf is
// served, also when its CRL later drops the entry.
func (e *evaluation) revocation(ok []probe.Address) {
	var revoked, unknown []string
	revokedFP := ""
	served := map[string]bool{}
	multi := false
	for _, a := range ok {
		fp := probe.Fingerprint(a.Chain[0])
		multi = multi || len(served) > 0 && !served[fp]
		served[fp] = true
	}
	which := func(fp string) string {
		if multi {
			return "leaf " + fp[:8] + " "
		}
		return ""
	}
	seen := map[string]bool{}
	for _, a := range ok {
		fp := probe.Fingerprint(a.Chain[0])
		if s := probe.StapleOf(a); s.Status == probe.StapleRevoked {
			revoked = append(revoked, fmt.Sprintf("%srevoked %s%s, says the OCSP response stapled on %s",
				which(fp), s.RevokedAt.UTC().Format("2006-01-02"), reasonText(crl.Reason(s.Reason)), a.IP))
			revokedFP = cmp.Or(revokedFP, fp)
		}
		if seen[fp] {
			continue
		}
		seen[fp] = true
		c, found := e.prev.CRL[fp]
		switch {
		case !found:
		case c.Revoked:
			revoked = append(revoked, fmt.Sprintf("%srevoked %s%s, listed in the CRL at %s",
				which(fp), c.RevokedAt.UTC().Format("2006-01-02"), reasonText(c.Reason), c.URL))
			revokedFP = cmp.Or(revokedFP, fp)
		case c.Unknown != "":
			unknown = append(unknown, fmt.Sprintf("%sthe CRL at %s could not be checked for %d days: %s", which(fp), c.URL, UnknownAfter, c.Unknown))
		}
	}
	switch {
	case len(revoked) > 0:
		e.open(Finding{Kind: Revoked, Severity: Critical, Fingerprint: revokedFP, Details: strings.Join(revoked, "; ")})
	case e.prev.Open[Revoked] && served[e.prev.RevokedFP]:
		e.keep(Revoked)
	}
	if len(unknown) > 0 {
		e.open(Finding{Kind: RevocationUnknown, Severity: Info, Details: strings.Join(unknown, "; ")})
	}
}

func reasonText(r string) string {
	if r == "" {
		return ""
	}
	return " (" + r + ")"
}
