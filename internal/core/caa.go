package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/sjoerd305/tlswatch/internal/caa"
	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/ct"
)

// CAA verdicts on an issuance.
const (
	CAAPermitted     = "permitted"
	CAAViolation     = "violation"
	CAAAcknowledged  = "acknowledged"
	CAAUnknownIssuer = "unknown_issuer" // the issuer table does not know the CA
	CAALookupFailed  = "lookup_failed"
)

// caaNamesMax bounds the CAA lookups for the names of one issuance below
// the watched domain; names past it are judged by the domain's own set.
const caaNamesMax = 20

func (s *Service) caaResolver() caa.Resolver {
	if s.CAAResolver != nil {
		return s.CAAResolver
	}
	return caa.System{}
}

// refreshCAA looks up the watch's relevant CAA record set and stores it.
// A set that differs from the one stored is recorded as a caa_changed
// event; the first lookup sets a baseline. It returns the set, or nil when
// the lookup failed: the issuances of this poll are then not judged.
func (s *Service) refreshCAA(ctx context.Context, d Domain) *caa.Set {
	now := s.now().Unix()
	set, err := caa.Lookup(ctx, s.caaResolver(), d.Name)
	if err != nil {
		if s.Log != nil {
			s.Log.Warn("caa lookup", "domain", d.Name, "err", err)
		}
		if _, err := s.DB.W.ExecContext(ctx, "UPDATE domains SET caa_error = ? WHERE id = ?", Clip(err.Error(), TextMax), d.ID); err != nil && s.Log != nil {
			s.Log.Error("caa store", "domain", d.Name, "err", err)
		}
		return nil
	}
	js, _ := json.Marshal(set)
	if _, err := s.DB.W.ExecContext(ctx, "UPDATE domains SET caa = ?, caa_checked_at = ?, caa_error = '' WHERE id = ?", string(js), now, d.ID); err != nil {
		if s.Log != nil {
			s.Log.Error("caa store", "domain", d.Name, "err", err)
		}
		return &set
	}
	if d.CAACheckedAt > 0 && !d.CAA.Equal(set) {
		details := fmt.Sprintf("CAA record changed: %s → %s", describeCAA(d.CAA), describeCAA(set))
		if _, err := s.DB.W.ExecContext(ctx, `INSERT INTO findings(domain_id, kind, severity, opened_at, resolved_at, details, fingerprint, last_alert_at) VALUES(?,?,?,?,?,?,'',?)`,
			d.ID, string(check.CAAChanged), string(check.Info), now, now, details, now); err != nil && s.Log != nil {
			s.Log.Error("caa event", "domain", d.Name, "err", err)
		}
	}
	return &set
}

// describeCAA is a record set in one line: where it was found and its
// issue and issuewild values, or that there is none.
func describeCAA(set caa.Set) string {
	if set.Empty() {
		return "none (any CA may issue)"
	}
	return set.Name + " " + strings.Join(set.Lines(), ", ")
}

// judgeCAA decides whether the CAA records permit an issuance's issuer
// for every name under the watched domain. A name below the domain with
// records of its own is judged by those; the others by the domain's set,
// which already climbed above the domain. It returns the verdict and,
// for a violation, why.
func (s *Service) judgeCAA(ctx context.Context, d Domain, set caa.Set, in ct.Issuance, cache map[string]caa.Set) (string, string) {
	ids := caa.Identifiers(in.IssuerOrg, in.IssuerCN)
	if ids == nil {
		return CAAUnknownIssuer, ""
	}
	issuer := in.IssuerOrg
	if issuer == "" {
		issuer = in.IssuerCN
	}
	looked := 0
	for _, name := range in.Names {
		if !ct.Under(name, d.Name, d.Subdomains) {
			continue
		}
		wildcard := strings.HasPrefix(name, "*.")
		bare := strings.ToLower(strings.TrimPrefix(name, "*."))
		applies := set
		if bare != strings.ToLower(d.Name) && looked < caaNamesMax {
			own, ok := cache[bare]
			if !ok {
				looked++
				var err error
				if own, err = s.lookupBelow(ctx, bare, d.Name); err != nil {
					return CAALookupFailed, err.Error()
				}
				cache[bare] = own
			}
			if !own.Empty() {
				applies = own
			}
		}
		if ok, why := caa.Permits(applies, ids, wildcard); !ok {
			return CAAViolation, fmt.Sprintf("%s issued for %s, but %s", issuer, name, why)
		}
	}
	return CAAPermitted, ""
}

// lookupBelow climbs from name up to, not including, the watched domain:
// the records a subdomain has of its own. Above it the domain's set holds.
func (s *Service) lookupBelow(ctx context.Context, name, domain string) (caa.Set, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	r := s.caaResolver()
	for n := name; n != domain && strings.HasSuffix(n, "."+domain); {
		recs, err := r.CAA(ctx, n)
		if err != nil {
			return caa.Set{}, fmt.Errorf("CAA of %s: %w", n, err)
		}
		if len(recs) > 0 {
			return caa.Set{Name: n, Records: recs}, nil
		}
		_, n, _ = strings.Cut(n, ".")
	}
	return caa.Set{}, nil
}

// recordCAA stores an issuance's verdict and opens caa_violation for a
// violation.
func (s *Service) recordCAA(ctx context.Context, d Domain, id int64, verdict, why string) error {
	if _, err := s.DB.W.ExecContext(ctx, "UPDATE issuances SET caa = ?, caa_detail = ?, caa_table = ? WHERE id = ?", verdict, Clip(why, TextMax), caa.IssuerTable, id); err != nil {
		return err
	}
	if verdict != CAAViolation {
		return nil
	}
	return s.openDomainFinding(ctx, d, check.Finding{Kind: check.CAAViolation, Severity: check.Warning, Details: why}, strconv.FormatInt(id, 10))
}

// reopenCAA opens the findings of a watch's unacknowledged CAA violations
// again after the watch was enabled; expired issuances stay closed.
func (s *Service) reopenCAA(ctx context.Context, d Domain, list []Issuance) error {
	for _, i := range list {
		if i.CAA != CAAViolation || i.NotAfter > 0 && i.NotAfter < s.now().Unix() {
			continue
		}
		f := check.Finding{Kind: check.CAAViolation, Severity: check.Warning, Details: i.CAADetail}
		if err := s.openDomainFinding(ctx, d, f, strconv.FormatInt(i.ID, 10)); err != nil {
			return err
		}
	}
	return nil
}
