package check

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

// OtherCert is an other certificate an address serves, as the target page
// and tlswatch check show it.
type OtherCert struct {
	Via         string // probe.ViaOtherKey or probe.ViaNoSNI
	KeyType     string
	Subject     string
	Fingerprint string
	NotAfter    time.Time
	// Problems are the certificate checks it fails, in the words of their
	// findings; empty when it passes.
	Problems []string
}

// The checks an other certificate is held to. An alternate certificate
// breaks the clients that get it in all the ways the main one would; the
// default certificate only matters when it is outright invalid, and is
// not judged for expiring soon.
var (
	alternateKinds = []Kind{Expired, Expiring, NotYetValid, ChainUntrusted, SelfSigned, HostnameMismatch, DistrustedCA}
	defaultKinds   = []Kind{Expired, NotYetValid, ChainUntrusted, SelfSigned, HostnameMismatch}
)

// others opens alternate_certificate and default_certificate from the other
// certificates the configuration test found. Like the legacy versions they
// are tested about once a day: a check that did not test them leaves the
// findings as they are, and so does a test that found nothing but could not
// reach every address.
func (e *evaluation) others(ok []probe.Address) {
	if e.t.SkipLegacy {
		return
	}
	tested, all := false, true
	for _, a := range ok {
		tested = tested || a.OthersChecked || len(a.Others) > 0
		all = all && a.OthersChecked
	}
	if !tested {
		e.keep(AlternateCertificate)
		e.keep(DefaultCertificate)
		return
	}
	e.otherCerts = map[string][]OtherCert{}
	type hit struct {
		text string
		ips  []string
	}
	hits := map[string][]*hit{}
	worst := map[string]Severity{}
	days := map[string]*int{}
	for _, a := range ok {
		for _, o := range a.Others {
			leaf := o.Chain[0]
			info := probe.Describe(leaf)
			_, th := thresholds(e.t, info)
			fs, _ := addressFacts(e.t, o.Address(a.IP), th, e.now)
			kinds := alternateKinds
			if o.Via == probe.ViaNoSNI {
				kinds = defaultKinds
			}
			oc := OtherCert{Via: o.Via, KeyType: info.KeyType, Subject: nameOf(leaf), Fingerprint: info.Fingerprint, NotAfter: leaf.NotAfter}
			for _, f := range fs {
				if !slices.Contains(kinds, f.Kind) {
					continue
				}
				oc.Problems = append(oc.Problems, f.Details)
				if f.Severity.Rank() > worst[o.Via].Rank() {
					worst[o.Via] = f.Severity
				}
				if f.DaysLeft != nil && (days[o.Via] == nil || *f.DaysLeft < *days[o.Via]) {
					d := *f.DaysLeft
					days[o.Via] = &d
				}
			}
			e.otherCerts[a.IP] = append(e.otherCerts[a.IP], oc)
			if len(oc.Problems) == 0 {
				continue
			}
			text := otherText(oc)
			i := slices.IndexFunc(hits[o.Via], func(h *hit) bool { return h.text == text })
			if i < 0 {
				hits[o.Via] = append(hits[o.Via], &hit{text: text})
				i = len(hits[o.Via]) - 1
			}
			hits[o.Via][i].ips = append(hits[o.Via][i].ips, a.IP)
		}
	}
	for _, v := range []struct {
		via  string
		kind Kind
	}{{probe.ViaOtherKey, AlternateCertificate}, {probe.ViaNoSNI, DefaultCertificate}} {
		hs := hits[v.via]
		if len(hs) == 0 {
			if !all {
				e.keep(v.kind)
			}
			continue
		}
		var parts []string
		for _, h := range hs {
			w := ""
			if len(h.ips) < len(ok) {
				w = " on " + strings.Join(h.ips, ", ")
			}
			parts = append(parts, h.text+w)
		}
		sev := worst[v.via]
		if v.kind == DefaultCertificate {
			sev = Info
		}
		e.open(Finding{Kind: v.kind, Severity: sev, DaysLeft: days[v.via], Details: strings.Join(parts, "; ")})
	}
}

// otherText words an other certificate and what is wrong with it:
// "RSA certificate www.example.nl (3fa2c1d0): www.example.nl expired
// 2026-09-01", "without SNI, old.example.nl (…): …".
func otherText(oc OtherCert) string {
	who := fmt.Sprintf("%s certificate %s (%s)", oc.KeyType, oc.Subject, shortFP(oc.Fingerprint))
	if oc.Via == probe.ViaNoSNI {
		who = fmt.Sprintf("without SNI, %s (%s)", oc.Subject, shortFP(oc.Fingerprint))
	}
	return who + ": " + strings.Join(oc.Problems, "; ")
}

func shortFP(fp string) string {
	if len(fp) > 8 {
		return fp[:8]
	}
	return fp
}

// mustStaple reports a must-staple leaf the address served without a
// staple a client accepts: none, one that is not a good response for the
// leaf, or a good one past its NextUpdate. A revoked staple is the revoked
// finding's business.
func mustStaple(a probe.Address, now time.Time) (Finding, bool) {
	if len(a.Chain) == 0 || !probe.MustStaple(a.Chain[0]) {
		return Finding{}, false
	}
	const why = "the certificate requires a stapled OCSP response (must-staple), so Firefox refuses the connection: "
	s := probe.StapleOf(a)
	var what string
	switch {
	case s.Status == "":
		what = "the server sent none"
	case s.Status == probe.StapleInvalid:
		what = "the stapled response is not valid for this certificate"
	case s.Status == probe.StapleUnknown:
		what = "the stapled response says the certificate is unknown to the responder"
	case s.Status == probe.StapleGood && !s.NextUpdate.IsZero() && now.After(s.NextUpdate):
		what = "the stapled response expired " + s.NextUpdate.UTC().Format("2006-01-02 15:04 MST")
	default:
		return Finding{}, false
	}
	return Finding{Kind: MustStaple, Severity: Critical, Details: why + what}, true
}
