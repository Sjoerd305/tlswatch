package caa

import "strings"

// IssuerTable is the version of the table below. It is stored next to
// every verdict, so the history shows which table a verdict came from.
const IssuerTable = 1

// issuer maps a CA, recognised by its issuer organisation or the start of
// its issuing CA's name, to the issuer domain names it publishes for CAA.
type issuer struct {
	orgs []string // matched case-insensitively against the issuer organisation
	cns  []string // matched as a case-insensitive prefix of the issuer CN
	ids  []string
}

// issuers holds the CAA identifiers the CAs publish in their CP/CPS or
// documentation. A CA that issues under several brands accepts each of
// its domains.
var issuers = []issuer{
	{orgs: []string{"Let's Encrypt"}, ids: []string{"letsencrypt.org"}},
	{orgs: []string{"Google Trust Services"}, ids: []string{"pki.goog"}},
	{orgs: []string{"ZeroSSL"}, cns: []string{"ZeroSSL"}, ids: []string{"sectigo.com", "zerossl.com"}},
	{orgs: []string{"Sectigo", "COMODO"}, ids: []string{"sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "trust-provider.com"}},
	{orgs: []string{"DigiCert", "Thawte", "GeoTrust", "RapidSSL", "Symantec", "Encryption Everywhere"},
		cns: []string{"DigiCert", "Thawte", "GeoTrust", "RapidSSL", "Encryption Everywhere"},
		ids: []string{"digicert.com", "www.digicert.com", "digicert.ne.jp", "cybertrust.ne.jp", "symantec.com", "thawte.com", "geotrust.com", "rapidssl.com", "digitalcertvalidation.com"}},
	{orgs: []string{"Microsoft Corporation"}, ids: []string{"microsoft.com", "digicert.com"}},
	{orgs: []string{"GlobalSign"}, ids: []string{"globalsign.com"}},
	{orgs: []string{"Amazon"}, ids: []string{"amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"}},
	{orgs: []string{"Buypass"}, ids: []string{"buypass.com", "buypass.no"}},
	{orgs: []string{"Entrust", "AffirmTrust"}, ids: []string{"entrust.net", "affirmtrust.com"}},
	{orgs: []string{"SSL Corporation", "SSL.com"}, ids: []string{"ssl.com"}},
	{orgs: []string{"GoDaddy.com", "Starfield Technologies"}, ids: []string{"godaddy.com", "starfieldtech.com"}},
	{orgs: []string{"Certum", "Asseco Data Systems", "Unizeto"}, ids: []string{"certum.pl", "certum.eu"}},
	{orgs: []string{"Hellenic Academic and Research Institutions"}, ids: []string{"harica.gr"}},
	{orgs: []string{"Actalis"}, ids: []string{"actalis.it"}},
	{orgs: []string{"IdenTrust"}, ids: []string{"identrust.com"}},
	{orgs: []string{"TrustAsia"}, ids: []string{"trustasia.com"}},
	{orgs: []string{"Telia"}, ids: []string{"telia.com", "teliasonera.com"}},
	{orgs: []string{"SECOM Trust Systems"}, ids: []string{"secomtrust.net"}},
	{orgs: []string{"QuoVadis"}, ids: []string{"quovadisglobal.com", "digicert.com"}},
}

// Identifiers returns the CAA issuer domains of the CA that issued a
// certificate, from its issuer organisation and CN; nil when the table
// does not know it, and the issuance cannot be judged.
func Identifiers(org, cn string) []string {
	lo, lc := strings.ToLower(org), strings.ToLower(cn)
	for _, is := range issuers {
		for _, o := range is.orgs {
			if lo != "" && strings.Contains(lo, strings.ToLower(o)) {
				return is.ids
			}
		}
		for _, c := range is.cns {
			if strings.HasPrefix(lc, strings.ToLower(c)) {
				return is.ids
			}
		}
	}
	return nil
}
