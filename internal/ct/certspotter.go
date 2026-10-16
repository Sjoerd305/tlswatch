package ct

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CertSpotter is the api.certspotter.com v1 issuances API. Without a key
// it works within the public rate limit; a key raises it. Entries come in
// id order, up to 100 a page, and `after` continues from an id, which is
// the cursor.
type CertSpotter struct {
	Client *http.Client
	APIKey string
	// BaseURL overrides the API root in tests.
	BaseURL string
}

func (c *CertSpotter) Name() string { return "certspotter" }

// certSpotterEntry is one issuance as the API returns it with
// expand=dns_names, expand=issuer and expand=cert.
type certSpotterEntry struct {
	ID       string   `json:"id"`
	DNSNames []string `json:"dns_names"`
	Issuer   struct {
		Name string `json:"name"`
	} `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Cert      struct {
		Type string `json:"type"` // "cert" or "precert"
		Data string `json:"data"` // base64 DER
	} `json:"cert"`
}

// Issuances pages through the entries after cursor.
func (c *CertSpotter) Issuances(ctx context.Context, domain string, subdomains bool, cursor string) ([]Issuance, string, error) {
	base := c.BaseURL
	if base == "" {
		base = "https://api.certspotter.com"
	}
	headers := map[string]string{}
	if c.APIKey != "" {
		headers["Authorization"] = "Bearer " + c.APIKey
	}
	var out []Issuance
	for page := 0; page < 50; page++ {
		q := url.Values{"domain": {domain}, "expand": {"dns_names", "issuer", "cert"}}
		if subdomains {
			q.Set("include_subdomains", "true")
		}
		if cursor != "" {
			q.Set("after", cursor)
		}
		var entries []certSpotterEntry
		if err := get(ctx, c.Client, base+"/v1/issuances?"+q.Encode(), headers, &entries); err != nil {
			return out, cursor, err
		}
		for _, e := range entries {
			i, err := c.issuance(e)
			if err != nil {
				return out, cursor, err
			}
			out = append(out, i)
			cursor = e.ID
		}
		if len(entries) < 100 {
			break
		}
	}
	return out, cursor, nil
}

func (c *CertSpotter) issuance(e certSpotterEntry) (Issuance, error) {
	// Cert Spotter has no page per entry, so the link opens the certificate
	// on crt.sh by its SHA-256 (which finds a precertificate as well), or the
	// domain's listing there when no certificate came with the entry.
	i := Issuance{ID: e.ID, Names: e.DNSNames, NotBefore: e.NotBefore.UTC(), NotAfter: e.NotAfter.UTC(), IssuerCN: e.Issuer.Name}
	if len(e.DNSNames) > 0 {
		i.LogURL = "https://crt.sh/?q=" + url.QueryEscape(e.DNSNames[0])
	}
	if e.Cert.Data != "" {
		der, err := base64.StdEncoding.DecodeString(e.Cert.Data)
		if err != nil {
			return i, fmt.Errorf("entry %s: %w", e.ID, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return i, fmt.Errorf("entry %s: %w", e.ID, err)
		}
		parsed := fromCertificate(cert)
		sum := sha256.Sum256(der)
		parsed.ID, parsed.LogURL = i.ID, "https://crt.sh/?q="+strings.ToUpper(hex.EncodeToString(sum[:]))
		if len(parsed.Names) == 0 {
			parsed.Names = i.Names
		}
		return parsed, nil
	}
	if i.Serial == "" {
		// Without the certificate there is no serial; the id stands in, so
		// the entry is still unique and visible.
		i.Serial = "CERTSPOTTER-" + e.ID
	}
	return i, nil
}
