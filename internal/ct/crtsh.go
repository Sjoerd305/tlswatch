package ct

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CrtSh is the crt.sh JSON interface. It has no cursor: every poll fetches
// the unexpired entries of the name and the caller keeps the highest id
// seen as the cursor. It is a free service run on goodwill, so the poll
// interval stays at an hour or more.
type CrtSh struct {
	Client *http.Client
	// BaseURL overrides the site in tests.
	BaseURL string
}

func (c *CrtSh) Name() string { return "crtsh" }

type crtShEntry struct {
	ID           int64  `json:"id"`
	IssuerName   string `json:"issuer_name"`
	CommonName   string `json:"common_name"`
	NameValue    string `json:"name_value"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	SerialNumber string `json:"serial_number"`
}

// Issuances fetches the entries of the domain (and, with subdomains, of
// the names under it) with an id above the cursor.
func (c *CrtSh) Issuances(ctx context.Context, domain string, subdomains bool, cursor string) ([]Issuance, string, error) {
	base := c.BaseURL
	if base == "" {
		base = "https://crt.sh"
	}
	after, _ := strconv.ParseInt(cursor, 10, 64)
	queries := []string{domain}
	if subdomains {
		queries = append(queries, "%."+domain)
	}
	seen := map[int64]bool{}
	var out []Issuance
	max := after
	for _, q := range queries {
		var entries []crtShEntry
		u := base + "/?" + url.Values{"q": {q}, "output": {"json"}, "exclude": {"expired"}, "deduplicate": {"Y"}}.Encode()
		if err := get(ctx, c.Client, u, nil, &entries); err != nil {
			return nil, cursor, err
		}
		for _, e := range entries {
			if e.ID <= after || seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			out = append(out, c.issuance(e))
			if e.ID > max {
				max = e.ID
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if max > after {
		cursor = strconv.FormatInt(max, 10)
	}
	return out, cursor, nil
}

func (c *CrtSh) issuance(e crtShEntry) Issuance {
	i := Issuance{ID: strconv.FormatInt(e.ID, 10), Serial: SerialHex(e.SerialNumber), LogURL: "https://crt.sh/?id=" + strconv.FormatInt(e.ID, 10)}
	i.IssuerCN, i.IssuerOrg = dnParts(e.IssuerName)
	for _, n := range strings.Split(e.NameValue, "\n") {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" && !contains(i.Names, n) {
			i.Names = append(i.Names, n)
		}
	}
	if cn := strings.ToLower(strings.TrimSpace(e.CommonName)); cn != "" && strings.Contains(cn, ".") && !contains(i.Names, cn) {
		i.Names = append(i.Names, cn)
	}
	i.Names = capNames(i.Names)
	i.NotBefore, _ = parseCrtShTime(e.NotBefore)
	i.NotAfter, _ = parseCrtShTime(e.NotAfter)
	return i
}

// parseCrtShTime reads crt.sh's "2026-10-14T09:12:00" (UTC, no zone).
func parseCrtShTime(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02T15:04:05", time.RFC3339, "2006-01-02T15:04:05.999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, &time.ParseError{Layout: "2006-01-02T15:04:05", Value: s}
}

// dnParts picks the CN and O out of a distinguished name as crt.sh writes
// it ("C=US, O=Let's Encrypt, CN=R11").
func dnParts(dn string) (cn, org string) {
	for _, part := range strings.Split(dn, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch strings.ToUpper(strings.TrimSpace(k)) {
		case "CN":
			cn = strings.TrimSpace(v)
		case "O":
			org = strings.TrimSpace(v)
		}
	}
	if cn == "" {
		cn = org
	}
	return cn, org
}
