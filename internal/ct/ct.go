// Package ct asks an index of the Certificate Transparency logs for the
// certificates issued for a domain. tlswatch does not tail the logs itself:
// an index (Cert Spotter, crt.sh) answers "what was issued for this name
// since my last visit" in one request. The Source interface keeps the
// choice open; the matching of issuances against served certificates is
// the core package's business.
package ct

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Issuance is one certificate for a watched domain as a log published it.
// A precertificate and the certificate it became share issuer and serial.
type Issuance struct {
	// ID is the source's own id of the entry, the cursor's unit.
	ID        string
	IssuerCN  string
	IssuerOrg string
	// Serial is the serial number as uppercase hex without leading zeros,
	// the form Describe stores for served certificates.
	Serial    string
	Names     []string
	NotBefore time.Time
	NotAfter  time.Time
	// LogURL is a page a person can open for the entry.
	LogURL string
}

// Source answers with the issuances of a domain newer than cursor, and the
// cursor to continue from. An empty cursor asks for everything the source
// has; the caller limits a first poll's backlog by date.
type Source interface {
	Name() string
	Issuances(ctx context.Context, domain string, subdomains bool, cursor string) ([]Issuance, string, error)
}

// Sources lists the source names, in the order they are offered.
var Sources = []string{"certspotter", "crtsh"}

// New returns the named source. The API key only matters to Cert Spotter.
func New(name, apiKey string, client *http.Client) (Source, error) {
	if client == nil {
		client = &http.Client{Timeout: httpTimeout}
	}
	switch name {
	case "certspotter", "":
		return &CertSpotter{Client: client, APIKey: apiKey}, nil
	case "crtsh":
		return &CrtSh{Client: client}, nil
	}
	return nil, fmt.Errorf("unknown source %q", name)
}

// Label is the source name as shown to people.
func Label(name string) string {
	switch name {
	case "crtsh":
		return "crt.sh"
	default:
		return "Cert Spotter"
	}
}

// httpTimeout bounds one request; a source answers a page in seconds.
const httpTimeout = 60 * time.Second

// maxBody caps a response: a page of a hundred issuances with their DER
// is well under a megabyte.
const maxBody = 8 << 20

// RetryAfterError is a source's request to wait before the next poll.
type RetryAfterError struct {
	After time.Duration
	Err   error
}

func (e *RetryAfterError) Error() string { return e.Err.Error() }
func (e *RetryAfterError) Unwrap() error { return e.Err }

// get fetches a JSON document. The User-Agent names the caller, as every
// outbound connection of tlswatch does. A 429, or a 503 with Retry-After,
// is a RetryAfterError.
func get(ctx context.Context, client *http.Client, u string, headers map[string]string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "tlswatch (+https://tlswatch.nl)")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return ue.Err
		}
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxBody {
		return errors.New("the answer is larger than 8 MB")
	}
	if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get("Retry-After") != "") {
		return &RetryAfterError{After: retryAfter(resp.Header.Get("Retry-After")), Err: statusError(resp.Status, body)}
	}
	if resp.StatusCode/100 != 2 {
		return statusError(resp.Status, body)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("the answer is not the JSON expected: %w", err)
	}
	return nil
}

func retryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if n, err := strconv.ParseFloat(v, 64); err == nil && n >= 0 {
		return time.Duration(n*float64(time.Second)) + time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 10 * time.Minute
}

func statusError(status string, body []byte) error {
	b := strings.TrimSpace(string(body))
	if b == "" || len(b) > 200 || strings.HasPrefix(b, "<") {
		return errors.New(status)
	}
	return fmt.Errorf("%s: %s", status, b)
}

// SerialHex formats a serial as Describe does: uppercase hex, no leading
// zeros, so the two sides of a match agree.
func SerialHex(s string) string {
	s = strings.ToUpper(strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, ":", ""), " ", "")))
	s = strings.TrimPrefix(s, "0X")
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

// fromCertificate fills an issuance from a parsed (pre)certificate.
func fromCertificate(c *x509.Certificate) Issuance {
	i := Issuance{IssuerCN: c.Issuer.CommonName, NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC()}
	if len(c.Issuer.Organization) > 0 {
		i.IssuerOrg = c.Issuer.Organization[0]
	}
	if i.IssuerCN == "" {
		i.IssuerCN = i.IssuerOrg
	}
	if c.SerialNumber != nil {
		i.Serial = SerialHex(fmt.Sprintf("%X", c.SerialNumber))
	}
	i.Names = append(i.Names, c.DNSNames...)
	if c.Subject.CommonName != "" && !contains(i.Names, c.Subject.CommonName) && strings.Contains(c.Subject.CommonName, ".") {
		i.Names = append(i.Names, c.Subject.CommonName)
	}
	for k := range i.Names {
		i.Names[k] = strings.ToLower(strings.TrimSuffix(i.Names[k], "."))
	}
	return i
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// Covers reports whether a certificate name (possibly a wildcard) covers
// host: equal, or host is directly under a wildcard's base.
func Covers(name, host string) bool {
	name, host = strings.ToLower(strings.TrimSuffix(name, ".")), strings.ToLower(strings.TrimSuffix(host, "."))
	if name == host {
		return true
	}
	if base, ok := strings.CutPrefix(name, "*."); ok {
		if rest, ok := strings.CutSuffix(host, "."+base); ok && rest != "" && !strings.Contains(rest, ".") {
			return true
		}
	}
	return false
}

// Under reports whether name belongs to domain: the domain itself, or a
// name below it when subdomains are included. A wildcard counts by its base.
func Under(name, domain string, subdomains bool) bool {
	name, domain = strings.ToLower(strings.TrimSuffix(name, ".")), strings.ToLower(strings.TrimSuffix(domain, "."))
	name = strings.TrimPrefix(name, "*.")
	if name == domain {
		return true
	}
	return subdomains && strings.HasSuffix(name, "."+domain)
}

// ValidDomain checks a watch's name: a registrable-looking DNS name,
// lower case, without a scheme, path, port or wildcard.
func ValidDomain(name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return "", errors.New("a domain name is required")
	}
	if strings.ContainsAny(name, "/:*@ ") {
		return "", errors.New("enter a plain domain name such as example.nl, without scheme, path, port or wildcard")
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return "", errors.New("enter a domain with at least two labels, such as example.nl")
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return "", fmt.Errorf("%q is not a valid DNS name", name)
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", fmt.Errorf("%q is not a valid DNS name", name)
			}
		}
	}
	if len(name) > 253 {
		return "", errors.New("the domain name is too long")
	}
	return name, nil
}
