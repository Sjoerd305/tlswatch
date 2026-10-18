// Package crl fetches certificate revocation lists and checks them against
// the certificate that should have signed them. Public CAs are dropping
// OCSP, so a CRL is how tlswatch learns a served leaf was revoked. The
// server fetches; a node fetches the CRL of a private CA that only its
// network reaches, and the server checks what it brought back.
package crl

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// MaxSize is the largest CRL fetched; a larger one is refused.
const MaxSize = 50 << 20

// Timeout bounds one fetch.
const Timeout = 30 * time.Second

// ErrTooLarge refuses a CRL over MaxSize.
var ErrTooLarge = errors.New("the CRL is larger than 50 MB")

// URL returns the first http:// or https:// CRL distribution point of c,
// "" when it names none. An LDAP distribution point is not fetched.
func URL(c *x509.Certificate) string {
	for _, u := range c.CRLDistributionPoints {
		if p, err := url.Parse(u); err == nil && (p.Scheme == "http" || p.Scheme == "https") && p.Host != "" && p.User == nil {
			return u
		}
	}
	return ""
}

// NewClient returns the outbound client for CRL fetches: no credentials,
// redirects only to http:// or https://, a 30-second timeout, and the
// proxy from the environment like every other outbound client. allow,
// when set, refuses an address it returns an error for, as a probe does;
// through a proxy it judges the proxy's address.
func NewClient(allow func(net.IP) error) *http.Client {
	d := &net.Dialer{Timeout: Timeout}
	if allow != nil {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip != nil {
				return allow(ip)
			}
			return nil
		}
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = d.DialContext
	return &http.Client{Timeout: Timeout, Transport: t, CheckRedirect: checkRedirect}
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" || req.URL.User != nil {
		return fmt.Errorf("redirected to a %s URL; a CRL is fetched over HTTP only", req.URL.Scheme)
	}
	return nil
}

// Fetch downloads the CRL at u. The error never repeats the URL, which
// the caller shows next to it.
func Fetch(ctx context.Context, client *http.Client, u string) ([]byte, error) {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "http" && p.Scheme != "https" || p.User != nil {
		return nil, errors.New("not an http:// or https:// URL without credentials")
	}
	if client == nil {
		client = NewClient(nil)
	}
	if client.CheckRedirect == nil {
		c := *client
		c.CheckRedirect = checkRedirect
		client = &c
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tlswatch (+https://tlswatch.nl)")
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			if ue.Timeout() {
				return nil, fmt.Errorf("timed out after %s", Timeout)
			}
			return nil, ue.Err
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the server answered %s", resp.Status)
	}
	if resp.ContentLength > MaxSize {
		return nil, ErrTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading the CRL: %w", err)
	}
	if len(body) > MaxSize {
		return nil, ErrTooLarge
	}
	return body, nil
}

var (
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
)

// Check parses data (DER, or PEM) as the CRL found at u and verifies that
// issuer signed it. A partitioned CRL must name u as its distribution
// point, so another partition of the same CA, validly signed but without
// the leaf, is not taken for it; a delta CRL is refused.
func Check(data []byte, issuer *x509.Certificate, u string) (*x509.RevocationList, error) {
	if b, _ := pem.Decode(data); b != nil && b.Type == "X509 CRL" {
		data = b.Bytes
	}
	rl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("not a CRL: %w", err)
	}
	if !bytes.Equal(rl.RawIssuer, issuer.RawSubject) {
		return nil, fmt.Errorf("issued by %s, not by the leaf's issuer %s", rl.Issuer, issuer.Subject)
	}
	if err := rl.CheckSignatureFrom(issuer); err != nil {
		return nil, fmt.Errorf("signature not valid: %w", err)
	}
	for _, ext := range rl.Extensions {
		switch {
		case ext.Id.Equal(oidDeltaCRLIndicator):
			return nil, errors.New("a delta CRL, not a full one")
		case ext.Id.Equal(oidIssuingDistributionPoint):
			uris, err := idpURIs(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("issuing distribution point: %w", err)
			}
			if len(uris) > 0 && !slices.ContainsFunc(uris, func(v string) bool { return sameURL(v, u) }) {
				return nil, fmt.Errorf("a partition for %s, not for this URL", strings.Join(uris, ", "))
			}
		}
	}
	return rl, nil
}

// idpURIs returns the URIs of an issuing distribution point's full name
// (RFC 5280, 5.2.5); none when it has no distribution point name.
func idpURIs(der []byte) ([]string, error) {
	in := cryptobyte.String(der)
	var seq, dp, full cryptobyte.String
	var hasDP, hasFull bool
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) ||
		!seq.ReadOptionalASN1(&dp, &hasDP, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, errors.New("malformed")
	}
	if !hasDP {
		return nil, nil
	}
	if !dp.ReadOptionalASN1(&full, &hasFull, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, errors.New("malformed name")
	}
	var uris []string
	for !full.Empty() {
		var name cryptobyte.String
		var tag cbasn1.Tag
		if !full.ReadAnyASN1(&name, &tag) {
			return nil, errors.New("malformed general name")
		}
		if tag == cbasn1.Tag(6).ContextSpecific() {
			uris = append(uris, string(name))
		}
	}
	return uris, nil
}

// sameURL compares two URLs, the scheme and host without regard to case.
func sameURL(a, b string) bool {
	pa, errA := url.Parse(a)
	pb, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return strings.EqualFold(pa.Scheme, pb.Scheme) && strings.EqualFold(pa.Host, pb.Host) && pa.RequestURI() == pb.RequestURI()
}

// Reason is the name of a CRL or OCSP revocation reason code (RFC 5280,
// 5.3.1), "" for unspecified.
func Reason(code int) string {
	switch code {
	case 1:
		return "key compromise"
	case 2:
		return "CA compromise"
	case 3:
		return "affiliation changed"
	case 4:
		return "superseded"
	case 5:
		return "cessation of operation"
	case 6:
		return "certificate hold"
	case 8:
		return "removed from CRL"
	case 9:
		return "privilege withdrawn"
	case 10:
		return "AA compromise"
	}
	return ""
}
