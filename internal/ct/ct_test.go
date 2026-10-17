package ct

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCoversAndUnder(t *testing.T) {
	cases := []struct {
		name, host string
		covers     bool
	}{
		{"portal.example.nl", "portal.example.nl", true},
		{"Portal.Example.NL.", "portal.example.nl", true},
		{"*.example.nl", "portal.example.nl", true},
		{"*.example.nl", "a.b.example.nl", false},
		{"*.example.nl", "example.nl", false},
		{"example.nl", "portal.example.nl", false},
	}
	for _, c := range cases {
		if got := Covers(c.name, c.host); got != c.covers {
			t.Errorf("Covers(%q, %q) = %v", c.name, c.host, got)
		}
	}
	if !Under("portal.example.nl", "example.nl", true) || Under("portal.example.nl", "example.nl", false) ||
		!Under("example.nl", "example.nl", false) || Under("example.com", "example.nl", true) ||
		!Under("*.example.nl", "example.nl", true) || Under("notexample.nl", "example.nl", true) {
		t.Error("Under")
	}
}

func TestValidDomain(t *testing.T) {
	if d, err := ValidDomain(" Example.NL. "); err != nil || d != "example.nl" {
		t.Errorf("%q %v", d, err)
	}
	for _, bad := range []string{"", "nl", "*.example.nl", "https://example.nl", "exa mple.nl", "-a.nl", "example.nl:443"} {
		if _, err := ValidDomain(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSerialHex(t *testing.T) {
	for in, want := range map[string]string{"00ab:cd": "ABCD", "0x0f": "F", "0": "0", "ABC": "ABC"} {
		if got := SerialHex(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// precert makes a certificate for names, signed by a throwaway issuer, as
// base64 DER.
func precert(t *testing.T, serial int64, issuerCN string, names ...string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iss := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: issuerCN, Organization: []string{"Test Org"}}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour * 24 * 365)}
	issDER, _ := x509.CreateCertificate(rand.Reader, iss, iss, &key.PublicKey, key)
	issCert, _ := x509.ParseCertificate(issDER)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issCert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestCertSpotter(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.RawQuery+"|"+r.Header.Get("Authorization"))
		if r.URL.Path != "/v1/issuances" {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Query().Get("after") {
		case "":
			fmt.Fprintf(w, `[{"id":"101","dns_names":["portal.example.nl"],"issuer":{"name":"C=US, O=Let's Encrypt, CN=R11"},
				"not_before":"2026-10-14T09:12:00Z","not_after":"2027-01-12T09:12:00Z","cert":{"type":"precert","data":%q}},
				{"id":"102","dns_names":["admin.example.nl"],"issuer":{"name":"CN=Sectigo"},"not_before":"2026-10-15T00:00:00Z","not_after":"2027-10-15T00:00:00Z"}]`,
				precert(t, 0xABCD, "R11", "portal.example.nl", "www.example.nl"))
		case "102":
			fmt.Fprint(w, `[]`)
		default:
			http.Error(w, "bad cursor", 400)
		}
	}))
	defer srv.Close()
	src := &CertSpotter{Client: srv.Client(), APIKey: "k1", BaseURL: srv.URL}
	got, cursor, err := src.Issuances(context.Background(), "example.nl", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if cursor != "102" || len(got) != 2 {
		t.Fatalf("cursor %q, %d issuances", cursor, len(got))
	}
	a := got[0]
	if a.ID != "101" || a.Serial != "ABCD" || a.IssuerCN != "R11" || a.IssuerOrg != "Test Org" || strings.Join(a.Names, ",") != "portal.example.nl,www.example.nl" || a.NotAfter.IsZero() {
		t.Fatalf("parsed from the certificate: %+v", a)
	}
	if !strings.HasPrefix(a.LogURL, "https://crt.sh/?q=") || len(a.LogURL) != len("https://crt.sh/?q=")+64 {
		t.Fatalf("log URL by SHA-256: %q", a.LogURL)
	}
	b := got[1]
	if b.Serial != "CERTSPOTTER-102" || b.IssuerCN != "CN=Sectigo" || b.Names[0] != "admin.example.nl" || b.LogURL != "https://crt.sh/?q=admin.example.nl" {
		t.Fatalf("without a certificate: %+v", b)
	}
	if !strings.Contains(calls[0], "include_subdomains=true") || !strings.Contains(calls[0], "expand=cert") || !strings.HasSuffix(calls[0], "|Bearer k1") {
		t.Fatalf("request: %v", calls)
	}
	if _, _, err := src.Issuances(context.Background(), "example.nl", true, "999"); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("bad status not reported: %v", err)
	}
}

func TestCertSpotterRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	src := &CertSpotter{Client: srv.Client(), BaseURL: srv.URL}
	_, _, err := src.Issuances(context.Background(), "example.nl", true, "")
	var ra *RetryAfterError
	if !errors.As(err, &ra) || ra.After < 2*time.Minute {
		t.Fatalf("%v", err)
	}
}

func TestCrtSh(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Query().Get("q"))
		entries := []map[string]any{
			{"id": 5, "issuer_name": "C=US, O=Let's Encrypt, CN=R11", "common_name": "example.nl", "name_value": "example.nl\nwww.example.nl",
				"not_before": "2026-10-14T09:12:00", "not_after": "2027-01-12T09:12:00", "serial_number": "04abcd"},
			{"id": 9, "issuer_name": "O=Sectigo Limited, CN=Sectigo RSA DV", "common_name": "admin.example.nl", "name_value": "admin.example.nl",
				"not_before": "2026-10-15T00:00:00", "not_after": "2027-10-15T00:00:00", "serial_number": "ff"},
		}
		if r.URL.Query().Get("q") == "example.nl" {
			entries = entries[:1]
		}
		_ = json.NewEncoder(w).Encode(entries)
	}))
	defer srv.Close()
	src := &CrtSh{Client: srv.Client(), BaseURL: srv.URL}
	got, cursor, err := src.Issuances(context.Background(), "example.nl", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if cursor != "9" || len(got) != 2 || strings.Join(queries, " ") != "example.nl %.example.nl" {
		t.Fatalf("cursor %q, %d issuances, queries %v", cursor, len(got), queries)
	}
	a := got[0]
	if a.ID != "5" || a.Serial != "4ABCD" || a.IssuerCN != "R11" || a.IssuerOrg != "Let's Encrypt" || strings.Join(a.Names, ",") != "example.nl,www.example.nl" ||
		a.NotBefore.Format(time.RFC3339) != "2026-10-14T09:12:00Z" || a.LogURL != "https://crt.sh/?id=5" {
		t.Fatalf("%+v", a)
	}
	got, cursor, err = src.Issuances(context.Background(), "example.nl", true, "9")
	if err != nil || len(got) != 0 || cursor != "9" {
		t.Fatalf("after the cursor: %v %d %q", err, len(got), cursor)
	}
}

// Certificate data that does not parse keeps the entry by its own fields;
// it does not fail every poll from then on.
func TestCertSpotterUnparsableCertificate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"id":"201","dns_names":["a.example.nl"],"issuer":{"name":"CN=R11"},"not_before":"2026-10-14T09:12:00Z","not_after":"2027-01-12T09:12:00Z","cert":{"type":"cert","data":"bm90IGEgY2VydA=="}},
			{"id":"202","dns_names":["b.example.nl"],"issuer":{"name":"CN=R11"},"not_before":"2026-10-14T09:12:00Z","not_after":"2027-01-12T09:12:00Z","cert":{"type":"cert","data":"%%%"}}]`)
	}))
	defer srv.Close()
	src := &CertSpotter{Client: srv.Client(), BaseURL: srv.URL}
	got, cursor, err := src.Issuances(context.Background(), "example.nl", true, "")
	if err != nil || cursor != "202" || len(got) != 2 {
		t.Fatalf("err %v, cursor %q, %d issuances", err, cursor, len(got))
	}
	if got[0].Serial != "CERTSPOTTER-201" || got[0].Names[0] != "a.example.nl" {
		t.Fatalf("entry kept by its fields: %+v", got[0])
	}
}
