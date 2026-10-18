package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// refuse is a transport that fails the test when used.
type refuse struct{ t *testing.T }

func (r refuse) RoundTrip(*http.Request) (*http.Response, error) {
	r.t.Error("fetched from the server")
	return nil, http.ErrNotSupported
}

// crlServer serves one CA's CRL, revoking the serials in revoked, or a
// 404 while down.
type crlServer struct {
	mu      sync.Mutex
	ca      ca
	revoked []*big.Int
	issued  time.Time
	down    bool
	fetches int
}

func (c *crlServer) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fetches++
	if c.down {
		http.NotFound(w, nil)
		return
	}
	tpl := &x509.RevocationList{Number: big.NewInt(c.issued.Unix()), ThisUpdate: c.issued, NextUpdate: c.issued.Add(7 * 24 * time.Hour)}
	for _, s := range c.revoked {
		tpl.RevokedCertificateEntries = append(tpl.RevokedCertificateEntries,
			x509.RevocationListEntry{SerialNumber: s, RevocationTime: c.issued.Add(-time.Hour), ReasonCode: 1})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tpl, c.ca.cert, c.ca.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(der)
}

// crlCA is a CA that may sign CRLs.
func crlCA(t *testing.T) ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Private CA", Organization: []string{"Example"}},
		NotBefore: time.Now().Add(-1000 * 24 * time.Hour), NotAfter: time.Now().Add(3000 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return ca{c, key}
}

func crlLeaf(t *testing.T, iss ca, url string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "portal.example.nl"}, DNSNames: []string{"portal.example.nl"},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(200 * 24 * time.Hour), CRLDistributionPoints: []string{url},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, iss.cert, &key.PublicKey, iss.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestCRLRevocation(t *testing.T) {
	e := newEnv(t)
	iss := crlCA(t)
	cs := &crlServer{ca: iss, issued: time.Now().Add(-time.Hour)}
	srv := httptest.NewServer(cs)
	defer srv.Close()
	e.svc.CRLClient = srv.Client()
	leaf := crlLeaf(t, iss, srv.URL+"/private.crl")
	tg := e.target(nil)
	r := result(served("192.0.2.1", leaf, iss.cert))
	run := func() {
		t.Helper()
		cur, _ := e.svc.Target(e.ctx, tg.ID)
		e.svc.RefreshCRLs(e.ctx, cur, r, nil)
		e.apply(tg.ID, r)
	}

	run()
	if _, open := e.open(tg.ID)[check.Revoked]; open || cs.fetches != 1 {
		t.Fatalf("clean CRL: open=%v fetches=%d", open, cs.fetches)
	}
	c, err := e.svc.CRLByURL(e.ctx, srv.URL+"/private.crl")
	if err != nil || c.FetchedAt == 0 || c.Entries != 0 || c.IssuerKey == "" {
		t.Fatalf("cached: %+v %v", c, err)
	}

	// Revoked an hour later: the copy is fresh, so nothing is fetched and
	// nothing opens until the next day.
	cs.mu.Lock()
	cs.revoked, cs.issued = append(cs.revoked, leaf.SerialNumber), cs.issued.Add(time.Hour)
	cs.mu.Unlock()
	e.clock.Add(time.Hour)
	run()
	if _, open := e.open(tg.ID)[check.Revoked]; open || cs.fetches != 1 {
		t.Fatalf("within the day: open=%v fetches=%d", open, cs.fetches)
	}
	e.clock.Add(CRLEvery)
	run()
	f, open := e.open(tg.ID)[check.Revoked]
	if !open || f.Severity != "critical" || !strings.Contains(f.Details, "key compromise") || cs.fetches != 2 {
		t.Fatalf("revoked: %+v fetches=%d", f, cs.fetches)
	}
	e.flush()
	if got := e.take("telegram"); len(got) != 1 || !strings.Contains(got[0].Subject, "revoked") {
		t.Fatalf("telegram: %+v", got)
	}
	cur, _ := e.svc.Target(e.ctx, tg.ID)
	rv, err := e.svc.TargetRevocation(e.ctx, cur, nil)
	if err != nil || !rv.Listed || rv.Entry.Reason != "key compromise" || rv.CRL == nil {
		t.Fatalf("page: %+v %v", rv, err)
	}
}

func TestCRLUnknownIsSilent(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.Channels.Save(e.ctx, notify.Channel{Name: "all", Kind: notify.KindWebhook, MinSeverity: "info", Enabled: true,
		Webhook: notify.WebhookSettings{URL: "https://hooks.example.nl/x"}}); err != nil {
		t.Fatal(err)
	}
	iss := crlCA(t)
	cs := &crlServer{ca: iss, down: true}
	srv := httptest.NewServer(cs)
	defer srv.Close()
	e.svc.CRLClient = srv.Client()
	tg := e.target(nil)
	r := result(served("192.0.2.1", crlLeaf(t, iss, srv.URL+"/down.crl"), iss.cert))

	for day := 1; day <= check.UnknownAfter; day++ {
		cur, _ := e.svc.Target(e.ctx, tg.ID)
		e.svc.RefreshCRLs(e.ctx, cur, r, nil)
		sum, err := e.svc.Apply(e.ctx, cur, r)
		if err != nil {
			t.Fatal(err)
		}
		_, open := e.open(tg.ID)[check.RevocationUnknown]
		if open != (day == check.UnknownAfter) {
			t.Fatalf("day %d: open=%v", day, open)
		}
		if sum.Queued != 0 {
			t.Fatalf("day %d: %d alerts queued", day, sum.Queued)
		}
		e.clock.Add(CRLEvery)
	}
	f := e.open(tg.ID)[check.RevocationUnknown]
	if f.Severity != check.Info || !strings.Contains(f.Details, "404") {
		t.Fatalf("unknown: %+v", f)
	}

	// The CRL comes back: the finding resolves.
	cs.mu.Lock()
	cs.down, cs.issued = false, time.Now()
	cs.mu.Unlock()
	cur, _ := e.svc.Target(e.ctx, tg.ID)
	e.svc.RefreshCRLs(e.ctx, cur, r, nil)
	e.apply(tg.ID, r)
	if _, open := e.open(tg.ID)[check.RevocationUnknown]; open {
		t.Fatal("still open after a good fetch")
	}
}

func TestCRLOnNodeForPrivateCA(t *testing.T) {
	e := newEnv(t)
	iss := crlCA(t)
	cs := &crlServer{ca: iss, issued: time.Now()}
	srv := httptest.NewServer(cs)
	defer srv.Close()
	// The server's own client is never used: only the node reaches it.
	e.svc.CRLClient = &http.Client{Transport: refuse{t}}
	id, tok, err := e.svc.CreateNode(e.ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.EnrolNode(e.ctx, tok, Enrolment{Facts: NodeFacts{Hostname: "probe1"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ConfirmNode(e.ctx, id, "dc1", "admin"); err != nil {
		t.Fatal(err)
	}
	var asked []string
	onNode := func(_ context.Context, nodeID int64, url string) ([]byte, error) {
		asked = append(asked, url)
		resp, err := srv.Client().Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	tg := e.target(nil)
	tg.NodeID, tg.Trust = id, probe.TrustBundle
	r := result(served("10.0.0.5", crlLeaf(t, iss, srv.URL+"/inside.crl"), iss.cert))
	e.svc.RefreshCRLs(e.ctx, tg, r, onNode)
	c, err := e.svc.CRLByURL(e.ctx, srv.URL+"/inside.crl")
	if err != nil || len(asked) != 1 || c.FetchedAt == 0 || c.NodeName != "dc1" {
		t.Fatalf("node fetch: %v %+v %v", asked, c, err)
	}
}
