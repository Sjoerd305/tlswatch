package sched

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/netip"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

func selfSignedCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// A scan runs in chunks, stores each chunk's endpoints with the target
// that already covers one, and ends done; a second scan from the same
// place waits for the first.
func TestScanRunsInChunks(t *testing.T) {
	s, c, _ := setup(t, 0)
	ctx := context.Background()
	if _, err := c.SaveTarget(ctx, core.Target{Name: "known", Host: "10.0.0.5", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem,
		AllAddresses: true, AllChannels: true, Enabled: true}, "test"); err != nil {
		t.Fatal(err)
	}
	cert := selfSignedCert(t, "app.internal.example")
	release := make(chan struct{})
	var chunks []int
	s.Scan = func(_ context.Context, req probe.ScanRequest) (probe.ScanResult, error) {
		<-release
		chunks = append(chunks, len(req.Addresses))
		var res probe.ScanResult
		for _, a := range req.Addresses {
			if a == netip.MustParseAddr("10.0.0.5") || a == netip.MustParseAddr("10.0.1.9") {
				res.Hits = append(res.Hits, probe.ScanHit{IP: a.String(), Port: 443, Protocol: probe.TLS, TLSVersion: "TLS 1.3", Chain: []*x509.Certificate{cert}})
			}
		}
		res.Probed = len(req.Addresses) * len(req.Ports)
		return res, nil
	}
	sc, addrs, err := c.CreateScan(ctx, core.ScanInput{Ranges: "10.0.0.0/23", Ports: "443"}, "op@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 510 || sc.Total != 510 {
		t.Fatalf("addresses %d, total %d", len(addrs), sc.Total)
	}
	if _, _, err := c.CreateScan(ctx, core.ScanInput{Ranges: "10.1.0.0/24"}, "op@example.test"); err != core.ErrScanBusy {
		t.Fatalf("second scan: %v", err)
	}
	s.StartScan(sc, addrs)
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, _ := c.Scan(ctx, sc.ID)
		if got.State != core.ScanRunning {
			if got.State != core.ScanDone || got.Probed != 510 || got.Found != 2 || got.Percent() != 100 {
				t.Fatalf("scan: %+v", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scan did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(chunks) != 2 || chunks[0] != 256 || chunks[1] != 254 {
		t.Fatalf("chunks %v", chunks)
	}
	res, err := c.ScanResults(ctx, sc.ID)
	if err != nil || len(res) != 2 {
		t.Fatalf("results: %v %+v", err, res)
	}
	if res[0].Address != "10.0.0.5" || res[0].TargetName != "known" || res[1].TargetID != 0 || res[1].SubjectCN != "app.internal.example" {
		t.Fatalf("results: %+v", res)
	}
}

func TestScanRangesAndPorts(t *testing.T) {
	for _, tc := range []struct {
		in            string
		public, local bool
		ok            bool
	}{
		{"10.0.0.0/24", false, false, true},
		{"10.0.0.0/20", false, false, true},
		{"10.0.0.0/19", false, false, false}, // more than 4096
		{"8.8.8.0/24", false, false, false},  // public
		{"8.8.8.0/24", true, false, true},
		{"127.0.0.0/30", true, false, false}, // loopback
		{"127.0.0.1", true, true, true},
		{"fd00::/120, 192.168.1.10", false, false, true},
		{"10.0.0.0/8", false, false, false},
		{"not a range", false, false, false},
	} {
		if _, _, err := core.ParseScanRanges(tc.in, tc.public, tc.local); (err == nil) != tc.ok {
			t.Errorf("%q public=%v local=%v: %v", tc.in, tc.public, tc.local, err)
		}
	}
	if p, err := core.ParseScanPorts(""); err != nil || len(p) != len(probe.DefaultScanPorts) {
		t.Fatalf("default ports: %v %v", p, err)
	}
	if _, err := core.ParseScanPorts("443, 70000"); err == nil {
		t.Fatal("port 70000 accepted")
	}
}

// A node gets chunks of about ten seconds at the scan's rate, so the
// progress moves; a local scan reports as it goes and takes full chunks.
func TestScanChunkSize(t *testing.T) {
	for _, tc := range []struct {
		node        int64
		rate, ports int
		want        int
	}{
		{0, 50, 8, 256},
		{1, 50, 8, 62},
		{1, 200, 1, 256},
		{1, 1, 16, 1},
	} {
		if got := chunkSize(core.Scan{NodeID: tc.node, Rate: tc.rate, Ports: make([]int, tc.ports)}); got != tc.want {
			t.Errorf("node %d rate %d ports %d: %d, want %d", tc.node, tc.rate, tc.ports, got, tc.want)
		}
	}
}

// The live pages follow a running scan: the stamp moves with its progress,
// and the server counts as busy, so they poll fast.
func TestScanMovesTheStamp(t *testing.T) {
	_, c, _ := setup(t, 0)
	ctx := context.Background()
	before, pending, _ := c.Stamp(ctx)
	sc, _, err := c.CreateScan(ctx, core.ScanInput{Ranges: "10.0.0.0/30", Ports: "443"}, "op@example.test")
	if err != nil {
		t.Fatal(err)
	}
	during, busy, _ := c.Stamp(ctx)
	if during == before || busy != pending+1 {
		t.Fatalf("stamp %s → %s, pending %d → %d", before, during, pending, busy)
	}
	if err := c.RecordScan(ctx, sc.ID, probe.ScanResult{Probed: 1}); err != nil {
		t.Fatal(err)
	}
	if after, _, _ := c.Stamp(ctx); after == during {
		t.Fatal("progress did not move the stamp")
	}
	if err := c.FinishScan(ctx, sc.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, n, _ := c.Stamp(ctx); n != pending {
		t.Fatalf("pending %d after the scan, want %d", n, pending)
	}
}
