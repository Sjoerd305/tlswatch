package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestScan(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	open, _ := strconv.Atoi(p)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().(*net.TCPAddr).Port
	l.Close()

	req := ScanRequest{Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Ports: []int{open, closed}, Rate: 200, Timeout: time.Second, AllowLocal: true}
	res, err := Scan(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Probed != 2 || len(res.Hits) != 1 || res.Hits[0].Port != open || len(res.Hits[0].Chain) == 0 || res.Hits[0].TLSVersion == "" {
		t.Fatalf("result: %+v", res)
	}
	// Local addresses are refused unless allowed, without a connect.
	req.AllowLocal = false
	if res, _ = Scan(context.Background(), req); res.Probed != 0 || res.Refused != 1 || len(res.Hits) != 0 {
		t.Fatalf("local refused: %+v", res)
	}
	// So is an address outside a node's allowlist.
	req.AllowLocal, req.Allow = true, func(net.IP) error { return net.InvalidAddrError("outside") }
	if res, _ = Scan(context.Background(), req); res.Probed != 0 || res.Refused != 1 {
		t.Fatalf("allowlist: %+v", res)
	}
	if _, err := Scan(context.Background(), ScanRequest{Addresses: make([]netip.Addr, MaxScanAddresses+1)}); err == nil {
		t.Fatal("an oversized scan ran")
	}
}

func TestScanAddresses(t *testing.T) {
	pf := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	for _, tc := range []struct {
		in   []netip.Prefix
		want int
	}{
		{pf("192.0.2.0/30"), 2}, // .1 and .2
		{pf("192.0.2.7/32"), 1}, // a single address
		{pf("192.0.2.0/31"), 2}, // point-to-point: both
		{pf("192.0.2.0/24", "192.0.2.128/25"), 254},
		{pf("2001:db8::/126"), 4},                // IPv6 has no broadcast
		{pf("10.0.0.0/8"), MaxScanAddresses + 1}, // stops past the limit
	} {
		if got := len(ScanAddresses(tc.in)); got != tc.want {
			t.Errorf("%v: %d addresses, want %d", tc.in, got, tc.want)
		}
	}
	if ScanProtocol(587) != SMTP || ScanProtocol(25) != SMTP || ScanProtocol(465) != TLS {
		t.Fatal("scan protocols")
	}
}

// Progress takes what the scan found as it goes; what it took is not
// returned again.
func TestScanProgress(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	// Reports every 100 ms, between connects a second apart: the timing of
	// one ticker against the other decides nothing.
	saved := scanReportEvery
	scanReportEvery = 100 * time.Millisecond
	t.Cleanup(func() { scanReportEvery = saved })
	var got ScanResult
	calls, early := 0, false
	req := ScanRequest{Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")}, Ports: []int{port},
		Rate: 1, Timeout: time.Second, AllowLocal: true, Progress: func(part ScanResult) {
			calls++
			early = early || got.Probed+part.Probed < 2
			got.Probed += part.Probed
			got.Hits = append(got.Hits, part.Hits...)
		}}
	res, err := Scan(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// At one connect a second the scan takes two seconds: reports come
	// before the second connect, and the rest at the end.
	if !early || calls < 2 || got.Probed != 2 || len(got.Hits) == 0 || res.Probed != 0 || len(res.Hits) != 0 {
		t.Fatalf("%d reports, %+v; returned %+v", calls, got, res)
	}
}
