package probe

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Scan limits. A scan is discovery, not a port scanner: a few thousand
// addresses at a low, fixed rate.
const (
	MaxScanAddresses = 4096 // per scan: a /20
	MaxScanPorts     = 16
	DefaultScanRate  = 50  // connects per second
	MaxScanRate      = 200 // connects per second
	ScanTimeout      = 3 * time.Second
)

// DefaultScanPorts are the ports a scan tries when none are given: HTTPS,
// its common alternative, LDAPS, IMAPS, POP3S, SMTPS, SMTP submission with
// STARTTLS and SIP over TLS.
var DefaultScanPorts = []int{443, 8443, 636, 993, 995, 465, 587, 5061}

// ScanProtocol is how a scan starts TLS on port: STARTTLS on the SMTP
// ports 25 and 587, implicit TLS on any other.
func ScanProtocol(port int) Protocol {
	if port == 25 || port == 587 {
		return SMTP
	}
	return TLS
}

// ScanRequest is one scan, or one chunk of one: every address of
// Addresses on every port of Ports.
type ScanRequest struct {
	Addresses  []netip.Addr
	Ports      []int
	Rate       int           // connects per second; DefaultScanRate when 0, at most MaxScanRate
	Timeout    time.Duration // per connect and handshake; ScanTimeout when 0
	AllowLocal bool
	Allow      func(net.IP) error // a node's allowlist
	Now        func() time.Time
	// Progress, when set, takes what the scan found and counted so far,
	// about once a second and once at the end; what it took is not in the
	// result Scan returns.
	Progress func(ScanResult)
}

// ScanHit is an address and port that completed a TLS handshake.
type ScanHit struct {
	IP         string
	Port       int
	Protocol   Protocol
	TLSVersion string
	Chain      []*x509.Certificate // as presented, leaf first
}

// ScanResult is what a scan found: the endpoints that answered with TLS,
// how many connects it made, and how many addresses it refused (local or
// outside the allowlist) without connecting.
type ScanResult struct {
	Hits    []ScanHit
	Probed  int
	Refused int
}

// ErrScanTooLarge refuses a request past the limits.
var ErrScanTooLarge = errors.New("scan too large")

// Scan connects to every address and port of req at a fixed rate, does the
// TLS handshake (STARTTLS on 25 and 587) and records each endpoint that
// answered with its chain. The chain is not verified and no SNI is sent:
// a scan finds what an address serves by default.
func Scan(ctx context.Context, req ScanRequest) (ScanResult, error) {
	if len(req.Addresses) > MaxScanAddresses || len(req.Ports) > MaxScanPorts {
		return ScanResult{}, fmt.Errorf("%w: at most %d addresses and %d ports", ErrScanTooLarge, MaxScanAddresses, MaxScanPorts)
	}
	rate := req.Rate
	if rate <= 0 {
		rate = DefaultScanRate
	}
	rate = min(rate, MaxScanRate)
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = ScanTimeout
	}
	if req.Now == nil {
		req.Now = time.Now
	}
	var res ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	// flush hands what was gathered since the last flush to Progress.
	flush := func() {
		if req.Progress == nil {
			return
		}
		mu.Lock()
		part := res
		res = ScanResult{}
		mu.Unlock()
		if part.Probed > 0 || part.Refused > 0 || len(part.Hits) > 0 {
			req.Progress(part)
		}
	}
	// The ticker stops before the last flush, so Progress is never called
	// after Scan returns.
	done, ticking := make(chan struct{}), sync.WaitGroup{}
	finish := func() (ScanResult, error) {
		close(done)
		ticking.Wait()
		flush()
		mu.Lock()
		defer mu.Unlock()
		return res, ctx.Err()
	}
	if req.Progress != nil {
		ticking.Add(1)
		go func() {
			defer ticking.Done()
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					flush()
				}
			}
		}()
	}
	tick := time.NewTicker(time.Second / time.Duration(rate))
	defer tick.Stop()
	// At the rate, no more than rate × timeout connects are in flight.
	slots := make(chan struct{}, rate*int(timeout/time.Second+1))
	for _, addr := range req.Addresses {
		ip := net.IP(addr.AsSlice())
		if !req.AllowLocal && IsLocalIP(ip) || req.Allow != nil && req.Allow(ip) != nil {
			mu.Lock()
			res.Refused++
			mu.Unlock()
			continue
		}
		for _, port := range req.Ports {
			select {
			case <-ctx.Done():
				wg.Wait()
				return finish()
			case <-tick.C:
			}
			slots <- struct{}{}
			mu.Lock()
			res.Probed++
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				r := Request{Host: addr.String(), Port: port, Protocol: ScanProtocol(port), Trust: TrustSelfSigned,
					Timeout: timeout, AllowLocal: req.AllowLocal, Allow: req.Allow, Now: req.Now}
				a, err := probeOnce(ctx, r, ip)
				if err != nil || !a.OK {
					return
				}
				mu.Lock()
				res.Hits = append(res.Hits, ScanHit{IP: a.IP, Port: port, Protocol: r.Protocol, TLSVersion: a.TLSVersion, Chain: a.Chain})
				mu.Unlock()
			}()
		}
	}
	wg.Wait()
	return finish()
}

// ScanAddresses expands prefixes into the addresses a scan probes: every
// address of each prefix, without the network and broadcast addresses of
// an IPv4 prefix shorter than /31, each once.
func ScanAddresses(prefixes []netip.Prefix) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, p := range prefixes {
		p = p.Masked()
		first := p.Addr()
		last := lastAddr(p)
		skipEnds := first.Is4() && p.Bits() < 31
		for a := first; p.Contains(a); a = a.Next() {
			if !(skipEnds && (a == first || a == last)) && !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
			if a == last || len(out) > MaxScanAddresses {
				break
			}
		}
	}
	return out
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
