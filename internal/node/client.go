package node

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

// ErrRestart ends Client.Run after the binary was replaced (or put back):
// the process exits and systemd starts the binary now in place.
var ErrRestart = errors.New("restart to run the new binary")

// Client is the node: it polls the server for jobs and runs them. Its only
// state is the credential file in Data.
type Client struct {
	Server     string // the server's base URL
	Data       string // the directory of the credential file
	Workers    int    // probes at once; the server leases no more
	Allow      []netip.Prefix
	AllowLocal bool
	Version    string
	Container  bool
	// Insecure is a plain http:// server (a lab): nothing it sends is
	// authenticated, so the node never replaces its binary from it.
	Insecure bool
	// NoUpdate keeps the node on its binary whatever the server says.
	NoUpdate bool
	// AllowUnsigned lets the node take a binary without a signed checksum,
	// which is what a development build of the server offers. Off, a node
	// updates only to a release whose SHA256SUMS the release key signed.
	AllowUnsigned bool
	// ReleaseKey verifies the signed checksums; nil means ReleasePublicKey.
	ReleaseKey ed25519.PublicKey
	Log        *slog.Logger
	HTTP       *http.Client
	// Executable is the running binary that a self-update replaces; nil
	// means os.Executable.
	Executable func() (string, error)
	// Probe is replaceable in tests.
	Probe func(context.Context, probe.Request) probe.Result

	cred    string
	gzip    atomic.Bool // the server accepts gzipped bodies (Accept-Encoding on its last poll answer)
	running sync.WaitGroup
	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

// NewHTTPClient is the node's client to the server: the operating system's
// trust store, HTTPS_PROXY honoured, and a timeout one poll hold past the
// ceiling, so a dead connection is noticed one hold after it breaks.
func NewHTTPClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = http.ProxyFromEnvironment
	return &http.Client{Timeout: ClientTimeout, Transport: t}
}

// CheckServer validates the server URL: https, or http only when insecure.
func CheckServer(server string, insecure bool) (string, error) {
	server = strings.TrimSuffix(strings.TrimSpace(server), "/")
	switch {
	case server == "":
		return "", errors.New("the server URL is missing (-server or TLSWATCH_NODE_SERVER)")
	case strings.HasPrefix(server, "https://"):
	case strings.HasPrefix(server, "http://"):
		if !insecure {
			return "", errors.New("the server URL is plain http; use https, or -insecure for a lab")
		}
	default:
		return "", fmt.Errorf("%q is not an http(s) URL", server)
	}
	return server, nil
}

// CredentialFile is where a node keeps its credential.
func CredentialFile(data string) string { return filepath.Join(data, "credential") }

func (c *Client) client() *http.Client {
	if c.HTTP == nil {
		c.HTTP = NewHTTPClient()
	}
	return c.HTTP
}

// Enrolled reports whether the node has a credential.
func (c *Client) Enrolled() bool {
	_, err := os.Stat(CredentialFile(c.Data))
	return err == nil
}

// Enrol exchanges an install token for the node's credential and writes
// it to the credential file (0600). It returns the node's number.
func (c *Client) Enrol(ctx context.Context, token string) (int64, error) {
	body, _ := json.Marshal(EnrolRequest{Token: strings.TrimSpace(token), Pool: c.workers(), Facts: GatherFacts(c.Version, c.Container)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Server+Prefix+"/enrol", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderVersion, c.Version)
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, fmt.Errorf("enrol with %s: %w", c.Server, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("enrol with %s: %s", c.Server, serverError(resp))
	}
	var er EnrolResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&er); err != nil || er.Credential == "" {
		return 0, fmt.Errorf("enrol with %s: unreadable answer", c.Server)
	}
	if err := os.MkdirAll(c.Data, 0o700); err != nil {
		return 0, err
	}
	tmp := CredentialFile(c.Data) + ".new"
	if err := os.WriteFile(tmp, []byte(er.Credential+"\n"), 0o600); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, CredentialFile(c.Data)); err != nil {
		return 0, err
	}
	c.cred = er.Credential
	return er.NodeID, nil
}

// serverError is the error text of a failed call.
func serverError(resp *http.Response) string {
	var e struct {
		Error string `json:"error"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if json.Unmarshal(b, &e) == nil && e.Error != "" {
		return e.Error
	}
	if s := strings.TrimSpace(string(b)); s != "" && len(s) < 300 {
		return resp.Status + ": " + s
	}
	return resp.Status
}

func (c *Client) readCredential() error {
	b, err := os.ReadFile(CredentialFile(c.Data))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("not enrolled: no credential in %s; run tlswatch node enrol -server URL -token TOKEN", c.Data)
		}
		return err
	}
	c.cred = strings.TrimSpace(string(b))
	return nil
}

func (c *Client) workers() int {
	if c.Workers < 1 {
		return 4
	}
	return c.Workers
}

// errUnauthorized is a credential the server no longer accepts.
var errUnauthorized = errors.New("credential not accepted")

// Run polls the server and runs its jobs until ctx ends, or until a
// self-update replaced the binary (ErrRestart). Failed polls back off from
// one second, doubling to a minute, and reset on the first success.
func (c *Client) Run(ctx context.Context) error {
	if err := c.readCredential(); err != nil {
		return err
	}
	c.cancels = map[string]context.CancelFunc{}
	restart := make(chan error, 1)
	polled := make(chan struct{})
	var pollOnce sync.Once
	if m, ok := readMarker(c.Data); ok {
		go c.watchUpdate(ctx, m, polled, restart)
	}
	rollback := readRollback(c.Data)
	jobCtx, stopJobs := context.WithCancel(context.Background())
	defer func() {
		stopJobs()
		c.running.Wait()
	}()
	c.Log.Info("node started", "server", c.Server, "version", c.Version, "workers", c.workers(), "allow", c.Allow)

	backoff := time.Second
	stuck := time.Second // wait after an update reply that changed nothing
	var factsAt time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-restart:
			return err
		default:
		}
		if time.Since(factsAt) >= FactsEvery {
			if err := c.sendFacts(ctx); err == nil {
				factsAt = time.Now()
			} else if ctx.Err() == nil {
				c.Log.Warn("facts not sent", "err", err)
			}
		}
		resp, err := c.poll(ctx, rollback)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, errUnauthorized) {
				c.Log.Error("the server does not accept this node's credential; enrol it again with a new install command from Settings › Nodes")
				backoff = time.Minute
				_ = c.readCredential() // a re-enrolment may have written a new one
			} else {
				c.Log.Warn("poll failed", "err", err, "retry_in", backoff.String())
			}
			select {
			case <-ctx.Done():
				return nil
			case err := <-restart:
				return err
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		// The binary in place works, and a reported rollback or failure
		// has reached the server.
		pollOnce.Do(func() { close(polled); clearUpdateFiles(c.Data) })
		if rollback != "" {
			clearUpdateFiles(c.Data)
			rollback = ""
		}
		if resp.Update {
			if err := c.update(ctx, resp.ServerVersion); err != nil {
				return err
			}
			rollback = readRollback(c.Data) // set when the update went nowhere
			// The binary was not replaced (a container, -no-self-update, a
			// failed download): a server that only answers "update" is not
			// polled in a tight loop.
			select {
			case <-ctx.Done():
				return nil
			case err := <-restart:
				return err
			case <-time.After(stuck):
			}
			stuck = min(stuck*2, time.Minute)
			continue
		}
		stuck = time.Second
		for _, j := range resp.Jobs {
			switch j.Kind {
			case KindProbe:
				if j.Probe != nil {
					c.start(jobCtx, j)
				}
			case KindCancel:
				c.mu.Lock()
				if cancel, ok := c.cancels[j.Cancel]; ok {
					cancel()
				}
				c.mu.Unlock()
			case KindUpdate:
				v := resp.ServerVersion
				if j.Update != nil {
					v = j.Update.Version
				}
				if err := c.update(ctx, v); err != nil {
					return err
				}
				rollback = readRollback(c.Data)
			default:
				c.Log.Warn("unknown job kind; this node may be older than the server", "kind", j.Kind)
			}
		}
	}
}

// do sends one authenticated call.
func (c *Client) do(ctx context.Context, method, path string, body []byte, hdr map[string]string) (*http.Response, error) {
	var rd io.Reader
	zipped := body != nil && c.gzip.Load()
	if zipped {
		body = gzipped(body)
	}
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cred)
	req.Header.Set(HeaderVersion, c.Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if zipped {
		req.Header.Set("Content-Encoding", "gzip")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		return nil, errUnauthorized
	}
	return resp, nil
}

func (c *Client) poll(ctx context.Context, rollback string) (PollResponse, error) {
	var out PollResponse
	hdr := map[string]string{}
	if rollback != "" {
		hdr[HeaderUpdateError] = rollback
	}
	resp, err := c.do(ctx, http.MethodGet, pollURL(c.Server), nil, hdr)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, errors.New(serverError(resp))
	}
	c.gzip.Store(strings.Contains(resp.Header.Get("Accept-Encoding"), "gzip"))
	err = json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&out)
	return out, err
}

// gzipped compresses a request body. Chains are base64 DER and a host's
// addresses usually present the same one, so results shrink well.
func gzipped(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

func (c *Client) sendFacts(ctx context.Context) error {
	body, _ := json.Marshal(GatherFacts(c.Version, c.Container))
	resp, err := c.do(ctx, http.MethodPost, c.Server+Prefix+"/facts", body, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return errors.New(serverError(resp))
	}
	return nil
}

// start runs one probe job in the background and posts its result. A
// result that cannot be delivered is dropped: the server asks again.
func (c *Client) start(ctx context.Context, j Job) {
	jctx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	c.cancels[j.ID] = cancel
	c.mu.Unlock()
	c.running.Add(1)
	go func() {
		defer c.running.Done()
		defer func() {
			cancel()
			c.mu.Lock()
			delete(c.cancels, j.ID)
			c.mu.Unlock()
		}()
		req := j.Probe.Request(time.Now())
		req.AllowLocal = req.AllowLocal && c.AllowLocal
		req.Allow = c.allow
		pf := probe.Probe
		if c.Probe != nil {
			pf = c.Probe
		}
		r := pf(jctx, req)
		if jctx.Err() != nil {
			c.Log.Info("job cancelled", "job", j.ID, "endpoint", endpoint(req))
			return
		}
		ok := 0
		for _, a := range r.Addresses {
			if a.OK {
				ok++
			}
		}
		c.Log.Info("probed", "job", j.ID, "endpoint", endpoint(req), "addresses", len(r.Addresses), "answered", ok,
			"dns_error", r.DNSError, "ms", r.Duration.Milliseconds())
		body, _ := json.Marshal(Result{Probe: EncodeResult(r)})
		pctx, pcancel := context.WithTimeout(context.Background(), ClientTimeout)
		defer pcancel()
		resp, err := c.do(pctx, http.MethodPost, c.Server+Prefix+"/jobs/"+j.ID+"/result", body, nil)
		if err != nil {
			c.Log.Warn("result not delivered", "job", j.ID, "err", err)
			return
		}
		resp.Body.Close()
	}()
}

func endpoint(r probe.Request) string {
	return net.JoinHostPort(r.Host, fmt.Sprint(r.Port))
}

// allow applies the node's allowlist: what the server must not be able to
// widen stays on the node.
func (c *Client) allow(ip net.IP) error {
	if len(c.Allow) == 0 {
		return nil
	}
	a, ok := netip.AddrFromSlice(ip)
	if ok {
		a = a.Unmap()
		for _, p := range c.Allow {
			if p.Contains(a) {
				return nil
			}
		}
	}
	return fmt.Errorf("%s is outside this node's allowlist", ip)
}

// ParseAllow reads a comma or space separated list of CIDRs (or single
// addresses).
func ParseAllow(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR or an address", f)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
