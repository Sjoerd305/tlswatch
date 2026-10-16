package node

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

// clock is a settable time for the dispatcher.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	core  *core.Service
	disp  *Dispatcher
	srv   *httptest.Server
	clock *clock
	log   *slog.Logger
	pub   ed25519.PublicKey // the test release key
	priv  ed25519.PrivateKey
}

func setup(t *testing.T) *env {
	t.Helper()
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	key, _ := secret.New(make([]byte, 32))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	chans := &notify.Channels{DB: d, Key: key}
	st := config.NewStore(d, key)
	c := &core.Service{DB: d, Settings: st, Channels: chans, Dispatcher: &notify.Dispatcher{DB: d, Channels: chans, Log: log}, Key: key, Log: log}
	ck := &clock{t: time.Now()}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	disp := &Dispatcher{Core: c, Version: "v1.2.0", Log: log, Now: ck.now, ReleaseKey: pub}
	srv := httptest.NewServer(disp)
	t.Cleanup(srv.Close)
	if err := st.SaveGeneral(context.Background(), config.General{BaseURL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	return &env{core: c, disp: disp, srv: srv, clock: ck, log: log, pub: pub, priv: priv}
}

func (e *env) client(t *testing.T, version string) *Client {
	return &Client{Server: e.srv.URL, Data: t.TempDir(), Workers: 2, Version: version, Log: e.log, HTTP: &http.Client{Timeout: 5 * time.Second}, ReleaseKey: e.pub}
}

// release stands in for GitHub: it serves the SHA256SUMS of the server's
// version listing files by content (asset name → bytes), signed with the
// test release key (or, with sign false, by a key nobody knows), and the
// files themselves.
func (e *env) release(t *testing.T, sign bool, assets map[string][]byte) {
	t.Helper()
	var b strings.Builder
	for name, content := range assets {
		sum := sha256.Sum256(content)
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	text := b.String()
	priv := e.priv
	if !sign {
		_, priv, _ = ed25519.GenerateKey(rand.Reader)
	}
	sig := hex.EncodeToString(ed25519.Sign(priv, []byte(text)))
	mux := http.NewServeMux()
	mux.HandleFunc("/"+e.disp.Version+"/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, text) })
	mux.HandleFunc("/"+e.disp.Version+"/SHA256SUMS.sig", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, sig+"\n") })
	for name, content := range assets {
		mux.HandleFunc("/"+e.disp.Version+"/"+name, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(content) })
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	e.disp.Releases = srv.URL
	e.disp.binary = binaryCache{} // forget what was fetched before
}

// ownAsset is the release asset name of the test server's own platform.
func (e *env) ownAsset() string {
	return "tlswatch-" + e.disp.Version + "-" + strings.ReplaceAll(OwnPlatform(), "/", "-")
}

// enrolled creates, enrols and confirms a node.
func (e *env) enrolled(t *testing.T, c *Client) core.Node {
	t.Helper()
	ctx := context.Background()
	_, tok, err := e.core.CreateNode(ctx, "admin@example.org")
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.Enrol(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.core.ConfirmNode(ctx, id, "dc1", "admin@example.org"); err != nil {
		t.Fatal(err)
	}
	e.disp.Refresh(ctx, id)
	n, err := e.core.Node(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func selfSigned(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestEnrolConfirmProbe(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cert := selfSigned(t, "portal.example.nl")
	c := e.client(t, "v1.2.0")
	var seen atomic.Value
	c.Probe = func(_ context.Context, req probe.Request) probe.Result {
		seen.Store(req)
		// The node's own verdict: not trusted, hostname not checked. The
		// server judges both again.
		return probe.Result{Host: req.Host, Port: req.Port, Duration: 12 * time.Millisecond,
			Addresses: []probe.Address{{IP: "10.0.3.5", OK: true, TLSVersion: "TLS 1.3", Chain: []*x509.Certificate{cert}, VerifyError: "unknown authority"}}}
	}
	n := e.enrolled(t, c)
	if fi, err := os.Stat(CredentialFile(c.Data)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("credential file: %v %v", fi, err)
	}
	if n.State != core.NodeConfirmed || n.Facts.Hostname == "" || n.Name != "dc1" {
		t.Fatalf("node after confirm: %+v", n)
	}
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	req := probe.Request{Host: "portal.example.nl", Port: 443, Protocol: probe.TLS, ServerName: "portal.example.nl",
		Trust: probe.TrustBundle, Roots: pool, Timeout: 2 * time.Second}
	pctx, pcancel := context.WithTimeout(ctx, 10*time.Second)
	defer pcancel()
	r, err := e.disp.Probe(pctx, n.ID, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Addresses) != 1 {
		t.Fatalf("addresses: %+v", r.Addresses)
	}
	a := r.Addresses[0]
	if !a.Verified || a.VerifyError != "" {
		t.Errorf("bundle chain not verified on the server: %+v", a)
	}
	if !a.HostnameChecked || !a.HostnameOK {
		t.Errorf("hostname not judged on the server: %+v", a)
	}
	if probe.Fingerprint(a.Chain[0]) != probe.Fingerprint(cert) {
		t.Error("chain did not survive the wire")
	}
	got := seen.Load().(probe.Request)
	if got.Timeout != 2*time.Second || got.Roots != nil || got.Allow == nil {
		t.Errorf("node request: %+v", got)
	}
	if st := e.disp.Status(n.ID); !st.Online || st.Completed != 1 {
		t.Errorf("status: %+v", st)
	}

	// System trust: the node's verdict against its own store stands.
	req.Trust, req.Roots = probe.TrustSystem, nil
	r, err = e.disp.Probe(pctx, n.ID, req)
	if err != nil {
		t.Fatal(err)
	}
	if a := r.Addresses[0]; a.Verified || a.VerifyError != "unknown authority" {
		t.Errorf("system trust: %+v", a)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestOfflineFailsFast(t *testing.T) {
	e := setup(t)
	c := e.client(t, "v1.2.0")
	n := e.enrolled(t, c)
	if !e.disp.Online(n.ID) {
		t.Fatal("a node is online during the start grace")
	}
	e.clock.add(OfflineAfter + time.Second)
	if e.disp.Online(n.ID) {
		t.Fatal("a node not seen for the offline window is online")
	}
	_, err := e.disp.Probe(context.Background(), n.ID, probe.Request{Host: "a.example", Port: 443})
	if !errors.Is(err, core.ErrNodeOffline) {
		t.Fatalf("probe on an offline node: %v", err)
	}
	// A poll brings it back.
	var back atomic.Int64
	e.disp.OnOnline = func(id int64) { back.Store(id) }
	e.disp.judge(context.Background())
	// The poll is held for want of jobs; the timeout ends it.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := c.poll(ctx, ""); err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}
	if !e.disp.Online(n.ID) || back.Load() != n.ID {
		t.Fatalf("node not back online after a poll (online=%v, OnOnline=%d)", e.disp.Online(n.ID), back.Load())
	}
}

func TestPendingAndDisabledNodesHold(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	_, tok, _ := e.core.CreateNode(ctx, "admin")
	c := e.client(t, "v1.2.0")
	id, err := c.Enrol(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if e.disp.Online(id) {
		t.Error("a pending node takes jobs")
	}
	// A token is spent once.
	if _, err := c.Enrol(ctx, tok); err == nil {
		t.Error("an install token was accepted twice")
	}
	if err := e.core.ConfirmNode(ctx, id, "x", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := e.core.SetNodeEnabled(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	e.disp.Refresh(ctx, id)
	if e.disp.Online(id) {
		t.Error("a disabled node takes jobs")
	}
	// Assigning targets is refused to a node that is not confirmed.
	_, tok2, _ := e.core.CreateNode(ctx, "admin")
	id2, _ := e.client(t, "v1").Enrol(ctx, tok2)
	_, err = e.core.SaveTarget(ctx, core.Target{Name: "t", Host: "a.example", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem,
		Enabled: true, AllChannels: true, NodeID: id2}, "admin")
	if err == nil {
		t.Error("a target was assigned to a pending node")
	}
}

func TestJobTimeoutRequeuesOnceThenGivesUp(t *testing.T) {
	e := setup(t)
	c := e.client(t, "v1.2.0")
	n := e.enrolled(t, c)
	res := make(chan error, 1)
	go func() {
		_, err := e.disp.Probe(context.Background(), n.ID, probe.Request{Host: "a.example", Port: 443, Timeout: time.Second})
		res <- err
	}()
	lease := func() []Job {
		for i := 0; i < 200; i++ {
			if jobs := e.disp.lease(n.ID, 4); len(jobs) > 0 {
				return jobs
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("no job to lease")
		return nil
	}
	first := lease()
	timeout := first[0].Probe.Timeout()
	e.clock.add(timeout + time.Second)
	e.disp.expireJobs()
	second := lease()
	if second[0].ID != first[0].ID {
		t.Fatal("the timed-out job was not queued again")
	}
	e.clock.add(timeout + time.Second)
	e.disp.expireJobs()
	if err := <-res; !errors.Is(err, core.ErrNodeNoResult) {
		t.Fatalf("after two leases: %v", err)
	}
	// A late result for it is discarded.
	e.disp.complete(n.ID, first[0].ID, Result{Probe: &ProbeResult{}})
}

func TestLeaseRespectsPool(t *testing.T) {
	e := setup(t)
	n := e.enrolled(t, e.client(t, "v1.2.0"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < 5; i++ {
		go func() { _, _ = e.disp.Probe(ctx, n.ID, probe.Request{Host: "a.example", Port: 443}) }()
	}
	time.Sleep(50 * time.Millisecond)
	if jobs := e.disp.lease(n.ID, 2); len(jobs) != 2 {
		t.Fatalf("leased %d of pool 2", len(jobs))
	}
	if jobs := e.disp.lease(n.ID, 2); len(jobs) != 0 {
		t.Fatalf("leased %d beyond the pool", len(jobs))
	}
	if st := e.disp.Status(n.ID); st.Queued != 3 || st.Running != 2 {
		t.Fatalf("status: %+v", st)
	}
}

func TestPauseDropsJobs(t *testing.T) {
	e := setup(t)
	n := e.enrolled(t, e.client(t, "v1.2.0"))
	res := make(chan error, 1)
	go func() {
		_, err := e.disp.Probe(context.Background(), n.ID, probe.Request{Host: "a.example", Port: 443})
		res <- err
	}()
	time.Sleep(30 * time.Millisecond)
	e.disp.Pause()
	if err := <-res; !errors.Is(err, core.ErrNodesPaused) {
		t.Fatalf("paused: %v", err)
	}
	if _, err := e.disp.Probe(context.Background(), n.ID, probe.Request{Host: "a.example"}); !errors.Is(err, core.ErrNodesPaused) {
		t.Fatalf("probe while paused: %v", err)
	}
	e.disp.Resume()
}

func TestBadCredentialAndUnknownProtocol(t *testing.T) {
	e := setup(t)
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/agent/v1/jobs", nil)
	req.Header.Set("Authorization", "Bearer nope")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad credential: %s", resp.Status)
	}
	resp, err = http.Get(e.srv.URL + "/agent/v9/jobs")
	if err != nil {
		t.Fatal(err)
	}
	var pr PollResponse
	_ = json.NewDecoder(resp.Body).Decode(&pr)
	resp.Body.Close()
	if !pr.Update || pr.ServerVersion != "v1.2.0" {
		t.Fatalf("unknown protocol reply: %+v", pr)
	}
}

func TestInstallScriptServedForValidToken(t *testing.T) {
	e := setup(t)
	_, tok, _ := e.core.CreateNode(context.Background(), "admin")
	resp, err := http.Get(e.srv.URL + "/agent/v1/install/" + tok)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "TOKEN='"+tok+"'") || !strings.Contains(string(body), "SERVER='"+e.srv.URL+"'") {
		t.Fatalf("install script: %s\n%s", resp.Status, body)
	}
	resp, _ = http.Get(e.srv.URL + "/agent/v1/install/unknown")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown token: %s", resp.Status)
	}
	resp, _ = http.Get(e.srv.URL + "/agent/v1/uninstall")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "userdel") {
		t.Fatalf("uninstall script: %s", resp.Status)
	}
	if q := shellQuote("it's"); q != `'it'\''s'` {
		t.Fatalf("shellQuote: %s", q)
	}
}

func TestDownloadOwnBinary(t *testing.T) {
	e := setup(t)
	bin := filepath.Join(t.TempDir(), "tlswatch")
	if err := os.WriteFile(bin, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.disp.Executable = func() (string, error) { return bin, nil }
	// Without signed release checksums, a release server serves nothing.
	resp, err := http.Get(e.srv.URL + "/agent/v1/download/" + OwnPlatform())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("download without checksums: %s", resp.Status)
	}
	// Signed by the wrong key: the same.
	e.release(t, false, map[string][]byte{e.ownAsset(): []byte("binary")})
	resp, _ = http.Get(e.srv.URL + "/agent/v1/download/" + OwnPlatform())
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("download with a bad signature: %s", resp.Status)
	}
	// Its own binary is the released one: served from here, checksum along.
	e.release(t, true, map[string][]byte{e.ownAsset(): []byte("binary")})
	resp, err = http.Get(e.srv.URL + "/agent/v1/download/" + OwnPlatform())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	want, _ := fileSHA256(bin)
	if string(body) != "binary" || resp.Header.Get(HeaderSHA256) != want {
		t.Fatalf("download: %q %s", body, resp.Header.Get(HeaderSHA256))
	}
	// The signed checksums are served for the node to check itself.
	resp, _ = http.Get(e.srv.URL + "/agent/v1/release/sums")
	sums, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if got, err := VerifySums(sums, []byte(resp.Header.Get(HeaderSumsSignature)), e.pub); err != nil || got[e.ownAsset()] != want {
		t.Fatalf("release sums: %v %v", got, err)
	}
	// Its own binary is not the released bytes (a container image): the
	// node is sent to the release asset instead.
	e.release(t, true, map[string][]byte{e.ownAsset(): []byte("released")})
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ = noFollow.Get(e.srv.URL + "/agent/v1/download/" + OwnPlatform())
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasSuffix(resp.Header.Get("Location"), "/v1.2.0/"+e.ownAsset()) {
		t.Fatalf("download of other bytes: %s %s", resp.Status, resp.Header.Get("Location"))
	}
}

// A node replaces its binary only with one in a SHA256SUMS the release key
// signed; a development build, a plain-http server and -no-self-update are
// refused with a reason the server shows.
func TestUpdateRefusals(t *testing.T) {
	e := setup(t)
	dir := t.TempDir()
	newBin := filepath.Join(dir, "server-tlswatch")
	_ = os.WriteFile(newBin, []byte("new"), 0o755)
	e.disp.Executable = func() (string, error) { return newBin, nil }
	ctx := context.Background()
	try := func(name string, c *Client, version, wantReason string) {
		t.Helper()
		exe := filepath.Join(t.TempDir(), "tlswatch")
		_ = os.WriteFile(exe, []byte("old"), 0o755)
		c.Executable = func() (string, error) { return exe, nil }
		if err := c.update(ctx, version); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if b, _ := os.ReadFile(exe); string(b) != "old" {
			t.Fatalf("%s: the binary was replaced", name)
		}
		if reason := readRollback(c.Data); !strings.Contains(reason, wantReason) {
			t.Fatalf("%s: reason %q, want %q", name, reason, wantReason)
		}
	}
	c := e.client(t, "v1.1.0")
	try("no checksums", c, "v1.2.0", "signed checksums")
	e.release(t, false, map[string][]byte{e.ownAsset(): []byte("new")})
	try("bad signature", c, "v1.2.0", "signed checksums")
	e.release(t, true, map[string][]byte{"tlswatch-v1.2.0-plan9-mips": []byte("new")})
	try("not listed", c, "v1.2.0", "not in the signed checksums")
	// The server is right, but the node was told not to.
	e.release(t, true, map[string][]byte{e.ownAsset(): []byte("new")})
	c.NoUpdate = true
	try("no-self-update", c, "v1.2.0", "does not update itself")
	c.NoUpdate, c.Insecure = false, true
	try("insecure", c, "v1.2.0", "plain http")
	c.Insecure = false
	// A development build has no signature: refused unless allowed.
	e.disp.Version = "2026.10.16-abc1234"
	try("development build", c, e.disp.Version, "development build")
	c.AllowUnsigned = true
	exe := filepath.Join(t.TempDir(), "tlswatch")
	_ = os.WriteFile(exe, []byte("old"), 0o755)
	c.Executable = func() (string, error) { return exe, nil }
	if err := c.update(ctx, e.disp.Version); !errors.Is(err, ErrRestart) {
		t.Fatalf("development build when allowed: %v", err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new" {
		t.Fatalf("binary not replaced: %q", b)
	}
}

func TestSelfUpdateAndRollback(t *testing.T) {
	e := setup(t)
	dir := t.TempDir()
	newBin := filepath.Join(dir, "server-tlswatch")
	if err := os.WriteFile(newBin, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.disp.Executable = func() (string, error) { return newBin, nil }
	e.release(t, true, map[string][]byte{e.ownAsset(): []byte("new")})
	c := e.client(t, "v1.1.0")
	exe := filepath.Join(dir, "tlswatch")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.Executable = func() (string, error) { return exe, nil }
	n := e.enrolled(t, c)

	// The server, a release, sends the node on another version an update.
	ctx := context.Background()
	if !e.disp.wantUpdate(ctx, n, "") {
		t.Fatal("no update for an outdated node")
	}
	if err := c.update(ctx, "v1.2.0"); !errors.Is(err, ErrRestart) {
		t.Fatalf("update: %v", err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new" {
		t.Fatalf("binary not replaced: %q", b)
	}
	if b, _ := os.ReadFile(exe + ".prev"); string(b) != "old" {
		t.Fatalf("old binary not kept: %q", b)
	}
	m, ok := readMarker(c.Data)
	if !ok || m.From != "v1.1.0" || m.To != "v1.2.0" {
		t.Fatalf("marker: %+v %v", m, ok)
	}

	// The new binary never reaches the server: it is rolled back.
	m.At = time.Now().Add(-UpdateWindow - time.Second)
	b, _ := json.Marshal(m)
	_ = os.WriteFile(filepath.Join(c.Data, markerFile), b, 0o600)
	c2 := &Client{Server: c.Server, Data: c.Data, Version: "v1.2.0", Log: c.Log, Executable: c.Executable}
	restart := make(chan error, 1)
	c2.watchUpdate(ctx, m, make(chan struct{}), restart)
	if err := <-restart; !errors.Is(err, ErrRestart) {
		t.Fatalf("rollback: %v", err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("binary not rolled back: %q", b)
	}
	reason := readRollback(c.Data)
	if reason == "" {
		t.Fatal("no rollback reason kept")
	}
	// The old binary reports it: the update is marked failed and not tried
	// again on its own.
	n, _ = e.core.Node(ctx, n.ID)
	if e.disp.wantUpdate(ctx, n, reason) {
		t.Fatal("update sent again while the failure is reported")
	}
	n, _ = e.core.Node(ctx, n.ID)
	if n.UpdateFailed != reason || n.UpdateStarted != 0 {
		t.Fatalf("failure not recorded: %+v", n)
	}
	if e.disp.wantUpdate(ctx, n, "") {
		t.Fatal("a failed update was retried without an admin")
	}
	if err := e.core.RequestNodeUpdate(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	n, _ = e.core.Node(ctx, n.ID)
	if !e.disp.wantUpdate(ctx, n, "") {
		t.Fatal("Update by an admin was not sent")
	}

	// A download that fails goes nowhere on the node, and the reason is
	// reported on its next poll so the server does not wait out the
	// window.
	e.disp.Executable = func() (string, error) { return "", errors.New("binary gone") }
	if err := c.update(ctx, "v1.2.0"); err != nil {
		t.Fatalf("failed update: %v", err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("binary changed by a failed update: %q", b)
	}
	if _, ok := readMarker(c.Data); ok {
		t.Fatal("marker written for a failed update")
	}
	reason = readRollback(c.Data)
	if reason == "" {
		t.Fatal("failed download not recorded")
	}
	n, _ = e.core.Node(ctx, n.ID)
	if e.disp.wantUpdate(ctx, n, reason) {
		t.Fatal("update sent again while the failure is reported")
	}
	n, _ = e.core.Node(ctx, n.ID)
	if n.UpdateFailed != reason || n.UpdateStarted != 0 {
		t.Fatalf("failure not recorded: %+v", n)
	}
}

func TestUpdatesOneAtATime(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	a := e.enrolled(t, e.client(t, "v1.1.0"))
	b := e.enrolled(t, e.client(t, "v1.1.0"))
	if !e.disp.wantUpdate(ctx, a, "") {
		t.Fatal("first node not updated")
	}
	if e.disp.wantUpdate(ctx, b, "") {
		t.Fatal("second node updated while the first runs")
	}
	a, _ = e.core.Node(ctx, a.ID)
	a.Version = "v1.2.0" // it came back on the new version
	e.disp.wantUpdate(ctx, a, "")
	if !e.disp.wantUpdate(ctx, b, "") {
		t.Fatal("second node not updated after the first finished")
	}
	// Containers and development builds are never updated on their own.
	c := e.client(t, "v1.1.0")
	c.Container = true
	cn := e.enrolled(t, c)
	e.clock.add(UpdateWindow + time.Second)
	if e.disp.wantUpdate(ctx, cn, "") {
		t.Fatal("a container was sent an update")
	}
	e.disp.Version = "0123456789ab"
	d := e.enrolled(t, e.client(t, "v1.1.0"))
	if e.disp.wantUpdate(ctx, d, "") {
		t.Fatal("a development server updated a node on its own")
	}
}

func TestNodeOfflineFinding(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	n := e.enrolled(t, e.client(t, "v1.2.0"))
	if _, err := e.core.SaveTarget(ctx, core.Target{Name: "t", Host: "a.example", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem,
		Enabled: true, AllChannels: true, NodeID: n.ID}, "admin"); err != nil {
		t.Fatal(err)
	}
	e.clock.add(FindingAfter + time.Minute)
	e.disp.reload(ctx)
	e.disp.findings(ctx)
	open, err := e.core.Findings(ctx, core.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].Kind != check.NodeOffline || open[0].NodeID != n.ID || open[0].TargetName != "dc1" {
		t.Fatalf("open findings: %+v", open)
	}
	if open[0].Severity != check.Warning {
		t.Fatalf("severity: %s", open[0].Severity)
	}
	// Coming back resolves it.
	n, _ = e.core.Node(ctx, n.ID)
	if err := e.core.NodeOnline(ctx, n); err != nil {
		t.Fatal(err)
	}
	if open, _ = e.core.Findings(ctx, core.FindingFilter{}); len(open) != 0 {
		t.Fatalf("finding not resolved: %+v", open)
	}
	// Deleting a node with targets is refused unless they move.
	if err := e.core.DeleteNode(ctx, n.ID, false); !errors.Is(err, core.ErrNodeInUse) {
		t.Fatalf("delete with targets: %v", err)
	}
	if err := e.core.DeleteNode(ctx, n.ID, true); err != nil {
		t.Fatal(err)
	}
	ts, _ := e.core.Targets(ctx)
	if len(ts) != 1 || ts[0].NodeID != 0 {
		t.Fatalf("target not moved: %+v", ts)
	}
}

func TestAllowlist(t *testing.T) {
	allow, err := ParseAllow("10.0.0.0/8, 192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{Allow: allow}
	for ip, ok := range map[string]bool{"10.1.2.3": true, "192.0.2.7": true, "192.0.2.8": false, "::ffff:10.0.0.1": true} {
		if err := c.allow(parse(ip)); (err == nil) != ok {
			t.Errorf("%s: %v", ip, err)
		}
	}
	if _, err := ParseAllow("nonsense"); err == nil {
		t.Error("bad CIDR accepted")
	}
}

func parse(s string) net.IP { return net.ParseIP(s) }

func TestIsRelease(t *testing.T) {
	for v, want := range map[string]bool{"v1.2.0": true, "v0.10.3": true, "v1.2.0-rc1": false, "v0.2.0-5-g5efacf7": false, "v1.2.0-dirty": false,
		"v0.2.0-5-g5efacf7-dirty": false, "2026.10.15-5efacf7": false, "dev": false, "0123456789ab": false} {
		if IsRelease(v) != want {
			t.Errorf("IsRelease(%q) = %v", v, !want)
		}
	}
}

// After a restart the start grace counts a node as online, but only a poll
// resolves its node_offline finding.
func TestGraceDoesNotResolveOfflineFinding(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	n := e.enrolled(t, e.client(t, "v1.2.0"))
	e.clock.add(FindingAfter + time.Minute)
	e.disp.reload(ctx)
	e.disp.findings(ctx)
	if open, _ := e.core.Findings(ctx, core.FindingFilter{}); len(open) != 1 {
		t.Fatalf("no node_offline finding: %+v", open)
	}
	// A new process: the node is online by grace only.
	d2 := &Dispatcher{Core: e.core, Version: "v1.2.0", Log: e.log, Now: e.clock.now}
	d2.reload(ctx)
	d2.judge(ctx)
	if !d2.Online(n.ID) {
		t.Fatal("not online during the start grace")
	}
	if open, _ := e.core.Findings(ctx, core.FindingFilter{}); len(open) != 1 {
		t.Fatal("the start grace resolved the finding of a node that never polled")
	}
	// Its first poll does.
	d2.mu.Lock()
	d2.state(n.ID).lastSeen = e.clock.now()
	d2.mu.Unlock()
	d2.judge(ctx)
	if open, _ := e.core.Findings(ctx, core.FindingFilter{}); len(open) != 0 {
		t.Fatalf("a poll did not resolve the finding: %+v", open)
	}
}

func TestResultsGzippedOnlyWhenAccepted(t *testing.T) {
	for _, accept := range []bool{true, false} {
		e := setup(t)
		var mu sync.Mutex
		encodings := map[string]string{} // path → Content-Encoding of the last call
		e.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			encodings[r.URL.Path] = r.Header.Get("Content-Encoding")
			mu.Unlock()
			if !accept {
				w = noAcceptEncoding{w}
			}
			e.disp.ServeHTTP(w, r)
		})
		ctx, cancel := context.WithCancel(context.Background())
		cert := selfSigned(t, "portal.example.nl")
		c := e.client(t, "v1.2.0")
		c.Probe = func(_ context.Context, req probe.Request) probe.Result {
			return probe.Result{Host: req.Host, Port: req.Port,
				Addresses: []probe.Address{{IP: "10.0.3.5", OK: true, Chain: []*x509.Certificate{cert}}, {IP: "10.0.3.6", OK: true, Chain: []*x509.Certificate{cert}}}}
		}
		n := e.enrolled(t, c)
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx) }()
		req := probe.Request{Host: "portal.example.nl", Port: 443, Protocol: probe.TLS, ServerName: "portal.example.nl", Timeout: 2 * time.Second}
		pctx, pcancel := context.WithTimeout(ctx, 10*time.Second)
		r, err := e.disp.Probe(pctx, n.ID, req)
		pcancel()
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Addresses) != 2 || probe.Fingerprint(r.Addresses[1].Chain[0]) != probe.Fingerprint(cert) {
			t.Fatalf("accept=%v: chain did not survive the wire: %+v", accept, r.Addresses)
		}
		var got string
		mu.Lock()
		for p, enc := range encodings {
			if strings.HasSuffix(p, "/result") {
				got = enc
			}
		}
		mu.Unlock()
		if want := map[bool]string{true: "gzip", false: ""}[accept]; got != want {
			t.Errorf("accept=%v: result sent with Content-Encoding %q, want %q", accept, got, want)
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

// noAcceptEncoding plays an older server that does not advertise gzip.
type noAcceptEncoding struct{ http.ResponseWriter }

func (w noAcceptEncoding) WriteHeader(code int) {
	w.Header().Del("Accept-Encoding")
	w.ResponseWriter.WriteHeader(code)
}

func (w noAcceptEncoding) Write(b []byte) (int, error) {
	w.Header().Del("Accept-Encoding")
	return w.ResponseWriter.Write(b)
}

func TestReadJSONCapsInflatedBody(t *testing.T) {
	zeros := gzipped(append(append([]byte(`{"x":"`), bytes.Repeat([]byte("0"), maxBody+1)...), `"}`...))
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(zeros))
	r.Header.Set("Content-Encoding", "gzip")
	var v map[string]string
	if err := readJSON(httptest.NewRecorder(), r, &v); err == nil {
		t.Fatal("a body inflating past the cap was accepted")
	}
	r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	r.Header.Set("Content-Encoding", "br")
	if err := readJSON(httptest.NewRecorder(), r, &v); err == nil {
		t.Fatal("an unknown encoding was accepted")
	}
}
