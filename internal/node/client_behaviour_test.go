package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

// fakeServer plays the server for the node's side: signed checksums of one
// release and whatever download, poll and result handlers a test sets.
type fakeServer struct {
	*httptest.Server
	pub      ed25519.PublicKey
	sumsText string
	sumsSig  string
	mu       sync.Mutex
	download http.HandlerFunc
	poll     http.HandlerFunc
	result   http.HandlerFunc
	facts    http.HandlerFunc
}

func newFakeServer(t *testing.T, version string, released []byte) *fakeServer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeServer{pub: pub}
	if released != nil {
		sum := sha256.Sum256(released)
		f.sumsText = fmt.Sprintf("%s  tlswatch-%s-%s-%s\n", hex.EncodeToString(sum[:]), version, runtime.GOOS, runtime.GOARCH)
		f.sumsSig = hex.EncodeToString(ed25519.Sign(priv, []byte(f.sumsText)))
	}
	mux := http.NewServeMux()
	mux.HandleFunc(Prefix+"/release/sums", func(w http.ResponseWriter, r *http.Request) {
		if f.sumsText == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set(HeaderSumsSignature, f.sumsSig)
		_, _ = io.WriteString(w, f.sumsText)
	})
	mux.HandleFunc(Prefix+"/download/", func(w http.ResponseWriter, r *http.Request) { f.handler(&f.download)(w, r) })
	mux.HandleFunc(Prefix+"/jobs", func(w http.ResponseWriter, r *http.Request) { f.handler(&f.poll)(w, r) })
	mux.HandleFunc(Prefix+"/jobs/", func(w http.ResponseWriter, r *http.Request) { f.handler(&f.result)(w, r) })
	f.facts = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	mux.HandleFunc(Prefix+"/facts", func(w http.ResponseWriter, r *http.Request) { f.handler(&f.facts)(w, r) })
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeServer) handler(h *http.HandlerFunc) http.HandlerFunc {
	f.mu.Lock()
	defer f.mu.Unlock()
	if *h == nil {
		return http.NotFound
	}
	return *h
}

func (f *fakeServer) set(h *http.HandlerFunc, fn http.HandlerFunc) {
	f.mu.Lock()
	*h = fn
	f.mu.Unlock()
}

// nodeAt is a client of the fake server whose running binary is exe
// (holding "old").
func nodeAt(t *testing.T, f *fakeServer, version string) (*Client, string) {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "tlswatch")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := &Client{Server: f.URL, Data: t.TempDir(), Workers: 2, Version: version, ReleaseKey: f.pub,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), HTTP: &http.Client{Timeout: 5 * time.Second},
		Executable: func() (string, error) { return exe, nil }, cred: "cred"}
	return c, exe
}

// unchanged checks that a failed update left the binary, wrote no marker,
// cleaned up the partial file and recorded a reason containing want.
func unchanged(t *testing.T, c *Client, exe, want string) {
	t.Helper()
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("binary changed: %q", b)
	}
	if _, err := os.Stat(exe + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial download left behind: %v", err)
	}
	if _, ok := readMarker(c.Data); ok {
		t.Fatal("marker written for a failed update")
	}
	if r := readRollback(c.Data); !strings.Contains(r, want) {
		t.Fatalf("reason %q, want %q", r, want)
	}
}

func serveBytes(b []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(b) }
}

func TestUpdateInterruptedDownloadKeepsBinary(t *testing.T) {
	f := newFakeServer(t, "v1.2.0", []byte("the new binary"))
	f.set(&f.download, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "the n")
		conn, _, err := http.NewResponseController(w).Hijack()
		if err == nil {
			conn.Close()
		}
	})
	c, exe := nodeAt(t, f, "v1.1.0")
	if err := c.update(context.Background(), "v1.2.0"); err != nil {
		t.Fatalf("update: %v", err)
	}
	unchanged(t, c, exe, "")
	if readRollback(c.Data) == "" {
		t.Fatal("no reason recorded for an interrupted download")
	}
}

func TestUpdateChecksumMismatchKeepsBinary(t *testing.T) {
	f := newFakeServer(t, "v1.2.0", []byte("the new binary"))
	f.set(&f.download, serveBytes([]byte("something else")))
	c, exe := nodeAt(t, f, "v1.1.0")
	if err := c.update(context.Background(), "v1.2.0"); err != nil {
		t.Fatalf("update: %v", err)
	}
	unchanged(t, c, exe, "checksum mismatch")
}

func TestUpdateServerErrorKeepsBinary(t *testing.T) {
	f := newFakeServer(t, "v1.2.0", []byte("the new binary"))
	f.set(&f.download, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "the server cannot read its own executable", http.StatusInternalServerError)
	})
	c, exe := nodeAt(t, f, "v1.1.0")
	if err := c.update(context.Background(), "v1.2.0"); err != nil {
		t.Fatalf("update: %v", err)
	}
	unchanged(t, c, exe, "cannot read its own executable")
}

func TestUpdateNonWritableBinaryDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	f := newFakeServer(t, "v1.2.0", []byte("the new binary"))
	f.set(&f.download, serveBytes([]byte("the new binary")))
	c, exe := nodeAt(t, f, "v1.1.0")
	dir := filepath.Dir(exe)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if err := c.update(context.Background(), "v1.2.0"); err != nil {
		t.Fatalf("update: %v", err)
	}
	unchanged(t, c, exe, "permission denied")
}

// When the old binary cannot be kept as tlswatch.prev, nothing is swapped:
// a rollback would have nothing to go back to.
func TestUpdateWithoutRoomForPreviousKeepsBinary(t *testing.T) {
	f := newFakeServer(t, "v1.2.0", []byte("the new binary"))
	f.set(&f.download, serveBytes([]byte("the new binary")))
	c, exe := nodeAt(t, f, "v1.1.0")
	if err := os.MkdirAll(filepath.Join(exe+".prev", "occupied"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := c.update(context.Background(), "v1.2.0"); err != nil {
		t.Fatalf("update: %v", err)
	}
	unchanged(t, c, exe, "keep the old binary")
}

func TestCopyFileKeepsContentAndMode(t *testing.T) {
	dir := t.TempDir()
	from, to := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(from, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, []byte("longer old content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(from, to); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(to); string(b) != "binary" {
		t.Fatalf("copy: %q", b)
	}
	if err := copyFile(filepath.Join(dir, "missing"), to); err == nil {
		t.Fatal("copied a missing file")
	}
}

// After a server rollback the nodes follow it down, to a signed release.
func TestUpdateFollowsServerDowngrade(t *testing.T) {
	f := newFakeServer(t, "v1.2.0", []byte("the older binary"))
	f.set(&f.download, serveBytes([]byte("the older binary")))
	c, exe := nodeAt(t, f, "v1.3.0")
	if err := c.update(context.Background(), "v1.2.0"); !errors.Is(err, ErrRestart) {
		t.Fatalf("downgrade: %v", err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "the older binary" {
		t.Fatalf("binary: %q", b)
	}
	if b, _ := os.ReadFile(exe + ".prev"); string(b) != "old" {
		t.Fatalf("previous: %q", b)
	}
	if m, ok := readMarker(c.Data); !ok || m.From != "v1.3.0" || m.To != "v1.2.0" {
		t.Fatalf("marker: %+v", m)
	}
}

// A development build is followed only with -allow-unsigned-update, and
// then with the checksum the server sent, also across a redirect.
func TestUnsignedUpdateChecksumAcrossRedirect(t *testing.T) {
	const dev = "2026.10.16-abc1234"
	content := []byte("dev binary")
	sum := sha256.Sum256(content)
	asset := httptest.NewServer(serveBytes(content))
	t.Cleanup(asset.Close)
	for _, tc := range []struct {
		name, header, reason string
	}{
		{"checksum on the redirect", hex.EncodeToString(sum[:]), ""},
		{"no checksum", "", "sent no checksum"},
		{"wrong checksum", strings.Repeat("0", 64), "checksum mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t, dev, nil)
			f.set(&f.download, func(w http.ResponseWriter, r *http.Request) {
				if tc.header != "" {
					w.Header().Set(HeaderSHA256, tc.header)
				}
				http.Redirect(w, r, asset.URL+"/asset", http.StatusFound)
			})
			c, exe := nodeAt(t, f, "v1.1.0")
			c.AllowUnsigned = true
			err := c.update(context.Background(), dev)
			if tc.reason == "" {
				if !errors.Is(err, ErrRestart) {
					t.Fatalf("update: %v (%s)", err, readRollback(c.Data))
				}
				if b, _ := os.ReadFile(exe); string(b) != string(content) {
					t.Fatalf("binary: %q", b)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			unchanged(t, c, exe, tc.reason)
		})
	}
}

func TestWatchUpdateOldBinaryRunningClearsMarker(t *testing.T) {
	f := newFakeServer(t, "v1.2.0", nil)
	c, exe := nodeAt(t, f, "v1.1.0")
	m := marker{From: "v1.1.0", To: "v1.2.0", At: time.Now().Add(-time.Hour)}
	b, _ := json.Marshal(m)
	_ = os.WriteFile(filepath.Join(c.Data, markerFile), b, 0o600)
	restart := make(chan error, 1)
	c.watchUpdate(context.Background(), m, make(chan struct{}), restart)
	if len(restart) != 0 {
		t.Fatal("the old binary restarted itself")
	}
	if _, ok := readMarker(c.Data); ok {
		t.Fatal("marker kept")
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("binary: %q", b)
	}
	// A new binary that polled in time stays.
	c.Version = "v1.2.0"
	_ = os.WriteFile(exe+".prev", []byte("previous"), 0o755)
	polled := make(chan struct{})
	close(polled)
	c.watchUpdate(context.Background(), marker{From: "v1.1.0", To: "v1.2.0", At: time.Now()}, polled, restart)
	if len(restart) != 0 {
		t.Fatal("rolled back after a successful poll")
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("binary replaced by the previous one: %q", b)
	}
}

// The first poll of a new binary clears the marker, and the rollback
// reason goes up on it.
func TestRunReportsRollbackAndClearsUpdateFiles(t *testing.T) {
	f := newFakeServer(t, "v1.2.0", nil)
	var reported atomic.Value
	var polls atomic.Int32
	f.set(&f.poll, func(w http.ResponseWriter, r *http.Request) {
		if polls.Add(1) == 1 {
			reported.Store(r.Header.Get(HeaderUpdateError))
			writeJSON(w, http.StatusOK, PollResponse{ServerVersion: "v1.2.0"})
			return
		}
		<-r.Context().Done()
	})
	c, _ := nodeAt(t, f, "v1.2.0")
	_ = os.WriteFile(filepath.Join(c.Data, "credential"), []byte("cred\n"), 0o600)
	b, _ := json.Marshal(marker{From: "v1.1.0", To: "v1.2.0", At: time.Now()})
	_ = os.WriteFile(filepath.Join(c.Data, markerFile), b, 0o600)
	b, _ = json.Marshal(map[string]string{"reason": "the swap failed"})
	_ = os.WriteFile(filepath.Join(c.Data, rollbackFile), b, 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for polls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got, _ := reported.Load().(string); got != "the swap failed" {
		t.Fatalf("reported %q", got)
	}
	if _, ok := readMarker(c.Data); ok {
		t.Fatal("marker kept after a successful poll")
	}
	if readRollback(c.Data) != "" {
		t.Fatal("rollback reason kept after it was reported")
	}
}

// A server on another protocol version answers every poll at once with the
// fixed "update" reply. A node that does not replace its binary (a
// container, -no-self-update, or an update that fails) must not answer
// that with a tight loop of polls against the server.
func TestFixedUpdateReplyDoesNotSpin(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*Client)
	}{
		{"container", func(c *Client) { c.Container = true }},
		{"no-self-update", func(c *Client) { c.NoUpdate = true }},
		{"failing update", func(c *Client) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t, "v9.0.0", nil)
			var polls atomic.Int32
			f.set(&f.poll, func(w http.ResponseWriter, r *http.Request) {
				polls.Add(1)
				writeJSON(w, http.StatusOK, PollResponse{ServerVersion: "v9.0.0", Update: true})
			})
			c, _ := nodeAt(t, f, "v1.2.0")
			tc.setup(c)
			_ = os.WriteFile(filepath.Join(c.Data, "credential"), []byte("cred\n"), 0o600)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := c.Run(ctx); err != nil {
				t.Fatal(err)
			}
			if n := polls.Load(); n > 5 {
				t.Fatalf("%d polls in one second against a server that only says update", n)
			}
		})
	}
}

// Kinds a later server may send are skipped, a cancel for a job the node
// does not run is ignored, and the probe jobs beside them still run, with
// the node's own local-address rule applied.
func TestClientSkipsUnknownJobsAndRunsTheRest(t *testing.T) {
	f := newFakeServer(t, "v1.2.0", nil)
	var polls atomic.Int32
	f.set(&f.poll, func(w http.ResponseWriter, r *http.Request) {
		if polls.Add(1) == 1 {
			writeJSON(w, http.StatusOK, PollResponse{ServerVersion: "v1.2.0", Jobs: []Job{
				{ID: "j1", Kind: "refresh"},
				{ID: "j2", Kind: KindCancel, Cancel: "not-running"},
				{ID: "j3", Kind: KindProbe},
				{ID: "j4", Kind: KindProbe, Probe: &ProbeJob{Host: "127.0.0.1", Port: 443, Protocol: probe.TLS, TimeoutMS: 1000, AllowLocal: true, ServerTime: time.Now()}},
			}})
			return
		}
		<-r.Context().Done()
	})
	results := make(chan string, 4)
	f.set(&f.result, func(w http.ResponseWriter, r *http.Request) {
		results <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	c, _ := nodeAt(t, f, "v1.2.0")
	_ = os.WriteFile(filepath.Join(c.Data, "credential"), []byte("cred\n"), 0o600)
	var allowLocal atomic.Bool
	allowLocal.Store(true)
	c.Probe = func(_ context.Context, req probe.Request) probe.Result {
		allowLocal.Store(req.AllowLocal)
		return probe.Result{Host: req.Host, Port: req.Port}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case p := <-results:
		if p != Prefix+"/jobs/j4/result" {
			t.Fatalf("result for %s", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the probe job beside unknown kinds did not run")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if allowLocal.Load() {
		t.Fatal("the server allowed a local address the node does not allow")
	}
	if len(results) != 0 {
		t.Fatalf("more results: %d", len(results))
	}
}

func TestClientPollErrors(t *testing.T) {
	f := newFakeServer(t, "v1.2.0", nil)
	c, _ := nodeAt(t, f, "v1.2.0")
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
		want string
	}{
		{"unauthorized", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }, errUnauthorized.Error()},
		{"json error", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "the server cannot check the credential now"})
		}, "cannot check the credential"},
		{"proxy page", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "bad gateway", http.StatusBadGateway) }, "502"},
		{"garbage", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "<html>") }, "invalid"},
	} {
		f.set(&f.poll, tc.h)
		_, err := c.poll(ctx, "")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestEnrolFailuresWriteNoCredential(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
		want string
	}{
		{"spent token", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "the install token is unknown, spent or expired"})
		}, "spent or expired"},
		{"no credential", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, EnrolResponse{NodeID: 3}) }, "unreadable"},
		{"garbage", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "nope") }, "unreadable"},
	} {
		srv := httptest.NewServer(tc.h)
		c := &Client{Server: srv.URL, Data: filepath.Join(t.TempDir(), "data"), Version: "v1.2.0", HTTP: srv.Client()}
		_, err := c.Enrol(context.Background(), "tok")
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
		if c.Enrolled() {
			t.Errorf("%s: a credential was written", tc.name)
		}
	}
}

func TestRunWithoutCredential(t *testing.T) {
	c := &Client{Server: "https://tlswatch.example", Data: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if c.Enrolled() {
		t.Fatal("enrolled without a credential")
	}
	if err := c.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("run without a credential: %v", err)
	}
	_ = os.WriteFile(CredentialFile(c.Data), []byte("  cred \n"), 0o600)
	if !c.Enrolled() {
		t.Fatal("not enrolled with a credential file")
	}
	if err := c.readCredential(); err != nil || c.cred != "cred" {
		t.Fatalf("credential %q: %v", c.cred, err)
	}
}

func TestCheckServer(t *testing.T) {
	for _, tc := range []struct {
		in       string
		insecure bool
		want     string
		ok       bool
	}{
		{" https://tlswatch.example.nl/ ", false, "https://tlswatch.example.nl", true},
		{"https://tlswatch.example.nl/base", false, "https://tlswatch.example.nl/base", true},
		{"http://lab:8080", false, "", false},
		{"http://lab:8080", true, "http://lab:8080", true},
		{"", false, "", false},
		{"tlswatch.example.nl", false, "", false},
		{"ftp://tlswatch.example.nl", true, "", false},
	} {
		got, err := CheckServer(tc.in, tc.insecure)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("CheckServer(%q, %v) = %q, %v", tc.in, tc.insecure, got, err)
		}
	}
}

func TestNewHTTPClient(t *testing.T) {
	c := NewHTTPClient()
	if c.Timeout != ClientTimeout {
		t.Fatalf("timeout %v", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.Proxy == nil {
		t.Fatal("HTTPS_PROXY is not honoured")
	}
	if tr == http.DefaultTransport {
		t.Fatal("the default transport is shared")
	}
}

func TestInContainer(t *testing.T) {
	t.Setenv("TLSWATCH_CONTAINER", "1")
	if !InContainer() {
		t.Fatal("TLSWATCH_CONTAINER=1 is not a container")
	}
	t.Setenv("TLSWATCH_CONTAINER", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	if !InContainer() {
		t.Fatal("a Kubernetes pod is not a container")
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	_, e1 := os.Stat("/.dockerenv")
	_, e2 := os.Stat("/run/.containerenv")
	if e1 != nil && e2 != nil && InContainer() {
		t.Fatal("a host without container traces is a container")
	}
}

func TestUninstallNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("would remove the real installation")
	}
	var out []string
	if err := Uninstall(func(s string) { out = append(out, s) }); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("uninstall without root: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("uninstall did something without root: %v", out)
	}
}

// Facts the server could not store yet (a restart within five minutes of
// the last report) are sent again when it asks, not an hour later.
func TestFactsSentAgainWhenTheServerAsks(t *testing.T) {
	f := newFakeServer(t, "v1.2.0", nil)
	var reports atomic.Int32
	f.set(&f.facts, func(w http.ResponseWriter, r *http.Request) {
		if reports.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	f.set(&f.poll, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
		writeJSON(w, http.StatusOK, PollResponse{ServerVersion: "v1.2.0"})
	})
	c, _ := nodeAt(t, f, "v1.2.0")
	_ = os.WriteFile(filepath.Join(c.Data, "credential"), []byte("cred\n"), 0o600)
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := reports.Load(); n != 2 {
		t.Fatalf("%d facts reports, want the refused one and one again after Retry-After", n)
	}
}
