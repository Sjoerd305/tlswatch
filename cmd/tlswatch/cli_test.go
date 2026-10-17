package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/node"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

// tlsServer serves a self-signed certificate valid until notAfter, and
// returns its address and the certificate as PEM.
func tlsServer(t *testing.T, notAfter time.Time) (string, []byte, []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "cli.test"}, DNSNames: []string{"cli.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(k)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://"), certPEM, keyPEM
}

func runCheck(t *testing.T, args ...string) (checkResult, int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := checkCmd(args, &out, &errOut)
	var res checkResult
	if out.Len() > 0 {
		if err := json.Unmarshal(out.Bytes(), &res); err != nil {
			t.Fatalf("output: %v: %s", err, out.String())
		}
	}
	return res, code, errOut.String()
}

func kinds(res checkResult) string {
	var k []string
	for _, f := range res.Findings {
		k = append(k, f.Kind)
	}
	return strings.Join(k, ",")
}

// The exit code follows the expiry thresholds: 0 ok, 1 warning, 2
// critical, with the flags after the endpoint as well as before it.
func TestCheckExitCodeByExpiry(t *testing.T) {
	soon, _, _ := tlsServer(t, time.Now().Add(20*24*time.Hour))
	later, _, _ := tlsServer(t, time.Now().Add(80*24*time.Hour))
	gone, _, _ := tlsServer(t, time.Now().Add(-24*time.Hour))
	for _, tc := range []struct {
		args   []string
		code   int
		status string
		kind   string
	}{
		{[]string{later, "-insecure", "-no-config-test"}, 0, "ok", ""},
		{[]string{soon, "-insecure", "-no-config-test"}, 1, "warning", string(check.Expiring)},
		{[]string{"-insecure", "-no-config-test", "-warn", "30", "-crit", "25", soon}, 2, "critical", string(check.Expiring)},
		{[]string{soon, "-insecure", "-no-config-test", "-warn=10", "-crit=5"}, 0, "ok", ""},
		{[]string{gone, "-insecure", "-no-config-test"}, 2, "critical", string(check.Expired)},
	} {
		res, code, stderr := runCheck(t, tc.args...)
		if code != tc.code || res.Status != tc.status || (tc.kind != "" && !strings.Contains(kinds(res), tc.kind)) {
			t.Errorf("%q: exit %d status %s findings %s (stderr %s)", tc.args, code, res.Status, kinds(res), stderr)
		}
		if res.DaysLeft == nil || res.NotAfter == "" {
			t.Errorf("%q: no expiry in the report", tc.args)
		}
	}
}

// An endpoint that refuses the connection is critical, with its error.
func TestCheckUnreachableIsCritical(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	res, code, _ := runCheck(t, addr, "-insecure", "-no-config-test", "-timeout", "2s")
	if code != 2 || res.Status != "critical" || !strings.Contains(kinds(res), string(check.Unreachable)) {
		t.Fatalf("closed port: exit %d status %s findings %s", code, res.Status, kinds(res))
	}
	if len(res.Addresses) != 1 || res.Addresses[0].OK || res.Addresses[0].Error == "" {
		t.Fatalf("addresses: %+v", res.Addresses)
	}
}

// -ca-file verifies against the bundle; a bundle with a private key, an
// empty one or a missing file is a usage error.
func TestCheckCAFile(t *testing.T) {
	addr, certPEM, keyPEM := tlsServer(t, time.Now().Add(80*24*time.Hour))
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ca := write("ca.pem", certPEM)
	res, code, stderr := runCheck(t, addr, "-ca-file", ca, "-no-config-test")
	// The leaf is its own root: verified, but self_signed on a bundle target.
	if len(res.Addresses) != 1 || !res.Addresses[0].Verified || strings.Contains(kinds(res), string(check.ChainUntrusted)) {
		t.Fatalf("bundle: exit %d %+v findings %s %s", code, res.Addresses, kinds(res), stderr)
	}
	// Without the bundle the system store does not know the root.
	if res, code, _ = runCheck(t, addr, "-no-config-test"); code != 2 || !strings.Contains(kinds(res), string(check.ChainUntrusted)) &&
		!strings.Contains(kinds(res), string(check.SelfSigned)) {
		t.Fatalf("system store: exit %d findings %s", code, kinds(res))
	}
	for name, path := range map[string]string{
		"private key": write("key.pem", append(append([]byte{}, certPEM...), keyPEM...)),
		"empty":       write("empty.pem", nil),
		"missing":     filepath.Join(dir, "missing.pem"),
	} {
		res, code, stderr := runCheck(t, addr, "-ca-file", path)
		if code != 2 || res.Target != "" || stderr == "" {
			t.Errorf("%s bundle: exit %d, stdout %+v, stderr %q", name, code, res, stderr)
		}
	}
}

func TestCheckEndpointParsing(t *testing.T) {
	for _, tc := range []struct {
		args       []string
		host       string
		port       int
		servername string
		proto      probe.Protocol
	}{
		{[]string{"example.org"}, "example.org", 443, "example.org", probe.TLS},
		{[]string{"example.org."}, "example.org", 443, "example.org", probe.TLS},
		{[]string{"example.org:8443"}, "example.org", 8443, "example.org", probe.TLS},
		{[]string{"[2001:db8::1]:8443"}, "2001:db8::1", 8443, "", probe.TLS},
		{[]string{"2001:db8::1"}, "2001:db8::1", 443, "", probe.TLS},
		{[]string{"192.0.2.1", "-servername", "portal.example.nl"}, "192.0.2.1", 443, "portal.example.nl", probe.TLS},
		{[]string{"mail.example.org", "-protocol", "smtp"}, "mail.example.org", probe.DefaultPort(probe.SMTP), "mail.example.org", probe.SMTP},
		{[]string{"-protocol=imap", "mail.example.org:993"}, "mail.example.org", 993, "mail.example.org", probe.IMAP},
	} {
		run, err := parseCheck(tc.args, io.Discard)
		if err != nil {
			t.Errorf("%q: %v", tc.args, err)
			continue
		}
		r := run.req
		if r.Host != tc.host || r.Port != tc.port || r.ServerName != tc.servername || r.Protocol != tc.proto {
			t.Errorf("%q: %s %d sni %q %s", tc.args, r.Host, r.Port, r.ServerName, r.Protocol)
		}
		if !r.Legacy || r.Trust != probe.TrustSystem || r.Timeout != 10*time.Second || run.warn != 30 || run.crit != 7 {
			t.Errorf("%q: defaults %+v warn %d crit %d", tc.args, r, run.warn, run.crit)
		}
	}
	for _, args := range [][]string{{"example.org:65536"}, {"example.org:"}, {"example.org:http"}, {"exa mple.org"}, {":443"},
		{"example.org", "-warn"}, {"example.org", "-timeout", "soon"}, {"example.org", "-insecure", "false"}} {
		if _, err := parseCheck(args, io.Discard); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
}

// The node's settings come from flags or the environment, flags winning.
func TestNodeFlagsAndEnvironment(t *testing.T) {
	t.Setenv("TLSWATCH_NODE_SERVER", "https://tlswatch.example.nl/")
	t.Setenv("TLSWATCH_NODE_DATA", "/srv/node")
	t.Setenv("TLSWATCH_NODE_WORKERS", "8")
	t.Setenv("TLSWATCH_NODE_ALLOW", "10.0.0.0/8, 192.0.2.7")
	t.Setenv("TLSWATCH_NODE_ALLOW_LOCAL", "true")
	t.Setenv("TLSWATCH_NODE_NO_UPDATE", "true")
	t.Setenv("TLSWATCH_NODE_ALLOW_UNSIGNED_UPDATE", "true")
	t.Setenv("TLSWATCH_NODE_TOKEN", "tok")
	fs, f := nodeFlagSet("node", false)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	c, err := nodeClient(f)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "https://tlswatch.example.nl" || c.Data != "/srv/node" || c.Workers != 8 || len(c.Allow) != 2 ||
		!c.AllowLocal || !c.NoUpdate || !c.AllowUnsigned || c.Insecure || *f.token != "tok" || c.Version != version {
		t.Fatalf("client from the environment: %+v", c)
	}
	fs, f = nodeFlagSet("node", false)
	if err := fs.Parse([]string{"-workers", "2", "-server", "http://lab:8080", "-insecure", "-allow", ""}); err != nil {
		t.Fatal(err)
	}
	if c, err = nodeClient(f); err != nil || c.Workers != 2 || c.Server != "http://lab:8080" || !c.Insecure || len(c.Allow) != 0 {
		t.Fatalf("flags over the environment: %+v %v", c, err)
	}
	// enrol has no probing or update flags.
	fs, f = nodeFlagSet("node enrol", true)
	if fs.Lookup("allow") != nil || fs.Lookup("no-self-update") != nil {
		t.Fatal("enrol takes probing flags")
	}
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if c, err = nodeClient(f); err != nil || c.NoUpdate || c.Allow != nil {
		t.Fatalf("enrol client: %+v %v", c, err)
	}
}

func TestNodeClientRefusals(t *testing.T) {
	for _, args := range [][]string{
		{"-server", "http://lab:8080"},
		{"-server", "tlswatch.example.nl"},
		{"-server", ""},
		{"-server", "https://tlswatch.example.nl", "-workers", "0"},
		{"-server", "https://tlswatch.example.nl", "-workers", "65"},
		{"-server", "https://tlswatch.example.nl", "-allow", "10.0.0.0/33"},
	} {
		t.Setenv("TLSWATCH_NODE_SERVER", "")
		fs, f := nodeFlagSet("node", false)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		if _, err := nodeClient(f); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
}

func TestNodeCmdNotEnrolledWithoutToken(t *testing.T) {
	t.Setenv("TLSWATCH_NODE_TOKEN", "")
	err := nodeCmd([]string{"-server", "https://tlswatch.example.nl", "-data", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("node without a credential or token: %v", err)
	}
}

func TestNodeUninstallSubcommandNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("would remove the real installation")
	}
	if err := nodeCmd([]string{"uninstall"}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("uninstall without root: %v", err)
	}
}

// fakeAgent answers enrolment and, once polled, interrupts the process as
// systemd's stop would.
func fakeAgent(t *testing.T, interrupt bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var polls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc(node.Prefix+"/enrol", func(w http.ResponseWriter, r *http.Request) {
		var req node.EnrolRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Token != "good" {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "the install token is unknown, spent or expired"})
			return
		}
		_ = json.NewEncoder(w).Encode(node.EnrolResponse{NodeID: 7, Credential: "secret-cred", ServerVersion: "v1.2.0"})
	})
	mux.HandleFunc(node.Prefix+"/facts", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc(node.Prefix+"/jobs", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-cred" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if polls.Add(1) == 1 && interrupt {
			_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
		}
		_ = json.NewEncoder(w).Encode(node.PollResponse{ServerVersion: "v1.2.0"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &polls
}

func TestNodeEnrolCommand(t *testing.T) {
	srv, _ := fakeAgent(t, false)
	data := filepath.Join(t.TempDir(), "node")
	if err := nodeEnrol([]string{"-server", srv.URL, "-data", data}); err == nil || !strings.Contains(err.Error(), "-token") {
		t.Fatalf("enrol without a token: %v", err)
	}
	if err := nodeEnrol([]string{"-server", srv.URL, "-token", "good", "-data", data}); err == nil {
		t.Fatal("enrolled with a plain-http server without -insecure")
	}
	if err := nodeEnrol([]string{"-server", srv.URL, "-token", "bad", "-data", data, "-insecure"}); err == nil || !strings.Contains(err.Error(), "spent or expired") {
		t.Fatalf("spent token: %v", err)
	}
	if err := nodeEnrol([]string{"-server", srv.URL, "-token", "good", "-data", data, "-insecure"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(node.CredentialFile(data))
	fi, _ := os.Stat(node.CredentialFile(data))
	if err != nil || strings.TrimSpace(string(b)) != "secret-cred" || fi.Mode().Perm() != 0o600 {
		t.Fatalf("credential file: %q %v", b, err)
	}
}

// The Docker command: no credential yet, a token in the environment; the
// node enrols at first start, polls, and stops cleanly on SIGINT.
func TestNodeCmdEnrolsAtFirstStartAndStops(t *testing.T) {
	srv, polls := fakeAgent(t, true)
	data := t.TempDir()
	t.Setenv("TLSWATCH_NODE_TOKEN", "good")
	t.Setenv("TLSWATCH_NODE_SERVER", srv.URL)
	t.Setenv("TLSWATCH_NODE_DATA", data)
	done := make(chan error, 1)
	go func() { done <- nodeCmd([]string{"-insecure"}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the node did not stop on SIGINT")
	}
	if polls.Load() == 0 {
		t.Fatal("the node never polled")
	}
	if b, _ := os.ReadFile(node.CredentialFile(data)); strings.TrimSpace(string(b)) != "secret-cred" {
		t.Fatalf("credential: %q", b)
	}
}

func TestEnrolWithRetryStopsWithContext(t *testing.T) {
	c := &node.Client{Server: "http://127.0.0.1:1", Data: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := enrolWithRetry(ctx, c, "tok"); err == nil {
		t.Fatal("enrolled with a cancelled context")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("retried after the context ended")
	}
}

// TestMainProcess runs main in a child process for the exit-code tests.
func TestMainProcess(t *testing.T) {
	args := os.Getenv("TLSWATCH_TEST_MAIN")
	if args == "" {
		t.Skip("helper process")
	}
	os.Args = append([]string{"tlswatch"}, strings.Split(args, "\x1f")...)
	if args == "<none>" {
		os.Args = os.Args[:1]
	}
	main()
	os.Exit(0)
}

func runMain(t *testing.T, env []string, args ...string) (int, string, string) {
	t.Helper()
	joined := strings.Join(args, "\x1f")
	if len(args) == 0 {
		joined = "<none>"
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainProcess$")
	cmd.Env = append(append(os.Environ(), "TLSWATCH_TEST_MAIN="+joined), env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String(), errOut.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), out.String(), errOut.String()
	}
	t.Fatal(err)
	return 0, "", ""
}

func TestMainExitCodes(t *testing.T) {
	if testing.Short() {
		t.Skip("runs child processes")
	}
	dir := t.TempDir()
	env := []string{"TLSWATCH_DB=" + filepath.Join(dir, "tlswatch.db"), "TLSWATCH_LISTEN=127.0.0.1:1", "TLSWATCH_NODE_SERVER=", "TLSWATCH_NODE_TOKEN="}
	for _, tc := range []struct {
		args []string
		code int
		out  string
	}{
		{nil, 2, ""},
		{[]string{"bogus"}, 2, ""},
		{[]string{"version"}, 0, "tlswatch "},
		{[]string{"--version"}, 0, "tlswatch "},
		{[]string{"help"}, 0, "tlswatch check HOST"},
		{[]string{"check"}, 2, ""},
		{[]string{"check", "a.example", "b.example"}, 2, ""},
		{[]string{"node", "-server", "https://tlswatch.example.nl", "-workers", "0"}, 1, ""},
		{[]string{"node", "-no-such-flag"}, 2, ""},
		{[]string{"node", "enrol", "-server", "https://tlswatch.example.nl"}, 1, ""},
		{[]string{"backup"}, 1, ""},
		{[]string{"create-admin"}, 1, ""},
		{[]string{"healthcheck"}, 1, ""},
		{[]string{"migrate"}, 0, "schema version"},
	} {
		code, out, stderr := runMain(t, env, tc.args...)
		if code != tc.code || !strings.Contains(out, tc.out) {
			t.Errorf("tlswatch %q: exit %d, want %d; stdout %q stderr %q", tc.args, code, tc.code, out, stderr)
		}
	}
}

// keyGuard refuses a missing key file next to a database that holds
// something sealed under it, unless TLSWATCH_ACCEPT_NEW_KEY says so.
func TestKeyGuardRefusesMissingKeyWithSealedData(t *testing.T) {
	dir := t.TempDir()
	d, err := db.Open(filepath.Join(dir, "tlswatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keyFile := filepath.Join(dir, "secret.key")
	if err := keyGuard(d, keyFile, log); err != nil {
		t.Fatalf("first start: %v", err)
	}
	key, _ := secret.New(make([]byte, 32))
	svc := &core.Service{DB: d, Key: key, Settings: config.NewStore(d, key), Log: log}
	if _, _, err := svc.CreateNode(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	if err := keyGuard(d, keyFile, log); err == nil || !strings.Contains(err.Error(), "TLSWATCH_ACCEPT_NEW_KEY") {
		t.Fatalf("missing key with a sealed install token: %v", err)
	}
	t.Setenv("TLSWATCH_ACCEPT_NEW_KEY", "true")
	if err := keyGuard(d, keyFile, log); err != nil {
		t.Fatalf("accepted new key: %v", err)
	}
	t.Setenv("TLSWATCH_ACCEPT_NEW_KEY", "")
	if err := os.WriteFile(keyFile, make([]byte, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := keyGuard(d, keyFile, log); err != nil {
		t.Fatalf("key file present: %v", err)
	}
}

// backup, rotate-key and create-admin on a database made by open().
func TestBackupRotateKeyAndCreateAdmin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TLSWATCH_DB", filepath.Join(dir, "tlswatch.db"))
	t.Setenv("TLSWATCH_SECRET_KEY_FILE", "")
	t.Setenv("TLSWATCH_LISTEN", "127.0.0.1:1")
	t.Setenv("TLSWATCH_LOG_JSON", "false")
	a, err := open()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.core.CreateNode(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	a.db.Close()
	keyFile := filepath.Join(dir, "secret.key")
	oldKey, err := os.ReadFile(keyFile)
	if err != nil || len(oldKey) == 0 {
		t.Fatalf("no secret key generated: %v", err)
	}

	if err := backup([]string{filepath.Join(dir, "copy.db")}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "copy.db")); err != nil || fi.Size() == 0 {
		t.Fatalf("backup: %v", err)
	}
	if err := backup(nil); err == nil {
		t.Fatal("backup without a path")
	}

	if err := rotateKey(); err != nil {
		t.Fatal(err)
	}
	newKey, _ := os.ReadFile(keyFile)
	if bytes.Equal(newKey, oldKey) {
		t.Fatal("key not rotated")
	}
	kept, _ := filepath.Glob(keyFile + ".old-*")
	if len(kept) != 1 {
		t.Fatalf("old key not kept: %v", kept)
	}
	// The install token is still readable under the new key.
	a, err = open()
	if err != nil {
		t.Fatal(err)
	}
	nodes, _ := a.core.Nodes(context.Background())
	if len(nodes) != 1 {
		t.Fatalf("nodes: %+v", nodes)
	}
	if tok, err := a.core.NodeToken(context.Background(), nodes[0].ID); err != nil || tok == "" {
		t.Fatalf("install token after rotation: %q %v", tok, err)
	}
	a.db.Close()

	out := filepath.Join(dir, "link")
	if err := createAdmin([]string{"-email", "admin@example.org", "-out", out}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("link file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(out); !strings.Contains(string(b), "/invite?token=") {
		t.Fatalf("link: %q", b)
	}
	if err := createAdmin([]string{"-email", "admin@example.org"}); err == nil {
		t.Fatal("the same admin was created twice")
	}
}

func TestHealthcheck(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, `{"db":"ok"}`)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	t.Setenv("TLSWATCH_LISTEN", "0.0.0.0:"+port)
	if err := healthcheck(); err != nil {
		t.Fatalf("healthy: %v", err)
	}
	status.Store(http.StatusServiceUnavailable)
	if err := healthcheck(); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("unhealthy: %v", err)
	}
	// rotate-key refuses while a server answers.
	status.Store(http.StatusOK)
	if err := rotateKey(); err == nil || !strings.Contains(err.Error(), "running") {
		t.Fatalf("rotate-key while running: %v", err)
	}
}

func TestLinkBaseAndDevAssets(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TLSWATCH_DB", filepath.Join(dir, "tlswatch.db"))
	t.Setenv("TLSWATCH_SECRET_KEY_FILE", "")
	t.Setenv("TLSWATCH_LISTEN", "0.0.0.0:9090")
	a, err := open()
	if err != nil {
		t.Fatal(err)
	}
	defer a.db.Close()
	if got := a.linkBase(context.Background()); got != "http://localhost:9090" {
		t.Fatalf("link base without a base URL: %s", got)
	}
	if err := a.settings.SaveGeneral(context.Background(), config.General{BaseURL: "https://tlswatch.example.nl"}); err != nil {
		t.Fatal(err)
	}
	if got := a.linkBase(context.Background()); got != "https://tlswatch.example.nl" {
		t.Fatalf("link base: %s", got)
	}
	old := version
	defer func() { version = old }()
	for v, want := range map[string]bool{"dev": true, "0123456789ab-dirty": true, "v1.2.0": false, "0123456789ab": false} {
		version = v
		if devAssets() != want {
			t.Errorf("devAssets(%q) = %v", v, !want)
		}
	}
}

// Node variables read as the server's do, and one that does not parse
// stops the node instead of being ignored: TLSWATCH_NODE_NO_UPDATE=1 is a
// security setting.
func TestNodeEnvironmentValues(t *testing.T) {
	t.Setenv("TLSWATCH_NODE_SERVER", "https://tlswatch.example.nl")
	t.Setenv("TLSWATCH_NODE_NO_UPDATE", "1")
	t.Setenv("TLSWATCH_NODE_ALLOW_LOCAL", "yes")
	fs, f := nodeFlagSet("node", false)
	if err := parseNodeFlags(fs, nil); err != nil {
		t.Fatal(err)
	}
	if c, err := nodeClient(f); err != nil || !c.NoUpdate || !c.AllowLocal {
		t.Fatalf("1 and yes: %+v %v", c, err)
	}
	for k, v := range map[string]string{"TLSWATCH_NODE_WORKERS": "abc", "TLSWATCH_NODE_NO_UPDATE": "maybe", "TLSWATCH_LOG_JSON": "garbage"} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			fs, f := nodeFlagSet("node", false)
			_ = parseNodeFlags(fs, nil)
			if _, err := nodeClient(f); err == nil || !strings.Contains(err.Error(), k) {
				t.Fatalf("%s=%s: %v", k, v, err)
			}
		})
	}
	fs, _ = nodeFlagSet("node", false)
	if err := parseNodeFlags(fs, []string{"-server", "https://tlswatch.example.nl", "enrol", "-token", "T"}); err == nil || !strings.Contains(err.Error(), `"enrol"`) {
		t.Fatalf("stray argument: %v", err)
	}
}

func TestCheckHelpExitsZero(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := checkCmd([]string{"-h"}, &out, &errOut); code != 0 || !strings.Contains(errOut.String(), "-servername") {
		t.Fatalf("check -h: exit %d, %q", code, errOut.String())
	}
	if code := checkCmd([]string{"-bogus"}, &out, &errOut); code != 2 {
		t.Fatalf("unknown flag: exit %d", code)
	}
}
