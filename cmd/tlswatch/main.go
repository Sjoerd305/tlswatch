// Command tlswatch monitors the TLS certificates served on a list of
// endpoints and alerts before they expire or when they change.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata" // time zones in the scratch Docker image

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/sched"
	"github.com/sjoerd305/tlswatch/internal/secret"
	"github.com/sjoerd305/tlswatch/internal/web"
)

// version is set at build time with -ldflags "-X main.version=v0.1.0".
var version = "dev"

const usage = `tlswatch monitors the TLS certificates served on your endpoints.

Usage:
  tlswatch serve                       run the web UI, scheduler and alerting
  tlswatch create-admin -email ADDR    create an admin and print a one-time password link
  tlswatch migrate                     apply database migrations (also done at start)
  tlswatch backup PATH                 write a consistent copy of the database
  tlswatch healthcheck                 exit 0 when the running server's /healthz is OK
  tlswatch check HOST[:PORT] [flags]   probe one endpoint, print JSON, exit 0/1/2 by severity
  tlswatch seed                        add a few public demo targets
  tlswatch version                     print the version

Configuration is done in the web UI. Optional environment variables:
  TLSWATCH_LISTEN (127.0.0.1:8080), TLSWATCH_DB (./data/tlswatch.db),
  TLSWATCH_SECRET_KEY_FILE (next to the database, generated if missing),
  TLSWATCH_LOG_JSON (true), TLSWATCH_DEBUG (false: debug logging);
  overrides for UI settings are listed in docs/.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "create-admin":
		err = createAdmin(args)
	case "migrate":
		err = migrate()
	case "backup":
		err = backup(args)
	case "healthcheck":
		err = healthcheck()
	case "check":
		os.Exit(checkCmd(args, os.Stdout, os.Stderr))
	case "seed":
		err = seed()
	case "version", "-version", "--version":
		fmt.Println("tlswatch", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tlswatch:", err)
		os.Exit(1)
	}
}

func logger(b config.Bootstrap) *slog.Logger {
	level := slog.LevelInfo
	if os.Getenv("TLSWATCH_DEBUG") == "true" {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	if b.LogJSON {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

type app struct {
	boot     config.Bootstrap
	log      *slog.Logger
	db       *db.DB
	key      *secret.Key
	settings *config.Store
	auth     *auth.Service
	channels *notify.Channels
	dispatch *notify.Dispatcher
	core     *core.Service
	sched    *sched.Scheduler
}

func open() (*app, error) {
	if err := config.CheckEnv(); err != nil {
		return nil, fmt.Errorf("invalid environment: %w", err)
	}
	b := config.LoadBootstrap()
	a := &app{boot: b, log: logger(b)}
	d, err := db.Open(b.DBPath)
	if err != nil {
		return nil, err
	}
	key, created, err := secret.LoadOrCreate(b.SecretKeyFile)
	if err != nil {
		d.Close()
		return nil, err
	}
	if created {
		a.log.Info("generated a new secret key; keep it with the database backups", "file", b.SecretKeyFile)
	}
	a.db, a.key = d, key
	a.settings = config.NewStore(d, key)
	a.auth = auth.New(d, key)
	a.channels = &notify.Channels{DB: d, Key: key}
	a.dispatch = &notify.Dispatcher{DB: d, Channels: a.channels, Log: a.log}
	a.core = &core.Service{DB: d, Settings: a.settings, Channels: a.channels, Dispatcher: a.dispatch, Log: a.log}
	a.dispatch.Link = func(ctx context.Context) string {
		st, _ := a.settings.Get(ctx)
		if st.General.BaseURL == "" {
			return ""
		}
		return st.General.BaseURL + "/findings"
	}
	a.sched = &sched.Scheduler{Core: a.core, Log: a.log, PruneSessions: a.auth.PruneSessions}
	return a, nil
}

func (a *app) linkBase(ctx context.Context) string {
	st, _ := a.settings.Get(ctx)
	if st.General.BaseURL != "" {
		return st.General.BaseURL
	}
	host, port, err := net.SplitHostPort(a.boot.Listen)
	if err != nil {
		return "http://" + a.boot.Listen
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := open()
	if err != nil {
		return err
	}
	defer a.db.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if n, err := a.auth.CountUsers(ctx); err == nil && n == 0 {
		link := a.linkBase(ctx) + "/setup"
		a.log.Info("no accounts yet: open tlswatch in a browser to create the first admin", "url", link)
		fmt.Fprintf(os.Stderr, "\n  Set up tlswatch: %s\n\n", link)
	}

	srv := &web.Server{Core: a.core, Sched: a.sched, Auth: a.auth, Settings: a.settings, Dispatch: a.dispatch,
		Log: a.log, Version: version, Listen: a.boot.Listen}
	h, err := srv.Handler()
	if err != nil {
		return err
	}
	hs := &http.Server{Addr: a.boot.Listen, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second,
		WriteTimeout: 150 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	ln, err := net.Listen("tcp", a.boot.Listen)
	if err != nil {
		return err
	}
	var bg sync.WaitGroup
	bg.Add(2)
	go func() { defer bg.Done(); a.sched.Run(ctx) }()
	go func() { defer bg.Done(); a.dispatch.Run(ctx) }()
	a.log.Info("tlswatch listening", "addr", ln.Addr().String(), "version", version, "db", a.boot.DBPath)
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	a.log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = hs.Shutdown(sctx)
	// Let running checks and deliveries finish before the database closes.
	done := make(chan struct{})
	go func() { bg.Wait(); close(done) }()
	select {
	case <-done:
	case <-sctx.Done():
		a.log.Warn("shutdown: checks or deliveries still running; closing anyway")
	}
	return err
}

func createAdmin(args []string) error {
	fs := flag.NewFlagSet("create-admin", flag.ExitOnError)
	email := fs.String("email", "", "e-mail address of the admin")
	name := fs.String("name", "", "display name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return errors.New("-email is required")
	}
	a, err := open()
	if err != nil {
		return err
	}
	defer a.db.Close()
	ctx := context.Background()
	u, err := a.auth.CreateUser(ctx, *email, *name, authz.Admin, auth.MethodLocal)
	if err != nil {
		return err
	}
	tok, err := a.auth.CreateToken(ctx, auth.TokenInvite, u.ID, auth.InviteTTL)
	if err != nil {
		return err
	}
	a.core.Audit(ctx, "cli", "user.create", "user "+u.Email, "role=admin via create-admin")
	fmt.Printf("Admin %s created. Set the password within 7 days:\n\n  %s/invite?token=%s\n\n", u.Email, a.linkBase(ctx), tok)
	return nil
}

func migrate() error {
	b := config.LoadBootstrap()
	d, err := db.Open(b.DBPath)
	if err != nil {
		return err
	}
	defer d.Close()
	fmt.Printf("database %s is at schema version %d\n", b.DBPath, db.SchemaVersion())
	return nil
}

// healthcheck asks the server on TLSWATCH_LISTEN for /healthz, for the
// container's HEALTHCHECK (the image has no curl).
func healthcheck() error {
	b := config.LoadBootstrap()
	host, port, err := net.SplitHostPort(b.Listen)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy (%s): %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func backup(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tlswatch backup PATH")
	}
	b := config.LoadBootstrap()
	d, err := db.OpenExisting(b.DBPath)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Backup(context.Background(), args[0]); err != nil {
		return err
	}
	fmt.Printf("backup written to %s (the secret key file %s is needed to read stored credentials)\n", args[0], b.SecretKeyFile)
	return nil
}

func seed() error {
	a, err := open()
	if err != nil {
		return err
	}
	defer a.db.Close()
	ctx := context.Background()
	demo := []core.Target{
		{Name: "Let's Encrypt site", Host: "letsencrypt.org", Tags: []string{"demo"}},
		{Name: "Expired", Host: "expired.badssl.com", Tags: []string{"demo", "badssl"}},
		{Name: "Self-signed", Host: "self-signed.badssl.com", Tags: []string{"demo", "badssl"}},
		{Name: "Wrong host", Host: "wrong.host.badssl.com", Tags: []string{"demo", "badssl"}},
		{Name: "Untrusted root", Host: "untrusted-root.badssl.com", Tags: []string{"demo", "badssl"}},
		{Name: "Gmail SMTP", Host: "smtp.gmail.com", Port: 587, Protocol: probe.SMTP, Tags: []string{"demo", "mail"}},
	}
	st, _ := a.settings.Get(ctx)
	added := 0
	for _, t := range demo {
		if t.Protocol == "" {
			t.Protocol = probe.TLS
		}
		if t.Port == 0 {
			t.Port = probe.DefaultPort(t.Protocol)
		}
		if t.Trust == "" {
			t.Trust = probe.TrustSystem
		}
		t.ServerName, t.AllAddresses, t.AllChannels, t.Enabled = t.Host, true, true, true
		if errs := t.Validate(st); len(errs) > 0 {
			return fmt.Errorf("%s: %v", t.Host, errs)
		}
		if _, err := a.core.SaveTarget(ctx, t, "seed"); err != nil {
			if strings.Contains(err.Error(), "already exists") {
				continue
			}
			return err
		}
		added++
	}
	fmt.Printf("%d demo targets added; they are checked when the server runs.\n", added)
	return nil
}

// checkResult is the JSON printed by the check subcommand.
type checkResult struct {
	Target     string         `json:"target"`
	Protocol   string         `json:"protocol"`
	ServerName string         `json:"servername,omitempty"`
	Status     string         `json:"status"`
	DaysLeft   *int           `json:"days_left,omitempty"`
	NotAfter   string         `json:"not_after,omitempty"`
	Subject    string         `json:"subject,omitempty"`
	Issuer     string         `json:"issuer,omitempty"`
	SANs       []string       `json:"sans,omitempty"`
	SHA256     string         `json:"sha256,omitempty"`
	Addresses  []checkAddress `json:"addresses"`
	Findings   []checkFinding `json:"findings"`
	DNSError   string         `json:"dns_error,omitempty"`
}

type checkAddress struct {
	Address    string `json:"address"`
	OK         bool   `json:"ok"`
	TLSVersion string `json:"tls_version,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Verified   bool   `json:"verified"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

type checkFinding struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Details  string `json:"details"`
}

// reorder moves flags before positional arguments so "check host -protocol
// smtp" works with the flag package.
func reorder(args []string, valued map[string]bool) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if valued[name] && !strings.Contains(a, "=") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

func checkCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	protocol := fs.String("protocol", "tls", "tls, smtp, imap, pop3, ftp or postgres")
	servername := fs.String("servername", "", "server name for SNI and verification (default: the host when it is a DNS name)")
	caFile := fs.String("ca-file", "", "PEM bundle to verify against instead of the system store")
	insecure := fs.Bool("insecure", false, "do not verify the chain (self-signed endpoints)")
	warn := fs.Int("warn", 30, "warning threshold in days")
	crit := fs.Int("crit", 7, "critical threshold in days")
	timeout := fs.Duration("timeout", 10*time.Second, "connect and handshake timeout")
	first := fs.Bool("first", false, "probe only the first resolved address")
	allowLocal := fs.Bool("allow-local", true, "allow loopback and link-local addresses")
	if err := fs.Parse(reorder(args, map[string]bool{"protocol": true, "servername": true, "ca-file": true, "warn": true, "crit": true, "timeout": true})); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: tlswatch check HOST[:PORT] [-protocol P] [-servername N] [-ca-file F] [-insecure]")
		return 2
	}
	proto, err := probe.ParseProtocol(*protocol)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	host, port := fs.Arg(0), probe.DefaultPort(proto)
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			fmt.Fprintln(stderr, "invalid port", p)
			return 2
		}
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if err := probe.ValidateHost(host); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	sni := *servername
	if sni == "" && net.ParseIP(host) == nil {
		sni = host
	}
	req := probe.Request{Host: host, Port: port, Protocol: proto, ServerName: sni, Trust: probe.TrustSystem,
		Timeout: *timeout, Retries: 1, FirstOnly: *first, AllowLocal: *allowLocal}
	if *insecure {
		req.Trust = probe.TrustSelfSigned
	}
	if *caFile != "" {
		b, err := os.ReadFile(*caFile)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		certs, err := core.ParseBundle(string(b))
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		pool := x509.NewCertPool()
		for _, c := range certs {
			pool.AddCert(c)
		}
		req.Trust, req.Roots = probe.TrustBundle, pool
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	r := probe.Probe(ctx, req)
	th := check.Thresholds{Warn: *warn, Crit: *crit}
	out := check.Evaluate(check.Target{Trust: req.Trust, ServerName: sni, Warn: warn, Crit: crit, Manual: th, Managed: th, RenewalSet: true, Debounce: 1},
		check.Previous{Open: map[check.Kind]bool{}}, r, time.Now())

	res := checkResult{Target: net.JoinHostPort(host, strconv.Itoa(port)), Protocol: string(proto), ServerName: sni, DNSError: r.DNSError,
		Addresses: []checkAddress{}, Findings: []checkFinding{}}
	for _, a := range r.Addresses {
		ca := checkAddress{Address: a.IP, OK: a.OK, TLSVersion: a.TLSVersion, Cipher: a.Cipher, Verified: a.Verified, Error: a.Error, DurationMS: a.Duration.Milliseconds()}
		if a.OK {
			ca.SHA256 = probe.Fingerprint(a.Chain[0])
		}
		res.Addresses = append(res.Addresses, ca)
	}
	if out.Leaf != nil {
		ci := probe.Describe(out.Leaf)
		d := check.DaysLeft(out.NotAfter, time.Now())
		res.DaysLeft, res.NotAfter = &d, out.NotAfter.UTC().Format(time.RFC3339)
		res.Subject, res.Issuer, res.SANs, res.SHA256 = ci.SubjectCN, ci.IssuerCN, ci.SANs, ci.Fingerprint
	}
	worst := 0
	for _, f := range out.Open {
		res.Findings = append(res.Findings, checkFinding{Kind: string(f.Kind), Severity: string(f.Severity), Details: f.Details})
		if f.Severity.Rank() > worst {
			worst = f.Severity.Rank()
		}
	}
	code := 0
	res.Status = "ok"
	switch {
	case worst >= check.Critical.Rank():
		res.Status, code = "critical", 2
	case worst >= check.Warning.Rank():
		res.Status, code = "warning", 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
	return code
}
