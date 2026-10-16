// Command tlswatch monitors the TLS certificates served on a list of
// endpoints and alerts before they expire or when they change.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata" // time zones in the scratch Docker image

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/node"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/sched"
	"github.com/sjoerd305/tlswatch/internal/secret"
	"github.com/sjoerd305/tlswatch/internal/web"
)

// version is set at build time with -ldflags "-X main.version=v0.1.0";
// without it, init takes the VCS revision Go recorded in the binary.
var version = "dev"

func init() {
	if version != "dev" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	var rev string
	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if len(rev) >= 12 {
		version = rev[:12]
		if modified {
			version += "-dirty"
		}
	}
}

// devAssets reports a build whose embedded files may change without the
// version changing, so the browser must not cache them for good.
func devAssets() bool { return version == "dev" || strings.HasSuffix(version, "-dirty") }

const usage = `tlswatch monitors the TLS certificates served on your endpoints.

Usage:
  tlswatch serve                       run the web UI, scheduler and alerting
  tlswatch create-admin -email ADDR    create an admin and print a one-time password link
  tlswatch migrate                     apply database migrations (also done at start)
  tlswatch backup PATH                 write a consistent copy of the database
  tlswatch healthcheck                 exit 0 when the running server's /healthz is OK
  tlswatch rotate-key                  re-encrypt stored credentials under a new secret key
                                       (stop the server first)
  tlswatch check HOST[:PORT] [flags]   probe one endpoint, print JSON, exit 0/1/2 by severity
  tlswatch node [flags]                run as a probe node inside another network
                                       (tlswatch node -h for enrol, uninstall and flags)
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
	case "rotate-key":
		err = rotateKey()
	case "check":
		os.Exit(checkCmd(args, os.Stdout, os.Stderr))
	case "node":
		err = nodeCmd(args)
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
	nodes    *node.Dispatcher
}

// keyGuard refuses to make a new secret key for a database that holds
// credentials sealed under one: a missing key file next to such a database
// is a mis-mounted volume, not a first start, and a new key would leave
// every stored credential unreadable while new ones are sealed under it.
// TLSWATCH_ACCEPT_NEW_KEY=true starts anyway, for when the key is really
// lost. It also warns when the key file is readable by others.
func keyGuard(d *db.DB, path string, log *slog.Logger) error {
	fi, err := os.Stat(path)
	if err == nil {
		if m := fi.Mode().Perm(); m&0o077 != 0 {
			log.Warn("the secret key file is readable by other users; make it mode 0600", "file", path, "mode", fmt.Sprintf("%04o", m))
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("secret key: %w", err)
	}
	sealed, err := hasSealed(context.Background(), d)
	if err != nil {
		return err
	}
	if !sealed {
		return nil
	}
	if os.Getenv("TLSWATCH_ACCEPT_NEW_KEY") == "true" {
		log.Error("the secret key file is missing while the database holds credentials sealed under it; starting with a new key as TLSWATCH_ACCEPT_NEW_KEY says, every stored credential must be entered again", "file", path)
		return nil
	}
	return fmt.Errorf("the secret key file %s is missing, but the database holds credentials sealed under it: restore the key file (is the volume mounted?), or set TLSWATCH_ACCEPT_NEW_KEY=true to start with a new key and enter every stored credential again", path)
}

// hasSealed reports whether the database holds anything sealed under the
// secret key: a channel, a sealed setting or a node install token.
func hasSealed(ctx context.Context, d *db.DB) (bool, error) {
	var channels, tokens int
	if err := d.R.QueryRowContext(ctx, "SELECT COUNT(*) FROM channels").Scan(&channels); err != nil {
		return false, err
	}
	if err := d.R.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes WHERE token_sealed IS NOT NULL").Scan(&tokens); err != nil {
		return false, err
	}
	if channels > 0 || tokens > 0 {
		return true, nil
	}
	return config.HasSealed(ctx, d)
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
	if err := keyGuard(d, b.SecretKeyFile, a.log); err != nil {
		d.Close()
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
	a.core = &core.Service{DB: d, Settings: a.settings, Channels: a.channels, Dispatcher: a.dispatch, Key: key, Log: a.log}
	a.dispatch.Link = func(ctx context.Context) string {
		st, _ := a.settings.Get(ctx)
		if st.General.BaseURL == "" {
			return ""
		}
		return st.General.BaseURL + "/findings"
	}
	a.sched = &sched.Scheduler{Core: a.core, Log: a.log, PruneSessions: a.auth.PruneSessions}
	a.nodes = &node.Dispatcher{Core: a.core, Version: version, Log: a.log, OnOnline: a.sched.NodeOnline}
	a.sched.Nodes = a.nodes
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

	srv := &web.Server{Core: a.core, Sched: a.sched, Nodes: a.nodes, Auth: a.auth, Settings: a.settings, Dispatch: a.dispatch, Key: a.key,
		Log: a.log, Version: version, DevAssets: devAssets(), Listen: a.boot.Listen}
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
	bg.Add(3)
	go func() { defer bg.Done(); a.sched.Run(ctx) }()
	go func() { defer bg.Done(); a.dispatch.Run(ctx) }()
	go func() { defer bg.Done(); a.nodes.Run(ctx) }()
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

// rotateKey replaces the secret key: the stored credentials are re-sealed
// under a new key in one transaction, then the key file is swapped and the
// old one kept next to it. A running server would keep using the old key,
// so it refuses while one answers on TLSWATCH_LISTEN.
func rotateKey() error {
	if healthcheck() == nil {
		return errors.New("tlswatch is running on TLSWATCH_LISTEN; stop it before rotating the key")
	}
	b := config.LoadBootstrap()
	if _, err := os.Stat(b.SecretKeyFile); err != nil {
		return fmt.Errorf("no secret key to rotate: %w", err)
	}
	old, _, err := secret.LoadOrCreate(b.SecretKeyFile)
	if err != nil {
		return err
	}
	next, raw, err := secret.Generate()
	if err != nil {
		return err
	}
	d, err := db.OpenExisting(b.DBPath)
	if err != nil {
		return err
	}
	defer d.Close()
	ctx := context.Background()
	tx, err := d.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	n, unreadable, err := notify.Reencrypt(ctx, tx, old, next)
	if err != nil {
		return err
	}
	settings, unreadableSettings, err := config.Reencrypt(ctx, tx, old, next)
	if err != nil {
		return err
	}
	unreadable = append(unreadable, unreadableSettings...)
	tokens, err := core.ReencryptNodeTokens(ctx, tx, old, next)
	if err != nil {
		return err
	}
	// The new key is on disk before the database depends on it.
	pending := b.SecretKeyFile + ".new"
	if err := secret.WriteFile(pending, raw); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		_ = os.Remove(pending)
		return err
	}
	kept := b.SecretKeyFile + ".old-" + time.Now().UTC().Format("20060102T150405Z")
	if err := os.Rename(b.SecretKeyFile, kept); err != nil {
		return fmt.Errorf("the database now uses the key in %s; move it to %s by hand: %w", pending, b.SecretKeyFile, err)
	}
	if err := os.Rename(pending, b.SecretKeyFile); err != nil {
		return fmt.Errorf("the database now uses the key in %s; move it to %s by hand: %w", pending, b.SecretKeyFile, err)
	}
	fmt.Printf("secret key rotated: %d channel(s), %d sealed setting(s) and %d node install token(s) re-encrypted", n, settings, tokens)
	fmt.Printf(".\nThe old key is kept in %s; delete it once backups made with it have expired.\n", kept)
	if len(unreadable) > 0 {
		fmt.Printf("Not re-encrypted, the old key could not read them either: %s. Enter their credentials again.\n", strings.Join(unreadable, ", "))
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

// checkResult is the JSON printed by the check subcommand.
