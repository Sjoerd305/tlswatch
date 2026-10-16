package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/node"
)

const nodeUsage = `tlswatch node runs this machine as a probe node of a tlswatch server.

Usage:
  tlswatch node [flags]                         poll the server and run its probes
  tlswatch node enrol -server URL -token TOKEN  exchange an install token for the credential
  tlswatch node uninstall                       remove what the install script put in place

Flags, each also read from the environment (the systemd unit reads
/etc/tlswatch-node.env):
`

// nodeDefaults are the node's flags with their environment variables.
type nodeFlags struct {
	server, data, allow, token *string
	workers                    *int
	allowLocal, insecure       *bool
	noUpdate, allowUnsigned    *bool
}

func nodeFlagSet(name string, enrol bool) (*flag.FlagSet, nodeFlags) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), nodeUsage)
		fs.PrintDefaults()
	}
	data := node.InstallData
	if node.InContainer() {
		data = "/data"
	}
	f := nodeFlags{
		server:  fs.String("server", os.Getenv("TLSWATCH_NODE_SERVER"), "the server's public URL (TLSWATCH_NODE_SERVER)"),
		data:    fs.String("data", envOr("TLSWATCH_NODE_DATA", data), "directory of the credential file (TLSWATCH_NODE_DATA)"),
		workers: fs.Int("workers", envInt("TLSWATCH_NODE_WORKERS", 4), "probes at once (TLSWATCH_NODE_WORKERS)"),
		token:   fs.String("token", os.Getenv("TLSWATCH_NODE_TOKEN"), "install token; without a credential the node enrols with it first (TLSWATCH_NODE_TOKEN)"),
	}
	if !enrol {
		f.allow = fs.String("allow", os.Getenv("TLSWATCH_NODE_ALLOW"), "CIDRs this node may probe, comma separated; empty means any (TLSWATCH_NODE_ALLOW)")
		f.allowLocal = fs.Bool("allow-local", os.Getenv("TLSWATCH_NODE_ALLOW_LOCAL") == "true", "allow loopback and link-local addresses (TLSWATCH_NODE_ALLOW_LOCAL)")
	}
	f.insecure = fs.Bool("insecure", false, "accept a plain http:// server, for a lab; the node then never replaces its binary from it")
	if !enrol {
		f.noUpdate = fs.Bool("no-self-update", os.Getenv("TLSWATCH_NODE_NO_UPDATE") == "true", "never replace the binary, whatever the server says (TLSWATCH_NODE_NO_UPDATE)")
		f.allowUnsigned = fs.Bool("allow-unsigned-update", os.Getenv("TLSWATCH_NODE_ALLOW_UNSIGNED_UPDATE") == "true", "also follow a development build of the server, which has no signed checksums (TLSWATCH_NODE_ALLOW_UNSIGNED_UPDATE)")
	}
	return fs, f
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return n
	}
	return def
}

func nodeClient(f nodeFlags) (*node.Client, error) {
	server, err := node.CheckServer(*f.server, *f.insecure)
	if err != nil {
		return nil, err
	}
	if *f.workers < 1 || *f.workers > 64 {
		return nil, errors.New("-workers must be 1 to 64")
	}
	c := &node.Client{Server: server, Data: *f.data, Workers: *f.workers, Version: version, Container: node.InContainer(), Insecure: *f.insecure,
		Log: logger(config.Bootstrap{LogJSON: envOr("TLSWATCH_LOG_JSON", "true") == "true"})}
	if f.allow != nil {
		if c.Allow, err = node.ParseAllow(*f.allow); err != nil {
			return nil, fmt.Errorf("-allow: %w", err)
		}
		c.AllowLocal = *f.allowLocal
		c.NoUpdate, c.AllowUnsigned = *f.noUpdate, *f.allowUnsigned
	}
	return c, nil
}

func nodeCmd(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "enrol", "enroll":
			return nodeEnrol(args[1:])
		case "uninstall":
			return node.Uninstall(func(s string) { fmt.Println(s) })
		}
	}
	fs, f := nodeFlagSet("node", false)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := nodeClient(f)
	if err != nil {
		return err
	}
	// The path to start again after a self-update, resolved before the
	// binary is replaced.
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if !c.Enrolled() {
		if *f.token == "" {
			return fmt.Errorf("not enrolled: no credential in %s; run tlswatch node enrol -server URL -token TOKEN, or pass -token", c.Data)
		}
		id, err := enrolWithRetry(ctx, c, *f.token)
		if err != nil {
			return err
		}
		c.Log.Info("enrolled; confirm the node in the UI", "node_id", id, "server", c.Server)
	}
	err = c.Run(ctx)
	if errors.Is(err, node.ErrRestart) {
		stop()
		c.Log.Info("starting the new binary", "path", self)
		// #nosec G204 -- this program's own path and arguments
		if err := syscall.Exec(self, os.Args, os.Environ()); err != nil {
			// systemd (Restart=always) or the container's restart policy
			// starts it instead.
			c.Log.Error("exec failed; exiting so the service manager restarts the node", "err", err)
		}
		return nil
	}
	return err
}

// enrolWithRetry enrols at the first start of a container, which may come
// up before the network does.
func enrolWithRetry(ctx context.Context, c *node.Client, token string) (int64, error) {
	wait := time.Second
	for {
		id, err := c.Enrol(ctx, token)
		if err == nil || ctx.Err() != nil || wait > 30*time.Second {
			return id, err
		}
		c.Log.Warn("enrolment failed; retrying", "err", err, "retry_in", wait.String())
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(wait):
		}
		wait *= 2
	}
}

func nodeEnrol(args []string) error {
	fs, f := nodeFlagSet("node enrol", true)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *f.token == "" {
		return errors.New("-token is required: the install token from Settings › Nodes › Add node")
	}
	c, err := nodeClient(f)
	if err != nil {
		return err
	}
	id, err := c.Enrol(context.Background(), *f.token)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	fmt.Printf("Enrolled with %s as node %d (%s); the credential is in %s.\n", c.Server, id, host, node.CredentialFile(c.Data))
	return nil
}
