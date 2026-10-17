package demo

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

func newCore(t *testing.T) *core.Service {
	t.Helper()
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	key, _ := secret.New([]byte("0123456789abcdef0123456789abcdef"))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	chans := &notify.Channels{DB: d, Key: key}
	return &core.Service{DB: d, Settings: config.NewStore(d, key), Channels: chans,
		Dispatcher: &notify.Dispatcher{DB: d, Channels: chans, Log: log}, Key: key, Log: log}
}

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "demo.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The file in the repository is the one a demo runs from: it must load.
func TestRepositoryDemoFile(t *testing.T) {
	f, err := Read("../../demo/demo.json")
	if err != nil {
		t.Fatal(err)
	}
	c := newCore(t)
	if ok, err := Load(context.Background(), c, f); err != nil || !ok {
		t.Fatalf("Load = %v, %v", ok, err)
	}
	ts, _ := c.Targets(context.Background())
	if len(ts) != len(f.Targets) {
		t.Errorf("%d targets loaded, the file has %d", len(ts), len(f.Targets))
	}
}

func TestLoad(t *testing.T) {
	ctx := context.Background()
	c := newCore(t)
	root, err := os.ReadFile("testdata/root.pem")
	if err != nil {
		t.Fatal(err)
	}
	f := File{
		Bundles: []Bundle{{Name: "Lab CA", PEM: string(root)}},
		Targets: []Target{
			{Host: "example.org", Tags: []string{"web"}},
			{Host: "mail.example.org", Protocol: "smtp", Renewal: "manual"},
			{Host: "192.0.2.10", ServerName: "portal.example.org", Trust: "bundle", Bundle: "Lab CA", FirstAddress: true},
			{Host: "nas.example.org", Port: 5001, Trust: "self-signed", SkipConfigTest: true, Disabled: true},
		},
		Domains: []Domain{{Name: "example.org", Subdomains: true}},
	}
	if ok, err := Load(ctx, c, f); err != nil || !ok {
		t.Fatalf("Load = %v, %v", ok, err)
	}
	ts, _ := c.Targets(ctx)
	by := map[string]core.Target{}
	for _, tg := range ts {
		by[tg.Host] = tg
	}
	if tg := by["example.org"]; tg.Port != 443 || tg.ServerName != "example.org" || !tg.AllAddresses || !tg.Enabled || tg.Trust != probe.TrustSystem {
		t.Errorf("defaults: %+v", tg)
	}
	if tg := by["mail.example.org"]; tg.Port != 587 || tg.Protocol != probe.SMTP || !tg.RenewalSet || tg.RenewalManaged {
		t.Errorf("smtp manual: %+v", tg)
	}
	if tg := by["192.0.2.10"]; tg.ServerName != "portal.example.org" || tg.Trust != probe.TrustBundle || tg.BundleID == 0 || tg.AllAddresses {
		t.Errorf("bundle: %+v", tg)
	}
	if tg := by["nas.example.org"]; tg.Port != 5001 || tg.Trust != probe.TrustSelfSigned || !tg.SkipLegacy || tg.Enabled {
		t.Errorf("self-signed: %+v", tg)
	}
	if ds, _ := c.Domains(ctx); len(ds) != 1 || !ds[0].Subdomains {
		t.Errorf("domains: %+v", ds)
	}
	// A second start finds the instance filled and leaves it alone.
	if ok, err := Load(ctx, c, File{Targets: []Target{{Host: "other.example.org"}}}); err != nil || ok {
		t.Errorf("second Load = %v, %v", ok, err)
	}
	if ts, _ := c.Targets(ctx); len(ts) != 4 {
		t.Errorf("%d targets after a second start", len(ts))
	}
}

func TestLoadRefuses(t *testing.T) {
	for name, f := range map[string]File{
		"bad host":       {Targets: []Target{{Host: "not a host"}}},
		"bad protocol":   {Targets: []Target{{Host: "example.org", Protocol: "gopher"}}},
		"unknown bundle": {Targets: []Target{{Host: "example.org", Trust: "bundle", Bundle: "nope"}}},
		"bad trust":      {Targets: []Target{{Host: "example.org", Trust: "everything"}}},
		"bad renewal":    {Targets: []Target{{Host: "example.org", Renewal: "sometimes"}}},
		"bad domain":     {Domains: []Domain{{Name: "-"}}},
	} {
		c := newCore(t)
		if _, err := Load(context.Background(), c, f); err == nil {
			t.Errorf("%s: loaded", name)
		}
		// All targets or none: a bad one leaves nothing behind.
		if ts, _ := c.Targets(context.Background()); len(ts) != 0 && name != "bad domain" {
			t.Errorf("%s: %d targets left behind", name, len(ts))
		}
	}
}

func TestRead(t *testing.T) {
	if _, err := Read(write(t, `{"targets":[{"host":"example.org"}]}`)); err != nil {
		t.Errorf("valid file: %v", err)
	}
	for name, body := range map[string]string{
		"unknown field": `{"targets":[{"hots":"example.org"}]}`,
		"empty":         `{}`,
		"not json":      `targets: []`,
	} {
		if _, err := Read(write(t, body)); err == nil || !strings.Contains(err.Error(), "TLSWATCH_DEMO") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Read(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file read")
	}
}
