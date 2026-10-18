// Package demo reads the file a demo instance is filled from. Demo mode
// (TLSWATCH_DEMO) names the file; the targets, domain watches and CA
// bundles in it live outside the binary, in the repository's demo folder
// or wherever the operator keeps them.
package demo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// File is a demo file.
type File struct {
	Bundles []Bundle `json:"bundles"`
	Targets []Target `json:"targets"`
	Domains []Domain `json:"domains"`
}

// Bundle is a CA bundle that targets name in their bundle field.
type Bundle struct {
	Name string `json:"name"`
	PEM  string `json:"pem"`
}

// Target is one target; anything left out follows the Add targets form.
type Target struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`     // the protocol's default when 0
	Name           string   `json:"name"`     // the host when empty
	Protocol       string   `json:"protocol"` // tls when empty
	ServerName     string   `json:"server_name"`
	Trust          string   `json:"trust"`   // system, bundle or self-signed; system when empty
	Bundle         string   `json:"bundle"`  // the bundle's name, with trust "bundle"
	Renewal        string   `json:"renewal"` // auto, managed or manual; auto when empty
	ExpectedIssuer string   `json:"expected_issuer"`
	WarnDays       *int     `json:"warn_days"`
	CritDays       *int     `json:"crit_days"`
	WarnPct        *int     `json:"warn_pct"`
	CritPct        *int     `json:"crit_pct"`
	RenewalPct     *int     `json:"renewal_pct"`
	FirstAddress   bool     `json:"first_address_only"`
	SkipConfigTest bool     `json:"skip_config_test"`
	Disabled       bool     `json:"disabled"`
	Tags           []string `json:"tags"`
	Notes          string   `json:"notes"`
}

// Domain is a Certificate Transparency watch.
type Domain struct {
	Name       string   `json:"name"`
	Subdomains bool     `json:"subdomains"`
	Tags       []string `json:"tags"`
	Notes      string   `json:"notes"`
}

// Read reads and checks a demo file. A field it does not know is an
// error, so a typo does not quietly fall back to a default.
func Read(path string) (File, error) {
	var f File
	data, err := os.ReadFile(path) // #nosec G304 -- path from the operator's own environment
	if err != nil {
		return f, fmt.Errorf("TLSWATCH_DEMO: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, fmt.Errorf("TLSWATCH_DEMO: %s: %w", path, err)
	}
	if len(f.Targets) == 0 && len(f.Domains) == 0 {
		return f, fmt.Errorf("TLSWATCH_DEMO: %s has no targets and no domains", path)
	}
	return f, nil
}

// Load fills an empty instance from the file: the bundles, then the
// targets, then the domain watches. An instance that already has any of
// them is left as it is, so a restart keeps the history the demo built up.
// It reports whether it loaded anything.
func Load(ctx context.Context, c *core.Service, f File) (bool, error) {
	ts, err := c.Targets(ctx)
	if err != nil {
		return false, err
	}
	ds, err := c.Domains(ctx)
	if err != nil {
		return false, err
	}
	bs, err := c.Bundles(ctx)
	if err != nil {
		return false, err
	}
	if len(ts) > 0 || len(ds) > 0 || len(bs) > 0 {
		return false, nil
	}
	const by = "demo"
	bundles := map[string]int64{}
	for _, b := range f.Bundles {
		id, err := c.SaveBundle(ctx, 0, b.Name, b.PEM)
		if err != nil {
			return false, fmt.Errorf("demo bundle %q: %w", b.Name, err)
		}
		bundles[b.Name] = id
	}
	st := c.CurrentSettings(ctx)
	targets := make([]core.Target, 0, len(f.Targets))
	for i, dt := range f.Targets {
		t, err := dt.target(bundles)
		if err == nil {
			err = firstError(t.Validate(st))
		}
		if err != nil {
			return false, fmt.Errorf("demo target %d (%s): %w", i+1, dt.Host, err)
		}
		targets = append(targets, t)
	}
	if _, i, err := c.AddTargets(ctx, targets, by); err != nil {
		return false, fmt.Errorf("demo target %d (%s): %w", i+1, targets[i].HostPort(), err)
	}
	for _, dd := range f.Domains {
		d := core.Domain{Name: dd.Name, Subdomains: dd.Subdomains, Tags: dd.Tags, Notes: dd.Notes, AllChannels: true, Enabled: true}
		if _, err := c.SaveDomain(ctx, d, by); err != nil {
			return false, fmt.Errorf("demo domain %q: %w", dd.Name, err)
		}
	}
	c.Audit(ctx, by, "demo.load", "instance", fmt.Sprintf("targets=%d domains=%d bundles=%d", len(targets), len(f.Domains), len(f.Bundles)))
	return true, nil
}

func (dt Target) target(bundles map[string]int64) (core.Target, error) {
	t := core.Target{
		Name: dt.Name, Host: dt.Host, Port: dt.Port, ServerName: dt.ServerName,
		Protocol: probe.TLS, Trust: probe.TrustSystem, ExpectedIssuer: dt.ExpectedIssuer,
		WarnDays: dt.WarnDays, CritDays: dt.CritDays, WarnPct: dt.WarnPct, CritPct: dt.CritPct, RenewalPct: dt.RenewalPct,
		AllAddresses: !dt.FirstAddress, SkipLegacy: dt.SkipConfigTest, Enabled: !dt.Disabled,
		AllChannels: true, Tags: dt.Tags, Notes: dt.Notes,
	}
	if dt.Protocol != "" {
		p, err := probe.ParseProtocol(dt.Protocol)
		if err != nil {
			return t, err
		}
		t.Protocol = p
	}
	if t.Port == 0 {
		t.Port = probe.DefaultPort(t.Protocol)
	}
	if t.ServerName == "" && net.ParseIP(strings.Trim(t.Host, "[]")) == nil {
		t.ServerName = t.Host
	}
	switch dt.Trust {
	case "", string(probe.TrustSystem):
	case string(probe.TrustSelfSigned):
		t.Trust = probe.TrustSelfSigned
	case string(probe.TrustBundle):
		id, ok := bundles[dt.Bundle]
		if !ok {
			return t, fmt.Errorf("no bundle named %q in the file", dt.Bundle)
		}
		t.Trust, t.BundleID = probe.TrustBundle, id
	default:
		return t, fmt.Errorf("trust %q: use system, bundle or self-signed", dt.Trust)
	}
	switch dt.Renewal {
	case "", "auto":
	case "managed", "manual":
		t.RenewalSet, t.RenewalManaged = true, dt.Renewal == "managed"
	default:
		return t, fmt.Errorf("renewal %q: use auto, managed or manual", dt.Renewal)
	}
	return t, nil
}

// firstError turns Validate's field errors into one error, the same one
// every run.
func firstError(errs map[string]string) error {
	if len(errs) == 0 {
		return nil
	}
	keys := make([]string, 0, len(errs))
	for k := range errs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return fmt.Errorf("%s: %s", keys[0], errs[keys[0]])
}
