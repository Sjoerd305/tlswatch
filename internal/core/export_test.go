package core

import (
	"errors"
	"strings"
	"testing"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

func planOps(p ImportPlan) map[string]string {
	m := map[string]string{}
	for _, c := range p.Changes {
		m[c.Label] = c.Op
	}
	return m
}

// An export imported again changes nothing; it holds only what differs
// from the defaults, names channels and bundles, and carries no
// credentials.
func TestExportRoundTrip(t *testing.T) {
	e := newEnv(t)
	b, err := e.svc.SaveBundle(e.ctx, 0, "Internal CA", string(pemOf(newCA(t, "Internal").cert)))
	if err != nil {
		t.Fatal(err)
	}
	e.target(nil)
	e.target(func(t *Target) {
		t.Name, t.Host, t.ServerName, t.Port, t.Protocol = "Mail", "mail.example.nl", "mail.example.nl", 25, probe.SMTP
		t.Trust, t.BundleID = probe.TrustBundle, b
		t.AllChannels, t.ChannelIDs = false, []int64{e.chC}
		t.Tags, t.Notes, t.SkipLegacy, t.AllAddresses = []string{"mail", "prod"}, "relay\nsecond line", true, false
		t.RenewalSet, t.RenewalManaged, t.WarnDays = true, true, intp(14)
	})
	off := e.target(func(t *Target) { t.Host, t.ServerName, t.Name = "10.0.0.5", "", "10.0.0.5" })
	// A DNS host stored without a server name is still the same target.
	e.target(func(t *Target) { t.Host, t.ServerName = "bare.example.nl", "" })
	if err := e.svc.SetEnabled(e.ctx, off.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SaveDomain(e.ctx, Domain{Name: "example.nl", Subdomains: false, AllChannels: false, ChannelIDs: []int64{e.chW}, Enabled: true}, "test"); err != nil {
		t.Fatal(err)
	}
	doc, err := e.svc.Export(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	text := string(doc)
	for _, want := range []string{"version: 1", "host: mail.example.nl", "port: 25", "protocol: smtp", "bundle: Internal CA", "channels: [telegram]",
		"tags: [mail, prod]", "renewal: managed", "warn_days: 14", "first_address_only: true", "skip_config_test: true", "disabled: true",
		"name: example.nl", "subdomains: false", "channels: [mail]"} {
		if !strings.Contains(text, want) {
			t.Errorf("the export lacks %q:\n%s", want, text)
		}
	}
	// The defaults are left out: the plain target is its host alone.
	if strings.Contains(text, "server_name") || strings.Contains(text, "trust: system") || strings.Contains(text, "port: 443") || strings.Contains(text, "123456:ABC") {
		t.Errorf("the export holds defaults or a credential:\n%s", text)
	}
	plan, err := e.svc.PlanImport(e.ctx, doc)
	if err != nil {
		t.Fatal(err)
	}
	for label, op := range planOps(plan) {
		if op != ImportUnchanged {
			t.Errorf("%s: %s after a round trip", label, op)
		}
	}
	if len(plan.Changes) != 5 {
		t.Fatalf("%d changes", len(plan.Changes))
	}
}

// An import adds, changes and reports what is absent; it removes only when
// asked, and all in one transaction.
func TestImportPlanAndApply(t *testing.T) {
	e := newEnv(t)
	keep := e.target(nil)
	gone := e.target(func(t *Target) { t.Host, t.ServerName = "old.example.nl", "old.example.nl" })
	doc := `
version: 1
targets:
  - host: portal.example.nl
    name: Portal
    warn_days: 21
    tags: [web]
  - host: new.example.nl
    port: 8443
    channels: []
domains:
  - name: Example.NL
`
	plan, err := e.svc.PlanImport(e.ctx, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	ops := planOps(plan)
	if ops["portal.example.nl:443"] != ImportChanged || ops["new.example.nl:8443"] != ImportAdded || ops["old.example.nl:443"] != ImportAbsent || ops["example.nl"] != ImportAdded {
		t.Fatalf("plan: %v", ops)
	}
	for _, c := range plan.Changes {
		if c.Op == ImportChanged {
			got := map[string]FieldDiff{}
			for _, d := range c.Diff {
				got[d.Field] = d
			}
			// WarnPct and CritPct were 0 on the fixture; the file leaves them to the default.
			if got["warn_days"].New != "21" || got["tags"].New != "[web]" || got["warn_pct"].Old != "0" || got["warn_pct"].New != "" {
				t.Fatalf("diff: %+v", c.Diff)
			}
		}
	}
	res, err := e.svc.ApplyImport(e.ctx, plan, false, "importer")
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 2 || res.Changed != 1 || res.Removed != 0 {
		t.Fatalf("result %+v", res)
	}
	if _, err := e.svc.Target(e.ctx, gone.ID); err != nil {
		t.Fatal("an absent target was removed without asking")
	}
	got, _ := e.svc.Target(e.ctx, keep.ID)
	if got.WarnDays == nil || *got.WarnDays != 21 || got.WarnPct != nil || strings.Join(got.Tags, ",") != "web" {
		t.Fatalf("changed target: %+v", got)
	}
	// Again, removing: only the absent target goes.
	plan, err = e.svc.PlanImport(e.ctx, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	res, err = e.svc.ApplyImport(e.ctx, plan, true, "importer")
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 0 || res.Changed != 0 || res.Removed != 1 {
		t.Fatalf("second import %+v", res)
	}
	if _, err := e.svc.Target(e.ctx, gone.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("the absent target survived the removal")
	}
	ts, _ := e.svc.targetsWithChannels(e.ctx)
	for _, tg := range ts {
		if tg.Port == 8443 && (tg.AllChannels || len(tg.ChannelIDs) != 0) {
			t.Fatalf("channels: [] did not mean none: %+v", tg)
		}
	}
}

// Every problem in a file is reported at once, with where it is, and
// nothing is planned.
func TestImportProblems(t *testing.T) {
	e := newEnv(t)
	for name, c := range map[string]struct{ doc, want string }{
		"not yaml":        {"version: 1\ntargets: [", "not a tlswatch export"},
		"version":         {"version: 2\n", "version 2"},
		"unknown field":   {"version: 1\ntargets:\n  - host: a.example.nl\n    prot: smtp\n", "prot"},
		"two documents":   {"version: 1\n---\nversion: 1\n", "more than one document"},
		"bad port":        {"version: 1\ntargets:\n  - host: a.example.nl\n    port: 70000\n", "targets[1] a.example.nl: Port must be 1 to 65535"},
		"no host":         {"version: 1\ntargets:\n  - name: x\n", "host is required"},
		"unknown bundle":  {"version: 1\ntargets:\n  - host: a.example.nl\n    trust: bundle\n    bundle: Nope\n", `no CA bundle named "Nope"`},
		"unknown channel": {"version: 1\ntargets:\n  - host: a.example.nl\n    channels: [pager]\n", `no channel named "pager"`},
		"unknown node":    {"version: 1\ntargets:\n  - host: a.example.nl\n    node: dc1\n", `no node named "dc1"`},
		"repeat":          {"version: 1\ntargets:\n  - host: a.example.nl\n  - host: A.example.nl.\n", "targets[2] A.example.nl.: repeats targets[1]"},
		"bad domain":      {"version: 1\ndomains:\n  - name: 'a b'\n", "domains[1]"},
	} {
		_, err := e.svc.PlanImport(e.ctx, []byte(c.doc))
		var ie *ImportError
		if !errors.As(err, &ie) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	_, err := e.svc.PlanImport(e.ctx, []byte("version: 1\ntargets:\n  - host: a.example.nl\n    port: 0x\n  - host: b.example.nl\n    retries: 9\n"))
	var ie *ImportError
	if !errors.As(err, &ie) || len(ie.Problems) < 1 {
		t.Fatalf("several problems: %v", err)
	}
}

func TestCSVToLines(t *testing.T) {
	lines, ok, err := CSVToLines("host,name,protocol,sni\nportal.example.nl,Portal site,,\n10.0.0.5:993,IMAP,imap,mail.example.nl\n")
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	want := "# host,name,protocol,sni\nportal.example.nl Portal site\n10.0.0.5:993 protocol=imap sni=mail.example.nl IMAP"
	if lines != want {
		t.Fatalf("%q", lines)
	}
	if _, ok, _ := CSVToLines("portal.example.nl Portal, the site\n"); ok {
		t.Fatal("the line format was taken for CSV")
	}
	if _, ok, err := CSVToLines("host,port\nx,1\n"); !ok || err == nil {
		t.Fatal("an unknown column was accepted")
	}
	if !LooksLikeExport("# tlswatch\n\nversion: 1\n") || LooksLikeExport("portal.example.nl\n") {
		t.Fatal("LooksLikeExport")
	}
}
