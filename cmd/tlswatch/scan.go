package main

import (
	"bytes"
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/web"
)

//go:embed scan.html
var scanHTML string

// scanReport is what tlswatch scan writes: the scan and every endpoint it
// found, each judged as tlswatch check judges one.
type scanReport struct {
	Version    string        `json:"tlswatch_version"`
	Ranges     []string      `json:"ranges"`
	Ports      []int         `json:"ports"`
	Rate       int           `json:"rate"`
	WarnDays   int           `json:"warn_days"`
	CritDays   int           `json:"crit_days"`
	StartedAt  string        `json:"started_at"`
	FinishedAt string        `json:"finished_at"`
	Probed     int           `json:"connects"`
	Refused    int           `json:"refused"`
	Status     string        `json:"status"` // the worst of the endpoints: ok, warning or critical
	Endpoints  []checkResult `json:"endpoints"`
}

// scanRun is one parsed scan command line.
type scanRun struct {
	prefixes   []netip.Prefix
	addrs      []netip.Addr
	ports      []int
	rate       int
	timeout    time.Duration
	trust      probe.TrustMode
	roots      *x509.CertPool
	configTest bool
	allowLocal bool
	warn, crit int
	out        string
	formats    []string
	workers    int
}

// scanCmd scans address ranges for TLS endpoints, checks every endpoint it
// finds as tlswatch check does, prints a summary and writes the report as
// HTML (in the style of the UI), CSV and JSON. The exit code is the worst
// severity found: 0 ok, 1 warning, 2 critical (2 also for usage errors).
func scanCmd(args []string, stdout, stderr io.Writer) int {
	run, err := parseScan(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		if !errors.Is(err, errUsage) {
			fmt.Fprintln(stderr, err)
		}
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rep, code, err := runScan(ctx, run, stderr, probe.Scan, probe.Probe, net.DefaultResolver.LookupHost)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	printScanSummary(stdout, rep, time.Now())
	written, err := writeScanReport(rep, run.out, run.formats)
	for _, w := range written {
		fmt.Fprintf(stdout, "wrote %s\n", w)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return code
}

func parseScan(args []string, stderr io.Writer) (scanRun, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, "usage: tlswatch scan RANGE... [flags]\n\nScans CIDRs or addresses (at most 4,096 addresses) for TLS endpoints, checks each one\nas tlswatch check does, and writes an HTML, CSV and JSON report. Exit code: 0 ok,\n1 warning, 2 critical. Only scan networks you own or are allowed to scan.\n\n")
		fs.PrintDefaults()
	}
	ports := fs.String("ports", "", "ports to try, comma separated, at most 16 (default "+joinPorts(probe.DefaultScanPorts)+")")
	rate := fs.Int("rate", probe.DefaultScanRate, fmt.Sprintf("connects per second, 1 to %d", probe.MaxScanRate))
	timeout := fs.Duration("timeout", probe.ScanTimeout, "connect and handshake timeout")
	caFile := fs.String("ca-file", "", "PEM bundle to verify against instead of the system store")
	insecure := fs.Bool("insecure", false, "do not verify chains (a network of self-signed endpoints)")
	noConfig := fs.Bool("no-config-test", false, "skip the configuration test (SSL 3.0, TLS 1.0 and 1.1, weak cipher suites, the grade)")
	allowLocal := fs.Bool("allow-local", true, "allow loopback and link-local addresses")
	warn := fs.Int("warn", 30, "warning threshold in days")
	crit := fs.Int("crit", 7, "critical threshold in days")
	out := fs.String("o", "", "path of the report without extension (default tlswatch-scan-DATE-TIME in the current directory)")
	format := fs.String("format", "html,csv,json", "reports to write: html, csv and json, comma separated, or none")
	if err := fs.Parse(reorder(args, map[string]bool{"ports": true, "rate": true, "timeout": true, "ca-file": true, "warn": true, "crit": true, "o": true, "format": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return scanRun{}, err
		}
		return scanRun{}, errUsage
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return scanRun{}, errUsage
	}
	run := scanRun{rate: *rate, timeout: *timeout, trust: probe.TrustSystem, configTest: !*noConfig, allowLocal: *allowLocal,
		warn: *warn, crit: *crit, out: *out, workers: 8}
	var err error
	// The user scans from their own machine, as with tlswatch check: public
	// ranges are theirs to choose.
	if run.prefixes, run.addrs, err = core.ParseScanRanges(strings.Join(fs.Args(), " "), true, *allowLocal); err != nil {
		return scanRun{}, err
	}
	if run.ports, err = core.ParseScanPorts(*ports); err != nil {
		return scanRun{}, err
	}
	if run.rate < 1 || run.rate > probe.MaxScanRate {
		return scanRun{}, fmt.Errorf("the rate must be 1 to %d connects per second", probe.MaxScanRate)
	}
	if *insecure {
		run.trust = probe.TrustSelfSigned
	}
	if *caFile != "" {
		pool, err := loadBundle(*caFile)
		if err != nil {
			return scanRun{}, err
		}
		run.trust, run.roots = probe.TrustBundle, pool
	}
	for _, f := range strings.Split(*format, ",") {
		switch f = strings.TrimSpace(strings.ToLower(f)); f {
		case "html", "csv", "json":
			if !slices.Contains(run.formats, f) {
				run.formats = append(run.formats, f)
			}
		case "none", "":
		default:
			return scanRun{}, fmt.Errorf("-format: %q is not html, csv, json or none", f)
		}
	}
	if run.out == "" {
		run.out = "tlswatch-scan-" + time.Now().Format("20060102-150405")
	}
	return run, nil
}

func joinPorts(ps []int) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ",")
}

type (
	scanFunc   func(context.Context, probe.ScanRequest) (probe.ScanResult, error)
	probeFunc  func(context.Context, probe.Request) probe.Result
	lookupFunc func(context.Context, string) ([]string, error)
)

// runScan scans, then checks every endpoint found, a few at a time.
func runScan(ctx context.Context, run scanRun, stderr io.Writer, scan scanFunc, probeOne probeFunc, lookup lookupFunc) (scanReport, int, error) {
	started := time.Now()
	rep := scanReport{Version: version, Ports: run.ports, Rate: run.rate, WarnDays: run.warn, CritDays: run.crit, StartedAt: started.UTC().Format(time.RFC3339), Endpoints: []checkResult{}}
	for _, p := range run.prefixes {
		rep.Ranges = append(rep.Ranges, p.String())
	}
	total := len(run.addrs) * len(run.ports)
	fmt.Fprintf(stderr, "Scanning %d %s on %d %s (%d connects at %d per second)…\n", len(run.addrs), plural(len(run.addrs), "address", "addresses"),
		len(run.ports), plural(len(run.ports), "port", "ports"), total, run.rate)
	// Progress hands over what the scan gathered since the last call, and
	// that part is not in the result Scan returns, so the two are summed.
	var mu sync.Mutex
	var got probe.ScanResult
	add := func(r probe.ScanResult) {
		mu.Lock()
		defer mu.Unlock()
		got.Hits = append(got.Hits, r.Hits...)
		got.Probed += r.Probed
		got.Refused += r.Refused
	}
	res, err := scan(ctx, probe.ScanRequest{Addresses: run.addrs, Ports: run.ports, Rate: run.rate, Timeout: run.timeout, AllowLocal: run.allowLocal,
		Progress: func(r probe.ScanResult) {
			add(r)
			mu.Lock()
			fmt.Fprintf(stderr, "\r%d of %d connects, %d TLS %s", got.Probed, total, len(got.Hits), plural(len(got.Hits), "endpoint", "endpoints"))
			mu.Unlock()
		}})
	add(res)
	fmt.Fprintln(stderr)
	if err != nil && len(got.Hits) == 0 {
		return rep, 2, err
	}
	rep.Probed, rep.Refused = got.Probed, got.Refused
	hits := got.Hits
	sort.Slice(hits, func(i, j int) bool {
		ai, aj := netip.MustParseAddr(hits[i].IP), netip.MustParseAddr(hits[j].IP)
		if c := ai.Compare(aj); c != 0 {
			return c < 0
		}
		return hits[i].Port < hits[j].Port
	})
	if len(hits) > 0 {
		fmt.Fprintf(stderr, "Checking %d %s…\n", len(hits), plural(len(hits), "endpoint", "endpoints"))
	}
	results := make([]checkResult, len(hits))
	codes := make([]int, len(hits))
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < run.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				results[i], codes[i] = checkHit(ctx, run, hits[i], probeOne, lookup)
			}
		}()
	}
	for i := range hits {
		next <- i
	}
	close(next)
	wg.Wait()
	code := 0
	for _, c := range codes {
		code = max(code, c)
	}
	rep.Endpoints = results
	rep.Status = map[int]string{0: "ok", 1: "warning", 2: "critical"}[code]
	rep.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	return rep, code, nil
}

// checkHit checks one endpoint the scan found, as tlswatch check would,
// with the first name in its certificate as server name when that name
// resolves to the address (as Add many does), and no server name otherwise.
func checkHit(ctx context.Context, run scanRun, hit probe.ScanHit, probeOne probeFunc, lookup lookupFunc) (checkResult, int) {
	sni := ""
	if len(hit.Chain) > 0 {
		sni = nameAt(ctx, hit.Chain[0].DNSNames, hit.IP, lookup)
	}
	req := probe.Request{Host: hit.IP, Port: hit.Port, Protocol: hit.Protocol, ServerName: sni, Trust: run.trust,
		Timeout: max(run.timeout, 5*time.Second), Retries: 1, FirstOnly: true, AllowLocal: run.allowLocal, Legacy: run.configTest}
	req.Roots = run.roots
	r := probeOne(ctx, req)
	now := time.Now()
	th := check.Thresholds{Warn: run.warn, Crit: run.crit}
	out := check.Evaluate(check.Target{Trust: req.Trust, ServerName: sni, Warn: &run.warn, Crit: &run.crit,
		Manual: th, Managed: th, RenewalSet: true, Debounce: 1, SkipLegacy: !req.Legacy}, check.Previous{Open: map[check.Kind]bool{}}, r, now)
	return checkReport(req, r, out, now)
}

// nameAt returns the first DNS name (no wildcard) that resolves to ip.
func nameAt(ctx context.Context, names []string, ip string, lookup lookupFunc) string {
	for i, n := range names {
		if i >= 5 {
			break
		}
		if strings.HasPrefix(n, "*.") {
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		addrs, err := lookup(lctx, n)
		cancel()
		if err == nil && slices.Contains(addrs, ip) {
			return n
		}
	}
	return ""
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// printScanSummary prints one line per endpoint, worst first.
func printScanSummary(w io.Writer, rep scanReport, now time.Time) {
	if len(rep.Endpoints) == 0 {
		fmt.Fprintf(w, "No TLS endpoints found in %s on ports %s.\n", strings.Join(rep.Ranges, ", "), joinPorts(rep.Ports))
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tENDPOINT\tNAME\tGRADE\tEXPIRES\tSUBJECT\tFINDINGS")
	for _, e := range byStatus(rep.Endpoints) {
		days := "—"
		if e.DaysLeft != nil {
			days = fmt.Sprintf("%d days", *e.DaysLeft)
			if *e.DaysLeft < 0 {
				days = "expired"
			}
		}
		var kinds []string
		for _, f := range e.Findings {
			kinds = append(kinds, f.Kind)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", e.Status, endpointOf(e), dash(e.ServerName), dash(e.Grade), days, dash(e.Subject), dash(strings.Join(kinds, ", ")))
	}
	_ = tw.Flush()
	c := countStatus(rep.Endpoints)
	fmt.Fprintf(w, "\n%d TLS %s: %d critical, %d warning, %d ok.\n", len(rep.Endpoints), plural(len(rep.Endpoints), "endpoint", "endpoints"), c.Critical, c.Warning, c.OK)
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func endpointOf(e checkResult) string {
	if e.Protocol != "" && e.Protocol != string(probe.TLS) {
		return e.Target + " " + e.Protocol
	}
	return e.Target
}

type statusCount struct{ Critical, Warning, OK int }

func countStatus(es []checkResult) statusCount {
	var c statusCount
	for _, e := range es {
		switch e.Status {
		case "critical":
			c.Critical++
		case "warning":
			c.Warning++
		default:
			c.OK++
		}
	}
	return c
}

func statusRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "warning":
		return 1
	}
	return 2
}

// byStatus orders endpoints worst first, then by address as scanned.
func byStatus(es []checkResult) []checkResult {
	out := slices.Clone(es)
	sort.SliceStable(out, func(i, j int) bool { return statusRank(out[i].Status) < statusRank(out[j].Status) })
	return out
}

// writeScanReport writes the report in each format, returning the files.
func writeScanReport(rep scanReport, base string, formats []string) ([]string, error) {
	var written []string
	for _, f := range formats {
		var b []byte
		var err error
		switch f {
		case "json":
			b, err = json.MarshalIndent(rep, "", "  ")
			b = append(b, '\n')
		case "csv":
			b, err = scanCSV(rep)
		case "html":
			b, err = scanHTMLReport(rep, time.Now())
		}
		if err != nil {
			return written, err
		}
		name := base + "." + f
		if err := os.WriteFile(name, b, 0o644); err != nil { // #nosec G306 -- a report for the user to open and share
			return written, err
		}
		written = append(written, name)
	}
	return written, nil
}

func scanCSV(rep scanReport) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"address", "port", "protocol", "server_name", "status", "grade", "days_left", "not_after", "subject", "issuer", "sans", "tls_version", "sha256", "findings"})
	for _, e := range rep.Endpoints {
		host, port, _ := net.SplitHostPort(e.Target)
		days := ""
		if e.DaysLeft != nil {
			days = strconv.Itoa(*e.DaysLeft)
		}
		tlsv := ""
		if len(e.Addresses) > 0 {
			tlsv = e.Addresses[0].TLSVersion
		}
		var fs []string
		for _, f := range e.Findings {
			fs = append(fs, f.Severity+": "+f.Kind+": "+f.Details)
		}
		_ = w.Write([]string{host, port, e.Protocol, e.ServerName, e.Status, e.Grade, days, e.NotAfter, e.Subject, e.Issuer,
			strings.Join(e.SANs, " "), tlsv, e.SHA256, strings.Join(fs, "; ")})
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

var fontURL = regexp.MustCompile(`url\("\.\./fonts/([a-z0-9-]+\.woff2)"\)`)

// reportCSS is the UI's stylesheet with its fonts inlined, so the report is
// one file that looks like tlswatch wherever it is opened.
func reportCSS() (template.CSS, error) {
	css, err := web.FS.ReadFile("static/css/app.css")
	if err != nil {
		return "", err
	}
	var ferr error
	out := fontURL.ReplaceAllFunc(css, func(m []byte) []byte {
		name := string(fontURL.FindSubmatch(m)[1])
		font, err := web.FS.ReadFile(path.Join("static/fonts", name))
		if err != nil {
			ferr = err
			return m
		}
		return []byte(`url("data:font/woff2;base64,` + base64.StdEncoding.EncodeToString(font) + `")`)
	})
	return template.CSS(out), ferr // #nosec G203 -- the embedded stylesheet of this binary
}

// reportRow is an endpoint as the HTML report shows it.
type reportRow struct {
	checkResult
	Class      string // crit, warn or ok
	Label      string // Critical, Warning, OK
	DaysClass  string
	Expires    string
	TLS        string
	GradeClass string
	GradeWhy   string
	SelfSigned bool
	Findings   []reportFinding
}

type reportFinding struct {
	Class, Short, Label, Details string
}

func scanHTMLReport(rep scanReport, now time.Time) ([]byte, error) {
	css, err := reportCSS()
	if err != nil {
		return nil, err
	}
	var rows []reportRow
	for _, e := range byStatus(rep.Endpoints) {
		r := reportRow{checkResult: e, Class: map[string]string{"critical": "crit", "warning": "warn"}[e.Status], GradeClass: check.GradeClass(e.Grade)}
		if r.Class == "" {
			r.Class = "ok"
		}
		r.Label = map[string]string{"crit": "Critical", "warn": "Warning", "ok": "OK"}[r.Class]
		if e.DaysLeft != nil {
			switch d := *e.DaysLeft; {
			case d < 0:
				r.Expires, r.DaysClass = "expired", "crit"
			case d <= rep.CritDays:
				r.DaysClass = "crit"
			case d <= rep.WarnDays:
				r.DaysClass = "warn"
			}
		}
		if len(e.Addresses) > 0 {
			r.TLS = e.Addresses[0].TLSVersion
			r.GradeWhy = strings.Join(e.Addresses[0].GradeReasons, "; ")
		}
		if r.GradeWhy == "" && e.Grade != "" {
			r.GradeWhy = "nothing to improve"
		}
		for _, f := range e.Findings {
			sev := check.Severity(f.Severity)
			r.Findings = append(r.Findings, reportFinding{Class: sev.Class(), Short: sev.Short(), Label: check.Kind(f.Kind).Label(), Details: f.Details})
			if f.Kind == string(check.SelfSigned) {
				r.SelfSigned = true
			}
		}
		rows = append(rows, r)
	}
	t, err := template.New("scan").Funcs(template.FuncMap{
		"date": func(s string) string {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return s
			}
			return t.Local().Format("2 Jan 2006")
		},
		"join":   strings.Join,
		"plural": plural,
	}).Parse(scanHTML)
	if err != nil {
		return nil, err
	}
	started, _ := time.Parse(time.RFC3339, rep.StartedAt)
	var buf bytes.Buffer
	err = t.Execute(&buf, map[string]any{"R": rep, "Rows": rows, "Count": countStatus(rep.Endpoints), "CSS": css,
		"Started": started.Local().Format("2 Jan 2006 15:04"), "Ports": joinPorts(rep.Ports), "Now": now})
	return buf.Bytes(), err
}
