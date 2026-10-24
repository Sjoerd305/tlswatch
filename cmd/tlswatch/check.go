package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

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
	Grade      string         `json:"grade,omitempty"`
	Addresses  []checkAddress `json:"addresses"`
	Findings   []checkFinding `json:"findings"`
	DNSError   string         `json:"dns_error,omitempty"`
}

// checkOther is an other certificate an address serves.
type checkOther struct {
	Via      string   `json:"via"`
	KeyType  string   `json:"key_type"`
	Subject  string   `json:"subject"`
	SHA256   string   `json:"sha256"`
	NotAfter string   `json:"not_after"`
	Problems []string `json:"problems,omitempty"`
}

type checkAddress struct {
	Address    string `json:"address"`
	OK         bool   `json:"ok"`
	TLSVersion string `json:"tls_version,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
	Group      string `json:"key_exchange_group,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Verified   bool   `json:"verified"`
	// Legacy lists the versions under TLS 1.2 the address accepted (SSL
	// 3.0, TLS 1.0, TLS 1.1);
	// absent when they were not tested or got no verdict. WeakSuites lists
	// the weak cipher suite classes accepted, with the suite picked for
	// each; Grade and GradeReasons the configuration grade that follows.
	Legacy     *[]string `json:"legacy_accepted,omitempty"`
	WeakSuites *[]string `json:"weak_suites_accepted,omitempty"`
	// DHGroupBits is the size of the Diffie-Hellman group the address uses
	// for DHE suites; absent when it accepts none or was not tested.
	DHGroupBits int `json:"dh_group_bits,omitempty"`
	// Others are the other certificates the address serves, by key type
	// ("other_key") and without SNI ("no_sni"), with the checks they fail.
	Others       []checkOther `json:"other_certificates,omitempty"`
	Grade        string       `json:"grade,omitempty"`
	GradeReasons []string     `json:"grade_reasons,omitempty"`
	// PQKex is whether the address negotiates post-quantum key exchange
	// (X25519MLKEM768); absent when not tested.
	PQKex      *bool  `json:"pq_kex,omitempty"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

type checkFinding struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Details  string `json:"details"`
}

// checkRun is one parsed check command line.
type checkRun struct {
	req        probe.Request
	warn, crit int
}

// errUsage reports a command line error already explained on stderr.
var errUsage = errors.New("usage")

// checkCmd probes one endpoint and prints the result as JSON. The exit code
// is the worst severity: 0 ok, 1 warning, 2 critical (2 also for usage
// errors).
func checkCmd(args []string, stdout, stderr io.Writer) int {
	run, err := parseCheck(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0 // the usage asked for, printed by the flag set
	}
	if err != nil {
		if !errors.Is(err, errUsage) {
			fmt.Fprintln(stderr, err)
		}
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	r := probe.Probe(ctx, run.req)
	now := time.Now()
	th := check.Thresholds{Warn: run.warn, Crit: run.crit}
	out := check.Evaluate(check.Target{Trust: run.req.Trust, ServerName: run.req.ServerName, Warn: &run.warn, Crit: &run.crit,
		Manual: th, Managed: th, RenewalSet: true, Debounce: 1, SkipLegacy: !run.req.Legacy}, check.Previous{Open: map[check.Kind]bool{}}, r, now)
	res, code := checkReport(run.req, r, out, now)
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
	return code
}

// parseCheck turns the command line into a probe request.
func parseCheck(args []string, stderr io.Writer) (checkRun, error) {
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
	noConfig := fs.Bool("no-config-test", false, "skip the configuration test (SSL 3.0, TLS 1.0 and 1.1, weak cipher suites, the grade)")
	noLegacy := fs.Bool("no-legacy", false, "alias of -no-config-test")
	if err := fs.Parse(reorder(args, map[string]bool{"protocol": true, "servername": true, "ca-file": true, "warn": true, "crit": true, "timeout": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return checkRun{}, err
		}
		return checkRun{}, errUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: tlswatch check HOST[:PORT] [-protocol P] [-servername N] [-ca-file F] [-insecure]")
		return checkRun{}, errUsage
	}
	proto, err := probe.ParseProtocol(*protocol)
	if err != nil {
		return checkRun{}, err
	}
	host, port, err := splitEndpoint(fs.Arg(0), probe.DefaultPort(proto))
	if err != nil {
		return checkRun{}, err
	}
	sni := *servername
	if sni == "" && net.ParseIP(host) == nil {
		sni = host
	}
	req := probe.Request{Host: host, Port: port, Protocol: proto, ServerName: sni, Trust: probe.TrustSystem,
		Timeout: *timeout, Retries: 1, FirstOnly: *first, AllowLocal: *allowLocal, Legacy: !*noLegacy && !*noConfig}
	if *insecure {
		req.Trust = probe.TrustSelfSigned
	}
	if *caFile != "" {
		if req.Roots, err = loadBundle(*caFile); err != nil {
			return checkRun{}, err
		}
		req.Trust = probe.TrustBundle
	}
	return checkRun{req: req, warn: *warn, crit: *crit}, nil
}

// splitEndpoint parses HOST or HOST:PORT, defaulting the port.
func splitEndpoint(arg string, defaultPort int) (string, int, error) {
	host, port := arg, defaultPort
	if h, p, err := net.SplitHostPort(arg); err == nil {
		host = h
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("invalid port %s", p)
		}
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if err := probe.ValidateHost(host); err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func loadBundle(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- path from the operator's command line
	if err != nil {
		return nil, err
	}
	certs, err := core.ParseBundle(string(b))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}

// checkReport builds the JSON report and the exit code. The status is the
// worst severity of the findings (check.Worst), the CLI's contract for
// scripts, not the UI's target status.
func checkReport(req probe.Request, r probe.Result, out check.Outcome, now time.Time) (checkResult, int) {
	res := checkResult{Target: net.JoinHostPort(req.Host, strconv.Itoa(req.Port)), Protocol: string(req.Protocol), ServerName: req.ServerName,
		DNSError: r.DNSError, Addresses: []checkAddress{}, Findings: []checkFinding{}}
	for _, a := range r.Addresses {
		ca := checkAddress{Address: a.IP, OK: a.OK, TLSVersion: a.TLSVersion, Cipher: a.Cipher, Verified: a.Verified, Error: a.Error, DurationMS: a.Duration.Milliseconds()}
		if a.OK {
			ca.SHA256 = probe.Fingerprint(a.Chain[0])
		}
		ca.Group = a.Group
		if a.PQChecked {
			pq := a.PQ
			ca.PQKex = &pq
		}
		if a.LegacyChecked || len(a.Legacy) > 0 {
			l := append([]string{}, a.Legacy...)
			ca.Legacy = &l
		}
		if a.SuitesChecked || len(a.Suites) > 0 {
			w := []string{}
			for i, c := range a.Suites {
				if c == probe.ClassCBC {
					continue
				}
				name := c.Label()
				if i < len(a.SuiteNames) {
					name += " (" + a.SuiteNames[i] + ")"
				}
				w = append(w, name)
			}
			ca.WeakSuites = &w
			ca.DHGroupBits = a.DHBits
		}
		for _, g := range out.AddressGrades {
			if g.IP == a.IP {
				for _, o := range g.Others {
					ca.Others = append(ca.Others, checkOther{Via: o.Via, KeyType: o.KeyType, Subject: o.Subject, SHA256: o.Fingerprint,
						NotAfter: o.NotAfter.UTC().Format(time.RFC3339), Problems: o.Problems})
				}
				ca.Grade, ca.GradeReasons = g.Grade, g.Reasons
			}
		}
		res.Addresses = append(res.Addresses, ca)
	}
	res.Grade = out.Grade
	if out.Leaf != nil {
		ci := probe.Describe(out.Leaf)
		d := check.DaysLeft(out.NotAfter, now)
		res.DaysLeft, res.NotAfter = &d, out.NotAfter.UTC().Format(time.RFC3339)
		res.Subject, res.Issuer, res.SANs, res.SHA256 = ci.SubjectCN, ci.IssuerCN, ci.SANs, ci.Fingerprint
	}
	for _, f := range out.Open {
		res.Findings = append(res.Findings, checkFinding{Kind: string(f.Kind), Severity: string(f.Severity), Details: f.Details})
	}
	switch check.Worst(out.Open) {
	case check.Critical:
		return withStatus(res, "critical"), 2
	case check.Warning:
		return withStatus(res, "warning"), 1
	}
	// A grade of C or F without a finding (a weak key under 2048 bits is
	// weak_signature, so this is rare) still fails a script.
	if out.GradeChecked && check.GradeRank(out.Grade) <= check.GradeRank(check.GradeC) {
		return withStatus(res, "warning"), 1
	}
	return withStatus(res, "ok"), 0
}

func withStatus(r checkResult, s string) checkResult { r.Status = s; return r }

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
