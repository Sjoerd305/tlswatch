package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

func TestCheckCommand(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	var out, errOut bytes.Buffer
	code := checkCmd([]string{addr, "-insecure", "-timeout", "5s"}, &out, &errOut)
	var res checkResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("output: %v: %s %s", err, out.String(), errOut.String())
	}
	if len(res.Addresses) != 1 || !res.Addresses[0].OK || res.SHA256 == "" {
		t.Fatalf("result: %+v", res)
	}
	// An IP target has no server name to verify, and -insecure skips the chain.
	if code != 0 || res.Status != "ok" || len(res.Findings) != 0 {
		t.Fatalf("exit %d, status %s, findings %+v", code, res.Status, res.Findings)
	}
	// With a server name the test server's example.com certificate mismatches.
	out.Reset()
	code = checkCmd([]string{addr, "-insecure", "-servername", "tlswatch.test"}, &out, &errOut)
	res = checkResult{}
	_ = json.Unmarshal(out.Bytes(), &res)
	if code != 2 || res.Status != "critical" || len(res.Findings) == 0 || res.Findings[0].Kind != string(check.HostnameMismatch) {
		t.Fatalf("exit %d, status %s, findings %+v", code, res.Status, res.Findings)
	}
}

func TestCheckUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"a", "b"}, {"example.org:0"}, {"example.org", "-protocol", "gopher"}} {
		var out, errOut bytes.Buffer
		if code := checkCmd(args, &out, &errOut); code != 2 || out.Len() != 0 || errOut.Len() == 0 {
			t.Errorf("%q: exit %d, stdout %q, stderr %q", args, code, out.String(), errOut.String())
		}
	}
}

func TestCheckReportStatus(t *testing.T) {
	req := probe.Request{Host: "example.org", Port: 443, Protocol: probe.TLS}
	cases := []struct {
		open   []check.Finding
		status string
		code   int
	}{
		{nil, "ok", 0},
		{[]check.Finding{{Kind: check.Expiring, Severity: check.Warning}}, "warning", 1},
		{[]check.Finding{{Kind: check.Expiring, Severity: check.Warning}, {Kind: check.Expired, Severity: check.Critical}}, "critical", 2},
	}
	for _, c := range cases {
		res, code := checkReport(req, probe.Result{}, check.Outcome{Open: c.open}, time.Now())
		if res.Status != c.status || code != c.code || res.Target != "example.org:443" {
			t.Errorf("%v: %s/%d", c.open, res.Status, code)
		}
	}
}
