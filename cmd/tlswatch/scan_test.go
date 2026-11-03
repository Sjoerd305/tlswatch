package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A scan finds the endpoint, checks it as tlswatch check does, prints a
// summary, writes the three reports and exits by the worst severity.
func TestScanCommand(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "https://"), ":")
	base := filepath.Join(t.TempDir(), "report")
	var out, errOut bytes.Buffer
	code := scanCmd([]string{"127.0.0.1", "-ports", port, "-rate", "200", "-o", base}, &out, &errOut)
	// The test server's certificate is from no public CA.
	if code != 2 {
		t.Fatalf("exit %d\n%s\n%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "127.0.0.1:"+port) || !strings.Contains(out.String(), "1 TLS endpoint: 1 critical") {
		t.Fatalf("summary:\n%s", out.String())
	}

	var rep scanReport
	b, err := os.ReadFile(base + ".json")
	if err != nil || json.Unmarshal(b, &rep) != nil {
		t.Fatalf("json: %v", err)
	}
	if len(rep.Endpoints) != 1 || rep.Status != "critical" || rep.Ranges[0] != "127.0.0.1/32" || rep.Probed != 1 {
		t.Fatalf("report: %+v", rep)
	}
	e := rep.Endpoints[0]
	if e.SHA256 == "" || len(e.Findings) == 0 || e.Grade == "" {
		t.Fatalf("endpoint: %+v", e)
	}

	f, _ := os.Open(base + ".csv")
	rows, err := csv.NewReader(f).ReadAll()
	f.Close()
	if err != nil || len(rows) != 2 || rows[0][0] != "address" || rows[1][0] != "127.0.0.1" || rows[1][4] != "critical" {
		t.Fatalf("csv: %v %q", err, rows)
	}

	page, err := os.ReadFile(base + ".html")
	if err != nil {
		t.Fatal(err)
	}
	h := string(page)
	for _, want := range []string{"<title>Scan of 127.0.0.1/32 · tlswatch</title>", `class="st sm crit">Critical`, `class="grade `,
		`data:font/woff2;base64,`, `<span class="n">1</span>`, "Findings"} {
		if !strings.Contains(h, want) {
			t.Errorf("html lacks %q", want)
		}
	}
	if strings.Contains(h, `url("../fonts/`) {
		t.Error("html still points at font files instead of carrying them")
	}

	// -insecure: the chain is not judged, and nothing else is wrong.
	out.Reset()
	if code := scanCmd([]string{"127.0.0.1", "-ports", port, "-insecure", "-no-config-test", "-format", "none"}, &out, &errOut); code != 0 {
		t.Fatalf("insecure: exit %d\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "wrote") {
		t.Fatal("-format none wrote a report")
	}
}

// A range with nothing listening is an empty report, exit 0.
func TestScanFindsNothing(t *testing.T) {
	base := filepath.Join(t.TempDir(), "empty")
	var out, errOut bytes.Buffer
	if code := scanCmd([]string{"127.0.0.1", "-ports", "1", "-o", base, "-format", "html"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	page, _ := os.ReadFile(base + ".html")
	if !strings.Contains(out.String(), "No TLS endpoints found") || !strings.Contains(string(page), "No TLS endpoints found") {
		t.Fatalf("summary %q", out.String())
	}
}

func TestScanUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"not-a-range"}, {"10.0.0.0/8"}, {"10.0.0.1", "-ports", "0"}, {"10.0.0.1", "-rate", "999"}, {"10.0.0.1", "-format", "pdf"}} {
		var out, errOut bytes.Buffer
		if code := scanCmd(args, &out, &errOut); code != 2 || out.Len() != 0 || errOut.Len() == 0 {
			t.Errorf("%q: exit %d, stdout %q, stderr %q", args, code, out.String(), errOut.String())
		}
	}
}
