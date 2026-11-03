package web

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The metric names follow the Prometheus conventions, since they are part
// of what dashboards and alert rules depend on and cannot change later
// without breaking them: _total only on counters, every counter ending in
// _total, and a Unix time named _timestamp_seconds.
func TestMetricNamesFollowConventions(t *testing.T) {
	src, err := os.ReadFile("metrics.go")
	if err != nil {
		t.Fatal(err)
	}
	decl := regexp.MustCompile(`p\.metric\("([a-z_]+)", "(gauge|counter)", "([^"]*)"`)
	found := decl.FindAllStringSubmatch(string(src), -1)
	if len(found) < 10 {
		t.Fatalf("found %d metric declarations; the pattern no longer matches metrics.go", len(found))
	}
	for _, m := range found {
		name, typ, help := m[1], m[2], m[3]
		if total := strings.HasSuffix(name, "_total"); total != (typ == "counter") {
			t.Errorf("%s is a %s: _total belongs on counters, and only there", name, typ)
		}
		if strings.Contains(help, "Unix time") && !strings.HasSuffix(name, "_timestamp_seconds") {
			t.Errorf("%s holds a Unix time but is not named _timestamp_seconds", name)
		}
		if !strings.HasPrefix(name, "tlswatch_") {
			t.Errorf("%s lacks the tlswatch_ prefix", name)
		}
	}
}
