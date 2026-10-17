package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/sjoerd305/tlswatch/internal/authz"
)

// generalForm is the Settings › General form as the browser sends it.
func generalForm(base string) url.Values {
	return url.Values{"base_url": {base}, "time_zone": {"UTC"}}
}

// A setting the environment supplies wins over the value saved in the UI,
// and the field is shown read-only with the variable's name.
func TestEnvOverrideWinsAndIsLocked(t *testing.T) {
	t.Setenv("TLSWATCH_BASE_URL", "https://env.example.nl/")
	t.Setenv("TLSWATCH_WORKERS", "3")
	hs := newHarness(t)
	ctx := context.Background()
	page := hs.do(authz.Admin, "GET", "/settings/general", nil, false).Body.String()
	if !strings.Contains(page, `value="https://env.example.nl"`) || !strings.Contains(page, "set by environment (TLSWATCH_BASE_URL)") || !strings.Contains(page, " readonly") {
		t.Fatal("the base URL is not shown as set by the environment")
	}
	if rec := hs.do(authz.Admin, "POST", "/settings/general", generalForm("https://ui.example.nl"), true); rec.Code != http.StatusSeeOther {
		t.Fatalf("save general: %d %s", rec.Code, rec.Body.String())
	}
	st, _ := hs.srv.Settings.Get(ctx)
	if st.General.BaseURL != "https://env.example.nl" || !st.Locked("base_url") {
		t.Fatalf("after a UI save the base URL is %q (locked %v)", st.General.BaseURL, st.Locked("base_url"))
	}
	// Links the server builds use the environment's value.
	if base := hs.do(authz.Admin, "GET", "/settings/signin", nil, false).Body.String(); !strings.Contains(base, "https://env.example.nl/auth/google/callback") {
		t.Error("the redirect URI does not use the environment's base URL")
	}
	defaults := hs.do(authz.Admin, "GET", "/settings/defaults", nil, false).Body.String()
	if !strings.Contains(defaults, "set by environment (TLSWATCH_WORKERS)") {
		t.Error("workers not shown as set by the environment")
	}
	d := url.Values{"manual_warn": {"30"}, "manual_crit": {"7"}, "managed_warn": {"10"}, "managed_crit": {"3"}, "interval_s": {"86400"},
		"timeout_s": {"10"}, "retries": {"2"}, "debounce": {"2"}, "remind_warn_s": {"604800"}, "remind_crit_s": {"86400"}, "workers": {"99"},
		"retention_days": {"180"}, "digest_weekday": {"1"}, "digest_hour": {"8"}}
	if rec := hs.do(authz.Admin, "POST", "/settings/defaults", d, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("save defaults: %d %s", rec.Code, rec.Body.String())
	}
	if st, _ := hs.srv.Settings.Get(ctx); st.Defaults.Workers != 3 {
		t.Fatalf("workers after a UI save: %d, want the environment's 3", st.Defaults.Workers)
	}
}

// With the metrics switched on by the environment alone, a token is still
// generated (the spec's default for TLSWATCH_METRICS_TOKEN), shown under
// Settings › General and accepted by /metrics; nothing has to be saved in
// the UI first.
func TestMetricsFromEnvGetAToken(t *testing.T) {
	t.Setenv("TLSWATCH_METRICS", "true")
	hs := newHarness(t)
	st, _ := hs.srv.Settings.Get(context.Background())
	if !st.General.Metrics {
		t.Fatal("TLSWATCH_METRICS=true not applied")
	}
	if st.General.MetricsToken == "" {
		t.Fatal("metrics enabled by the environment, but no token was generated: /metrics refuses every request and Settings › General shows none")
	}
	if rec := hs.metrics(); rec.Code != http.StatusOK {
		t.Fatalf("/metrics with the generated token: %d", rec.Code)
	}
}

// A metrics token supplied by the environment is used, but saving
// Settings › General does not copy it into the database (and so into every
// backup), where it would outlive the variable.
func TestEnvMetricsTokenNotStored(t *testing.T) {
	const envTok = "env-token-0123456789abcdef"
	t.Setenv("TLSWATCH_METRICS_TOKEN", envTok)
	hs := newHarness(t)
	f := generalForm("")
	f.Set("metrics", "1")
	if rec := hs.do(authz.Admin, "POST", "/settings/general", f, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d", rec.Code)
	}
	if st, _ := hs.srv.Settings.Get(context.Background()); st.General.MetricsToken != envTok {
		t.Fatalf("token in use: %q, want the environment's", st.General.MetricsToken)
	}
	var raw string
	_ = hs.db.R.QueryRow("SELECT value FROM settings WHERE key = 'general'").Scan(&raw)
	if strings.Contains(raw, envTok) {
		t.Fatalf("the environment's metrics token was written to the database: %s", raw)
	}
}
