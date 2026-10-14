package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestEnvOverrides(t *testing.T) {
	t.Setenv("TLSWATCH_RETENTION_DAYS", "30")
	t.Setenv("TLSWATCH_BEHIND_PROXY", "true")
	t.Setenv("TZ", "Europe/Amsterdam")
	if err := CheckEnv(); err != nil {
		t.Fatal(err)
	}
	st := DefaultSettings()
	applyEnv(&st)
	if st.Defaults.RetentionDays != 30 || !st.General.BehindProxy || st.General.TimeZone != "Europe/Amsterdam" {
		t.Fatalf("not applied: %+v %+v", st.Defaults, st.General)
	}
	if st.Env["retention_days"] != "TLSWATCH_RETENTION_DAYS" {
		t.Fatalf("env sources: %v", st.Env)
	}
}

func TestInvalidEnvIsReportedAndIgnored(t *testing.T) {
	t.Setenv("TLSWATCH_RETENTION_DAYS", "1")
	t.Setenv("TLSWATCH_BEHIND_PROXY", "yes please")
	t.Setenv("TLSWATCH_WORKERS", "x")
	t.Setenv("TLSWATCH_BASE_URL", "tlswatch.example.nl")
	t.Setenv("TLSWATCH_GOOGLE_SECRET_FILE", "/nonexistent/secret")
	t.Setenv("TZ", "Not/AZone")
	err := CheckEnv()
	if err == nil {
		t.Fatal("invalid environment accepted")
	}
	for _, name := range []string{"TLSWATCH_RETENTION_DAYS", "TLSWATCH_BEHIND_PROXY", "TLSWATCH_WORKERS", "TLSWATCH_BASE_URL", "TLSWATCH_GOOGLE_SECRET_FILE"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("%s not reported: %v", name, err)
		}
	}
	if strings.Contains(err.Error(), "TZ") {
		t.Errorf("TZ reported: %v", err)
	}

	// The stored values stand: an invalid override changes nothing.
	st := DefaultSettings()
	st.General.BehindProxy = true
	want := st
	applyEnv(&st)
	if !reflect.DeepEqual(st.Defaults, want.Defaults) || st.General != want.General || len(st.Env) != 0 {
		t.Fatalf("invalid override applied: %+v %+v %v", st.Defaults, st.General, st.Env)
	}
}
