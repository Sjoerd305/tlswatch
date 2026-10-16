package config

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/secret"
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

// A key rotation re-seals every sealed setting, and one sealed under a key
// the instance does not have is reported as unreadable, not silently empty.
func TestReencryptSealedSettings(t *testing.T) {
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()
	k1, _, _ := secret.Generate()
	k2, _, _ := secret.Generate()
	st := NewStore(d, k1)
	if err := st.SaveSignIn(ctx, SignIn{GoogleClientID: "id", GoogleClientSecret: "gsecret"}, false); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveCT(ctx, CT{Source: "certspotter", IntervalS: 3600, APIKey: "ctkey"}, false); err != nil {
		t.Fatal(err)
	}
	tx, _ := d.W.BeginTx(ctx, nil)
	n, unreadable, err := Reencrypt(ctx, tx, k1, k2)
	if err != nil || n != 2 || len(unreadable) != 0 {
		t.Fatalf("reencrypt: n=%d unreadable=%v err=%v", n, unreadable, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, err := NewStore(d, k2).Get(ctx)
	if err != nil || got.CT.APIKey != "ctkey" || got.SignIn.GoogleClientSecret != "gsecret" || got.CT.KeyUnreadable || got.SignIn.SecretUnreadable {
		t.Fatalf("after rotation: ct=%q unreadable=%v google=%q unreadable=%v err=%v", got.CT.APIKey, got.CT.KeyUnreadable, got.SignIn.GoogleClientSecret, got.SignIn.SecretUnreadable, err)
	}
	// Read with the old key, both are stored but unreadable.
	got, err = NewStore(d, k1).Get(ctx)
	if err != nil || got.CT.APIKey != "" || !got.CT.KeyUnreadable || got.SignIn.GoogleClientSecret != "" || !got.SignIn.SecretUnreadable || got.GoogleEnabled() {
		t.Fatalf("with the old key: ct=%q unreadable=%v google=%q unreadable=%v enabled=%v err=%v", got.CT.APIKey, got.CT.KeyUnreadable, got.SignIn.GoogleClientSecret, got.SignIn.SecretUnreadable, got.GoogleEnabled(), err)
	}
	tx, _ = d.W.BeginTx(ctx, nil)
	if n, unreadable, err := Reencrypt(ctx, tx, k1, k2); err != nil || n != 0 || len(unreadable) != 2 {
		t.Fatalf("reencrypt with the wrong old key: n=%d unreadable=%v err=%v", n, unreadable, err)
	}
	tx.Rollback()
	if ok, err := HasSealed(ctx, d); err != nil || !ok {
		t.Fatalf("HasSealed: %v %v", ok, err)
	}
}
