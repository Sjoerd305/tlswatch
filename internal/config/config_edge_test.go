package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

func TestLoadBootstrap(t *testing.T) {
	for _, k := range []string{"TLSWATCH_LISTEN", "TLSWATCH_DB", "TLSWATCH_SECRET_KEY_FILE", "TLSWATCH_LOG_JSON"} {
		t.Setenv(k, "") // empty counts as unset
	}
	b := LoadBootstrap()
	want := Bootstrap{Listen: "127.0.0.1:8080", DBPath: "./data/tlswatch.db", SecretKeyFile: filepath.Join("data", "secret.key"), LogJSON: true}
	if b != want {
		t.Fatalf("defaults: %+v, want %+v", b, want)
	}
	// The key file follows the database unless named.
	t.Setenv("TLSWATCH_DB", "/srv/tw/state.db")
	t.Setenv("TLSWATCH_LISTEN", "0.0.0.0:9000")
	t.Setenv("TLSWATCH_LOG_JSON", "false")
	b = LoadBootstrap()
	if b.DBPath != "/srv/tw/state.db" || b.SecretKeyFile != "/srv/tw/secret.key" || b.Listen != "0.0.0.0:9000" || b.LogJSON {
		t.Fatalf("from the environment: %+v", b)
	}
	t.Setenv("TLSWATCH_SECRET_KEY_FILE", "/run/secrets/key")
	if b = LoadBootstrap(); b.SecretKeyFile != "/run/secrets/key" {
		t.Fatalf("named key file: %+v", b)
	}
	for v, want := range map[string]bool{"0": false, "TRUE": true, "f": false, "garbage": true} {
		t.Setenv("TLSWATCH_LOG_JSON", v)
		if got := LoadBootstrap().LogJSON; got != want {
			t.Errorf("TLSWATCH_LOG_JSON=%q: %v, want %v", v, got, want)
		}
	}
}

func newStore(t *testing.T) (*Store, *db.DB) {
	t.Helper()
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	k, _, _ := secret.Generate()
	return NewStore(d, k), d
}

// The environment wins over a value saved in the UI, which stays stored for
// when the variable goes; the field reports where its value comes from.
func TestStoreEnvWinsOverSaved(t *testing.T) {
	ctx := context.Background()
	st, d := newStore(t)
	if err := st.SaveGeneral(ctx, General{BaseURL: "https://ui.example.nl/", AllowLocal: false}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveSignIn(ctx, SignIn{GoogleClientID: "ui-id", GoogleClientSecret: "ui-secret"}, false); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(t.TempDir(), "google")
	if err := os.WriteFile(secretFile, []byte("env-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TLSWATCH_BASE_URL", "https://env.example.nl/")
	t.Setenv("TLSWATCH_ALLOW_LOCAL", "true")
	t.Setenv("TLSWATCH_GOOGLE_CLIENT_ID", "env-id")
	t.Setenv("TLSWATCH_GOOGLE_SECRET_FILE", secretFile)
	st.Invalidate()
	got, err := st.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.General.BaseURL != "https://env.example.nl" || !got.General.AllowLocal || got.SignIn.GoogleClientID != "env-id" || got.SignIn.GoogleClientSecret != "env-secret" {
		t.Fatalf("overrides not applied: %+v %+v", got.General, got.SignIn)
	}
	for field, env := range map[string]string{"base_url": "TLSWATCH_BASE_URL", "allow_local": "TLSWATCH_ALLOW_LOCAL", "google_client_id": "TLSWATCH_GOOGLE_CLIENT_ID", "google_client_secret": "TLSWATCH_GOOGLE_SECRET_FILE"} {
		if !got.Locked(field) || got.Env[field] != env {
			t.Errorf("%s not locked by %s: %v", field, env, got.Env)
		}
	}
	if got.Locked("time_zone") || got.Locked("workers") {
		t.Errorf("fields the environment does not set are locked: %v", got.Env)
	}
	// A save does not lose the override, and the stored values are intact.
	if err := st.SaveGeneral(ctx, General{BaseURL: "https://other.example.nl"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get(ctx); got.General.BaseURL != "https://env.example.nl" || !got.General.AllowLocal {
		t.Fatalf("after a save: %+v", got.General)
	}
	os.Unsetenv("TLSWATCH_BASE_URL")
	os.Unsetenv("TLSWATCH_ALLOW_LOCAL")
	os.Unsetenv("TLSWATCH_GOOGLE_CLIENT_ID")
	os.Unsetenv("TLSWATCH_GOOGLE_SECRET_FILE")
	got, _ = NewStore(d, st.key).Get(ctx)
	if got.General.BaseURL != "https://other.example.nl" || got.General.AllowLocal || got.SignIn.GoogleClientID != "ui-id" || got.SignIn.GoogleClientSecret != "ui-secret" || len(got.Env) != 0 {
		t.Fatalf("without the environment: %+v %+v %v", got.General, got.SignIn, got.Env)
	}
}

// The cache returns copies: a caller changing its Settings' fields does not
// change what the next caller gets.
func TestStoreCacheIsACopy(t *testing.T) {
	ctx := context.Background()
	st, _ := newStore(t)
	a, _ := st.Get(ctx)
	a.General.BaseURL = "https://mutated.example"
	a.Defaults.Workers = 1
	b, _ := st.Get(ctx)
	if b.General.BaseURL != "" || b.Defaults.Workers != 8 {
		t.Fatalf("the cached settings were changed through a copy: %+v %+v", b.General, b.Defaults)
	}
}

func TestGeneralValidation(t *testing.T) {
	ctx := context.Background()
	st, _ := newStore(t)
	for _, bad := range []General{{BaseURL: "tlswatch.example.nl"}, {BaseURL: "ftp://x.example"}, {BaseURL: "https://"}, {BaseURL: "javascript:alert(1)"}, {TimeZone: "Mars/Olympus"}} {
		if err := st.SaveGeneral(ctx, bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if err := st.SaveGeneral(ctx, General{BaseURL: "https://x.example///", TimeZone: "Europe/Amsterdam", Metrics: true}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Get(ctx)
	if got.General.BaseURL != "https://x.example" || got.Location().String() != "Europe/Amsterdam" || len(got.General.MetricsToken) != 64 {
		t.Fatalf("saved: %+v", got.General)
	}
	if (Settings{General: General{TimeZone: "Nope/Nope"}}).Location() != time.Local {
		t.Error("an unknown zone does not fall back to local time")
	}
	if ok, err := HasSealed(ctx, st.db); err != nil || ok {
		t.Errorf("HasSealed without sealed settings: %v %v", ok, err)
	}
}
