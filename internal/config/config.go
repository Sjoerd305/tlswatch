// Package config holds the bootstrap configuration read from the environment
// and the runtime settings an admin edits in the UI.
//
// Bootstrap values (listen address, database path, secret key file, log
// format) are needed before the database opens and come from the
// environment only. Everything else lives in the settings table; an
// environment variable, when set, overrides the stored value and the UI shows
// that field as read-only.
package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

// Bootstrap is the configuration needed to open the database.
type Bootstrap struct {
	Listen        string
	DBPath        string
	SecretKeyFile string
	LogJSON       bool
}

// LoadBootstrap reads the bootstrap variables with their defaults.
func LoadBootstrap() Bootstrap {
	b := Bootstrap{
		Listen:  env("TLSWATCH_LISTEN", "127.0.0.1:8080"),
		DBPath:  env("TLSWATCH_DB", "./data/tlswatch.db"),
		LogJSON: envBool("TLSWATCH_LOG_JSON", true),
	}
	b.SecretKeyFile = env("TLSWATCH_SECRET_KEY_FILE", filepath.Join(filepath.Dir(b.DBPath), "secret.key"))
	return b
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v, ok := os.LookupEnv(k)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// Thresholds are the expiry thresholds for one renewal style.
type Thresholds struct {
	WarnDays int `json:"warn_days"`
	CritDays int `json:"crit_days"`
}

// General holds instance-wide behaviour.
type General struct {
	BaseURL     string `json:"base_url"`
	BehindProxy bool   `json:"behind_proxy"`
	AllowLocal  bool   `json:"allow_local"`
	TimeZone    string `json:"time_zone"`
}

// SignIn holds the Google sign-in settings. The secret is stored encrypted.
type SignIn struct {
	GoogleClientID     string `json:"google_client_id"`
	GoogleClientSecret string `json:"-"`
	GoogleDomain       string `json:"google_domain"`
}

// Defaults are the global defaults targets follow while their own field is
// empty.
type Defaults struct {
	Manual         Thresholds `json:"manual"`
	Managed        Thresholds `json:"managed"`
	IntervalS      int        `json:"interval_s"`
	AllAddresses   bool       `json:"all_addresses"`
	TimeoutS       int        `json:"timeout_s"`
	Retries        int        `json:"retries"`
	Debounce       int        `json:"debounce"`
	RemindWarnS    int        `json:"remind_warn_s"` // 0 = never
	RemindCritS    int        `json:"remind_crit_s"` // 0 = never
	Workers        int        `json:"workers"`
	RetentionDays  int        `json:"retention_days"`
	DigestEnabled  bool       `json:"digest_enabled"`
	DigestWeekday  int        `json:"digest_weekday"` // 0 = Sunday
	DigestHour     int        `json:"digest_hour"`
	DigestChannels []int64    `json:"digest_channels"` // empty = every SMTP channel
}

// Settings is the full runtime configuration.
type Settings struct {
	General  General
	SignIn   SignIn
	Defaults Defaults
	// Env lists the setting names that the environment overrides, keyed by
	// form field name (for example "base_url").
	Env map[string]string

	loc *time.Location // resolved TimeZone, set by Store.Get
}

// Locked reports whether a field is set by the environment.
func (s Settings) Locked(field string) bool { _, ok := s.Env[field]; return ok }

// Location returns the display time zone.
func (s Settings) Location() *time.Location {
	if s.loc != nil {
		return s.loc
	}
	if s.General.TimeZone != "" {
		if loc, err := time.LoadLocation(s.General.TimeZone); err == nil {
			return loc
		}
	}
	return time.Local
}

// GoogleEnabled reports whether Google sign-in is configured.
func (s Settings) GoogleEnabled() bool {
	return s.SignIn.GoogleClientID != "" && s.SignIn.GoogleClientSecret != ""
}

// DefaultSettings returns the built-in defaults from the specification.
func DefaultSettings() Settings {
	return Settings{
		General: General{},
		Defaults: Defaults{
			Manual:        Thresholds{WarnDays: 30, CritDays: 7},
			Managed:       Thresholds{WarnDays: 10, CritDays: 3},
			IntervalS:     86400,
			AllAddresses:  true,
			TimeoutS:      10,
			Retries:       2,
			Debounce:      2,
			RemindWarnS:   7 * 86400,
			RemindCritS:   86400,
			Workers:       8,
			RetentionDays: 180,
			DigestWeekday: 1,
			DigestHour:    8,
		},
		Env: map[string]string{},
	}
}

// Validate checks ranges from the specification.
func (d Defaults) Validate() error {
	var errs []string
	chk := func(t Thresholds, label string) {
		if t.WarnDays < 1 || t.WarnDays > 365 {
			errs = append(errs, label+" warning must be 1 to 365 days")
		}
		if t.CritDays < 1 || t.CritDays > t.WarnDays-1 {
			errs = append(errs, label+" critical must be 1 to warning minus 1 days")
		}
	}
	chk(d.Manual, "Manual renewal:")
	chk(d.Managed, "Renewal managed:")
	if d.IntervalS < 3600 || d.IntervalS > 7*86400 {
		errs = append(errs, "Interval must be 1 hour to 7 days")
	}
	if d.TimeoutS < 2 || d.TimeoutS > 60 {
		errs = append(errs, "Connect timeout must be 2 to 60 seconds")
	}
	if d.Retries < 0 || d.Retries > 5 {
		errs = append(errs, "Retries must be 0 to 5")
	}
	if d.Debounce < 1 || d.Debounce > 5 {
		errs = append(errs, "Debounce must be 1 to 5 checks")
	}
	if d.RemindWarnS != 0 && d.RemindWarnS < 86400 {
		errs = append(errs, "Warning reminders must be at least 1 day, or never")
	}
	if d.RemindCritS != 0 && d.RemindCritS < 3600 {
		errs = append(errs, "Critical reminders must be at least 1 hour, or never")
	}
	if d.Workers < 1 || d.Workers > 256 {
		errs = append(errs, "Workers must be 1 to 256")
	}
	if d.RetentionDays < 7 || d.RetentionDays > 3650 {
		errs = append(errs, "Retention must be 7 to 3650 days")
	}
	if d.DigestWeekday < 0 || d.DigestWeekday > 6 || d.DigestHour < 0 || d.DigestHour > 23 {
		errs = append(errs, "Digest day or hour out of range")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// Validate checks the general settings.
func (g General) Validate() error {
	if g.BaseURL != "" {
		u, err := url.Parse(g.BaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("Base URL must be an absolute http or https URL")
		}
	}
	if g.TimeZone != "" {
		if _, err := time.LoadLocation(g.TimeZone); err != nil {
			return fmt.Errorf("unknown time zone %q", g.TimeZone)
		}
	}
	return nil
}

// Store loads and saves settings with a small cache.
type Store struct {
	db  *db.DB
	key *secret.Key

	mu     sync.Mutex
	cached *Settings
}

// NewStore returns a settings store.
func NewStore(d *db.DB, k *secret.Key) *Store { return &Store{db: d, key: k} }

const (
	keyGeneral  = "general"
	keySignIn   = "signin"
	keySecret   = "signin.google_client_secret"
	keyDefaults = "defaults"
)

// Get returns the current settings, environment overrides applied.
func (s *Store) Get(ctx context.Context) (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached != nil {
		return *s.cached, nil
	}
	st := DefaultSettings()
	if err := s.load(ctx, keyGeneral, &st.General); err != nil {
		return st, err
	}
	if err := s.load(ctx, keySignIn, &st.SignIn); err != nil {
		return st, err
	}
	if err := s.load(ctx, keyDefaults, &st.Defaults); err != nil {
		return st, err
	}
	var sealed string
	err := s.db.R.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", keySecret).Scan(&sealed)
	if err == nil && sealed != "" {
		if pt, err := s.open(sealed); err == nil {
			st.SignIn.GoogleClientSecret = string(pt)
		}
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return st, err
	}
	applyEnv(&st)
	st.loc = st.Location()
	cp := st
	s.cached = &cp
	return st, nil
}

func (s *Store) load(ctx context.Context, key string, into any) error {
	var v string
	err := s.db.R.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(v), into)
}

func (s *Store) save(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.W.ExecContext(ctx, "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, string(b))
	s.invalidate()
	return err
}

func (s *Store) invalidate() {
	s.mu.Lock()
	s.cached = nil
	s.mu.Unlock()
}

// Reencrypt re-seals the stored secrets (the Google client secret) from old
// to new within tx, for a key rotation. It reports whether there was one.
func Reencrypt(ctx context.Context, tx *sql.Tx, old, new *secret.Key) (bool, error) {
	var v string
	err := tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", keySecret).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) || err == nil && v == "" {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var raw []byte
	if err := json.Unmarshal([]byte(v), &raw); err != nil {
		return false, err
	}
	pt, err := old.Open(raw)
	if err != nil {
		return false, fmt.Errorf("the stored Google client secret cannot be decrypted with the current key: %w", err)
	}
	b, _ := json.Marshal(new.Seal(pt))
	_, err = tx.ExecContext(ctx, "UPDATE settings SET value = ? WHERE key = ?", string(b), keySecret)
	return err == nil, err
}

func (s *Store) open(v string) ([]byte, error) {
	var raw []byte
	if err := json.Unmarshal([]byte(v), &raw); err != nil {
		return nil, err
	}
	return s.key.Open(raw)
}

// SaveGeneral stores the general settings.
func (s *Store) SaveGeneral(ctx context.Context, g General) error {
	if err := g.Validate(); err != nil {
		return err
	}
	g.BaseURL = strings.TrimRight(g.BaseURL, "/")
	return s.save(ctx, keyGeneral, g)
}

// SaveSignIn stores the Google settings; an empty secret keeps the stored
// one unless clearSecret is set.
func (s *Store) SaveSignIn(ctx context.Context, si SignIn, clearSecret bool) error {
	if err := s.save(ctx, keySignIn, si); err != nil {
		return err
	}
	switch {
	case clearSecret:
		_, err := s.db.W.ExecContext(ctx, "DELETE FROM settings WHERE key = ?", keySecret)
		s.invalidate()
		return err
	case si.GoogleClientSecret != "":
		b, _ := json.Marshal(s.key.Seal([]byte(si.GoogleClientSecret)))
		_, err := s.db.W.ExecContext(ctx, "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", keySecret, string(b))
		s.invalidate()
		return err
	}
	return nil
}

// SaveDefaults stores the global defaults.
func (s *Store) SaveDefaults(ctx context.Context, d Defaults) error {
	if err := d.Validate(); err != nil {
		return err
	}
	return s.save(ctx, keyDefaults, d)
}

// HasGoogleSecret reports whether a client secret is stored or set by env.
func (s Settings) HasGoogleSecret() bool { return s.SignIn.GoogleClientSecret != "" }

// envVar is one environment override of a UI setting. apply changes st
// only when v is valid.
type envVar struct {
	name, env string
	apply     func(st *Settings, v string) error
}

func boolVar(dst func(*Settings) *bool) func(*Settings, string) error {
	return func(st *Settings, v string) error {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return errors.New("must be true or false")
		}
		*dst(st) = b
		return nil
	}
}

func intVar(lo, hi int, dst func(*Settings) *int) func(*Settings, string) error {
	return func(st *Settings, v string) error {
		n, err := strconv.Atoi(v)
		if err != nil || n < lo || n > hi {
			return fmt.Errorf("must be a number from %d to %d", lo, hi)
		}
		*dst(st) = n
		return nil
	}
}

var envVars = []envVar{
	{"base_url", "TLSWATCH_BASE_URL", func(st *Settings, v string) error {
		g := st.General
		g.BaseURL = strings.TrimRight(v, "/")
		if err := g.Validate(); err != nil {
			return err
		}
		st.General.BaseURL = g.BaseURL
		return nil
	}},
	{"behind_proxy", "TLSWATCH_BEHIND_PROXY", boolVar(func(st *Settings) *bool { return &st.General.BehindProxy })},
	{"allow_local", "TLSWATCH_ALLOW_LOCAL", boolVar(func(st *Settings) *bool { return &st.General.AllowLocal })},
	{"time_zone", "TZ", func(st *Settings, v string) error {
		if _, err := time.LoadLocation(v); err != nil {
			return fmt.Errorf("unknown time zone %q", v)
		}
		st.General.TimeZone = v
		return nil
	}},
	{"workers", "TLSWATCH_WORKERS", intVar(1, 256, func(st *Settings) *int { return &st.Defaults.Workers })},
	{"retention_days", "TLSWATCH_RETENTION_DAYS", intVar(7, 3650, func(st *Settings) *int { return &st.Defaults.RetentionDays })},
	{"google_client_id", "TLSWATCH_GOOGLE_CLIENT_ID", func(st *Settings, v string) error { st.SignIn.GoogleClientID = v; return nil }},
	{"google_domain", "TLSWATCH_GOOGLE_DOMAIN", func(st *Settings, v string) error { st.SignIn.GoogleDomain = v; return nil }},
	{"google_client_secret", "TLSWATCH_GOOGLE_SECRET_FILE", func(st *Settings, v string) error {
		b, err := os.ReadFile(v) // #nosec G304 -- path from the operator's own environment
		if err != nil {
			return fmt.Errorf("cannot read %s: %w", v, err)
		}
		st.SignIn.GoogleClientSecret = strings.TrimSpace(string(b))
		return nil
	}},
}

// applyEnv applies the valid environment overrides; CheckEnv reports the
// invalid ones at startup.
func applyEnv(st *Settings) {
	for _, e := range envVars {
		if v, ok := os.LookupEnv(e.env); ok && v != "" && e.apply(st, v) == nil {
			st.Env[e.name] = e.env
		}
	}
}

// CheckEnv validates the environment overrides, so a typo stops startup
// instead of being silently ignored. TZ is left out: it is shared with the
// rest of the system and may use forms Go does not load; an unknown zone is
// ignored.
func CheckEnv() error {
	var errs []error
	for _, e := range envVars {
		if v, ok := os.LookupEnv(e.env); ok && v != "" && e.env != "TZ" {
			st := DefaultSettings()
			if err := e.apply(&st, v); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", e.env, err))
			}
		}
	}
	return errors.Join(errs...)
}
