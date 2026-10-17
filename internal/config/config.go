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
	"crypto/rand"
	"database/sql"
	"encoding/hex"
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
	"github.com/sjoerd305/tlswatch/internal/usererr"
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

// EnvBool reads a bootstrap boolean variable; unset or invalid is def, and
// CheckEnv reports an invalid one.
func EnvBool(k string, def bool) bool { return envBool(k, def) }

func envBool(k string, def bool) bool {
	v, ok := os.LookupEnv(k)
	if !ok || v == "" {
		return def
	}
	b, err := ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// ParseBool reads a boolean environment value: what strconv.ParseBool
// takes, and yes or no.
func ParseBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "y", "on":
		return true, nil
	case "no", "n", "off":
		return false, nil
	}
	return strconv.ParseBool(strings.TrimSpace(v))
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
	// Metrics serves /metrics in the Prometheus text format; it names
	// every target, so a request must carry MetricsToken as a bearer token.
	Metrics      bool   `json:"metrics"`
	MetricsToken string `json:"metrics_token"`
}

// SignIn holds the Google sign-in settings. The secret is stored encrypted.
type SignIn struct {
	GoogleClientID     string `json:"google_client_id"`
	GoogleClientSecret string `json:"-"`
	GoogleDomain       string `json:"google_domain"`
	// SecretUnreadable is set when a client secret is stored but the
	// instance key cannot open it (another key): it must be entered again.
	SecretUnreadable bool `json:"-"`
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

// Nodes holds the settings of Settings › Nodes.
type Nodes struct {
	// AutoUpdate keeps every node on the server's version: one at a time,
	// a node on another version is sent an update.
	AutoUpdate bool `json:"auto_update"`
}

// CT holds the Certificate Transparency settings. The API key is stored
// encrypted like the Google client secret.
type CT struct {
	Source    string `json:"source"` // certspotter or crtsh
	IntervalS int    `json:"interval_s"`
	APIKey    string `json:"-"`
	// KeyUnreadable is set when a key is stored but the instance key
	// cannot open it (another key): it must be entered again.
	KeyUnreadable bool `json:"-"`
}

// Validate checks the CT settings.
func (c CT) Validate() error {
	if c.Source != "certspotter" && c.Source != "crtsh" {
		return errors.New("the source must be Cert Spotter or crt.sh")
	}
	if c.IntervalS < 15*60 || c.IntervalS > 24*3600 {
		return errors.New("the poll interval must be between 15 minutes and 24 hours")
	}
	return nil
}

// Settings is the full runtime configuration.
type Settings struct {
	General  General
	SignIn   SignIn
	Defaults Defaults
	Nodes    Nodes
	CT       CT
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
		Nodes:   Nodes{AutoUpdate: true},
		CT:      CT{Source: "certspotter", IntervalS: 3600},
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
	keyNodes    = "nodes"
	keyCT       = "ct"
	keyCTKey    = "ct.api_key"
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
	if err := s.load(ctx, keyNodes, &st.Nodes); err != nil {
		return st, err
	}
	if err := s.load(ctx, keyCT, &st.CT); err != nil {
		return st, err
	}
	var err error
	if st.CT.APIKey, st.CT.KeyUnreadable, err = s.loadSealed(ctx, keyCTKey); err != nil {
		return st, err
	}
	if st.SignIn.GoogleClientSecret, st.SignIn.SecretUnreadable, err = s.loadSealed(ctx, keySecret); err != nil {
		return st, err
	}
	stored := st.General
	applyEnv(&st)
	// Metrics switched on by the environment alone still need a token,
	// shown under Settings › General: one is made and kept once.
	if st.General.Metrics && st.General.MetricsToken == "" {
		stored.MetricsToken = NewToken()
		b, _ := json.Marshal(stored)
		if _, err := s.db.W.ExecContext(ctx, "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", keyGeneral, string(b)); err != nil {
			return st, err
		}
		st.General.MetricsToken = stored.MetricsToken
	}
	st.loc = st.Location()
	cp := st
	s.cached = &cp
	return st, nil
}

// loadSealed reads a value stored encrypted under the secret key: "" when
// none is stored, and "" with unreadable set when one is stored that the
// key cannot open (it was sealed under another key).
func (s *Store) loadSealed(ctx context.Context, key string) (value string, unreadable bool, err error) {
	var sealed string
	err = s.db.R.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) || err == nil && sealed == "" {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	pt, err := s.open(key, sealed)
	if err != nil {
		return "", true, nil
	}
	return string(pt), false, nil
}

// sealedKeys are the settings stored encrypted under the instance key.
var sealedKeys = []string{keySecret, keyCTKey}

// sealedNames names the sealed settings for people.
var sealedNames = map[string]string{keySecret: "Google client secret", keyCTKey: "CT API key"}

// HasSealed reports whether any setting is stored sealed: a database that
// needs its key.
func HasSealed(ctx context.Context, d *db.DB) (bool, error) {
	for _, k := range sealedKeys {
		var v string
		err := d.R.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", k).Scan(&v)
		if err == nil && v != "" {
			return true, nil
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
	}
	return false, nil
}

// SaveCT stores the Certificate Transparency settings; an empty key keeps
// the stored one unless clearKey is set.
func (s *Store) SaveCT(ctx context.Context, c CT, clearKey bool) error {
	if err := c.Validate(); err != nil {
		return usererr.Wrap(err)
	}
	if err := s.save(ctx, keyCT, c); err != nil {
		return err
	}
	switch {
	case clearKey:
		_, err := s.db.W.ExecContext(ctx, "DELETE FROM settings WHERE key = ?", keyCTKey)
		s.invalidate()
		return err
	case c.APIKey != "":
		b, _ := json.Marshal(s.key.Seal("settings:"+keyCTKey, []byte(c.APIKey)))
		_, err := s.db.W.ExecContext(ctx, "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", keyCTKey, string(b))
		s.invalidate()
		return err
	}
	return nil
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
	b, err := s.keepEnvLocked(ctx, key, v)
	if err != nil {
		return err
	}
	_, err = s.db.W.ExecContext(ctx, "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, string(b))
	s.invalidate()
	return err
}

// keepEnvLocked encodes v for the settings row key, with every field the
// environment sets taken from what is stored instead: a form shows the
// environment's value and posts it back, but that value belongs to the
// environment and must not outlive the variable in the database or land
// in a backup. Fields are matched by their JSON names, which are the
// override names.
func (s *Store) keepEnvLocked(ctx context.Context, key string, v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	locked := DefaultSettings()
	applyEnv(&locked)
	if len(locked.Env) == 0 {
		return b, nil
	}
	var in, stored map[string]json.RawMessage
	if err := json.Unmarshal(b, &in); err != nil {
		return b, nil // not an object: nothing to keep
	}
	var raw string
	err = s.db.R.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	_ = json.Unmarshal([]byte(raw), &stored)
	for name := range locked.Env {
		if _, ok := in[name]; !ok {
			continue
		}
		if old, ok := stored[name]; ok {
			in[name] = old
		} else {
			delete(in, name)
		}
	}
	return json.Marshal(in)
}

// Invalidate drops the cached settings, after the database was replaced.
func (s *Store) Invalidate() { s.invalidate() }

func (s *Store) invalidate() {
	s.mu.Lock()
	s.cached = nil
	s.mu.Unlock()
}

// Reencrypt re-seals every sealed setting from old to new within tx, for a
// key rotation or a restore. It returns how many it re-sealed and the names
// of those old could not open; those are left as they are.
func Reencrypt(ctx context.Context, tx *sql.Tx, old, new *secret.Key) (n int, unreadable []string, err error) {
	for _, k := range sealedKeys {
		var v string
		err := tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", k).Scan(&v)
		if errors.Is(err, sql.ErrNoRows) || err == nil && v == "" {
			continue
		}
		if err != nil {
			return n, unreadable, err
		}
		var raw []byte
		if err := json.Unmarshal([]byte(v), &raw); err != nil {
			return n, unreadable, err
		}
		pt, err := old.Open("settings:"+k, raw)
		if err != nil {
			// Sealed under yet another key: left as it is, and reported
			// as unreadable by Get.
			unreadable = append(unreadable, sealedNames[k])
			continue
		}
		b, _ := json.Marshal(new.Seal("settings:"+k, pt))
		if _, err := tx.ExecContext(ctx, "UPDATE settings SET value = ? WHERE key = ?", string(b), k); err != nil {
			return n, unreadable, err
		}
		n++
	}
	return n, unreadable, nil
}

func (s *Store) open(key, v string) ([]byte, error) {
	var raw []byte
	if err := json.Unmarshal([]byte(v), &raw); err != nil {
		return nil, err
	}
	return s.key.Open("settings:"+key, raw)
}

// SaveGeneral stores the general settings.
func (s *Store) SaveGeneral(ctx context.Context, g General) error {
	if err := g.Validate(); err != nil {
		return usererr.Wrap(err)
	}
	g.BaseURL = strings.TrimRight(g.BaseURL, "/")
	if g.Metrics && g.MetricsToken == "" {
		g.MetricsToken = NewToken()
	}
	return s.save(ctx, keyGeneral, g)
}

// NewToken is a fresh bearer token for /metrics: 32 random bytes, hex.
func NewToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
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
		b, _ := json.Marshal(s.key.Seal("settings:"+keySecret, []byte(si.GoogleClientSecret)))
		_, err := s.db.W.ExecContext(ctx, "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", keySecret, string(b))
		s.invalidate()
		return err
	}
	return nil
}

// SaveDefaults stores the global defaults.
func (s *Store) SaveDefaults(ctx context.Context, d Defaults) error {
	if err := d.Validate(); err != nil {
		return usererr.Wrap(err)
	}
	return s.save(ctx, keyDefaults, d)
}

// SaveNodes stores the node settings.
func (s *Store) SaveNodes(ctx context.Context, n Nodes) error { return s.save(ctx, keyNodes, n) }

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
		b, err := ParseBool(v)
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
	{"metrics", "TLSWATCH_METRICS", boolVar(func(st *Settings) *bool { return &st.General.Metrics })},
	{"metrics_token", "TLSWATCH_METRICS_TOKEN", func(st *Settings, v string) error {
		if len(v) < 16 {
			return errors.New("the metrics token must be at least 16 characters")
		}
		st.General.MetricsToken = v
		return nil
	}},
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
	for _, k := range []string{"TLSWATCH_LOG_JSON", "TLSWATCH_DEBUG", "TLSWATCH_ACCEPT_NEW_KEY"} {
		if v := os.Getenv(k); v != "" {
			if _, err := ParseBool(v); err != nil {
				errs = append(errs, fmt.Errorf("%s: %q is not true or false", k, v))
			}
		}
	}
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
