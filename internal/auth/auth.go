// Package auth handles local passwords, one-time links, server-side
// sessions and Google sign-in (OpenID Connect).
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

// Errors returned by the service. Login failures are deliberately neutral.
var (
	ErrInvalidCredentials = errors.New("invalid e-mail or password")
	ErrLocked             = errors.New("too many failed attempts; try again later")
	ErrDisabled           = errors.New("account disabled")
	ErrTokenInvalid       = errors.New("this link is invalid, used or expired")
	ErrNotAllowed         = errors.New("this account is not allowed to sign in here")
	ErrNotFound           = errors.New("user not found")
	ErrLastAdmin          = errors.New("at least one enabled admin must remain")
	ErrExists             = errors.New("a user with this e-mail already exists")
	ErrSetupDone          = errors.New("setup is already complete")
)

// Login methods.
const (
	MethodLocal  = "local"
	MethodGoogle = "google"
)

const (
	maxFailures     = 5
	lockDuration    = 15 * time.Minute
	ipMaxFailures   = 20
	ipWindow        = 15 * time.Minute
	defaultIdle     = 8 * time.Hour
	sessionTouchMin = 60 // seconds between last_seen updates
)

// User is a person who signs in.
type User struct {
	ID          int64
	Email       string
	Name        string
	Role        authz.Role
	Method      string
	Enabled     bool
	Theme       string
	LastLogin   int64
	CreatedAt   int64
	HasPassword bool
}

// DisplayName is the name, or the e-mail when no name is set.
func (u User) DisplayName() string {
	if u.Name != "" {
		return u.Name
	}
	return u.Email
}

// Service is the authentication service.
type Service struct {
	DB          *db.DB
	Key         *secret.Key
	Now         func() time.Time
	IdleTimeout time.Duration
	Breached    *Breached

	mu      sync.Mutex
	ipFails map[string][]int64
}

// New returns a service with defaults.
func New(d *db.DB, k *secret.Key) *Service {
	return &Service{DB: d, Key: k, Now: time.Now, IdleTimeout: defaultIdle, Breached: DefaultBreached()}
}

func (s *Service) now() int64 { return s.Now().Unix() }

const userCols = "id, email, name, role, method, password_hash, enabled, theme, last_login, created_at"

type rowScanner interface{ Scan(...any) error }

func scanUser(r rowScanner) (User, string, error) {
	var u User
	var hash, role string
	var enabled int
	err := r.Scan(&u.ID, &u.Email, &u.Name, &role, &u.Method, &hash, &enabled, &u.Theme, &u.LastLogin, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return u, "", ErrNotFound
	}
	u.Role = authz.Role(role)
	u.Enabled = enabled == 1
	u.HasPassword = hash != ""
	return u, hash, err
}

// NormalizeEmail validates and lowercases an e-mail address.
func NormalizeEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	a, err := mail.ParseAddress(email)
	if err != nil || a.Address != email || !strings.Contains(email, "@") {
		return "", fmt.Errorf("%q is not a valid e-mail address", email)
	}
	return strings.ToLower(email), nil
}

func validMethod(m string) bool { return m == MethodLocal || m == MethodGoogle }

// CreateUser adds a user without a password.
func (s *Service) CreateUser(ctx context.Context, email, name string, role authz.Role, method string) (User, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	if _, err := authz.ParseRole(string(role)); err != nil {
		return User{}, err
	}
	if !validMethod(method) {
		return User{}, fmt.Errorf("unknown login method %q", method)
	}
	name = strings.TrimSpace(name)
	res, err := s.DB.W.ExecContext(ctx,
		`INSERT INTO users (email, name, role, method, created_at) VALUES (?, ?, ?, ?, ?)`,
		email, name, string(role), method, s.now())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, ErrExists
		}
		return User{}, err
	}
	id, _ := res.LastInsertId()
	return s.UserByID(ctx, id)
}

// UserByID loads a user.
func (s *Service) UserByID(ctx context.Context, id int64) (User, error) {
	u, _, err := scanUser(s.DB.R.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE id = ?", id))
	return u, err
}

// UserByEmail loads a user by e-mail, case-insensitively.
func (s *Service) UserByEmail(ctx context.Context, email string) (User, error) {
	u, _, err := scanUser(s.DB.R.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE email = ?", strings.TrimSpace(email)))
	return u, err
}

// ListUsers returns all users by name.
func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.DB.R.QueryContext(ctx, "SELECT "+userCols+" FROM users ORDER BY lower(name), email")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, _, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountUsers returns the number of users.
func (s *Service) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.DB.R.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&n)
	return n, err
}

// UpdateUser changes a user's name, role, method and status. Disabling a
// user ends their sessions; switching to Google removes the password. The
// last enabled admin can be neither demoted nor disabled.
func (s *Service) UpdateUser(ctx context.Context, id int64, name string, role authz.Role, method string, enabled bool) error {
	if _, err := authz.ParseRole(string(role)); err != nil {
		return err
	}
	if !validMethod(method) {
		return fmt.Errorf("unknown login method %q", method)
	}
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var curRole string
	var curEnabled int
	if err := tx.QueryRowContext(ctx, "SELECT role, enabled FROM users WHERE id = ?", id).Scan(&curRole, &curEnabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if curRole == string(authz.Admin) && curEnabled == 1 && (role != authz.Admin || !enabled) {
		var admins int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM users WHERE role = 'admin' AND enabled = 1").Scan(&admins); err != nil {
			return err
		}
		if admins <= 1 {
			return ErrLastAdmin
		}
	}
	q := "UPDATE users SET name = ?, role = ?, method = ?, enabled = ? WHERE id = ?"
	if method == MethodGoogle {
		q = "UPDATE users SET name = ?, role = ?, method = ?, enabled = ?, password_hash = '' WHERE id = ?"
	}
	if _, err := tx.ExecContext(ctx, q, strings.TrimSpace(name), string(role), method, boolInt(enabled), id); err != nil {
		return err
	}
	if !enabled {
		if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = ?", id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetPassword checks the policy and stores a new password hash. It also
// clears a lockout.
func (s *Service) SetPassword(ctx context.Context, id int64, pw string) error {
	u, err := s.UserByID(ctx, id)
	if err != nil {
		return err
	}
	if u.Method != MethodLocal {
		return errors.New("this account signs in with Google and has no password")
	}
	if err := s.CheckPasswordPolicy(pw, u.Email); err != nil {
		return err
	}
	h, err := HashPassword(pw)
	if err != nil {
		return err
	}
	_, err = s.DB.W.ExecContext(ctx, "UPDATE users SET password_hash = ?, failed_count = 0, locked_until = 0 WHERE id = ?", h, id)
	return err
}

// SetTheme stores the user's theme choice.
func (s *Service) SetTheme(ctx context.Context, id int64, theme string) error {
	switch theme {
	case "system", "light", "dark":
	default:
		return fmt.Errorf("unknown theme %q", theme)
	}
	_, err := s.DB.W.ExecContext(ctx, "UPDATE users SET theme = ? WHERE id = ?", theme, id)
	return err
}

// SetName changes the user's display name.
func (s *Service) SetName(ctx context.Context, id int64, name string) error {
	_, err := s.DB.W.ExecContext(ctx, "UPDATE users SET name = ? WHERE id = ?", strings.TrimSpace(name), id)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Login checks a local e-mail and password. Every failure that could reveal
// whether the account exists returns ErrInvalidCredentials.
func (s *Service) Login(ctx context.Context, email, pw, ip string) (User, error) {
	now := s.now()
	if s.ipBlocked(ip, now) {
		return User{}, ErrLocked
	}
	row := s.DB.R.QueryRowContext(ctx, "SELECT "+userCols+", failed_count, locked_until FROM users WHERE email = ?", strings.TrimSpace(email))
	var u User
	var hash, role string
	var enabled, failed int
	var lockedUntil int64
	err := row.Scan(&u.ID, &u.Email, &u.Name, &role, &u.Method, &hash, &enabled, &u.Theme, &u.LastLogin, &u.CreatedAt, &failed, &lockedUntil)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (u.Method != MethodLocal || hash == "")) {
		VerifyPassword(dummyHash(), pw)
		s.ipFail(ip, now)
		return User{}, ErrInvalidCredentials
	}
	if err != nil {
		return User{}, err
	}
	u.Role = authz.Role(role)
	u.Enabled = enabled == 1
	u.HasPassword = true
	if lockedUntil > now {
		VerifyPassword(dummyHash(), pw)
		return User{}, ErrLocked
	}
	if !VerifyPassword(hash, pw) {
		s.ipFail(ip, now)
		failed++
		lock := int64(0)
		if failed >= maxFailures {
			lock = now + int64(lockDuration/time.Second)
			failed = 0
		}
		if _, err := s.DB.W.ExecContext(ctx, "UPDATE users SET failed_count = ?, locked_until = ? WHERE id = ?", failed, lock, u.ID); err != nil {
			return User{}, err
		}
		if lock > 0 {
			return User{}, ErrLocked
		}
		return User{}, ErrInvalidCredentials
	}
	if !u.Enabled {
		return User{}, ErrInvalidCredentials
	}
	if _, err := s.DB.W.ExecContext(ctx, "UPDATE users SET failed_count = 0, locked_until = 0 WHERE id = ?", u.ID); err != nil {
		return User{}, err
	}
	return u, nil
}

func (s *Service) ipBlocked(ip string, now int64) bool {
	if ip == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pruneIP(ip, now)) >= ipMaxFailures
}

func (s *Service) ipFail(ip string, now int64) {
	if ip == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ipFails == nil {
		s.ipFails = map[string][]int64{}
	}
	s.ipFails[ip] = append(s.pruneIP(ip, now), now)
	if len(s.ipFails) > 10000 { // bound memory under a spray of addresses
		for k := range s.ipFails {
			if len(s.pruneIP(k, now)) == 0 {
				delete(s.ipFails, k)
			}
		}
	}
}

// pruneIP drops failures older than the window; s.mu must be held.
func (s *Service) pruneIP(ip string, now int64) []int64 {
	cut := now - int64(ipWindow/time.Second)
	fails := s.ipFails[ip]
	i := 0
	for i < len(fails) && fails[i] <= cut {
		i++
	}
	fails = fails[i:]
	if s.ipFails != nil {
		if len(fails) == 0 {
			delete(s.ipFails, ip)
		} else {
			s.ipFails[ip] = fails
		}
	}
	return fails
}
