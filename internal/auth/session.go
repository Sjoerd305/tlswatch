package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
)

// Token kinds.
const (
	TokenInvite = "invite"

	// InviteTTL is how long an invitation or password link stays valid.
	InviteTTL = 7 * 24 * time.Hour
)

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// CreateToken stores a one-time token and returns its raw value. Creating an
// invite invalidates earlier unused invites for the same user.
func (s *Service) CreateToken(ctx context.Context, kind string, userID int64, ttl time.Duration) (string, error) {
	if kind != TokenInvite {
		return "", errors.New("unknown token kind")
	}
	raw := randomToken()
	now := s.now()
	var uid any
	if userID > 0 {
		uid = userID
		if _, err := s.DB.W.ExecContext(ctx, "UPDATE tokens SET used_at = ? WHERE kind = ? AND user_id = ? AND used_at = 0", now, kind, userID); err != nil {
			return "", err
		}
	}
	_, err := s.DB.W.ExecContext(ctx,
		"INSERT INTO tokens (hash, kind, user_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
		hashToken(raw), kind, uid, now+int64(ttl/time.Second), now)
	if err != nil {
		return "", err
	}
	return raw, nil
}

// PeekToken checks a token without using it.
func (s *Service) PeekToken(ctx context.Context, kind, raw string) (int64, error) {
	var uid sql.NullInt64
	err := s.DB.R.QueryRowContext(ctx,
		"SELECT user_id FROM tokens WHERE hash = ? AND kind = ? AND used_at = 0 AND expires_at > ?",
		hashToken(raw), kind, s.now()).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrTokenInvalid
	}
	return uid.Int64, err
}

// UseToken marks a token used and returns its user; it fails when the token
// was already used, expired or never existed.
func (s *Service) UseToken(ctx context.Context, kind, raw string) (int64, error) {
	now := s.now()
	var uid sql.NullInt64
	err := s.DB.W.QueryRowContext(ctx,
		"UPDATE tokens SET used_at = ? WHERE hash = ? AND kind = ? AND used_at = 0 AND expires_at > ? RETURNING user_id",
		now, hashToken(raw), kind, now).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrTokenInvalid
	}
	return uid.Int64, err
}

// CreateFirstAdmin creates the first admin with a password. It only works
// while no user exists; the check and the insert run in one write
// transaction, so two browsers racing on the setup screen cannot both
// become admin.
func (s *Service) CreateFirstAdmin(ctx context.Context, email, name, pw string) (User, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	if err := s.CheckPasswordPolicy(pw, email); err != nil {
		return User{}, err
	}
	hash, err := HashPassword(pw)
	if err != nil {
		return User{}, err
	}
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n); err != nil {
		return User{}, err
	}
	if n > 0 {
		return User{}, ErrSetupDone
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO users(email, name, role, method, password_hash, enabled, created_at)
		VALUES(?, ?, ?, ?, ?, 1, ?)`, email, strings.TrimSpace(name), string(authz.Admin), MethodLocal, hash, s.now())
	if err != nil {
		return User{}, err
	}
	id, _ := res.LastInsertId()
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return s.UserByID(ctx, id)
}

// Session is a signed-in browser.
type Session struct {
	Hash      string
	User      User
	CSRF      string
	CreatedAt int64
	LastSeen  int64
}

// NewSession starts a session and returns the cookie value and CSRF token.
func (s *Service) NewSession(ctx context.Context, userID int64) (string, string, error) {
	raw, csrf := randomToken(), randomToken()
	now := s.now()
	if _, err := s.DB.W.ExecContext(ctx,
		"INSERT INTO sessions (hash, user_id, csrf, created_at, last_seen) VALUES (?, ?, ?, ?, ?)",
		hashToken(raw), userID, csrf, now, now); err != nil {
		return "", "", err
	}
	if _, err := s.DB.W.ExecContext(ctx, "UPDATE users SET last_login = ? WHERE id = ?", now, userID); err != nil {
		return "", "", err
	}
	return raw, csrf, nil
}

// ErrNoSession is returned for a missing, expired or revoked session.
var ErrNoSession = errors.New("no valid session")

// Session loads the session for a cookie value.
func (s *Service) Session(ctx context.Context, raw string) (*Session, error) {
	if raw == "" {
		return nil, ErrNoSession
	}
	h := hashToken(raw)
	row := s.DB.R.QueryRowContext(ctx,
		"SELECT s.csrf, s.created_at, s.last_seen, "+prefixed("u.", userCols)+" FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.hash = ?", h)
	sess := &Session{Hash: h}
	var hash, role string
	var enabled int
	u := &sess.User
	err := row.Scan(&sess.CSRF, &sess.CreatedAt, &sess.LastSeen,
		&u.ID, &u.Email, &u.Name, &role, &u.Method, &hash, &enabled, &u.Theme, &u.LastLogin, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	u.Role, u.Enabled, u.HasPassword = authz.Role(role), enabled == 1, hash != ""
	now := s.now()
	if !u.Enabled || now-sess.LastSeen > int64(s.IdleTimeout/time.Second) {
		_, _ = s.DB.W.ExecContext(ctx, "DELETE FROM sessions WHERE hash = ?", h)
		return nil, ErrNoSession
	}
	if now-sess.LastSeen >= sessionTouchMin {
		if _, err := s.DB.W.ExecContext(ctx, "UPDATE sessions SET last_seen = ? WHERE hash = ?", now, h); err != nil {
			return nil, err
		}
		sess.LastSeen = now
	}
	return sess, nil
}

func prefixed(p, cols string) string {
	parts := strings.Split(cols, ", ")
	for i, c := range parts {
		parts[i] = p + c
	}
	return strings.Join(parts, ", ")
}

// DeleteSession ends one session (sign out).
func (s *Service) DeleteSession(ctx context.Context, raw string) error {
	_, err := s.DB.W.ExecContext(ctx, "DELETE FROM sessions WHERE hash = ?", hashToken(raw))
	return err
}

// DeleteUserSessions ends every session of a user.
func (s *Service) DeleteUserSessions(ctx context.Context, userID int64) error {
	_, err := s.DB.W.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = ?", userID)
	return err
}

// PruneSessions removes idle sessions and spent tokens.
func (s *Service) PruneSessions(ctx context.Context) error {
	now := s.now()
	if _, err := s.DB.W.ExecContext(ctx, "DELETE FROM sessions WHERE last_seen < ?", now-int64(s.IdleTimeout/time.Second)); err != nil {
		return err
	}
	_, err := s.DB.W.ExecContext(ctx, "DELETE FROM tokens WHERE expires_at < ? OR (used_at > 0 AND used_at < ?)", now-86400, now-86400)
	return err
}
