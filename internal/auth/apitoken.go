package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// API tokens authenticate the public REST API (/api/v2) as
// "Authorization: Bearer <token>". They never sign anyone in to the
// browser UI, and a session cookie never works for the API.

// APITokenPrefix starts every API token, so a leaked one is recognisable
// in a log or a secret scanner.
const APITokenPrefix = "tlsw_"

// API token lifetimes: at least MinAPITokenTTL and at most MaxAPITokenTTL;
// only admins may make one without expiry.
const (
	MinAPITokenTTL = 30 * 24 * time.Hour
	MaxAPITokenTTL = 366 * 24 * time.Hour
	// apiTokenTouch is how often a token's last use is written.
	apiTokenTouch = 60
)

// ErrNoAPIToken is returned for an unknown, expired or revoked token, or
// one of a disabled user.
var ErrNoAPIToken = errors.New("invalid or expired API token")

// APIToken is one token as the Account page lists it.
type APIToken struct {
	ID        int64
	UserID    int64
	Name      string
	Prefix    string // the first characters, to tell tokens apart
	Role      authz.Role
	ExpiresAt int64 // 0: never
	CreatedAt int64
	LastUsed  int64
	LastIP    string
}

// Expired reports whether the token has expired at now.
func (t APIToken) Expired(now int64) bool { return t.ExpiresAt > 0 && t.ExpiresAt <= now }

// APISession is a request authenticated by an API token: the token, its
// user, and the role in force, the lower of the token's and the user's.
type APISession struct {
	Token APIToken
	User  User
	Role  authz.Role
}

const apiTokenCols = "id, user_id, name, prefix, role, expires_at, created_at, last_used, last_ip" // #nosec G101 -- column names, not a credential

func scanAPIToken(r rowScanner) (APIToken, error) {
	var t APIToken
	var role string
	err := r.Scan(&t.ID, &t.UserID, &t.Name, &t.Prefix, &role, &t.ExpiresAt, &t.CreatedAt, &t.LastUsed, &t.LastIP)
	t.Role = authz.Role(role)
	return t, err
}

// CreateAPIToken makes a token for u and returns it with its raw value,
// which is shown once; only its hash is kept. The role may be no higher
// than the user's; ttl 0 is no expiry, which only an admin may choose.
func (s *Service) CreateAPIToken(ctx context.Context, u User, name string, role authz.Role, ttl time.Duration) (APIToken, string, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return APIToken{}, "", usererr.New("Give the token a name, such as the system that uses it")
	case utf8.RuneCountInString(name) > 80:
		return APIToken{}, "", usererr.New("The name is limited to 80 characters")
	}
	if _, err := authz.ParseRole(string(role)); err != nil {
		return APIToken{}, "", usererr.New(fmt.Sprintf("Unknown role %q", role))
	}
	if !authz.AtMost(role, u.Role) {
		return APIToken{}, "", usererr.New("A token's role can be no higher than your own")
	}
	switch {
	case ttl == 0 && u.Role != authz.Admin:
		return APIToken{}, "", usererr.New("Only admins can make a token that does not expire")
	case ttl != 0 && (ttl < MinAPITokenTTL || ttl > MaxAPITokenTTL):
		return APIToken{}, "", usererr.New("A token expires after 30 days to 1 year")
	}
	raw := APITokenPrefix + randomToken()
	now := s.now()
	t := APIToken{UserID: u.ID, Name: name, Prefix: raw[:len(APITokenPrefix)+6], Role: role, CreatedAt: now}
	if ttl > 0 {
		t.ExpiresAt = now + int64(ttl/time.Second)
	}
	var count int
	if err := s.DB.R.QueryRowContext(ctx, "SELECT COUNT(*) FROM api_tokens WHERE user_id = ?", u.ID).Scan(&count); err != nil {
		return APIToken{}, "", err
	}
	if count >= 50 {
		return APIToken{}, "", usererr.New("You have 50 tokens; revoke one you no longer use first")
	}
	res, err := s.DB.W.ExecContext(ctx, "INSERT INTO api_tokens(user_id, name, hash, prefix, role, expires_at, created_at) VALUES(?,?,?,?,?,?,?)",
		u.ID, t.Name, hashToken(raw), t.Prefix, string(role), t.ExpiresAt, now)
	if err != nil {
		return APIToken{}, "", err
	}
	t.ID, err = res.LastInsertId()
	return t, raw, err
}

// APITokens lists a user's tokens, newest first.
func (s *Service) APITokens(ctx context.Context, userID int64) ([]APIToken, error) {
	rows, err := s.DB.R.QueryContext(ctx, "SELECT "+apiTokenCols+" FROM api_tokens WHERE user_id = ? ORDER BY id DESC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteAPIToken revokes one of a user's tokens.
func (s *Service) DeleteAPIToken(ctx context.Context, userID, id int64) (APIToken, error) {
	t, err := scanAPIToken(s.DB.R.QueryRowContext(ctx, "SELECT "+apiTokenCols+" FROM api_tokens WHERE id = ? AND user_id = ?", id, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	if err != nil {
		return t, err
	}
	_, err = s.DB.W.ExecContext(ctx, "DELETE FROM api_tokens WHERE id = ? AND user_id = ?", id, userID)
	return t, err
}

// APIAuth looks up the token of an API request. A token of a disabled
// user, or past its expiry, opens nothing; the role in force is the lower
// of the token's and the user's current one, so demoting a user demotes
// their tokens. The last use is written at most once a minute.
func (s *Service) APIAuth(ctx context.Context, raw, ip string) (*APISession, error) {
	if !strings.HasPrefix(raw, APITokenPrefix) || len(raw) > 200 {
		return nil, ErrNoAPIToken
	}
	// #nosec G202 -- prefixed joins constant column names
	row := s.DB.R.QueryRowContext(ctx, "SELECT "+prefixed("a.", apiTokenCols)+", "+prefixed("u.", userCols)+
		" FROM api_tokens a JOIN users u ON u.id = a.user_id WHERE a.hash = ?", hashToken(raw))
	var t APIToken
	var role string
	u, _, err := scanUser(scanFirst{row, []any{&t.ID, &t.UserID, &t.Name, &t.Prefix, &role, &t.ExpiresAt, &t.CreatedAt, &t.LastUsed, &t.LastIP}})
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNoAPIToken
	}
	if err != nil {
		return nil, err
	}
	t.Role = authz.Role(role)
	now := s.now()
	if !u.Enabled || t.Expired(now) {
		return nil, ErrNoAPIToken
	}
	if now-t.LastUsed >= apiTokenTouch || t.LastIP != ip {
		if _, err := s.DB.W.ExecContext(ctx, "UPDATE api_tokens SET last_used = ?, last_ip = ? WHERE id = ?", now, ip, t.ID); err != nil {
			return nil, err
		}
		t.LastUsed, t.LastIP = now, ip
	}
	return &APISession{Token: t, User: u, Role: authz.Lower(t.Role, u.Role)}, nil
}

// scanFirst scans columns into lead before the ones the caller passes, so
// scanUser can read a row whose user columns come after others.
type scanFirst struct {
	r    rowScanner
	lead []any
}

func (s scanFirst) Scan(dest ...any) error { return s.r.Scan(append(s.lead, dest...)...) }
