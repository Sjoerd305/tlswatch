package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP is HMAC-SHA-1, which authenticator apps expect
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/secret"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// TOTP parameters (RFC 6238): HMAC-SHA-1, 6 digits, 30-second steps, one
// step of drift either way.
const (
	totpPeriod  = 30
	totpDigits  = 6
	totpDrift   = 1
	totpSecretN = 20 // bytes, the size of an SHA-1 block output

	// RecoveryCodes is how many single-use recovery codes a user gets.
	RecoveryCodes = 10

	// totpSetupTTL is how long a QR code shown for setup stays usable.
	totpSetupTTL = 15 * time.Minute
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// totpCode is the code of a secret at a time step.
func totpCode(key []byte, step int64) string {
	m := hmac.New(sha1.New, key)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- a time step is positive
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

// totpStep matches code against the steps around now and returns the one
// it belongs to, or 0. A step at or before last was used already.
func totpStep(key []byte, code string, now, last int64) int64 {
	cur := now / totpPeriod
	for step := cur - totpDrift; step <= cur+totpDrift; step++ {
		if step > last && subtle.ConstantTimeCompare([]byte(totpCode(key, step)), []byte(code)) == 1 {
			return step
		}
	}
	return 0
}

// TOTPSetup is a secret offered for setup: shown as a QR code and as
// text, and carried sealed in the form until the user confirms it with a
// code.
type TOTPSetup struct {
	Secret string // base32, for typing in by hand
	URI    string // otpauth:// URI, for the QR code
	Sealed string // for the form
}

type pendingTOTP struct {
	Secret  []byte `json:"s"`
	Expires int64  `json:"e"`
}

func pendingContext(userID int64) string { return "totp.pending:" + strconv.FormatInt(userID, 10) }

func totpContext(userID int64) string { return "users.totp:" + strconv.FormatInt(userID, 10) }

// BeginTOTP makes a new secret for a user to set up. Nothing is stored
// until ConfirmTOTP.
func (s *Service) BeginTOTP(u User, issuer string) (TOTPSetup, error) {
	if u.Method != MethodLocal {
		return TOTPSetup{}, usererr.New("Two-factor sign-in is for accounts with a password; single sign-on has its own.")
	}
	key := make([]byte, totpSecretN)
	if _, err := rand.Read(key); err != nil {
		return TOTPSetup{}, err
	}
	return s.totpSetup(u, issuer, pendingTOTP{Secret: key, Expires: s.Now().Add(totpSetupTTL).Unix()}), nil
}

// ReopenTOTP shows a setup again, after a wrong code, so the user does not
// scan a new QR code.
func (s *Service) ReopenTOTP(u User, issuer, sealed string) (TOTPSetup, error) {
	p, err := s.openPending(u.ID, sealed)
	if err != nil {
		return TOTPSetup{}, err
	}
	return s.totpSetup(u, issuer, p), nil
}

func (s *Service) totpSetup(u User, issuer string, p pendingTOTP) TOTPSetup {
	b, _ := json.Marshal(p) // #nosec G117 -- sealed below, never sent in the clear
	enc := b32.EncodeToString(p.Secret)
	q := url.Values{"secret": {enc}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {strconv.Itoa(totpDigits)}, "period": {strconv.Itoa(totpPeriod)}}
	uri := "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(u.Email) + "?" + q.Encode()
	return TOTPSetup{Secret: enc, URI: uri, Sealed: base64.RawURLEncoding.EncodeToString(s.Key.Seal(pendingContext(u.ID), b))}
}

func (s *Service) openPending(userID int64, sealed string) (pendingTOTP, error) {
	var p pendingTOTP
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return p, ErrSetupExpired
	}
	b, err := s.Key.Open(pendingContext(userID), raw)
	if err != nil {
		return p, ErrSetupExpired
	}
	if json.Unmarshal(b, &p) != nil || p.Expires < s.now() || len(p.Secret) != totpSecretN {
		return pendingTOTP{}, ErrSetupExpired
	}
	return p, nil
}

// ErrSetupExpired is returned when the QR code shown for setup is too old
// or was made for someone else.
var ErrSetupExpired = usererr.New("This setup has expired. Scan the new QR code.")

// ErrCodeMismatch is returned when the code entered at setup is not the
// secret's.
var ErrCodeMismatch = usererr.New("The code does not match. Check that the time on your phone is right, and enter the code the app shows now.")

// ConfirmTOTP turns TOTP on for the user once code matches the secret of
// the setup, replacing any earlier secret, and returns new recovery codes.
func (s *Service) ConfirmTOTP(ctx context.Context, u User, sealed, code string) ([]string, error) {
	p, err := s.openPending(u.ID, sealed)
	if err != nil {
		return nil, err
	}
	step := totpStep(p.Secret, normalizeCode(code), s.now(), 0)
	if step == 0 {
		return nil, ErrCodeMismatch
	}
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "UPDATE users SET totp_sealed = ?, totp_since = ?, totp_last_step = ? WHERE id = ? AND method = ?",
		s.Key.Seal(totpContext(u.ID), p.Secret), s.now(), step, u.ID, MethodLocal)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	codes, err := newRecoveryCodes(ctx, tx, u.ID)
	if err != nil {
		return nil, err
	}
	return codes, tx.Commit()
}

// ResetTOTP turns TOTP off for a user and drops the recovery codes.
func (s *Service) ResetTOTP(ctx context.Context, id int64) error {
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE users SET totp_sealed = NULL, totp_since = 0, totp_last_step = 0 WHERE id = ?", id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM recovery_codes WHERE user_id = ?", id); err != nil {
		return err
	}
	return tx.Commit()
}

// NewRecoveryCodes replaces a user's recovery codes.
func (s *Service) NewRecoveryCodes(ctx context.Context, id int64) ([]string, error) {
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	codes, err := newRecoveryCodes(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	return codes, tx.Commit()
}

// RecoveryCodesLeft is the number of unused recovery codes of a user.
func (s *Service) RecoveryCodesLeft(ctx context.Context, id int64) (int, error) {
	var n int
	err := s.DB.R.QueryRowContext(ctx, "SELECT count(*) FROM recovery_codes WHERE user_id = ? AND used_at = 0", id).Scan(&n)
	return n, err
}

// recoveryAlphabet leaves out the letters and digits read as one another.
const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

func newRecoveryCodes(ctx context.Context, tx *sql.Tx, id int64) ([]string, error) {
	if _, err := tx.ExecContext(ctx, "DELETE FROM recovery_codes WHERE user_id = ?", id); err != nil {
		return nil, err
	}
	codes := make([]string, 0, RecoveryCodes)
	for range RecoveryCodes {
		// 12 characters of 31: about 59 bits, three groups of four.
		var c strings.Builder
		for n := 0; n < 12; {
			var b [1]byte
			if _, err := rand.Read(b[:]); err != nil {
				return nil, err
			}
			if int(b[0]) >= 256/len(recoveryAlphabet)*len(recoveryAlphabet) {
				continue // keeps every character equally likely
			}
			if n > 0 && n%4 == 0 {
				c.WriteByte('-')
			}
			c.WriteByte(recoveryAlphabet[int(b[0])%len(recoveryAlphabet)])
			n++
		}
		codes = append(codes, c.String())
		if _, err := tx.ExecContext(ctx, "INSERT INTO recovery_codes (user_id, hash) VALUES (?, ?)", id, hashToken(normalizeCode(c.String()))); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

// normalizeCode drops what people type around a code: spaces, dashes and
// capitals.
func normalizeCode(code string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '\t' {
			return -1
		}
		return r
	}, code))
}

// LoginCode completes a sign-in that Login answered with ErrSecondFactor:
// code is the current TOTP code or an unused recovery code. A wrong code
// counts towards the lockout like a wrong password. recovery reports that
// a recovery code was used, and was spent.
func (s *Service) LoginCode(ctx context.Context, id int64, code, ip string) (u User, recovery bool, err error) {
	now := s.now()
	if s.ipBlocked(ip, now) {
		return User{}, false, ErrLocked
	}
	var failed int
	var lockedUntil, lastStep int64
	var sealed []byte
	u, _, err = scanUser(s.DB.R.QueryRowContext(ctx, "SELECT "+userCols+", failed_count, locked_until, totp_sealed, totp_last_step FROM users WHERE id = ?", id),
		&failed, &lockedUntil, &sealed, &lastStep)
	if errors.Is(err, ErrNotFound) || err == nil && (!u.Enabled || u.Method != MethodLocal || !u.HasTOTP()) {
		// Changed since the password was checked: start again.
		return User{}, false, ErrTokenInvalid
	}
	if err != nil {
		return User{}, false, err
	}
	if lockedUntil > now && !s.spared(u.ID, ip, failed) {
		return User{}, false, ErrLocked
	}
	ok, recovery, err := s.checkCode(ctx, u.ID, sealed, lastStep, normalizeCode(code), now)
	if err != nil {
		return User{}, false, err
	}
	if !ok {
		s.ipFail(ip, now)
		return User{}, false, s.countFailure(ctx, u.ID, ip, now, ErrInvalidCode)
	}
	if err := s.signedIn(ctx, u.ID, ip); err != nil {
		return User{}, false, err
	}
	return u, recovery, nil
}

// checkCode checks a normalised code, spending it: a TOTP code moves the
// last accepted step on, a recovery code is marked used. Each update is
// conditional, so a code used twice at once is accepted once.
func (s *Service) checkCode(ctx context.Context, id int64, sealed []byte, lastStep int64, code string, now int64) (ok, recovery bool, err error) {
	if len(code) == totpDigits && strings.Trim(code, "0123456789") == "" {
		key, err := s.Key.Open(totpContext(id), sealed)
		if err != nil {
			return false, false, fmt.Errorf("open TOTP secret of user %d: %w", id, err)
		}
		step := totpStep(key, code, now, lastStep)
		if step == 0 {
			return false, false, nil
		}
		res, err := s.DB.W.ExecContext(ctx, "UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?", step, id, step)
		if err != nil {
			return false, false, err
		}
		n, _ := res.RowsAffected()
		return n == 1, false, nil
	}
	if code == "" {
		return false, false, nil
	}
	res, err := s.DB.W.ExecContext(ctx, "UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND hash = ? AND used_at = 0", now, id, hashToken(code))
	if err != nil {
		return false, false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, n == 1, nil
}

// MFAState is what the browser carries between the password and the code,
// sealed in a short-lived cookie.
type MFAState struct {
	UserID  int64  `json:"u"`
	Next    string `json:"n"`
	Expires int64  `json:"e"`
}

// mfaTTL is how long the code may take after the password.
const mfaTTL = 5 * time.Minute

// SealMFA seals the state of a sign-in waiting for its code.
func (s *Service) SealMFA(userID int64, next string) string {
	b, _ := json.Marshal(MFAState{UserID: userID, Next: next, Expires: s.Now().Add(mfaTTL).Unix()})
	return base64.RawURLEncoding.EncodeToString(s.Key.Seal("mfa.state", b))
}

// OpenMFA opens and checks a sealed sign-in state.
func (s *Service) OpenMFA(v string) (MFAState, error) {
	var st MFAState
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return st, ErrTokenInvalid
	}
	b, err := s.Key.Open("mfa.state", raw)
	if err != nil || json.Unmarshal(b, &st) != nil || st.Expires < s.now() || st.UserID == 0 {
		return MFAState{}, ErrTokenInvalid
	}
	return st, nil
}

// ReencryptTOTP re-seals the TOTP secrets from old to new within tx, for a
// key rotation or a restore. A secret old cannot open is dropped with the
// recovery codes: that user signs in with the password alone until they
// set TOTP up again. It returns how many it re-sealed and the e-mail
// addresses of those dropped.
func ReencryptTOTP(ctx context.Context, tx *sql.Tx, old, new *secret.Key) (n int, dropped []string, err error) {
	rows, err := tx.QueryContext(ctx, "SELECT id, email, totp_sealed FROM users WHERE totp_sealed IS NOT NULL")
	if err != nil {
		return 0, nil, err
	}
	type row struct {
		id    int64
		email string
		blob  []byte
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.email, &r.blob); err != nil {
			rows.Close()
			return 0, nil, err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	for _, r := range all {
		pt, err := old.Open(totpContext(r.id), r.blob)
		if err != nil {
			for _, q := range []string{"UPDATE users SET totp_sealed = NULL, totp_since = 0, totp_last_step = 0 WHERE id = ?", "DELETE FROM recovery_codes WHERE user_id = ?"} {
				if _, err := tx.ExecContext(ctx, q, r.id); err != nil {
					return n, dropped, err
				}
			}
			dropped = append(dropped, r.email)
			continue
		}
		if _, err := tx.ExecContext(ctx, "UPDATE users SET totp_sealed = ? WHERE id = ?", new.Seal(totpContext(r.id), pt), r.id); err != nil {
			return n, dropped, err
		}
		n++
	}
	return n, dropped, nil
}
