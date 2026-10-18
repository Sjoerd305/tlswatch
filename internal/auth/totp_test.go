package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

// The test vectors of RFC 6238, appendix B (SHA-1), cut to six digits.
func TestTOTPVectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, tc := range []struct {
		at   int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		if got := totpCode(key, tc.at/totpPeriod); got != tc.want {
			t.Errorf("T=%d: %s, want %s", tc.at, got, tc.want)
		}
	}
}

// enableTOTP sets TOTP up for u and returns the secret and recovery codes.
func enableTOTP(t *testing.T, s *Service, u User) ([]byte, []string) {
	t.Helper()
	setup, err := s.BeginTOTP(u, "tlswatch")
	if err != nil {
		t.Fatal(err)
	}
	key, err := b32.DecodeString(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(setup.URI, "otpauth://totp/tlswatch:") || !strings.Contains(setup.URI, "secret="+setup.Secret) {
		t.Fatalf("uri: %s", setup.URI)
	}
	ctx := context.Background()
	if _, err := s.ConfirmTOTP(ctx, u, setup.Sealed, "000000"+"x"); !errors.Is(err, ErrCodeMismatch) {
		t.Fatalf("wrong code at setup: %v", err)
	}
	codes, err := s.ConfirmTOTP(ctx, u, setup.Sealed, totpCode(key, s.Now().Unix()/totpPeriod))
	if err != nil || len(codes) != RecoveryCodes {
		t.Fatalf("confirm: %v %v", codes, err)
	}
	return key, codes
}

func TestTOTPSetup(t *testing.T) {
	s, c := newService(t)
	ctx := context.Background()
	u := mkLocal(t, s, "a@example.nl", authz.Admin)
	other := mkLocal(t, s, "b@example.nl", authz.Viewer)
	setup, _ := s.BeginTOTP(u, "tlswatch")
	key, _ := b32.DecodeString(setup.Secret)
	code := totpCode(key, s.Now().Unix()/totpPeriod)
	// A setup made for one user does not set up another.
	if _, err := s.ConfirmTOTP(ctx, other, setup.Sealed, code); !errors.Is(err, ErrSetupExpired) {
		t.Fatalf("other user's setup: %v", err)
	}
	reopened, err := s.ReopenTOTP(u, "tlswatch", setup.Sealed)
	if err != nil || reopened.Secret != setup.Secret {
		t.Fatalf("reopen: %v", err)
	}
	c.add(16 * time.Minute)
	if _, err := s.ConfirmTOTP(ctx, u, setup.Sealed, totpCode(key, s.Now().Unix()/totpPeriod)); !errors.Is(err, ErrSetupExpired) {
		t.Fatalf("expired setup: %v", err)
	}
	enableTOTP(t, s, u)
	got, _ := s.UserByID(ctx, u.ID)
	if !got.HasTOTP() {
		t.Fatal("TOTP not on")
	}
	if n, _ := s.RecoveryCodesLeft(ctx, u.ID); n != RecoveryCodes {
		t.Fatalf("recovery codes left: %d", n)
	}
	var sealed []byte
	_ = s.DB.R.QueryRow("SELECT totp_sealed FROM users WHERE id = ?", u.ID).Scan(&sealed)
	if len(sealed) == 0 || strings.Contains(string(sealed), string(key)) {
		t.Fatal("secret not sealed")
	}
	g, _ := s.CreateUser(ctx, "g@example.nl", "", authz.Viewer, MethodGoogle)
	if _, err := s.BeginTOTP(g, "tlswatch"); err == nil {
		t.Fatal("TOTP offered to a Google account")
	}
}

func TestLoginWithCode(t *testing.T) {
	s, c := newService(t)
	ctx := context.Background()
	u := mkLocal(t, s, "a@example.nl", authz.Admin)
	key, codes := enableTOTP(t, s, u)
	c.add(time.Minute) // past the step used at setup

	if _, err := s.Login(ctx, "a@example.nl", goodPW, "10.0.0.1"); !errors.Is(err, ErrSecondFactor) {
		t.Fatalf("password alone: %v", err)
	}
	now := func() string { return totpCode(key, s.Now().Unix()/totpPeriod) }
	got, recovery, err := s.LoginCode(ctx, u.ID, now(), "10.0.0.1")
	if err != nil || recovery || got.ID != u.ID {
		t.Fatalf("code: %+v %v %v", got, recovery, err)
	}
	// The same code cannot be used twice, and the steps around now are
	// accepted once each.
	if _, _, err := s.LoginCode(ctx, u.ID, now(), "10.0.0.1"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replayed code: %v", err)
	}
	c.add(totpPeriod * time.Second)
	if _, _, err := s.LoginCode(ctx, u.ID, totpCode(key, s.Now().Unix()/totpPeriod+1), "10.0.0.1"); err != nil {
		t.Fatalf("one step ahead: %v", err)
	}
	if _, _, err := s.LoginCode(ctx, u.ID, totpCode(key, s.Now().Unix()/totpPeriod-1), "10.0.0.1"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("a step before one already used: %v", err)
	}
	c.add(5 * totpPeriod * time.Second)
	if _, _, err := s.LoginCode(ctx, u.ID, totpCode(key, s.Now().Unix()/totpPeriod-2), "10.0.0.1"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("two steps behind: %v", err)
	}

	// A recovery code works once, typed any way.
	_, recovery, err = s.LoginCode(ctx, u.ID, " "+strings.ToUpper(strings.ReplaceAll(codes[0], "-", " "))+" ", "10.0.0.1")
	if err != nil || !recovery {
		t.Fatalf("recovery code: %v %v", recovery, err)
	}
	if _, _, err := s.LoginCode(ctx, u.ID, codes[0], "10.0.0.1"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("recovery code twice: %v", err)
	}
	if n, _ := s.RecoveryCodesLeft(ctx, u.ID); n != RecoveryCodes-1 {
		t.Fatalf("left: %d", n)
	}
	fresh, _ := s.NewRecoveryCodes(ctx, u.ID)
	if _, _, err := s.LoginCode(ctx, u.ID, codes[1], "10.0.0.1"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("old recovery code after new ones: %v", err)
	}
	if _, _, err := s.LoginCode(ctx, u.ID, fresh[0], "10.0.0.1"); err != nil {
		t.Fatalf("new recovery code: %v", err)
	}

	// Turned off, the password signs in alone again.
	if err := s.ResetTOTP(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, "a@example.nl", goodPW, "10.0.0.1"); err != nil {
		t.Fatalf("after reset: %v", err)
	}
	if _, _, err := s.LoginCode(ctx, u.ID, now(), "10.0.0.1"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("code without TOTP: %v", err)
	}
}

// A wrong code counts like a wrong password, and the right password does
// not reset the count while the code is still missing.
func TestCodeLockout(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	u := mkLocal(t, s, "a@example.nl", authz.Admin)
	key, _ := enableTOTP(t, s, u)
	if _, err := s.Login(ctx, "a@example.nl", "wrong password!", "10.0.0.9"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal(err)
	}
	for i := range 4 {
		if _, err := s.Login(ctx, "a@example.nl", goodPW, "10.0.0.9"); !errors.Is(err, ErrSecondFactor) {
			t.Fatalf("%d: %v", i, err)
		}
		_, _, err := s.LoginCode(ctx, u.ID, "123456", "10.0.0.9")
		if i < 3 && !errors.Is(err, ErrInvalidCode) || i == 3 && !errors.Is(err, ErrLocked) {
			t.Fatalf("wrong code %d: %v", i, err)
		}
	}
	if _, _, err := s.LoginCode(ctx, u.ID, totpCode(key, s.Now().Unix()/totpPeriod+1), "10.0.0.9"); !errors.Is(err, ErrLocked) {
		t.Fatalf("right code while locked: %v", err)
	}
	if _, err := s.Login(ctx, "a@example.nl", goodPW, "10.0.0.9"); !errors.Is(err, ErrLocked) {
		t.Fatalf("password while locked: %v", err)
	}
}

func TestMFAState(t *testing.T) {
	s, c := newService(t)
	v := s.SealMFA(7, "/targets")
	st, err := s.OpenMFA(v)
	if err != nil || st.UserID != 7 || st.Next != "/targets" {
		t.Fatalf("open: %+v %v", st, err)
	}
	if _, err := s.OpenMFA(s.SealState(OIDCState{State: "x", Expires: s.Now().Add(time.Hour).Unix()})); err == nil {
		t.Fatal("an OIDC state opened as a sign-in state")
	}
	c.add(6 * time.Minute)
	if _, err := s.OpenMFA(v); err == nil {
		t.Fatal("expired state opened")
	}
}

// Switching a user to single sign-on drops TOTP with the password.
func TestSSODropsTOTP(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	u := mkLocal(t, s, "a@example.nl", authz.Operator)
	enableTOTP(t, s, u)
	if err := s.UpdateUser(ctx, u.ID, "", authz.Operator, MethodOIDC, true); err != nil {
		t.Fatal(err)
	}
	got, _ := s.UserByID(ctx, u.ID)
	if got.HasTOTP() || got.HasPassword || got.Method != MethodOIDC {
		t.Fatalf("after switch: %+v", got)
	}
	if n, _ := s.RecoveryCodesLeft(ctx, u.ID); n != 0 {
		t.Fatalf("recovery codes kept: %d", n)
	}
}

func TestReencryptTOTP(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	a := mkLocal(t, s, "a@example.nl", authz.Admin)
	b := mkLocal(t, s, "b@example.nl", authz.Viewer)
	keyA, _ := enableTOTP(t, s, a)
	enableTOTP(t, s, b)
	// b's secret sealed under a key nobody has any more.
	stray, _, _ := secret.Generate()
	if _, err := s.DB.W.Exec("UPDATE users SET totp_sealed = ? WHERE id = ?", stray.Seal(totpContext(b.ID), []byte("x")), b.ID); err != nil {
		t.Fatal(err)
	}
	next, _, _ := secret.Generate()
	tx, _ := s.DB.W.BeginTx(ctx, nil)
	n, dropped, err := ReencryptTOTP(ctx, tx, s.Key, next)
	if err != nil || n != 1 || len(dropped) != 1 || dropped[0] != "b@example.nl" {
		t.Fatalf("reencrypt: %d %v %v", n, dropped, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	s.Key = next
	if _, _, err := s.LoginCode(ctx, a.ID, totpCode(keyA, s.Now().Unix()/totpPeriod+1), ""); err != nil {
		t.Fatalf("code after rotation: %v", err)
	}
	var sealed sql.NullString
	_ = s.DB.R.QueryRow("SELECT totp_sealed FROM users WHERE id = ?", b.ID).Scan(&sealed)
	if gb, _ := s.UserByID(ctx, b.ID); gb.HasTOTP() || sealed.Valid {
		t.Fatal("unreadable secret kept")
	}
}
