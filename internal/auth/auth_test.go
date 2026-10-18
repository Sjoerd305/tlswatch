package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

func TestMain(m *testing.M) {
	argonMemory, argonTime, argonThreads = 1024, 1, 1 // keep -race runs fast
	os.Exit(m.Run())
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newService(t *testing.T) (*Service, *clock) {
	t.Helper()
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	k, err := secret.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := New(d, k)
	c := &clock{t: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	s.Now = c.now
	return s, c
}

const goodPW = "correct-mule-staple-7"

func mkLocal(t *testing.T, s *Service, email string, role authz.Role) User {
	t.Helper()
	ctx := context.Background()
	u, err := s.CreateUser(ctx, email, "Test", role, MethodLocal)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword(ctx, u.ID, goodPW); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestHashRoundtrip(t *testing.T) {
	h, err := HashPassword("secret pass")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=") || strings.Count(h, "$") != 5 {
		t.Fatalf("not a PHC string: %s", h)
	}
	if !VerifyPassword(h, "secret pass") || VerifyPassword(h, "secret pasS") {
		t.Fatal("verify mismatch")
	}
	for _, bad := range []string{"", "$argon2i$v=19$m=1,t=1,p=1$AA$AA", "plain", h[:len(h)-4] + "!!!!"} {
		if VerifyPassword(bad, "secret pass") {
			t.Fatalf("malformed hash %q verified", bad)
		}
	}
}

func TestPolicy(t *testing.T) {
	s, _ := newService(t)
	cases := map[string]error{
		"short":                  ErrPasswordTooShort,
		"Password1234":           ErrPasswordLeaked,
		"QWERTYUIOP123":          ErrPasswordLeaked,
		"jan.devries@example.nl": ErrPasswordIsEmail,
		"jan.devries1":           nil,
		goodPW:                   nil,
	}
	for pw, want := range cases {
		if got := s.CheckPasswordPolicy(pw, "Jan.deVries@example.nl"); !errors.Is(got, want) {
			t.Errorf("%q: got %v, want %v", pw, got, want)
		}
	}
	if err := s.CheckPasswordPolicy("jan.devries1x", "jan.devries1x@example.nl"); !errors.Is(err, ErrPasswordIsEmail) {
		t.Errorf("local part accepted: %v", err)
	}
	if err := s.CheckPasswordPolicy("ééééééééééé", ""); !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("11 runes accepted: %v", err)
	}
}

func TestLoginLockout(t *testing.T) {
	s, c := newService(t)
	ctx := context.Background()
	mkLocal(t, s, "op@example.nl", authz.Operator)

	if _, err := s.Login(ctx, "OP@example.nl", goodPW, "10.0.0.1"); err != nil {
		t.Fatalf("good login: %v", err)
	}
	// Failures from another address than the last good one lock the account.
	for i := 1; i <= 4; i++ {
		if _, err := s.Login(ctx, "op@example.nl", "wrong", "10.0.0.2"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := s.Login(ctx, "op@example.nl", "wrong", "10.0.0.2"); !errors.Is(err, ErrLocked) {
		t.Fatalf("5th failure: %v", err)
	}
	if _, err := s.Login(ctx, "op@example.nl", goodPW, "10.0.0.2"); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked account let in: %v", err)
	}
	c.add(15*time.Minute + time.Second)
	if _, err := s.Login(ctx, "op@example.nl", goodPW, "10.0.0.2"); err != nil {
		t.Fatalf("after lock expiry: %v", err)
	}
}

// An address without an account locks after the same number of failures,
// so the lockout does not reveal which addresses exist.
func TestLockoutDoesNotRevealAccounts(t *testing.T) {
	s, c := newService(t)
	ctx := context.Background()
	mkLocal(t, s, "op@example.nl", authz.Operator)
	for _, email := range []string{"op@example.nl", "nobody@example.nl"} {
		var errs []error
		for i := 0; i < maxFailures+1; i++ {
			_, err := s.Login(ctx, email, "wrong", "")
			errs = append(errs, err)
		}
		for i, err := range errs {
			want := ErrInvalidCredentials
			if i >= maxFailures-1 {
				want = ErrLocked
			}
			if !errors.Is(err, want) {
				t.Fatalf("%s attempt %d: %v, want %v", email, i+1, err, want)
			}
		}
	}
	c.add(lockDuration + time.Second)
	if _, err := s.Login(ctx, "nobody@example.nl", "wrong", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("after the lock: %v", err)
	}
}

// Failures from other addresses cannot lock an account out of the address
// it last signed in from.
func TestLockoutSparesLastGoodAddress(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	mkLocal(t, s, "admin@example.nl", authz.Admin)
	if _, err := s.Login(ctx, "admin@example.nl", goodPW, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxFailures; i++ {
		_, _ = s.Login(ctx, "admin@example.nl", "wrong", "203.0.113.9")
	}
	if _, err := s.Login(ctx, "admin@example.nl", goodPW, "198.51.100.7"); !errors.Is(err, ErrLocked) {
		t.Fatalf("other address: %v", err)
	}
	if _, err := s.Login(ctx, "admin@example.nl", goodPW, "10.0.0.1"); err != nil {
		t.Fatalf("last good address locked out: %v", err)
	}
}

func TestLoginNeutralErrors(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	mkLocal(t, s, "a@example.nl", authz.Viewer)
	_, errUnknown := s.Login(ctx, "nobody@example.nl", goodPW, "")
	_, errWrong := s.Login(ctx, "a@example.nl", "wrong password", "")
	if errUnknown != ErrInvalidCredentials || errWrong != ErrInvalidCredentials {
		t.Fatalf("errors differ: %v / %v", errUnknown, errWrong)
	}
	g, _ := s.CreateUser(ctx, "g@example.nl", "", authz.Viewer, MethodGoogle)
	if _, err := s.Login(ctx, g.Email, "", ""); err != ErrInvalidCredentials {
		t.Fatalf("google user: %v", err)
	}
	// Disabled: neutral too. Keep another admin around.
	mkLocal(t, s, "admin@example.nl", authz.Admin)
	u, _ := s.UserByEmail(ctx, "a@example.nl")
	if err := s.UpdateUser(ctx, u.ID, u.Name, u.Role, MethodLocal, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, "a@example.nl", goodPW, ""); err != ErrInvalidCredentials {
		t.Fatalf("disabled: %v", err)
	}
}

func TestIPRateLimit(t *testing.T) {
	s, c := newService(t)
	ctx := context.Background()
	mkLocal(t, s, "a@example.nl", authz.Viewer)
	for i := 0; i < ipMaxFailures; i++ {
		s.Login(ctx, "nobody"+string(rune('a'+i))+"@example.nl", "x", "192.0.2.9")
	}
	if _, err := s.Login(ctx, "a@example.nl", goodPW, "192.0.2.9"); !errors.Is(err, ErrLocked) {
		t.Fatalf("IP not limited: %v", err)
	}
	if _, err := s.Login(ctx, "a@example.nl", goodPW, "192.0.2.10"); err != nil {
		t.Fatalf("other IP blocked: %v", err)
	}
	c.add(ipWindow + time.Second)
	if _, err := s.Login(ctx, "a@example.nl", goodPW, "192.0.2.9"); err != nil {
		t.Fatalf("after window: %v", err)
	}
}

func TestTokens(t *testing.T) {
	s, c := newService(t)
	ctx := context.Background()
	u := mkLocal(t, s, "a@example.nl", authz.Viewer)
	raw, err := s.CreateToken(ctx, TokenInvite, u.ID, InviteTTL)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := s.PeekToken(ctx, TokenInvite, raw); err != nil || id != u.ID {
		t.Fatalf("peek: %d %v", id, err)
	}
	if _, err := s.PeekToken(ctx, "setup", raw); err != ErrTokenInvalid {
		t.Fatalf("wrong kind accepted: %v", err)
	}
	if id, err := s.UseToken(ctx, TokenInvite, raw); err != nil || id != u.ID {
		t.Fatalf("use: %d %v", id, err)
	}
	if _, err := s.UseToken(ctx, TokenInvite, raw); err != ErrTokenInvalid {
		t.Fatalf("reused: %v", err)
	}
	raw2, _ := s.CreateToken(ctx, TokenInvite, u.ID, InviteTTL)
	raw3, _ := s.CreateToken(ctx, TokenInvite, u.ID, InviteTTL)
	if _, err := s.PeekToken(ctx, TokenInvite, raw2); err != ErrTokenInvalid {
		t.Fatalf("older invite still valid: %v", err)
	}
	c.add(InviteTTL + time.Second)
	if _, err := s.UseToken(ctx, TokenInvite, raw3); err != ErrTokenInvalid {
		t.Fatalf("expired accepted: %v", err)
	}
}

func TestCreateFirstAdmin(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	if _, err := s.CreateFirstAdmin(ctx, "a@example.nl", "A", "short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("policy: %v", err)
	}
	if _, err := s.CreateFirstAdmin(ctx, "not an address", "A", goodPW); err == nil {
		t.Fatal("bad e-mail accepted")
	}
	u, err := s.CreateFirstAdmin(ctx, "A@example.nl", "A", goodPW)
	if err != nil || u.Role != authz.Admin || u.Email != "a@example.nl" || !u.HasPassword || u.Method != MethodLocal {
		t.Fatalf("first admin: %+v %v", u, err)
	}
	if _, err := s.Login(ctx, "a@example.nl", goodPW, "192.0.2.1"); err != nil {
		t.Fatalf("login with the chosen password: %v", err)
	}
	if _, err := s.CreateFirstAdmin(ctx, "b@example.nl", "B", goodPW); err != ErrSetupDone {
		t.Fatalf("second admin through setup: %v", err)
	}
}

func TestCreateFirstAdminRace(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := s.CreateFirstAdmin(ctx, fmt.Sprintf("u%d@example.nl", i), "", goodPW); err == nil {
				ok.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if n, _ := s.CountUsers(ctx); ok.Load() != 1 || n != 1 {
		t.Fatalf("%d setups succeeded, %d users", ok.Load(), n)
	}
}

func TestSessions(t *testing.T) {
	s, c := newService(t)
	ctx := context.Background()
	admin := mkLocal(t, s, "admin@example.nl", authz.Admin)
	u := mkLocal(t, s, "v@example.nl", authz.Viewer)
	raw, csrf, err := s.NewSession(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := s.Session(ctx, raw)
	if err != nil || sess.User.ID != u.ID || sess.CSRF != csrf {
		t.Fatalf("session: %+v %v", sess, err)
	}
	c.add(7 * time.Hour)
	if _, err := s.Session(ctx, raw); err != nil {
		t.Fatalf("within idle: %v", err)
	}
	c.add(7 * time.Hour) // 7 h since last touch: still fine
	if _, err := s.Session(ctx, raw); err != nil {
		t.Fatalf("touch did not extend: %v", err)
	}
	c.add(8*time.Hour + time.Minute)
	if _, err := s.Session(ctx, raw); err != ErrNoSession {
		t.Fatalf("idle session alive: %v", err)
	}
	raw, _, _ = s.NewSession(ctx, u.ID)
	if err := s.UpdateUser(ctx, u.ID, "", authz.Viewer, MethodLocal, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, raw); err != ErrNoSession {
		t.Fatalf("disabled user session alive: %v", err)
	}
	raw, _, _ = s.NewSession(ctx, admin.ID)
	if err := s.DeleteSession(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, raw); err != ErrNoSession {
		t.Fatalf("signed-out session alive: %v", err)
	}
	if err := s.PruneSessions(ctx); err != nil {
		t.Fatal(err)
	}
}

// An active session still ends MaxAge after sign-in.
func TestSessionMaxAge(t *testing.T) {
	s, c := newService(t)
	ctx := context.Background()
	u := mkLocal(t, s, "v@example.nl", authz.Viewer)
	raw, _, _ := s.NewSession(ctx, u.ID)
	for elapsed := time.Duration(0); elapsed+6*time.Hour < s.MaxAge; elapsed += 6 * time.Hour {
		c.add(6 * time.Hour)
		if _, err := s.Session(ctx, raw); err != nil {
			t.Fatalf("active session ended after %v: %v", elapsed, err)
		}
	}
	c.add(7 * time.Hour)
	if _, err := s.Session(ctx, raw); err != ErrNoSession {
		t.Fatalf("session alive past its maximum age: %v", err)
	}
	stale, _, _ := s.NewSession(ctx, u.ID)
	c.add(s.MaxAge + time.Hour)
	if err := s.PruneSessions(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.DB.R.QueryRow("SELECT COUNT(*) FROM sessions WHERE hash = ?", hashToken(stale)).Scan(&n)
	if n != 0 {
		t.Fatal("expired session not pruned")
	}
}

func TestLastAdmin(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	a := mkLocal(t, s, "a@example.nl", authz.Admin)
	if err := s.UpdateUser(ctx, a.ID, "", authz.Operator, MethodLocal, true); err != ErrLastAdmin {
		t.Fatalf("demote last admin: %v", err)
	}
	if err := s.UpdateUser(ctx, a.ID, "", authz.Admin, MethodLocal, false); err != ErrLastAdmin {
		t.Fatalf("disable last admin: %v", err)
	}
	b := mkLocal(t, s, "b@example.nl", authz.Admin)
	if err := s.UpdateUser(ctx, a.ID, "", authz.Operator, MethodLocal, true); err != nil {
		t.Fatalf("demote with second admin: %v", err)
	}
	if err := s.UpdateUser(ctx, b.ID, "", authz.Admin, MethodLocal, false); err != ErrLastAdmin {
		t.Fatalf("disable new last admin: %v", err)
	}
	if _, err := s.CreateUser(ctx, "B@example.nl", "", authz.Viewer, MethodLocal); err != ErrExists {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := s.CreateUser(ctx, "not an email", "", authz.Viewer, MethodLocal); err == nil {
		t.Fatal("bad e-mail accepted")
	}
}

func TestDeleteAndUnlockUser(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	a := mkLocal(t, s, "a@example.nl", authz.Admin)
	if err := s.DeleteUser(ctx, a.ID); err != ErrLastAdmin {
		t.Fatalf("delete last admin: %v", err)
	}
	v := mkLocal(t, s, "v@example.nl", authz.Viewer)
	raw, _, err := s.NewSession(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.W.ExecContext(ctx, "UPDATE users SET locked_until = ? WHERE id = ?", s.now()+600, v.ID); err != nil {
		t.Fatal(err)
	}
	us, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range us {
		if u.ID == v.ID && !u.Locked(s.now()) {
			t.Fatal("lockout not listed")
		}
	}
	if err := s.Unlock(ctx, v.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Unlock(ctx, 999); err != ErrNotFound {
		t.Fatalf("unlock unknown: %v", err)
	}
	if err := s.DeleteUser(ctx, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, raw); err != ErrNoSession {
		t.Fatalf("session of a deleted user: %v", err)
	}
	if err := s.DeleteUser(ctx, v.ID); err != ErrNotFound {
		t.Fatalf("delete twice: %v", err)
	}
}

func TestStateSeal(t *testing.T) {
	s, c := newService(t)
	cfg := OIDCConfig{ClientID: "cid", ClientSecret: "cs", RedirectURL: "https://w.example/auth/google/callback", Domain: "example.nl"}
	redirect, st, err := s.OIDCStart(cfg)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") != st.Nonce || q.Get("state") != st.State || q.Get("hd") != "example.nl" {
		t.Fatalf("auth URL: %s", redirect)
	}
	got, err := s.OpenState(s.SealState(st))
	if err != nil || got != st {
		t.Fatalf("roundtrip: %+v %v", got, err)
	}
	if _, err := s.OpenState("garbage"); err == nil {
		t.Fatal("garbage opened")
	}
	sealed := s.SealState(st)
	c.add(11 * time.Minute)
	if _, err := s.OpenState(sealed); err == nil {
		t.Fatal("expired state opened")
	}
}

func TestOIDCFinish(t *testing.T) {
	s, _ := newService(t)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "g@example.nl", "", authz.Operator, MethodGoogle); err != nil {
		t.Fatal(err)
	}
	mkLocal(t, s, "local@example.nl", authz.Admin)
	var claims map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("code_verifier") == "" || r.Form.Get("code") != "the-code" {
			http.Error(w, "bad request", 400)
			return
		}
		b, _ := json.Marshal(claims)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": jwt})
	}))
	defer srv.Close()
	cfg := OIDCConfig{ClientID: "cid", ClientSecret: "cs", Domain: "example.nl", RedirectURL: "https://w.example/cb", TokenURL: srv.URL, AuthURL: srv.URL}
	_, st, _ := s.OIDCStart(cfg)
	base := func() map[string]any {
		return map[string]any{
			"iss": "https://accounts.google.com", "aud": "cid", "exp": s.Now().Add(time.Hour).Unix(),
			"nonce": st.Nonce, "email": "G@example.nl", "email_verified": true, "hd": "example.nl", "name": "Gee",
		}
	}
	claims = base()
	u, _, err := s.OIDCFinish(ctx, cfg, st, st.State, "the-code")
	if err != nil || u.Email != "g@example.nl" || u.Name != "Gee" {
		t.Fatalf("good: %+v %v", u, err)
	}
	if _, _, err := s.OIDCFinish(ctx, cfg, st, "other-state", "the-code"); err != ErrTokenInvalid {
		t.Fatalf("state mismatch: %v", err)
	}
	bad := map[string]func(map[string]any){
		"aud":      func(m map[string]any) { m["aud"] = "someone-else" },
		"nonce":    func(m map[string]any) { m["nonce"] = "replayed" },
		"hd":       func(m map[string]any) { m["hd"] = "gmail.com" },
		"iss":      func(m map[string]any) { m["iss"] = "https://evil.example" },
		"exp":      func(m map[string]any) { m["exp"] = s.Now().Add(-time.Minute).Unix() },
		"verified": func(m map[string]any) { m["email_verified"] = false },
		"unknown":  func(m map[string]any) { m["email"] = "stranger@example.nl" },
		"local":    func(m map[string]any) { m["email"] = "local@example.nl" },
	}
	for name, mutate := range bad {
		claims = base()
		mutate(claims)
		if _, _, err := s.OIDCFinish(ctx, cfg, st, st.State, "the-code"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	claims = base()
	claims["aud"] = []string{"x", "cid"}
	if _, _, err := s.OIDCFinish(ctx, cfg, st, st.State, "the-code"); err != nil {
		t.Errorf("aud array: %v", err)
	}
}

// The last good address is spared a lock only so far: from hardMaxFailures
// failures in a row it is locked out like any other, and the count is kept
// in the database in one statement.
func TestLockoutHardCap(t *testing.T) {
	s, c := newService(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, "cap@example.nl", "Cap", authz.Operator, MethodLocal)
	if err := s.SetPassword(ctx, u.ID, goodPW); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, "Cap@Example.nl", goodPW, "10.0.0.1"); err != nil {
		t.Fatalf("sign-in with a capitalised address: %v", err)
	}
	for i := 1; i < hardMaxFailures; i++ {
		_, err := s.Login(ctx, "cap@example.nl", "wrong", "10.0.0.1")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failure %d from the last good address: %v", i, err)
		}
		c.add(time.Minute) // under the per-address rate, which is separate
	}
	if _, err := s.Login(ctx, "cap@example.nl", "wrong", "10.0.0.1"); !errors.Is(err, ErrLocked) {
		t.Fatalf("failure %d from the last good address: %v, want the lock", hardMaxFailures, err)
	}
	if _, err := s.Login(ctx, "cap@example.nl", goodPW, "10.0.0.1"); !errors.Is(err, ErrLocked) {
		t.Fatalf("good password while hard-locked: %v", err)
	}
	c.add(lockDuration + time.Second)
	if _, err := s.Login(ctx, "cap@example.nl", goodPW, "10.0.0.1"); err != nil {
		t.Fatalf("after the lock: %v", err)
	}
}
