package web

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/db"
)

func apiLimitHarness(t *testing.T) (*harness, *time.Time) {
	t.Helper()
	hs := newHarness(t)
	now := time.Now()
	hs.srv.Now = func() time.Time { return now }
	hs.srv.Auth.Now = hs.srv.Now
	return hs, &now
}

func (hs *harness) apiFromIP(header, ip, path string, forwarded ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = net.JoinHostPort(ip, "1234")
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	if len(forwarded) > 0 {
		r.Header.Set("X-Forwarded-For", forwarded[0])
	}
	w := httptest.NewRecorder()
	hs.h.ServeHTTP(w, r)
	return w
}

func exhaustAPIFailures(t *testing.T, hs *harness) {
	t.Helper()
	for i := 0; i < apiFailBurst; i++ {
		if w := hs.api("tlsw_wrong", "GET", "/api/v2/targets", ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d %s", i, w.Code, w.Body.String())
		}
	}
}

func TestAPISharedIPDoesNotBlockValidTokens(t *testing.T) {
	hs, now := apiLimitHarness(t)
	viewer := hs.apiToken(authz.Viewer, authz.Viewer)
	admin := hs.apiToken(authz.Admin, authz.Admin)
	exhaustAPIFailures(t, hs)
	for _, token := range []string{viewer, admin} {
		if w := hs.api(token, "GET", "/api/v2/targets", ""); w.Code != http.StatusOK {
			t.Fatalf("valid token behind blocked IP: %d %s", w.Code, w.Body.String())
		}
	}
	// Successful authentication does not reset the failure budget.
	w := hs.api("tlsw_wrong", "GET", "/api/v2/targets", "")
	if w.Code != http.StatusTooManyRequests || errCode(t, w) != "rate_limited" {
		t.Fatalf("bad token after valid requests: %d %s", w.Code, w.Body.String())
	}
	if retry, err := strconv.Atoi(w.Header().Get("Retry-After")); err != nil || retry < 1 {
		t.Fatalf("missing retry delay: %q", w.Header().Get("Retry-After"))
	}
	if w := hs.api(viewer, "GET", "/api/v2/channels", ""); w.Code != http.StatusForbidden || errCode(t, w) != "forbidden" {
		t.Fatalf("viewer bypassed role check: %d %s", w.Code, w.Body.String())
	}
	// Distinct addresses have distinct failed-authentication budgets.
	if w := hs.apiFromIP("Bearer tlsw_wrong", "192.0.2.2", "/api/v2/targets"); w.Code != http.StatusUnauthorized {
		t.Fatalf("other IP inherited block: %d", w.Code)
	}
	*now = now.Add(apiFailEvery - time.Second)
	if w := hs.api("tlsw_wrong", "GET", "/api/v2/targets", ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("early retry: %d", w.Code)
	}
	*now = now.Add(time.Second)
	if w := hs.api("tlsw_wrong", "GET", "/api/v2/targets", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("recovered attempt: %d", w.Code)
	}
	if w := hs.api("tlsw_wrong", "GET", "/api/v2/targets", ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("one refill allowed multiple failures: %d", w.Code)
	}
	if w := hs.api(viewer, "GET", "/api/v2/targets", ""); w.Code != http.StatusOK {
		t.Fatalf("valid token blocked again after refill: %d", w.Code)
	}
}

func TestAPIMissingAndMalformedCredentialsAreLimited(t *testing.T) {
	for _, header := range []string{"", "Bearer ", "Bearer \t", "Basic credentials", "bearer tlsw_wrong", "Bearer wrong", "Bearer tlsw_" + strings.Repeat("x", 201), "Bearer tlsw_unknown"} {
		t.Run(header, func(t *testing.T) {
			hs, _ := apiLimitHarness(t)
			for i := 0; i < apiFailBurst; i++ {
				w := hs.apiFromIP(header, "192.0.2.1", "/api/v2/targets")
				if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" || errCode(t, w) != "unauthorized" {
					t.Fatalf("attempt %d: %d %s", i, w.Code, w.Body.String())
				}
			}
			w := hs.apiFromIP(header, "192.0.2.1", "/api/v2/targets")
			if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" || errCode(t, w) != "rate_limited" {
				t.Fatalf("exhausted budget: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestAPIValidTokenStillHasOwnRateLimit(t *testing.T) {
	hs, now := apiLimitHarness(t)
	first := hs.apiToken(authz.Viewer, authz.Viewer)
	second := hs.apiToken(authz.Admin, authz.Admin)
	exhaustAPIFailures(t, hs)
	for i := 0; i < apiBurst; i++ {
		if w := hs.api(first, "GET", "/api/v2/targets", ""); w.Code != http.StatusOK {
			t.Fatalf("valid request %d: %d", i, w.Code)
		}
	}
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		w := hs.apiFromIP("Bearer "+first, ip, "/api/v2/targets")
		if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "This token is limited") || w.Header().Get("Retry-After") == "" {
			t.Fatalf("token limit from %s: %d %s", ip, w.Code, w.Body.String())
		}
	}
	if w := hs.api(second, "GET", "/api/v2/targets", ""); w.Code != http.StatusOK {
		t.Fatalf("different token inherited limit: %d", w.Code)
	}
	*now = now.Add(time.Second)
	if w := hs.api(first, "GET", "/api/v2/targets", ""); w.Code != http.StatusOK {
		t.Fatalf("token rate did not recover: %d", w.Code)
	}
}

func TestAPIInvalidTokensCannotBypassBlockedAddress(t *testing.T) {
	for _, kind := range []string{"expired", "revoked", "disabled_user"} {
		t.Run(kind, func(t *testing.T) {
			hs, now := apiLimitHarness(t)
			ctx := context.Background()
			u, err := hs.srv.Auth.UserByID(ctx, hs.userID(authz.Viewer))
			if err != nil {
				t.Fatal(err)
			}
			token, raw, err := hs.srv.Auth.CreateAPIToken(ctx, u, "invalid", authz.Viewer, 30*24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "expired":
				_, err = hs.db.W.Exec("UPDATE api_tokens SET expires_at = ? WHERE id = ?", now.Unix(), token.ID)
			case "revoked":
				_, err = hs.srv.Auth.DeleteAPIToken(ctx, u.ID, token.ID)
			case "disabled_user":
				_, err = hs.db.W.Exec("UPDATE users SET enabled = 0 WHERE id = ?", u.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			exhaustAPIFailures(t, hs)
			if w := hs.api(raw, "GET", "/api/v2/targets", ""); w.Code != http.StatusTooManyRequests {
				t.Fatalf("invalid token bypassed IP block: %d %s", w.Code, w.Body.String())
			}
			if w := hs.apiFromIP("Bearer "+raw, "192.0.2.2", "/api/v2/targets"); w.Code != http.StatusUnauthorized {
				t.Fatalf("invalid token authenticated on clean IP: %d", w.Code)
			}
		})
	}
}

func TestAPIAuthLookupFailureIsNotAnInvalidCredential(t *testing.T) {
	hs, _ := apiLimitHarness(t)
	good := hs.apiToken(authz.Viewer, authz.Viewer)
	broken, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	_ = broken.Close()
	for i := 0; i < apiFailBurst-1; i++ {
		if w := hs.api("tlsw_wrong", "GET", "/api/v2/targets", ""); w.Code != http.StatusUnauthorized {
			t.Fatal(w.Code)
		}
	}
	hs.srv.Auth.DB = broken
	defer func() { hs.srv.Auth.DB = hs.db }()
	w := hs.api(good, "GET", "/api/v2/targets", "")
	if w.Code != http.StatusServiceUnavailable || errCode(t, w) != "unavailable" {
		t.Fatalf("lookup error: %d %s", w.Code, w.Body.String())
	}
	hs.srv.Auth.DB = hs.db
	if w := hs.api("tlsw_wrong", "GET", "/api/v2/targets", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("lookup error spent failure slot: %d", w.Code)
	}
	if w := hs.api("tlsw_wrong", "GET", "/api/v2/targets", ""); w.Code != http.StatusTooManyRequests {
		t.Fatalf("IP not exhausted: %d", w.Code)
	}
	hs.srv.Auth.DB = broken
	w = hs.api(good, "GET", "/api/v2/targets", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("IP block hid lookup error: %d", w.Code)
	}
	hs.srv.Auth.DB = hs.db
	if w := hs.api(good, "GET", "/api/v2/targets", ""); w.Code != http.StatusOK {
		t.Fatalf("recovered database: %d", w.Code)
	}
}

func TestAPIConcurrentFailuresHaveOneSharedBudget(t *testing.T) {
	hs, _ := apiLimitHarness(t)
	good := hs.apiToken(authz.Viewer, authz.Viewer)
	const requests = 80
	results := make(chan int, requests)
	for i := 0; i < requests; i++ {
		header := ""
		if i%2 == 0 {
			header = "Bearer tlsw_wrong"
		}
		go func() { results <- hs.apiFromIP(header, "192.0.2.1", "/api/v2/targets").Code }()
	}
	counts := map[int]int{}
	for i := 0; i < requests; i++ {
		counts[<-results]++
	}
	if counts[http.StatusUnauthorized] != apiFailBurst || counts[http.StatusTooManyRequests] != requests-apiFailBurst {
		t.Fatalf("concurrent status counts: %v", counts)
	}
	if w := hs.api(good, "GET", "/api/v2/targets", ""); w.Code != http.StatusOK {
		t.Fatalf("concurrent failures blocked valid token: %d", w.Code)
	}
}

func TestAPIProxyFailureBudgetsDoNotBlockValidClients(t *testing.T) {
	for _, trust := range []bool{false, true} {
		t.Run(strconv.FormatBool(trust), func(t *testing.T) {
			hs, _ := apiLimitHarness(t)
			good := hs.apiToken(authz.Viewer, authz.Viewer)
			st, err := hs.srv.Settings.Get(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			st.General.BehindProxy = trust
			if err := hs.srv.Settings.SaveGeneral(context.Background(), st.General); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < apiFailBurst; i++ {
				w := hs.apiFromIP("Bearer tlsw_wrong", "127.0.0.1", "/api/v2/targets", "192.0.2.1")
				if w.Code != http.StatusUnauthorized {
					t.Fatalf("proxy failure %d: %d", i, w.Code)
				}
			}
			for _, client := range []string{"192.0.2.1", "192.0.2.2"} {
				w := hs.apiFromIP("Bearer "+good, "127.0.0.1", "/api/v2/targets", client)
				if w.Code != http.StatusOK {
					t.Fatalf("valid proxy client %s: %d", client, w.Code)
				}
			}
			want := http.StatusTooManyRequests
			if trust {
				want = http.StatusUnauthorized
			}
			w := hs.apiFromIP("Bearer tlsw_wrong", "127.0.0.1", "/api/v2/targets", "192.0.2.2")
			if w.Code != want {
				t.Fatalf("proxy trust=%t: second client's invalid request=%d, want %d", trust, w.Code, want)
			}
		})
	}
}
