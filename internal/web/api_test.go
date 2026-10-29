package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/notify"
)

// apiToken makes an API token of role for the harness user of userRole.
func (hs *harness) apiToken(userRole, role authz.Role) string {
	hs.t.Helper()
	u, err := hs.srv.Auth.UserByID(context.Background(), hs.userID(userRole))
	if err != nil {
		hs.t.Fatal(err)
	}
	_, raw, err := hs.srv.Auth.CreateAPIToken(context.Background(), u, "test "+string(role), role, 30*24*time.Hour)
	if err != nil {
		hs.t.Fatal(err)
	}
	return raw
}

// api sends a request to the public API with a bearer token ("" for none)
// and a JSON body ("" for none).
func (hs *harness) api(token, method, path, body string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, req)
	return rec
}

func decodeJSON[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("%d %s: %v", rec.Code, rec.Body.String(), err)
	}
	return v
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	return decodeJSON[apiErrorBody](t, rec).Error.Code
}

// Every endpoint of the public API refuses a request without a token, and
// a session cookie in its place, with 401; and every role is refused, with
// 403, what the policy does not give it, through a token of that role.
func TestEveryAPIRouteIsGuarded(t *testing.T) {
	hs := newHarness(t)
	tokens := map[authz.Role]string{}
	for _, role := range authz.Roles {
		tokens[role] = hs.apiToken(authz.Admin, role)
	}
	routes := hs.srv.apiRoutes()
	if len(routes) < 20 {
		t.Fatalf("only %d API routes", len(routes))
	}
	for _, a := range routes {
		// Each route gets a fresh failure budget: this suite checks permissions.
		hs.srv.apiFails = limiter{}
		path := concrete(a.Path)
		if rec := hs.api("", a.Method, path, ""); rec.Code != http.StatusUnauthorized || errCode(t, rec) != "unauthorized" {
			t.Errorf("%s %s without a token: %d %s", a.Method, path, rec.Code, rec.Body.String())
		}
		// An admin's session cookie and CSRF token open nothing here.
		req := httptest.NewRequest(a.Method, path, strings.NewReader(url.Values{"csrf": {hs.sess[authz.Admin].csrf}}.Encode()))
		req.Header.Set("X-CSRF-Token", hs.sess[authz.Admin].csrf)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: hs.sess[authz.Admin].cookie})
		rec := httptest.NewRecorder()
		hs.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with a session cookie: %d, want 401", a.Method, path, rec.Code)
		}
		for _, role := range authz.Roles {
			rec := hs.api(tokens[role], a.Method, path, "")
			allowed := authz.Allowed(role, a.Action)
			if !allowed && (rec.Code != http.StatusForbidden || errCode(t, rec) != "forbidden") {
				t.Errorf("%s %s as a %s token: %d, want 403", a.Method, path, role, rec.Code)
			}
			if allowed && (rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized) {
				t.Errorf("%s %s as a %s token: %d, but the policy allows it: %s", a.Method, path, role, rec.Code, rec.Body.String())
			}
		}
	}
}

// A token opens no page of the UI and passes no CSRF check.
func TestAPITokenNeverWorksForTheUI(t *testing.T) {
	hs := newHarness(t)
	tok := hs.apiToken(authz.Admin, authz.Admin)
	for _, p := range []string{"/", "/targets", "/settings/users", "/api/v1/stamp"} {
		req := httptest.NewRequest("GET", p, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		hs.h.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Errorf("GET %s with an API token: 200", p)
		}
	}
	req := httptest.NewRequest("POST", "/targets/1/disable", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST with an API token: %d", rec.Code)
	}
	if tg, _ := hs.srv.Core.Target(context.Background(), 1); !tg.Enabled {
		t.Fatal("an API token disabled a target through the UI")
	}
}

// A token's role is capped by its user's: at creation, and again when the
// user is demoted. Disabling or deleting the user revokes the tokens; an
// expired or revoked token opens nothing.
func TestAPITokenLifecycle(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	op, _ := hs.srv.Auth.UserByID(ctx, hs.userID(authz.Operator))
	if _, _, err := hs.srv.Auth.CreateAPIToken(ctx, op, "x", authz.Admin, 30*24*time.Hour); err == nil {
		t.Fatal("an operator made an admin token")
	}
	if _, _, err := hs.srv.Auth.CreateAPIToken(ctx, op, "x", authz.Operator, 0); err == nil {
		t.Fatal("an operator made a token without expiry")
	}
	if _, _, err := hs.srv.Auth.CreateAPIToken(ctx, op, "x", authz.Operator, 400*24*time.Hour); err == nil {
		t.Fatal("a token for more than a year")
	}
	if _, _, err := hs.srv.Auth.CreateAPIToken(ctx, op, " ", authz.Operator, 30*24*time.Hour); err == nil {
		t.Fatal("a token without a name")
	}
	admin, _ := hs.srv.Auth.UserByID(ctx, hs.userID(authz.Admin))
	if _, raw, err := hs.srv.Auth.CreateAPIToken(ctx, admin, "forever", authz.Admin, 0); err != nil || !strings.HasPrefix(raw, auth.APITokenPrefix) {
		t.Fatalf("an admin's token without expiry: %v %q", err, raw)
	}

	tok := hs.apiToken(authz.Operator, authz.Operator)
	if rec := hs.api(tok, "POST", "/api/v2/targets/1/check", ""); rec.Code == http.StatusForbidden {
		t.Fatalf("operator token: %d", rec.Code)
	}
	// Demoted: the token acts as a viewer.
	if err := hs.srv.Auth.UpdateUser(ctx, op.ID, op.Name, authz.Viewer, op.Method, true); err != nil {
		t.Fatal(err)
	}
	if rec := hs.api(tok, "POST", "/api/v2/targets/1/check", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("token of a demoted user: %d, want 403", rec.Code)
	}
	if rec := hs.api(tok, "GET", "/api/v2/targets", ""); rec.Code != http.StatusOK {
		t.Fatalf("token of a demoted user reads: %d", rec.Code)
	}
	// Disabled: revoked, and enabling again does not bring it back.
	if err := hs.srv.Auth.UpdateUser(ctx, op.ID, op.Name, authz.Operator, op.Method, false); err != nil {
		t.Fatal(err)
	}
	if err := hs.srv.Auth.UpdateUser(ctx, op.ID, op.Name, authz.Operator, op.Method, true); err != nil {
		t.Fatal(err)
	}
	if rec := hs.api(tok, "GET", "/api/v2/targets", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token of a disabled user: %d", rec.Code)
	}
	if n := hs.count(fmt.Sprintf("SELECT COUNT(*) FROM api_tokens WHERE user_id = %d", op.ID)); n != 0 {
		t.Fatalf("%d tokens left after disabling", n)
	}
	// Expired.
	vtok := hs.apiToken(authz.Viewer, authz.Viewer)
	if _, err := hs.db.W.Exec("UPDATE api_tokens SET expires_at = ? WHERE user_id = ?", time.Now().Unix()-1, hs.userID(authz.Viewer)); err != nil {
		t.Fatal(err)
	}
	if rec := hs.api(vtok, "GET", "/api/v2/targets", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired token: %d", rec.Code)
	}
	// Revoked through the Account page, by its owner only.
	atok := hs.apiToken(authz.Admin, authz.Viewer)
	list, _ := hs.srv.Auth.APITokens(ctx, admin.ID)
	id := list[0].ID
	if rec := hs.do(authz.Viewer, "POST", fmt.Sprintf("/account/tokens/%d/delete", id), nil, true); rec.Code != http.StatusNotFound {
		t.Fatalf("another user revokes the token: %d", rec.Code)
	}
	if rec := hs.api(atok, "GET", "/api/v2/targets", ""); rec.Code != http.StatusOK {
		t.Fatalf("token before revoking: %d", rec.Code)
	}
	if rec := hs.do(authz.Admin, "POST", fmt.Sprintf("/account/tokens/%d/delete", id), nil, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if rec := hs.api(atok, "GET", "/api/v2/targets", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d", rec.Code)
	}
	// Deleting the user deletes their tokens.
	vtok = hs.apiToken(authz.Viewer, authz.Viewer)
	if err := hs.srv.Auth.DeleteUser(ctx, hs.userID(authz.Viewer)); err != nil {
		t.Fatal(err)
	}
	if rec := hs.api(vtok, "GET", "/api/v2/targets", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token of a deleted user: %d", rec.Code)
	}
}

// The Account page makes a token, shows it once, and lists it with its
// last use; the role offered is capped by the user's.
func TestAccountTokensPage(t *testing.T) {
	hs := newHarness(t)
	page := hs.do(authz.Operator, "GET", "/account", nil, false).Body.String()
	if !strings.Contains(page, `value="operator"`) || strings.Contains(page, `<option value="admin"`) || strings.Contains(page, ">Never<") {
		t.Fatal("the operator's token form offers the wrong roles or lifetimes")
	}
	rec := hs.do(authz.Operator, "POST", "/account/tokens", url.Values{"name": {"ci"}, "role": {"operator"}, "expiry": {"30"}}, true)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, auth.APITokenPrefix) {
		t.Fatalf("create token: %d", rec.Code)
	}
	i := strings.Index(body, `data-copy="`+auth.APITokenPrefix)
	raw := body[i+len(`data-copy="`):]
	raw = raw[:strings.Index(raw, `"`)]
	if rec := hs.api(raw, "GET", "/api/v2/targets", ""); rec.Code != http.StatusOK {
		t.Fatalf("the shown token: %d", rec.Code)
	}
	page = hs.do(authz.Operator, "GET", "/account", nil, false).Body.String()
	if strings.Contains(page, raw) || !strings.Contains(page, "ci <span") {
		t.Fatal("the token is shown again, or not listed")
	}
	if rec := hs.do(authz.Operator, "POST", "/account/tokens", url.Values{"name": {"x"}, "role": {"admin"}, "expiry": {"30"}}, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("operator asks for an admin token: %d", rec.Code)
	}
	if n := hs.count("SELECT COUNT(*) FROM audit WHERE action = 'token.create'"); n != 1 {
		t.Fatalf("%d token.create audit entries", n)
	}
}

// Targets through the API: add, get, change (null returns an override to
// its default), check, page through, delete; every write audited with the
// token's name.
func TestAPITargets(t *testing.T) {
	hs := newHarness(t)
	tok := hs.apiToken(authz.Operator, authz.Operator)
	rec := hs.api(tok, "POST", "/api/v2/targets", `{"host":"Portal.Example.NL","warn_days":20,"tags":["prod","web"],"renewal":"manual"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	tg := decodeJSON[map[string]any](t, rec)
	id := int64(tg["id"].(float64))
	if tg["host"] != "portal.example.nl" || tg["server_name"] != "portal.example.nl" || tg["port"] != float64(443) || tg["warn_days"] != float64(20) ||
		tg["renewal"] != "manual" || tg["channel_ids"] != nil || rec.Header().Get("Location") != fmt.Sprintf("/api/v2/targets/%d", id) {
		t.Fatalf("created: %v", tg)
	}
	if eff := tg["effective"].(map[string]any); eff["warn_days"] != float64(20) || eff["crit_days"] != float64(7) {
		t.Fatalf("effective: %v", eff)
	}
	// Errors: a duplicate, an invalid value, an unknown field, null for a
	// required field, a body that is not JSON.
	if rec := hs.api(tok, "POST", "/api/v2/targets", `{"host":"portal.example.nl"}`); rec.Code != http.StatusConflict || errCode(t, rec) != "conflict" {
		t.Fatalf("duplicate: %d %s", rec.Code, rec.Body.String())
	}
	rec = hs.api(tok, "POST", "/api/v2/targets", `{"host":"x.example.nl","port":70000,"interval_s":5}`)
	if e := decodeJSON[apiErrorBody](t, rec).Error; rec.Code != http.StatusBadRequest || e.Code != "invalid" || e.Fields["port"] == "" || e.Fields["interval_s"] == "" {
		t.Fatalf("invalid: %d %s", rec.Code, rec.Body.String())
	}
	if rec := hs.api(tok, "POST", "/api/v2/targets", `{"host":"x.example.nl","prot":"smtp"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rec.Code)
	}
	if rec := hs.api(tok, "POST", "/api/v2/targets", `{}`); rec.Code != http.StatusBadRequest || decodeJSON[apiErrorBody](t, rec).Error.Fields["host"] == "" {
		t.Fatalf("no host: %d %s", rec.Code, rec.Body.String())
	}
	if rec := hs.api(tok, "PATCH", fmt.Sprintf("/api/v2/targets/%d", id), `{"host":null}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("null host: %d", rec.Code)
	}
	if rec := hs.api(tok, "POST", "/api/v2/targets", `[1]`); rec.Code != http.StatusBadRequest {
		t.Fatalf("an array: %d", rec.Code)
	}
	req := httptest.NewRequest("POST", "/api/v2/targets", strings.NewReader("host=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+tok)
	r2 := httptest.NewRecorder()
	hs.h.ServeHTTP(r2, req)
	if r2.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("a form body: %d", r2.Code)
	}

	// Change: a new host carries the server name along; null resets.
	rec = hs.api(tok, "PATCH", fmt.Sprintf("/api/v2/targets/%d", id), `{"host":"shop.example.nl","warn_days":null,"channel_ids":[],"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body.String())
	}
	tg = decodeJSON[map[string]any](t, rec)
	if tg["server_name"] != "shop.example.nl" || tg["warn_days"] != nil || tg["enabled"] != false || tg["status"] != core.StatusDisabled {
		t.Fatalf("patched: %v", tg)
	}
	if ids, ok := tg["channel_ids"].([]any); !ok || len(ids) != 0 {
		t.Fatalf("channel_ids: %v", tg["channel_ids"])
	}
	if rec := hs.api(tok, "PATCH", fmt.Sprintf("/api/v2/targets/%d", id), `{"channel_ids":[999]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown channel: %d", rec.Code)
	}

	// Pages of one, through the cursor, cover every target once.
	for _, h := range []string{"a.example.nl", "b.example.nl", "c.example.nl"} {
		if rec := hs.api(tok, "POST", "/api/v2/targets", `{"host":"`+h+`","tags":["batch"]}`); rec.Code != http.StatusCreated {
			t.Fatal(rec.Body.String())
		}
	}
	seen := map[float64]bool{}
	cursor, pages := "", 0
	for {
		p := "/api/v2/targets?limit=1"
		if cursor != "" {
			p += "&cursor=" + cursor
		}
		rec := hs.api(tok, "GET", p, "")
		page := decodeJSON[struct {
			Data []map[string]any `json:"data"`
			Next *string          `json:"next_cursor"`
		}](t, rec)
		pages++
		for _, d := range page.Data {
			if seen[d["id"].(float64)] {
				t.Fatal("a target on two pages")
			}
			seen[d["id"].(float64)] = true
		}
		if page.Next == nil {
			break
		}
		cursor = *page.Next
		if pages > 10 {
			t.Fatal("the cursor does not end")
		}
	}
	if len(seen) != 5 {
		t.Fatalf("%d targets over %d pages, want 5", len(seen), pages)
	}
	if rec := hs.api(tok, "GET", "/api/v2/targets?tag=batch", ""); len(decodeJSON[apiList](t, rec).Data.([]any)) != 3 {
		t.Fatalf("tag filter: %s", rec.Body.String())
	}
	for _, q := range []string{"limit=0", "limit=x", "cursor=!!!"} {
		if rec := hs.api(tok, "GET", "/api/v2/targets?"+q, ""); rec.Code != http.StatusBadRequest {
			t.Errorf("?%s: %d", q, rec.Code)
		}
	}

	if rec := hs.api(tok, "POST", "/api/v2/targets/1/check", ""); rec.Code != http.StatusOK || decodeJSON[map[string]any](t, rec)["status"] != core.StatusUnreachable {
		t.Fatalf("check now: %d %s", rec.Code, rec.Body.String())
	}
	if rec := hs.api(tok, "DELETE", fmt.Sprintf("/api/v2/targets/%d", id), ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := hs.api(tok, "GET", fmt.Sprintf("/api/v2/targets/%d", id), ""); rec.Code != http.StatusNotFound || errCode(t, rec) != "not_found" {
		t.Fatalf("after delete: %d", rec.Code)
	}
	for _, p := range []string{"/api/v2/targets/abc", "/api/v2/targets/0", "/api/v2/nothing", "/api/v2/certificates/zz"} {
		if rec := hs.api(tok, "GET", p, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d", p, rec.Code)
		}
	}
	entries, _ := hs.srv.Core.AuditLog(context.Background(), "token", 100)
	actions := map[string]bool{}
	for _, e := range entries {
		if strings.Contains(e.Details, `token="test operator"`) && e.User == "operator@example.test" {
			actions[e.Action] = true
		}
	}
	for _, a := range []string{"target.create", "target.update", "target.check", "target.delete"} {
		if !actions[a] {
			t.Errorf("no %s audit entry naming the token", a)
		}
	}
}

// Domain watches, findings and their acknowledgement, issuances,
// certificates, channels and the export through the API.
func TestAPIResources(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	op := hs.apiToken(authz.Operator, authz.Operator)
	admin := hs.apiToken(authz.Admin, authz.Admin)

	rec := hs.api(op, "POST", "/api/v2/domains", `{"name":"Example.NL","subdomains":false,"tags":["prod"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create domain: %d %s", rec.Code, rec.Body.String())
	}
	d := decodeJSON[map[string]any](t, rec)
	did := int64(d["id"].(float64))
	if d["name"] != "example.nl" || d["subdomains"] != false {
		t.Fatalf("domain: %v", d)
	}
	if rec := hs.api(op, "POST", "/api/v2/domains", `{"name":"example.nl"}`); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate domain: %d", rec.Code)
	}
	if rec := hs.api(op, "POST", "/api/v2/domains", `{"name":"not a domain"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad domain: %d", rec.Code)
	}
	rec = hs.api(op, "PATCH", fmt.Sprintf("/api/v2/domains/%d", did), `{"enabled":false,"notes":"n"}`)
	if d := decodeJSON[map[string]any](t, rec); rec.Code != http.StatusOK || d["enabled"] != false || d["notes"] != "n" || d["status"] != core.StatusDisabled {
		t.Fatalf("patch domain: %d %s", rec.Code, rec.Body.String())
	}
	if rec := hs.api(op, "GET", "/api/v2/domains?status=disabled", ""); len(decodeJSON[apiList](t, rec).Data.([]any)) != 1 {
		t.Fatalf("domains filter: %s", rec.Body.String())
	}
	if rec := hs.api(op, "GET", fmt.Sprintf("/api/v2/issuances?domain_id=%d", did), ""); rec.Code != http.StatusOK {
		t.Fatalf("issuances: %d", rec.Code)
	}
	if rec := hs.api(op, "DELETE", fmt.Sprintf("/api/v2/domains/%d", did), ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete domain: %d", rec.Code)
	}

	// A finding to acknowledge: the harness target is unreachable after a check.
	for range 2 { // past the debounce
		if _, err := hs.srv.Sched.CheckNow(ctx, 1); err != nil {
			t.Fatal(err)
		}
	}
	rec = hs.api(op, "GET", "/api/v2/findings?target_id=1", "")
	list := decodeJSON[struct {
		Data []apiFindingJSON `json:"data"`
	}](t, rec)
	if rec.Code != http.StatusOK || len(list.Data) == 0 {
		t.Fatalf("findings: %d %s", rec.Code, rec.Body.String())
	}
	fid := list.Data[0].ID
	if rec := hs.api(op, "GET", "/api/v2/findings?state=nope", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad state: %d", rec.Code)
	}
	if rec := hs.api(op, "POST", fmt.Sprintf("/api/v2/findings/%d/ack", fid), `{"until":"tomorrow"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad until: %d", rec.Code)
	}
	until := time.Now().Add(72 * time.Hour).Format("2006-01-02")
	rec = hs.api(op, "POST", fmt.Sprintf("/api/v2/findings/%d/ack", fid), `{"until":"`+until+`","comment":"maintenance"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("ack: %d %s", rec.Code, rec.Body.String())
	}
	f := decodeJSON[map[string]any](t, rec)
	ack, _ := f["acknowledged"].(map[string]any)
	if ack == nil || ack["comment"] != "maintenance" || !strings.Contains(ack["by"].(string), "token test operator") || ack["until"] == nil {
		t.Fatalf("acknowledged: %v", f)
	}
	if rec := hs.api(op, "GET", fmt.Sprintf("/api/v2/findings/%d", fid), ""); rec.Code != http.StatusOK {
		t.Fatalf("get finding: %d", rec.Code)
	}

	if rec := hs.api(op, "GET", "/api/v2/certificates?all=1", ""); rec.Code != http.StatusOK {
		t.Fatalf("certificates: %d", rec.Code)
	}

	// Channels are an admin's; the list has no credentials.
	ch := notify.Channel{Name: "Ops", Kind: notify.KindWebhook, MinSeverity: "warning", Enabled: true, Webhook: notify.WebhookSettings{URL: "https://hooks.example.test/x", Secret: "s3cr3t-value"}}
	if _, err := hs.srv.Core.Channels.Save(ctx, ch); err != nil {
		t.Fatal(err)
	}
	if rec := hs.api(op, "GET", "/api/v2/channels", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("channels as operator: %d", rec.Code)
	}
	rec = hs.api(admin, "GET", "/api/v2/channels", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"Ops"`) || strings.Contains(rec.Body.String(), "s3cr3t") {
		t.Fatalf("channels: %d %s", rec.Code, rec.Body.String())
	}

	rec = hs.api(op, "GET", "/api/v2/export", "")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/yaml") || !strings.Contains(rec.Body.String(), "host: example.org") {
		t.Fatalf("export: %d %s", rec.Code, rec.Body.String())
	}
}

type apiFindingJSON struct {
	ID   int64      `json:"id"`
	Kind check.Kind `json:"kind"`
}

// A token past its burst is refused with 429 and Retry-After. Failed
// authentication is limited by address without blocking valid credentials.
func TestAPIRateLimits(t *testing.T) {
	hs := newHarness(t)
	tok := hs.apiToken(authz.Viewer, authz.Viewer)
	limited := false
	for i := 0; i < apiBurst+50 && !limited; i++ {
		rec := hs.api(tok, "GET", "/api/v2/findings", "")
		limited = rec.Code == http.StatusTooManyRequests && rec.Header().Get("Retry-After") != "" && errCode(t, rec) == "rate_limited"
	}
	if !limited {
		t.Fatal("a token was never rate limited")
	}
	hs = newHarness(t)
	tok = hs.apiToken(authz.Viewer, authz.Viewer)
	for i := 0; i < apiFailBurst; i++ {
		if rec := hs.api("tlsw_wrong", "GET", "/api/v2/targets", ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("bad token %d: %d", i, rec.Code)
		}
	}
	if rec := hs.api("tlsw_wrong", "GET", "/api/v2/targets", ""); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("invalid token after %d failures: %d", apiFailBurst, rec.Code)
	}
	if rec := hs.api(tok, "GET", "/api/v2/targets", ""); rec.Code != http.StatusOK {
		t.Fatalf("valid token behind blocked address: %d", rec.Code)
	}
}

// The OpenAPI document needs no token and describes every endpoint.
func TestOpenAPIDocument(t *testing.T) {
	hs := newHarness(t)
	rec := hs.api("", "GET", "/api/v2/openapi.json", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi: %d", rec.Code)
	}
	doc := decodeJSON[struct {
		OpenAPI    string                               `json:"openapi"`
		Paths      map[string]map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]map[string]any `json:"schemas"`
		} `json:"components"`
	}](t, rec)
	if doc.OpenAPI != "3.1.0" {
		t.Fatalf("version %q", doc.OpenAPI)
	}
	for _, a := range hs.srv.apiRoutes() {
		op, ok := doc.Paths[a.Path][strings.ToLower(a.Method)]
		if !ok {
			t.Errorf("%s %s is not in the document", a.Method, a.Path)
			continue
		}
		if op["x-role-action"] != string(a.Action) {
			t.Errorf("%s %s: x-role-action %v", a.Method, a.Path, op["x-role-action"])
		}
	}
	for _, name := range []string{"Target", "TargetInput", "Certificate", "Finding", "Domain", "DomainInput", "Issuance", "Channel", "ErrorBody", "AckInput"} {
		if doc.Components.Schemas[name] == nil {
			t.Errorf("no schema %s", name)
		}
	}
	props := doc.Components.Schemas["Target"]["properties"].(map[string]any)
	if nb, _ := props["not_after"].(map[string]any); nb["format"] != "date-time" {
		t.Errorf("not_after: %v", props["not_after"])
	}
}

// Add many takes an export document: a preview of what it adds, changes
// and leaves out, then the import on confirmation; a stale preview is shown
// again instead of imported. A CSV file adds targets like the line format.
func TestImportThroughAddMany(t *testing.T) {
	hs := newHarness(t)
	ctx := context.Background()
	doc := "version: 1\ntargets:\n  - host: example.org\n    tags: [kept]\n  - host: new.example.nl\ndomains:\n  - name: example.nl\n"
	rec := hs.do(authz.Operator, "POST", "/targets/bulk-add", url.Values{"hosts": {doc}}, true)
	page := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(page, "Targets added") || !strings.Contains(page, "Targets changed") || !strings.Contains(page, "Domains added") {
		t.Fatalf("preview: %d", rec.Code)
	}
	if ts, _ := hs.srv.Core.Targets(ctx); len(ts) != 1 {
		t.Fatal("the preview saved something")
	}
	i := strings.Index(page, `name="digest" value="`)
	digest := page[i+len(`name="digest" value="`):]
	digest = digest[:strings.Index(digest, `"`)]
	// Something changes between the preview and the confirmation.
	if _, err := hs.srv.Core.SaveTarget(ctx, core.Target{Host: "late.example.nl", ServerName: "late.example.nl", Port: 443, Protocol: "tls", Trust: "system", AllAddresses: true, AllChannels: true, Enabled: true}, "x"); err != nil {
		t.Fatal(err)
	}
	rec = hs.do(authz.Operator, "POST", "/targets/import", url.Values{"yaml": {doc}, "digest": {digest}}, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "changed since the preview") {
		t.Fatalf("stale confirmation: %d", rec.Code)
	}
	page = rec.Body.String()
	i = strings.Index(page, `name="digest" value="`)
	digest = page[i+len(`name="digest" value="`):]
	digest = digest[:strings.Index(digest, `"`)]
	rec = hs.do(authz.Operator, "POST", "/targets/import", url.Values{"yaml": {doc}, "digest": {digest}}, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	ts, _ := hs.srv.Core.Targets(ctx)
	ds, _ := hs.srv.Core.Domains(ctx)
	if len(ts) != 3 || len(ds) != 1 {
		t.Fatalf("%d targets and %d domains after the import", len(ts), len(ds))
	}
	if n := hs.count("SELECT COUNT(*) FROM audit WHERE details LIKE 'import=true%'"); n != 3 {
		t.Fatalf("%d import audit entries", n)
	}
	// A problem in the file goes back to the form, listed.
	rec = hs.do(authz.Operator, "POST", "/targets/bulk-add", url.Values{"hosts": {"version: 1\ntargets:\n  - host: a.example.nl\n    port: 0x1ffff\n"}}, true)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "targets[1] a.example.nl") {
		t.Fatalf("bad file: %d", rec.Code)
	}
	// A viewer cannot import.
	if rec := hs.do(authz.Viewer, "POST", "/targets/import", url.Values{"yaml": {doc}, "digest": {digest}}, true); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer import: %d", rec.Code)
	}
	rec = hs.do(authz.Operator, "POST", "/targets/bulk-add", url.Values{"hosts": {"host,name\ncsv1.example.nl,First\ncsv2.example.nl,Second\n"}, "protocol": {"tls"}, "trust_mode": {"system"}, "all_channels": {"1"}}, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("csv: %d %s", rec.Code, rec.Body.String())
	}
	if ts, _ := hs.srv.Core.Targets(ctx); len(ts) != 5 {
		t.Fatalf("%d targets after the CSV", len(ts))
	}
	// Settings › Export downloads the same document.
	rec = hs.do(authz.Admin, "GET", "/settings/export.yaml", nil, false)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "host: csv1.example.nl") || !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("export: %d", rec.Code)
	}
	if rec := hs.do(authz.Admin, "GET", "/settings/export", nil, false); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Download YAML") {
		t.Fatalf("export page: %d", rec.Code)
	}
}
