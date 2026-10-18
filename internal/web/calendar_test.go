package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
)

// A user creates a feed under Account, sees its URL once, a calendar
// client fetches it without signing in, and revoking it ends that.
func TestCalendarFeed(t *testing.T) {
	hs := newHarness(t)
	now := time.Now().Unix()
	if _, err := hs.db.W.Exec(`INSERT INTO certificates(fingerprint, subject, subject_cn, issuer, issuer_cn, issuer_org, serial, not_before, not_after,
		key_type, key_bits, sig_alg, is_ca, self_signed, pem, first_seen, last_seen) VALUES('fp1','CN=portal.example.org','portal.example.org','CN=R11','R11','Let''s Encrypt','1',?,?,'ECDSA',256,'ECDSA-SHA256',0,0,'',?,?)`,
		now-30*86400, now+60*86400, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := hs.db.W.Exec(`UPDATE targets SET current_fp = 'fp1', not_after = ?, enabled = 1, renewal_managed = 1, renewal_set = 1, tags = 'web' WHERE id = 1`, now+60*86400); err != nil {
		t.Fatal(err)
	}
	rec := hs.do(authz.Viewer, "POST", "/account/calendars", url.Values{"tag": {"web"}}, true)
	m := regexp.MustCompile(`http://[^"<]+/calendar/([A-Za-z0-9_-]+)\.ics`).FindStringSubmatch(rec.Body.String())
	if rec.Code != http.StatusOK || m == nil {
		t.Fatalf("create: %d, no URL shown", rec.Code)
	}
	if hs.count("SELECT COUNT(*) FROM audit WHERE action = 'calendar.create' AND details = 'tag web'") != 1 {
		t.Error("creation not audited")
	}
	if strings.Contains(hs.do(authz.Viewer, "GET", "/account", nil, false).Body.String(), m[1]) {
		t.Fatal("the token is shown again")
	}
	fetch := func(token string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		hs.h.ServeHTTP(rec, httptest.NewRequest("GET", "/calendar/"+token+".ics", nil))
		return rec
	}
	got := fetch(m[1])
	body := got.Body.String()
	if got.Code != http.StatusOK || !strings.HasPrefix(got.Header().Get("Content-Type"), "text/calendar") {
		t.Fatalf("fetch: %d %s", got.Code, got.Header().Get("Content-Type"))
	}
	for _, want := range []string{"BEGIN:VCALENDAR\r\n", "UID:fp1@tlswatch\r\n", "UID:renew-fp1@tlswatch\r\n", "SUMMARY:Certificate expires: portal.example.org (t)",
		"X-WR-CALNAME:tlswatch expiries · web", "DTSTART;VALUE=DATE:" + time.Unix(now+60*86400, 0).In(hs.srv.Core.CurrentSettings(context.Background()).Location()).Format("20060102")} {
		if !strings.Contains(body, want) {
			t.Errorf("feed lacks %q:\n%s", want, body)
		}
	}
	for _, l := range strings.Split(body, "\r\n") {
		if len(l) > 75 {
			t.Errorf("line longer than 75 octets: %q", l)
		}
	}
	// Another tag: the target is left out.
	if _, err := hs.db.W.Exec(`UPDATE targets SET tags = 'mail' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fetch(m[1]).Body.String(), "BEGIN:VEVENT") {
		t.Error("a target outside the tag is in the feed")
	}
	if fetch("nonsense").Code != http.StatusNotFound {
		t.Error("an unknown token answered")
	}
	// Revoked: the URL stops working.
	var id int64
	if err := hs.db.R.QueryRow("SELECT id FROM calendars").Scan(&id); err != nil {
		t.Fatal(err)
	}
	if rec := hs.do(authz.Operator, "POST", "/account/calendars/"+strconv.FormatInt(id, 10)+"/delete", nil, true); rec.Code == http.StatusSeeOther {
		t.Fatal("another user revoked the feed")
	}
	if rec := hs.do(authz.Viewer, "POST", "/account/calendars/"+strconv.FormatInt(id, 10)+"/delete", nil, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if fetch(m[1]).Code != http.StatusNotFound || hs.count("SELECT COUNT(*) FROM audit WHERE action = 'calendar.revoke'") != 1 {
		t.Fatal("a revoked feed still answers, or the revocation is not audited")
	}
}
