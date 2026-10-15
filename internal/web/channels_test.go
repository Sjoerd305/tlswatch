package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/sjoerd305/tlswatch/internal/authz"
)

// Every channel kind has a form that renders, saves, keeps its credential
// when the field is left empty, and never shows the credential back.
func TestChannelKindsForms(t *testing.T) {
	hs := newHarness(t)
	kinds := []struct {
		kind, secret, dest string
		form               url.Values
	}{
		{"slack", "https://hooks.slack.com/services/T1/B2/XYZq9hid", "hooks.slack.com", url.Values{"webhook_url": {"https://hooks.slack.com/services/T1/B2/XYZq9hid"}}},
		{"discord", "https://discord.com/api/webhooks/42/TOKq9hid", "discord.com", url.Values{"webhook_url": {"https://discord.com/api/webhooks/42/TOKq9hid"}}},
		{"ntfy", "tk_q9hid", "https://ntfy.lan/tlswatch", url.Values{"server": {"https://ntfy.lan/"}, "topic": {"tlswatch"}, "token": {"tk_q9hid"}}},
		{"webhook", "hmac_q9hid", "https://automation.lan/hook", url.Values{"url": {"https://automation.lan/hook?key=k"}, "secret": {"hmac_q9hid"}}},
	}
	for i, k := range kinds {
		id := i + 1
		page := hs.do(authz.Admin, "GET", "/settings/channels?new="+k.kind, nil, false)
		if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `name="kind" value="`+k.kind+`"`) {
			t.Fatalf("%s: new form %d", k.kind, page.Code)
		}
		f := url.Values{"kind": {k.kind}, "name": {k.kind + " ops"}, "min_severity": {"critical"}, "enabled": {"1"}}
		for key, v := range k.form {
			f[key] = v
		}
		if rec := hs.do(authz.Admin, "POST", "/settings/channels", f, true); rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: save: %d %s", k.kind, rec.Code, rec.Body.String())
		}
		var blob []byte
		var dest string
		if err := hs.db.R.QueryRow("SELECT settings, destination FROM channels WHERE id = ?", id).Scan(&blob, &dest); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(blob), "q9hid") || dest != k.dest {
			t.Fatalf("%s: settings in clear text or destination %q", k.kind, dest)
		}
		list := hs.do(authz.Admin, "GET", "/settings/channels", nil, false).Body.String()
		if strings.Contains(list, "q9hid") || !strings.Contains(list, k.dest) {
			t.Fatalf("%s: channel table shows the credential or not the destination", k.kind)
		}
		edit := hs.do(authz.Admin, "GET", "/settings/channels?edit="+url.QueryEscape(itoa(id)), nil, false)
		if edit.Code != http.StatusOK || strings.Contains(edit.Body.String(), "q9hid") || !strings.Contains(edit.Body.String(), "leave empty to keep") {
			t.Fatalf("%s: edit form %d shows the credential", k.kind, edit.Code)
		}
		// Saving with the credential field empty keeps it; the validation
		// error for a missing credential only applies to a new channel.
		f.Set("id", itoa(id))
		for _, key := range []string{"webhook_url", "token", "secret"} {
			if f.Has(key) {
				f.Set(key, "")
			}
		}
		f.Set("min_severity", "warning")
		if rec := hs.do(authz.Admin, "POST", "/settings/channels", f, true); rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: update: %d %s", k.kind, rec.Code, rec.Body.String())
		}
		c, err := hs.srv.Core.Channels.Get(context.Background(), int64(id))
		if err != nil || c.MinSeverity != "warning" {
			t.Fatalf("%s: after update: %+v %v", k.kind, c, err)
		}
		var kept bool
		for _, s := range c.Secrets() {
			kept = kept || s == k.secret
		}
		if !kept {
			t.Fatalf("%s: credential not kept: %+v", k.kind, c.Secrets())
		}
	}
	// A new Slack channel without a URL is refused with a message.
	f := url.Values{"kind": {"slack"}, "name": {"empty"}, "min_severity": {"info"}, "enabled": {"1"}}
	rec := hs.do(authz.Admin, "POST", "/settings/channels", f, true)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Webhook URL") {
		t.Fatalf("empty slack: %d", rec.Code)
	}
	// An unknown kind falls back to SMTP and fails SMTP validation.
	f = url.Values{"kind": {"pigeon"}, "name": {"x"}, "min_severity": {"info"}}
	if rec := hs.do(authz.Admin, "POST", "/settings/channels", f, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown kind: %d", rec.Code)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
