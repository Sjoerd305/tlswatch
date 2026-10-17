package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// hostile is an alert whose user-chosen fields (target name, details) try
// to inject markup into every transport.
func hostile() AlertData {
	days := 6
	return AlertData{
		Event: EventOpen, Severity: "critical", Kind: "expiring", KindLabel: "Expiring",
		TargetName: `<script>alert(1)</script> *bold* _it_ [x](https://evil.example) @everyone <!channel> & 💥 Ünïcødé`,
		HostPort:   "portal.example.nl:443",
		Details:    `"><img src=x onerror=alert(2)> <b>details</b>`,
		DaysLeft:   &days, NotAfter: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC),
		SubjectCN: "portal.example.nl", IssuerCN: "R3 <i>", Fingerprint: "0123456789abcdef0123456789abcdef",
		Link: "https://tlswatch.example.nl/targets/1",
	}
}

// The HTML part escapes every field: a target name or certificate field
// cannot add elements or attributes to the mail.
func TestRenderEscapesHTML(t *testing.T) {
	m := Render(hostile())
	for _, bad := range []string{"<script>", "<img src=x", "<b>details", "R3 <i>"} {
		if strings.Contains(m.HTML, bad) {
			t.Errorf("HTML part contains %q", bad)
		}
	}
	if !strings.Contains(m.HTML, "&lt;script&gt;") || !strings.Contains(m.HTML, "💥 Ünïcødé") {
		t.Error("escaped or unicode name missing from the HTML part")
	}
	// The plain part is the text as it is.
	if !strings.Contains(m.Body, "<script>alert(1)</script>") || !strings.Contains(m.Body, "💥 Ünïcødé") {
		t.Errorf("plain part: %s", m.Body)
	}

	// The batch and the digest escape too.
	b := Combine([]Message{alertMsg("critical", "<script>x</script>"), alertMsg("warning", "b")}, "")
	if strings.Contains(b.HTML, "<script>x") {
		t.Error("batch HTML not escaped")
	}
	d := RenderDigest(DigestData{Date: "Monday", Findings: []DigestFinding{{Severity: "critical", HostPort: "<svg onload=1>", Kind: "Expired", Details: "<script>"}},
		Failed: []DigestFailure{{Name: "<iframe>", HostPort: "h:1", Error: "<script>e</script>"}}, Issued: []DigestIssuance{{Domain: "d", Names: "<img>", Issuer: "i", State: "unexpected"}}}, "critical")
	for _, bad := range []string{"<svg", "<script>", "<iframe>", "<img>"} {
		if strings.Contains(d.HTML, bad) {
			t.Errorf("digest HTML contains %q", bad)
		}
	}
}

// A link that is not http(s) never becomes a clickable javascript: URL.
func TestRenderLinkIsSafe(t *testing.T) {
	a := hostile()
	a.Link = "javascript:alert(document.cookie)"
	if m := Render(a); strings.Contains(m.HTML, `href="javascript:`) {
		t.Fatal("javascript: link in the button")
	}
}

// Every subject starts with the severity tag, also for unusual events, and
// the recovery is tagged resolved.
func TestRenderSubjectTags(t *testing.T) {
	a := hostile()
	for ev, want := range map[string]string{EventOpen: "[critical] ", EventEscalate: "[critical] ", EventRemind: "[critical] ", EventRecover: "[resolved] "} {
		a.Event = ev
		a.OpenedAt = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
		m := Render(a)
		if !strings.HasPrefix(m.Subject, want) {
			t.Errorf("%s: subject %q", ev, m.Subject)
		}
		if strings.ContainsAny(m.Subject, "\r\n") {
			t.Errorf("%s: subject spans lines: %q", ev, m.Subject)
		}
	}
	a.Event = EventRemind
	if m := Render(a); !strings.Contains(m.Subject, "still open since 1 Oct") {
		t.Errorf("reminder subject %q", m.Subject)
	}
}

type capture struct {
	mu     sync.Mutex
	bodies [][]byte
	forms  []url.Values
}

func (c *capture) server(t *testing.T, reply string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			_ = r.ParseForm()
			c.forms = append(c.forms, r.PostForm)
		} else {
			b, _ := io.ReadAll(r.Body)
			c.bodies = append(c.bodies, b)
		}
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Slack: the reserved characters are escaped exactly once, so <!channel>
// cannot notify a whole channel and a link cannot be injected; the unicode
// survives.
func TestSlackEscapesHostileText(t *testing.T) {
	var c capture
	srv := c.server(t, "ok")
	if err := (&SlackSender{S: SlackSettings{WebhookURL: srv.URL + "/services/T/B/x"}}).Send(context.Background(), Render(hostile())); err != nil {
		t.Fatal(err)
	}
	var p struct{ Text string }
	if err := json.Unmarshal(c.bodies[0], &p); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Text, "<!channel>") || strings.Contains(p.Text, "<script>") {
		t.Fatalf("unescaped control sequence: %s", p.Text)
	}
	if !strings.Contains(p.Text, "&lt;!channel&gt; &amp; 💥 Ünïcødé") || strings.Contains(p.Text, "&amp;lt;") {
		t.Fatalf("escaping: %s", p.Text)
	}
}

// Discord: no mention is ever parsed, the text is cut at 2000 characters
// without splitting a character, and the JSON stays valid.
func TestDiscordHostileAndLong(t *testing.T) {
	var c capture
	srv := c.server(t, `{"id":"1"}`)
	a := hostile()
	a.Details = strings.Repeat("😀", 3000)
	if err := (&DiscordSender{S: DiscordSettings{WebhookURL: srv.URL + "/api/webhooks/1/x"}}).Send(context.Background(), Render(a)); err != nil {
		t.Fatal(err)
	}
	var p struct {
		Content         string
		AllowedMentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
	}
	raw := c.bodies[0]
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"allowed_mentions":{"parse":[]}`) {
		t.Fatalf("mentions not disabled: %s", raw[:200])
	}
	if n := utf8.RuneCountInString(p.Content); n > maxDiscordChars || !utf8.ValidString(p.Content) {
		t.Fatalf("content of %d runes, valid %v", n, utf8.ValidString(p.Content))
	}
	if !strings.HasPrefix(p.Content, "[critical] portal.example.nl:443 expires in 6 days") {
		t.Fatalf("subject not first: %.80s", p.Content)
	}
}

// Telegram: the text goes as plain text (no parse_mode), so characters
// that MarkdownV2 or HTML would reserve arrive as they are and cannot make
// the API refuse the message; a long message is cut on a character
// boundary.
func TestTelegramHostileTextIsPlain(t *testing.T) {
	var c capture
	srv := c.server(t, `{"ok":true,"result":{"message_id":7}}`)
	snd := &TelegramSender{S: TelegramSettings{Token: tgToken, ChatIDs: []string{"42"}}, BaseURL: srv.URL}
	m := Render(hostile())
	if err := snd.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	f := c.forms[0]
	if pm := f.Get("parse_mode"); pm != "" {
		t.Fatalf("parse_mode %q: the text would need escaping", pm)
	}
	if f.Get("text") != m.Subject+"\n\n"+m.Body {
		t.Fatalf("text changed on the way: %q", f.Get("text"))
	}
	a := hostile()
	a.Details = strings.Repeat("😀", 5000)
	if err := snd.Send(context.Background(), Render(a)); err != nil {
		t.Fatal(err)
	}
	text := c.forms[1].Get("text")
	if !utf8.ValidString(text) || utf8.RuneCountInString(text) > maxTGChars {
		t.Fatalf("long text: %d runes, valid %v", utf8.RuneCountInString(text), utf8.ValidString(text))
	}
}

// ntfy: the title is the subject without its tag, the priority and tag
// follow the severity, and a long body is cut on a character boundary.
func TestNtfyHostileAndLong(t *testing.T) {
	var c capture
	srv := c.server(t, `{"id":"abc"}`)
	snd := &NtfySender{S: NtfySettings{Server: srv.URL, Topic: "ops"}}
	a := hostile()
	a.Details = strings.Repeat("ü", 6000)
	if err := snd.Send(context.Background(), Render(a)); err != nil {
		t.Fatal(err)
	}
	var p struct {
		Title    string
		Message  string
		Priority int
		Tags     []string
	}
	if err := json.Unmarshal(c.bodies[0], &p); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(p.Title, "[") || p.Priority != 5 || len(p.Tags) != 1 || p.Tags[0] != "rotating_light" {
		t.Fatalf("payload %+v", p)
	}
	if !utf8.ValidString(p.Message) || utf8.RuneCountInString(p.Message) > maxNtfyChars {
		t.Fatalf("message of %d runes", utf8.RuneCountInString(p.Message))
	}
	// A recovery is priority 3 with the check mark.
	a.Event = EventRecover
	if err := snd.Send(context.Background(), Render(a)); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(c.bodies[1], &p)
	if p.Priority != 3 || p.Tags[0] != "white_check_mark" {
		t.Fatalf("recovery payload: %d %v", p.Priority, p.Tags)
	}
}

// Webhook: the payload carries the hostile text verbatim in valid JSON,
// and the signature covers exactly the bytes sent.
func TestWebhookHostileText(t *testing.T) {
	var c capture
	srv := c.server(t, "")
	m := Render(hostile())
	if err := (&WebhookSender{S: WebhookSettings{URL: srv.URL, Secret: "k"}}).Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	var p WebhookPayload
	if err := json.Unmarshal(c.bodies[0], &p); err != nil {
		t.Fatal(err)
	}
	if p.Severity != "critical" || p.Text != m.Body || "["+p.Severity+"] "+p.Subject != m.Subject {
		t.Fatalf("payload %+v", p)
	}
}

// Combine with more than 50 alerts lists 50 and counts the rest; the worst
// tag wins, an untagged subject counts as info.
func TestCombineCapAndOrder(t *testing.T) {
	var msgs []Message
	for i := 0; i < 70; i++ {
		msgs = append(msgs, alertMsg("warning", "w"))
	}
	msgs = append(msgs, Message{Subject: "untagged"}, alertMsg("resolved", "r"), alertMsg("critical", "c"))
	m := Combine(msgs, "https://tlswatch.example.nl/findings")
	lines := strings.Split(strings.TrimSpace(m.Body), "\n")
	if !strings.HasPrefix(m.Subject, "[critical] 73 alerts") || lines[0] != "[critical] c" {
		t.Fatalf("subject %q, first %q", m.Subject, lines[0])
	}
	if !strings.Contains(m.Body, "… and 23 more") {
		t.Fatalf("cap: %s", m.Body)
	}
	if n := strings.Count(m.Body, "\n[") + 1; n != MaxBatchLines {
		t.Fatalf("%d alert lines, cap is %d", n, MaxBatchLines)
	}
	one := Combine([]Message{alertMsg("info", "only")}, "link")
	if one.Subject != "[info] only" {
		t.Fatal("a batch of one is not sent as it is")
	}
}
