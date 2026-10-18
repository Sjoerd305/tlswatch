package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// recordingServer is a server that records each request's method, path, headers
// and JSON body, and answers with status and reply.
type recordingServer struct {
	mu     sync.Mutex
	reqs   []recordedRequest
	status int
	reply  string
}

type recordedRequest struct {
	method, path, auth string
	body               map[string]any
}

func (c *recordingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	c.mu.Lock()
	c.reqs = append(c.reqs, recordedRequest{r.Method, r.URL.EscapedPath(), r.Header.Get("Authorization"), body})
	status, reply := c.status, c.reply
	c.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	io.WriteString(w, reply)
}

func TestTeamsCard(t *testing.T) {
	c := &recordingServer{status: http.StatusAccepted}
	srv := httptest.NewServer(c)
	defer srv.Close()
	s := &TeamsSender{S: TeamsSettings{WebhookURL: srv.URL + "/workflows/abc/triggers/manual/paths/invoke?sig=SECRETSIG"}}
	if err := s.Send(context.Background(), Message{Subject: "[critical] portal:443 certificate expired", Body: "Target: Portal\nDetails: expired\n"}); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(c.reqs[0].body)
	for _, want := range []string{`"contentType":"application/vnd.microsoft.card.adaptive"`, `"color":"Attention"`, `"text":"Target: Portal"`, `"text":"Details: expired"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("card lacks %s: %s", want, b)
		}
	}
	// The URL's signature never shows in an error.
	c.status, c.reply = http.StatusUnauthorized, "bad sig=SECRETSIG"
	err := s.Send(context.Background(), Message{Subject: "[info] x"})
	var perm *PermanentError
	if err == nil || strings.Contains(err.Error(), "SECRETSIG") || !errors.As(err, &perm) {
		t.Fatalf("error: %v", err)
	}
	if err := (TeamsSettings{WebhookURL: "ftp://x"}).Validate(); err == nil {
		t.Fatal("ftp URL accepted")
	}
}

func TestMatrixNotice(t *testing.T) {
	c := &recordingServer{reply: `{"event_id":"$ev1"}`}
	srv := httptest.NewServer(c)
	defer srv.Close()
	s := &MatrixSender{S: MatrixSettings{Homeserver: srv.URL + "/", RoomID: "!room:example.org", Token: "syt_secret"}}
	ref, err := s.SendRef(context.Background(), Message{Subject: "[warning] @room <b>portal</b>", Body: "line one\nline two\n", Ref: "abc123"})
	if err != nil || ref != "$ev1" {
		t.Fatalf("send: %q %v", ref, err)
	}
	r := c.reqs[0]
	if r.method != http.MethodPut || r.path != "/_matrix/client/v3/rooms/%21room:example.org/send/m.room.message/abc123" || r.auth != "Bearer syt_secret" {
		t.Fatalf("request: %+v", r)
	}
	if r.body["msgtype"] != "m.notice" || strings.Contains(r.body["body"].(string), "@room") ||
		!strings.Contains(r.body["formatted_body"].(string), "&lt;b&gt;portal&lt;/b&gt;") || !strings.Contains(r.body["formatted_body"].(string), "line one<br>line two") {
		t.Fatalf("body: %+v", r.body)
	}
	c.status, c.reply = http.StatusForbidden, `{"errcode":"M_FORBIDDEN","error":"syt_secret is not in the room"}`
	if _, err := s.SendRef(context.Background(), Message{Subject: "x"}); err == nil || strings.Contains(err.Error(), "syt_secret") {
		t.Fatalf("error: %v", err)
	}
	for _, bad := range []MatrixSettings{{Homeserver: srv.URL, RoomID: "#ops:example.org", Token: "t"}, {Homeserver: srv.URL, RoomID: "!a:b"}} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestPagerDutyEvents(t *testing.T) {
	c := &recordingServer{status: http.StatusAccepted, reply: `{"status":"success"}`}
	srv := httptest.NewServer(c)
	defer srv.Close()
	key := strings.Repeat("a", 32)
	s := &PagerDutySender{S: PagerDutySettings{RoutingKey: key}, Endpoint: srv.URL}
	ctx := context.Background()
	if ref, err := s.SendRef(ctx, Message{Subject: "[critical] portal:443 certificate expired", Body: "details\n", Event: EventOpen, FindingID: 42}); err != nil || ref != "tlswatch-finding-42" {
		t.Fatalf("trigger: %q %v", ref, err)
	}
	if _, err := s.SendRef(ctx, Message{Subject: "[resolved] portal:443", Event: EventRecover, FindingID: 42}); err != nil {
		t.Fatal(err)
	}
	trig, res := c.reqs[0].body, c.reqs[1].body
	payload := trig["payload"].(map[string]any)
	if trig["event_action"] != "trigger" || trig["dedup_key"] != "tlswatch-finding-42" || trig["routing_key"] != key ||
		payload["severity"] != "critical" || payload["summary"] != "portal:443 certificate expired" {
		t.Fatalf("trigger: %+v", trig)
	}
	if res["event_action"] != "resolve" || res["dedup_key"] != "tlswatch-finding-42" || res["payload"] != nil {
		t.Fatalf("resolve: %+v", res)
	}
	// A test triggers and resolves one incident of its own.
	c.reqs = nil
	if _, err := s.SendRef(ctx, Message{Subject: "[info] test", Ref: "r1", Event: "test"}); err != nil || len(c.reqs) != 2 ||
		c.reqs[0].body["dedup_key"] != "tlswatch-test-r1" || c.reqs[1].body["event_action"] != "resolve" {
		t.Fatalf("test: %v %+v", err, c.reqs)
	}
	var perm *PermanentError
	if _, err := s.SendRef(ctx, Message{Subject: "digest", Event: EventDigest}); !errors.As(err, &perm) {
		t.Fatalf("digest: %v", err)
	}
	c.status, c.reply = http.StatusBadRequest, `{"status":"invalid event","errors":["`+key+` is not valid"]}`
	if _, err := s.SendRef(ctx, Message{Subject: "x", Event: EventOpen, FindingID: 1}); !errors.As(err, &perm) || strings.Contains(err.Error(), key) {
		t.Fatalf("400: %v", err)
	}
	if (PagerDutySettings{RoutingKey: "short"}).Validate() == nil || (PagerDutySettings{RoutingKey: key, Region: "eu"}).Destination() != "https://events.eu.pagerduty.com/v2/enqueue" {
		t.Fatal("settings")
	}
}

// Alerts to PagerDuty are sent one by one with their event and finding;
// alerts to other channels of the same run are still batched.
func TestOutboxNeverBatchesPagerDuty(t *testing.T) {
	o := newOutbox(t)
	pd, err := o.chans.Save(o.ctx, Channel{Name: "pd", Kind: KindPagerDuty, MinSeverity: "warning", Enabled: true,
		PagerDuty: PagerDutySettings{RoutingKey: strings.Repeat("b", 32)}})
	if err != nil {
		t.Fatal(err)
	}
	ops := o.channel("ops")
	if _, err := o.db.W.Exec("INSERT INTO domains(id, name, created_at, updated_at) VALUES(1, 'example.nl', 1, 1)"); err != nil {
		t.Fatal(err)
	}
	var findings []int64
	for i := 0; i < 2; i++ {
		res, err := o.db.W.Exec("INSERT INTO findings(domain_id, kind, severity, opened_at, details, fingerprint) VALUES(1, 'unexpected_certificate', 'warning', 1, 'x', ?)", i)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		findings = append(findings, id)
	}
	tx, _ := o.db.W.BeginTx(o.ctx, nil)
	for _, f := range findings {
		for _, ch := range []int64{pd, ops} {
			if err := Enqueue(o.ctx, tx, f, ch, EventOpen, alertMsg("critical", "expired"), o.clock.Now()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	o.clock.Add(BatchDelay + 1)
	o.flush()
	got := o.take("pd")
	if len(got) != 2 || got[0].Event != EventOpen || got[0].FindingID != findings[0] || got[1].FindingID != findings[1] {
		t.Fatalf("pagerduty: %+v", got)
	}
	if ops := o.take("ops"); len(ops) != 1 || ops[0].FindingID != 0 {
		t.Fatalf("batched channel: %+v", ops)
	}
}
