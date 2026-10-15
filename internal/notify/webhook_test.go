package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebhookSend(t *testing.T) {
	var got WebhookPayload
	var sig, sev, ref string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad request", 400)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if err := VerifySignature("s3cret", body, r.Header.Get("X-TLSWatch-Signature")); err != nil {
			http.Error(w, err.Error(), 401)
			return
		}
		sig, sev, ref = r.Header.Get("X-TLSWatch-Signature"), r.Header.Get("X-TLSWatch-Severity"), r.Header.Get("X-TLSWatch-Ref")
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(204)
	}))
	defer srv.Close()
	s := &WebhookSender{S: WebhookSettings{URL: srv.URL + "/hook?token=abc", Secret: "s3cret"}, Now: func() time.Time { return time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC) }}
	r, err := s.SendRef(context.Background(), Message{Subject: "[critical] portal:443 expires in 6 days", Body: "Target: portal\n", Ref: "ref1"})
	if err != nil {
		t.Fatal(err)
	}
	if r != "ref1" || ref != "ref1" || sev != "critical" || !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("ref %q header ref %q severity %q signature %q", r, ref, sev, sig)
	}
	want := WebhookPayload{Source: "tlswatch", Ref: "ref1", Severity: "critical", Subject: "portal:443 expires in 6 days", Text: "Target: portal\n", SentAt: "2026-10-15T12:00:00Z"}
	if got != want {
		t.Fatalf("payload %+v", got)
	}
	if d := s.S.Destination(); d != srv.URL+"/hook" {
		t.Fatalf("destination %q shows the query", d)
	}
}

func TestWebhookErrors(t *testing.T) {
	status := 500
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status == 429 {
			w.Header().Set("Retry-After", "7")
		}
		w.WriteHeader(status)
		w.Write([]byte(`{"error":"boom s3cret"}`))
	}))
	defer srv.Close()
	s := &WebhookSender{S: WebhookSettings{URL: srv.URL, Secret: "s3cret"}}
	err := s.Send(context.Background(), Message{Subject: "s"})
	if err == nil || !strings.Contains(err.Error(), "500") || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("got %v", err)
	}
	status = 429
	err = s.Send(context.Background(), Message{Subject: "s"})
	var ra *RetryAfterError
	if !errors.As(err, &ra) || ra.After < 7*time.Second || ra.After > 9*time.Second {
		t.Fatalf("got %v", err)
	}
	srv.Close()
	if err := s.Send(context.Background(), Message{Subject: "s"}); err == nil {
		t.Fatal("connection error not reported")
	}
}

func TestWebhookValidate(t *testing.T) {
	for _, bad := range []string{"", "hooks.example.org", "ftp://x/y", "https://user:pw@x/y", "https:///path"} {
		if err := (WebhookSettings{URL: bad}).Validate(); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if err := (WebhookSettings{URL: "http://automation.lan:5678/webhook/abc"}).Validate(); err != nil {
		t.Fatal(err)
	}
}
