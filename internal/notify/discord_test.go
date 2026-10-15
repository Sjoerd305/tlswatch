package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscordSend(t *testing.T) {
	var got map[string]string
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"id":"1234567890","channel_id":"42","content":"…"}`))
	}))
	defer srv.Close()
	s := &DiscordSender{S: DiscordSettings{WebhookURL: srv.URL + "/api/webhooks/42/TOKEN"}}
	ref, err := s.SendRef(context.Background(), Message{Subject: "[info] x", Body: strings.Repeat("y", 3000)})
	if err != nil {
		t.Fatal(err)
	}
	if ref != "1234567890" || query != "wait=true" {
		t.Fatalf("ref %q query %q", ref, query)
	}
	if n := len([]rune(got["content"])); n != maxDiscordChars || !strings.HasPrefix(got["content"], "[info] x\n\nyyy") {
		t.Fatalf("content %d runes: %.20q", n, got["content"])
	}
}

func TestDiscordErrorsHideURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte(`{"message":"Invalid Webhook Token","code":50027}`))
	}))
	defer srv.Close()
	s := &DiscordSender{S: DiscordSettings{WebhookURL: srv.URL + "/api/webhooks/42/TOKEN"}}
	err := s.Send(context.Background(), Message{Subject: "s"})
	if err == nil || !strings.Contains(err.Error(), "401 Invalid Webhook Token") || strings.Contains(err.Error(), "TOKEN") {
		t.Fatalf("got %v", err)
	}
	if d := s.S.Destination(); strings.Contains(d, "TOKEN") {
		t.Fatalf("destination %q shows the token", d)
	}
}
