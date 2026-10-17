package notify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSlackSend(t *testing.T) {
	var got map[string]string
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	s := &SlackSender{S: SlackSettings{WebhookURL: srv.URL + "/services/T1/B2/XYZ"}}
	if err := s.Send(context.Background(), Message{Subject: "[critical] portal:443 expires in 6 days", Body: "Expires: <soon> & more\n"}); err != nil {
		t.Fatal(err)
	}
	if path != "/services/T1/B2/XYZ" || got["text"] != "[critical] portal:443 expires in 6 days\n\nExpires: &lt;soon&gt; &amp; more" {
		t.Fatalf("path %q text %q", path, got["text"])
	}
	if d := s.S.Destination(); d != strings.TrimPrefix(srv.URL, "http://") {
		t.Fatalf("destination %q shows more than the host", d)
	}
}

func TestSlackErrorsHideURL(t *testing.T) {
	status := 404
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status == 429 {
			w.Header().Set("Retry-After", "30")
		}
		w.WriteHeader(status)
		w.Write([]byte("channel_not_found"))
	}))
	defer srv.Close()
	s := &SlackSender{S: SlackSettings{WebhookURL: srv.URL + "/services/T1/B2/XYZ"}}
	err := s.Send(context.Background(), Message{Subject: "s"})
	if err == nil || !strings.Contains(err.Error(), "channel_not_found") || strings.Contains(err.Error(), "XYZ") {
		t.Fatalf("got %v", err)
	}
	status = 429
	err = s.Send(context.Background(), Message{Subject: "s"})
	var ra *RetryAfterError
	if !errors.As(err, &ra) || ra.After < 30*time.Second {
		t.Fatalf("got %v", err)
	}
	srv.Close()
	err = s.Send(context.Background(), Message{Subject: "s"})
	if err == nil || strings.Contains(err.Error(), "XYZ") || strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("connection error leaks the URL or is nil: %v", err)
	}
}

// A target named "@channel" must not ping a Mattermost or Rocket.Chat
// channel, nor a Telegram user; e-mail addresses stay as they are.
func TestNoMentions(t *testing.T) {
	for in, want := range map[string]string{
		"@channel expires":         "@⁠channel expires",
		"see @all, (@here)":        "see @⁠all, (@⁠here)",
		"by ops@example.nl":        "by ops@example.nl",
		"@everyone\n@Ops_team now": "@⁠everyone\n@⁠Ops_team now",
		"a @ b":                    "a @ b",
	} {
		if got := noMentions(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if got := slackEscape("<@channel>"); got != "&lt;@⁠channel&gt;" {
		t.Errorf("slack: %q", got)
	}
}
