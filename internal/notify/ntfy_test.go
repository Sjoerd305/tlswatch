package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNtfySend(t *testing.T) {
	var got map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || r.Method != http.MethodPost {
			http.Error(w, "bad path "+r.URL.Path, 404)
			return
		}
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"id":"abc123","time":1,"event":"message","topic":"ops"}`))
	}))
	defer srv.Close()
	s := &NtfySender{S: NtfySettings{Server: srv.URL + "/", Topic: "ops", Token: "tk_secret"}}
	ref, err := s.SendRef(context.Background(), Message{Subject: "[warning] portal:443 expires in 20 days", Body: strings.Repeat("x", 5000)})
	if err != nil {
		t.Fatal(err)
	}
	if ref != "abc123" || auth != "Bearer tk_secret" {
		t.Fatalf("ref %q auth %q", ref, auth)
	}
	if got["topic"] != "ops" || got["title"] != "portal:443 expires in 20 days" || got["priority"] != float64(4) {
		t.Fatalf("payload %v", got)
	}
	if tags, _ := got["tags"].([]any); len(tags) != 1 || tags[0] != "warning" {
		t.Fatalf("tags %v", got["tags"])
	}
	if n := len([]rune(got["message"].(string))); n != maxNtfyChars {
		t.Fatalf("message truncated to %d", n)
	}
	if d := s.S.Destination(); d != srv.URL+"/ops" {
		t.Fatalf("destination %q", d)
	}
}

func TestNtfyErrorsHideToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"code":40301,"http":403,"error":"forbidden tk_secret"}`))
	}))
	defer srv.Close()
	s := &NtfySender{S: NtfySettings{Server: srv.URL, Topic: "ops", Token: "tk_secret"}}
	err := s.Send(context.Background(), Message{Subject: "s"})
	if err == nil || !strings.Contains(err.Error(), "403 forbidden") || strings.Contains(err.Error(), "tk_secret") {
		t.Fatalf("got %v", err)
	}
}

func TestNtfyValidate(t *testing.T) {
	if err := (NtfySettings{Topic: "tlswatch-ops"}).Validate(); err != nil {
		t.Fatal(err)
	}
	if d := (NtfySettings{Topic: "ops"}).Destination(); d != "https://ntfy.sh/ops" {
		t.Fatalf("default server: %q", d)
	}
	for _, bad := range []NtfySettings{{Topic: ""}, {Topic: "has space"}, {Topic: "a/b"}, {Server: "ntfy.lan", Topic: "ops"}, {Topic: strings.Repeat("a", 65)}} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}
