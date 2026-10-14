package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const tgToken = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"

func TestTelegramSend(t *testing.T) {
	var mu sync.Mutex
	var chats, texts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bot"+tgToken+"/sendMessage" || r.Method != http.MethodPost {
			http.Error(w, "bad path", 404)
			return
		}
		r.ParseForm()
		mu.Lock()
		chats = append(chats, r.Form.Get("chat_id"))
		texts = append(texts, r.Form.Get("text"))
		mu.Unlock()
		w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer srv.Close()
	s := &TelegramSender{S: TelegramSettings{Token: tgToken, ChatIDs: []string{"-1001234567890", "@opsalerts"}}, BaseURL: srv.URL}
	if err := s.Send(context.Background(), Message{Subject: "[critical] x", Body: "a\nb"}); err != nil {
		t.Fatal(err)
	}
	if len(chats) != 2 || chats[1] != "@opsalerts" || texts[0] != "[critical] x\n\na\nb" {
		t.Fatalf("chats %q texts %q", chats, texts)
	}
	long := strings.Repeat("é", 5000)
	if err := s.Send(context.Background(), Message{Subject: "s", Body: long}); err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(texts[len(texts)-1])); n != 4096 {
		t.Fatalf("truncated to %d runes", n)
	}
}

func TestTelegramErrorsHideToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`))
	}))
	defer srv.Close()
	s := &TelegramSender{S: TelegramSettings{Token: tgToken, ChatIDs: []string{"42"}}, BaseURL: srv.URL}
	err := s.Send(context.Background(), Message{Subject: "s"})
	if err == nil || !strings.Contains(err.Error(), "chat not found") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), tgToken) {
		t.Fatalf("token leaked: %v", err)
	}
	srv.Close()
	err = s.Send(context.Background(), Message{Subject: "s"})
	if err == nil || strings.Contains(err.Error(), tgToken) || strings.Contains(err.Error(), "AAHdq") {
		t.Fatalf("connection error leaks token or is nil: %v", err)
	}
}

func TestTelegramOKFalseWith200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"description":"Forbidden: bot was blocked by the user"}`))
	}))
	defer srv.Close()
	s := &TelegramSender{S: TelegramSettings{Token: tgToken, ChatIDs: []string{"42"}}, BaseURL: srv.URL}
	if err := s.Send(context.Background(), Message{}); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("got %v", err)
	}
}

func TestTelegramValidate(t *testing.T) {
	good := TelegramSettings{Token: tgToken, ChatIDs: []string{"-1001234567890"}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if good.Destination() != "chat -1001234567890" {
		t.Fatal(good.Destination())
	}
	two := TelegramSettings{Token: tgToken, ChatIDs: []string{"1", "@chan_name"}}
	if two.Validate() != nil || two.Destination() != "chats 1, @chan_name" || strings.Contains(two.Destination(), tgToken) {
		t.Fatal(two.Destination())
	}
	for _, bad := range []TelegramSettings{
		{Token: "nope", ChatIDs: []string{"1"}},
		{Token: tgToken},
		{Token: tgToken, ChatIDs: []string{"not a chat"}},
	} {
		if bad.Validate() == nil {
			t.Errorf("expected error for %+v", bad.ChatIDs)
		}
	}
}

func TestRedact(t *testing.T) {
	if got := Redact("a secret b", "secret", ""); got != "a [redacted] b" {
		t.Fatal(got)
	}
}
