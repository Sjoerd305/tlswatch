package notify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFailedStatus(t *testing.T) {
	for status, permanent := range map[int]bool{
		400: true, 401: true, 403: true, 404: true, 410: true, 413: true, 422: true,
		408: false, 409: false, 425: false, 429: false, 500: false, 502: false, 503: false,
	} {
		var perm *PermanentError
		if got := errors.As(failed(status, errors.New("x")), &perm); got != permanent {
			t.Errorf("%d: permanent %v, want %v", status, got, permanent)
		}
	}
}

// A channel whose endpoint is gone (a deleted webhook, a revoked token)
// fails for good; a server error is retried. The error still carries no
// credential.
func TestHTTPChannelsPermanentFailure(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusUnauthorized, http.StatusInternalServerError} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			fmt.Fprint(w, `{"message":"Unknown Webhook","error":"unknown topic"}`)
		}))
		hook := srv.URL + "/hooks/s3cr3t-path-0123456789"
		senders := map[string]Sender{
			"slack":   &SlackSender{S: SlackSettings{WebhookURL: hook}, Client: srv.Client()},
			"discord": &DiscordSender{S: DiscordSettings{WebhookURL: hook}, Client: srv.Client()},
			"ntfy":    &NtfySender{S: NtfySettings{Server: srv.URL, Topic: "alerts", Token: "tk_s3cr3t"}, Client: srv.Client()},
			"webhook": &WebhookSender{S: WebhookSettings{URL: hook}, Client: srv.Client()},
		}
		for name, snd := range senders {
			err := snd.Send(context.Background(), Message{Subject: "[critical] x", Body: "b"})
			var perm *PermanentError
			if err == nil || errors.As(err, &perm) != (status < 500) {
				t.Errorf("%s %d: %v, permanent %v", name, status, err, errors.As(err, &perm))
			}
			if err != nil && (strings.Contains(err.Error(), "s3cr3t")) {
				t.Errorf("%s %d: credential in the error: %v", name, status, err)
			}
		}
		srv.Close()
	}
}

// Telegram: a chat that does not exist is settled for good, so a retry
// for another chat's temporary failure does not try it again; with only
// permanent failures the alert fails at once.
func TestTelegramPermanentChat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.PostForm.Get("chat_id") {
		case "1":
			fmt.Fprint(w, `{"ok":true,"result":{"message_id":7}}`)
		case "2":
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"ok":false,"description":"Bad Request: chat not found"}`)
		default:
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, `{"ok":false,"description":"Bad Gateway"}`)
		}
	}))
	defer srv.Close()
	snd := &TelegramSender{S: TelegramSettings{Token: tgToken, ChatIDs: []string{"1", "2", "3"}}, BaseURL: srv.URL}
	reached, _, err := snd.SendSkipping(context.Background(), Message{Subject: "s"}, nil)
	var perm *PermanentError
	if err == nil || errors.As(err, &perm) || strings.Join(reached, ",") != "1,2" {
		t.Fatalf("mixed: reached %v, %v", reached, err)
	}
	snd.S.ChatIDs = []string{"1", "2"}
	if _, _, err := snd.SendSkipping(context.Background(), Message{Subject: "s"}, nil); !errors.As(err, &perm) {
		t.Fatalf("only a missing chat failed: %v", err)
	}
}
