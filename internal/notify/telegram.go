package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// TelegramSettings configure a Telegram channel. They are stored encrypted.
type TelegramSettings struct {
	Token   string   `json:"token"`
	ChatIDs []string `json:"chat_ids"`
}

var (
	tokenRe    = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]{20,}$`)
	channelRe  = regexp.MustCompile(`^@[A-Za-z][A-Za-z0-9_]{3,}$`)
	maxTGChars = 4096
)

// Validate checks the settings before they are saved.
func (t TelegramSettings) Validate() error {
	if !tokenRe.MatchString(t.Token) {
		return errors.New("bot token must look like 123456789:AA… as given by @BotFather")
	}
	if len(t.ChatIDs) == 0 {
		return errors.New("at least one chat ID is required")
	}
	for _, c := range t.ChatIDs {
		if _, err := strconv.ParseInt(c, 10, 64); err != nil && !channelRe.MatchString(c) {
			return fmt.Errorf("chat ID %q must be a number or @channelname", c)
		}
	}
	return nil
}

// Destination is a summary for the channel table; it never shows the token.
func (t TelegramSettings) Destination() string {
	if len(t.ChatIDs) == 1 {
		return "chat " + t.ChatIDs[0]
	}
	return "chats " + strings.Join(t.ChatIDs, ", ")
}

// TelegramSender posts messages with the Bot API.
type TelegramSender struct {
	S       TelegramSettings
	Client  *http.Client
	BaseURL string // default "https://api.telegram.org"
}

// Send posts m as plain text to every chat.
func (t *TelegramSender) Send(ctx context.Context, m Message) error {
	_, err := t.SendSkipping(ctx, m, nil)
	return err
}

// SendSkipping posts m to every chat not in done, also after one fails,
// and returns the chats it reached. The error joins the failures; it is a
// *RetryAfterError when Telegram asked to slow down.
func (t *TelegramSender) SendSkipping(ctx context.Context, m Message, done []string) ([]string, error) {
	text := m.Subject + "\n\n" + m.Body
	if utf8.RuneCountInString(text) > maxTGChars {
		r := []rune(text)
		text = string(r[:maxTGChars-1]) + "…"
	}
	var reached []string
	var errs []error
	var wait time.Duration
	for _, chat := range t.S.ChatIDs {
		if slices.Contains(done, chat) {
			continue
		}
		err := t.sendOne(ctx, chat, text)
		if err == nil {
			reached = append(reached, chat)
			continue
		}
		var ra *RetryAfterError
		if errors.As(err, &ra) {
			wait = max(wait, ra.After)
		}
		errs = append(errs, err)
	}
	err := errors.Join(errs...)
	if err == nil {
		return reached, nil
	}
	err = redactErr(err, t.S.Token, url.PathEscape(t.S.Token))
	if wait > 0 {
		err = &RetryAfterError{Err: err, After: wait}
	}
	return reached, err
}

func (t *TelegramSender) sendOne(ctx context.Context, chat, text string) error {
	base := t.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	client := t.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	form := url.Values{"chat_id": {chat}, "text": {text}, "disable_web_page_preview": {"true"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/bot"+t.S.Token+"/sendMessage", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("telegram chat %s: %w", chat, ue.Err)
		}
		return fmt.Errorf("telegram chat %s: %w", chat, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var r struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	_ = json.Unmarshal(body, &r)
	if resp.StatusCode/100 != 2 || !r.OK {
		desc := r.Description
		if desc == "" {
			desc = resp.Status
		}
		err := fmt.Errorf("telegram chat %s: %s", chat, desc)
		if r.Parameters.RetryAfter > 0 {
			return &RetryAfterError{Err: err, After: time.Duration(r.Parameters.RetryAfter) * time.Second}
		}
		return err
	}
	return nil
}
