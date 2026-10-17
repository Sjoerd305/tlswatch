package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// httpTimeout bounds one request of an HTTP transport.
const httpTimeout = 30 * time.Second

// maxBody is how much of a response body a transport reads.
const maxBody = 64 << 10

// httpPost sends body to rawURL and returns the status and the start of
// the response body. A connection error is returned without the URL, so a
// webhook URL that is itself the credential does not end up in the alert
// log. A 429, or a 503 with Retry-After, becomes a *RetryAfterError; the
// caller decides what the other statuses mean.
func httpPost(ctx context.Context, client *http.Client, rawURL, contentType string, body []byte, headers map[string]string) (int, []byte, error) {
	if client == nil {
		client = &http.Client{Timeout: httpTimeout}
	}
	// A webhook endpoint does not redirect; one that does would have the
	// alert posted wherever it points. The copy leaves the caller's client
	// as it is.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("the endpoint redirected; alerts are posted only to the configured URL")
	}
	client = &c
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "tlswatch")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return 0, nil, ue.Err
		}
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get("Retry-After") != "") {
		return resp.StatusCode, data, &RetryAfterError{Err: statusError(resp.Status, data), After: retryAfter(resp.Header.Get("Retry-After"))}
	}
	return resp.StatusCode, data, nil
}

// retryAfter parses a Retry-After header in seconds, or as an HTTP date.
// Nothing usable gives a minute.
func retryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if n, err := strconv.ParseFloat(v, 64); err == nil && n >= 0 {
		return time.Duration(n*float64(time.Second)) + time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return time.Minute
}

// failed marks err, the outcome of a response with status, as permanent
// when a retry cannot change it: a client error (a webhook deleted, a
// token revoked, a message refused), except a timeout, a conflict and a
// rate limit. A server error is temporary.
func failed(status int, err error) error {
	switch {
	case status < 400 || status >= 500, status == http.StatusRequestTimeout, status == http.StatusConflict,
		status == http.StatusTooEarly, status == http.StatusTooManyRequests:
		return err
	}
	return &PermanentError{Err: err}
}

// statusError describes a failed response: the status line and, when the
// body is short, the body too, since webhook APIs put the reason there.
func statusError(status string, body []byte) error {
	b := strings.TrimSpace(string(body))
	if b == "" || len(b) > 200 {
		return errors.New(status)
	}
	return fmt.Errorf("%s: %s", status, b)
}

// validateURL checks a webhook or server URL: absolute, http or https,
// with a host and no credentials in it.
func validateURL(what, raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%s is required", what)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%s must be an http:// or https:// URL", what)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%s must not contain a username or password", what)
	}
	return u, nil
}
