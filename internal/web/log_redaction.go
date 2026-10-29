package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const redactedLogDetail = "[redacted: credential-bearing URL]"

// logPath classifies a copy of the path, never the request used for routing.
// Be conservative on malformed routes too: HEAD, extra separators, dot
// segments, unknown versions and encoded prefixes can all produce error logs.
func logPath(original string) (string, bool) {
	p := original
	for i := 0; i < 4; i++ {
		if !strings.Contains(p, "%") {
			break
		}
		decoded, err := url.PathUnescape(p)
		if err != nil {
			return "[redacted: malformed path]", true
		}
		p = decoded
	}
	// Bound decoding work and fail closed on more deeply nested encodings.
	if strings.Contains(p, "%") {
		return "[redacted: encoded path]", true
	}
	parts := strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' })
	agent := -1
	for i, part := range parts {
		switch {
		case strings.EqualFold(part, "calendar"):
			return "/calendar/[redacted].ics", true
		case strings.EqualFold(part, "agent"):
			agent = i
		case agent >= 0 && strings.EqualFold(part, "install"):
			version := "[version]"
			if i > agent+1 && logProtocolVersion(parts[agent+1]) {
				version = parts[agent+1]
			}
			return "/agent/" + version + "/install/[redacted]", true
		}
	}
	return original, false
}

// Only a short numeric protocol version is safe to retain as metadata.
func logProtocolVersion(v string) bool {
	if len(v) < 2 || len(v) > 9 || v[0] != 'v' {
		return false
	}
	for _, c := range v[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func safeLogPath(r *http.Request) string {
	p, _ := logPath(r.URL.Path)
	return p
}

func credentialLogURL(r *http.Request) bool {
	if _, sensitive := logPath(r.URL.Path); sensitive {
		return true
	}
	if r.URL.User != nil {
		return true
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return true
	}
	for key := range query {
		switch strings.ToLower(key) {
		case "token", "access_token", "id_token", "refresh_token", "client_secret":
			return true
		case "code", "state":
			// Findings also use ?state=open; only sign-in's code/state
			// carry authentication material.
			if strings.HasPrefix(strings.ToLower(r.URL.Path), "/auth/") {
				return true
			}
		}
	}
	return false
}

// Arbitrary error and panic strings can repeat the URL in a different
// encoding, embed just its token or come from a Stringer. For credential URLs,
// retain the error's type, not its value; withhold free-form stack details too.
// Ordinary request errors keep their original diagnostic detail.
func safeLogError(r *http.Request, value any) any {
	if credentialLogURL(r) {
		return fmt.Sprintf("%T %s", value, redactedLogDetail)
	}
	return value
}

func safeLogStack(r *http.Request, stack string) string {
	if credentialLogURL(r) {
		return redactedLogDetail
	}
	return stack
}
