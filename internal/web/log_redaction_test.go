package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/db"
)

func TestLogPathCredentialVariants(t *testing.T) {
	const secret = "SecretToken_ForLogReview123"
	deep := "/%63alendar/" + secret + ".ics"
	for i := 0; i < 8; i++ {
		deep = strings.ReplaceAll(deep, "%", "%25")
	}
	for _, tc := range []struct{ path, want string }{
		{"/agent/v1/install/" + secret, "/agent/v1/install/[redacted]"},
		{"/agent/v999/install/" + secret + "/extra", "/agent/v999/install/[redacted]"},
		{"/agent//v1///install//" + secret, "/agent/v1/install/[redacted]"},
		{"/agent/v1/./install/" + secret, "/agent/v1/install/[redacted]"},
		{"/AGENT/v1/INSTALL/" + secret, "/agent/v1/install/[redacted]"},
		{"/agent/" + secret + "/install/" + secret, "/agent/[version]/install/[redacted]"},
		{"/agent/v1/i%6estall/" + secret, "/agent/v1/install/[redacted]"},
		{"%2fagent%2fv1%2finstall%2f" + secret, "/agent/v1/install/[redacted]"},
		{"/calendar/" + secret + ".ics", "/calendar/[redacted].ics"},
		{"/calendar/" + secret + ".ics/extra", "/calendar/[redacted].ics"},
		{"//CALENDAR//" + secret + ".ICS", "/calendar/[redacted].ics"},
		{"/prefix/../calendar/" + secret + ".ics", "/calendar/[redacted].ics"},
		{"\\calendar\\" + secret + ".ics", "/calendar/[redacted].ics"},
		{"/%2563alendar/" + secret + ".ics", "/calendar/[redacted].ics"},
		{"/calendar/%zz" + secret, "[redacted: malformed path]"},
		{deep, "[redacted: encoded path]"},
		{"/targets/42", "/targets/42"},
		{"/agent/v1/jobs", "/agent/v1/jobs"},
		{"/agent/v1/download/linux/amd64", "/agent/v1/download/linux/amd64"},
		{"/api/v2/targets", "/api/v2/targets"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			got, _ := logPath(tc.path)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func encodedLogToken(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func TestLogDetailsCannotRepeatURLCredentials(t *testing.T) {
	const token = "SecretToken_ForLogReview123"
	for _, path := range []string{
		"/agent/v1/install/" + token,
		"/calendar/" + token + ".ics",
		"/agent/v1/download/linux/amd64?token=" + token,
		"/invite?%74oken=" + token,
		"/auth/oidc/callback?code=" + token + "&state=" + token,
		"/callback?ACCESS_TOKEN=" + token,
		"/invite?token=%zz",
	} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest("GET", path, nil)
			err := fmt.Errorf("request %s failed with token %s / %s", r.URL.RequestURI(), token, encodedLogToken(token))
			text := fmt.Sprint(safeLogError(r, err))
			if strings.Contains(text, token) || strings.Contains(text, encodedLogToken(token)) || !strings.Contains(text, redactedLogDetail) {
				t.Fatalf("unsafe error detail: %q", text)
			}
			if safeLogStack(r, err.Error()) != redactedLogDetail {
				t.Fatal("unsafe stack detail")
			}
		})
	}
	for _, path := range []string{"/targets?q=mail", "/api/v2/findings?state=open", "/findings?state=resolved&code=filter-value"} {
		r := httptest.NewRequest("GET", path, nil)
		err := errors.New("database is temporarily unavailable")
		if safeLogError(r, err) != err || safeLogStack(r, "ordinary trace") != "ordinary trace" || safeLogPath(r) != r.URL.Path {
			t.Fatalf("ordinary diagnostics changed for %s", path)
		}
	}
}

func credentialLogHarness(t *testing.T) (*harness, string, string) {
	t.Helper()
	hs := newHarness(t)
	ctx := context.Background()
	st, err := hs.srv.Settings.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st.General.BaseURL = "https://tlswatch.example.test"
	if err := hs.srv.Settings.SaveGeneral(ctx, st.General); err != nil {
		t.Fatal(err)
	}
	_, install, err := hs.srv.Core.CreateNode(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	_, calendar, err := hs.srv.Core.CreateCalendar(ctx, hs.userID(authz.Viewer), "")
	if err != nil {
		t.Fatal(err)
	}
	return hs, install, calendar
}

func captureCredentialLogs(hs *harness, buf *bytes.Buffer, format string, level slog.Level) {
	buf.Reset()
	options := &slog.HandlerOptions{Level: level}
	var h slog.Handler = slog.NewJSONHandler(buf, options)
	if format == "text" {
		h = slog.NewTextHandler(buf, options)
	}
	hs.srv.Log = slog.New(h)
	hs.srv.Nodes.Log = hs.srv.Log
}

func assertNoLogTokens(t *testing.T, buf *bytes.Buffer, tokens ...string) {
	t.Helper()
	for _, token := range tokens {
		for _, value := range []string{token, encodedLogToken(token), strings.ToLower(encodedLogToken(token)), url.QueryEscape(token)} {
			if strings.Contains(buf.String(), value) {
				t.Fatal("credential appeared in captured logs")
			}
		}
	}
}

func TestCredentialRequestLogsAndRouting(t *testing.T) {
	hs, install, calendar := credentialLogHarness(t)
	for _, format := range []string{"json", "text"} {
		for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo} {
			for _, tc := range []struct {
				method, path string
				status       int
				script       bool
			}{
				{"GET", "/agent/v1/install/" + install, 200, true},
				{"HEAD", "/agent/v1/install/" + install, 404, false},
				{"POST", "/agent/v1/install/" + install, 404, false},
				{"GET", "/agent/v1/install/" + install + "/", 404, false},
				{"GET", "/agent/v999/install/" + install, 404, false},
				{"GET", "/agent//v1/install/" + install, 404, false},
				{"GET", "/agent/v1/./install/" + install, 404, false},
				{"GET", "/agent/v1/%69nstall/" + install, 200, true},
				{"GET", "/agent/v1/%2569nstall/" + install, 404, false},
				{"GET", "/agent/v1/install/" + fmt.Sprintf("%%%02X", install[0]) + install[1:], 200, true},
				{"GET", "/calendar/" + calendar + ".ics", 200, false},
				{"GET", "/calendar/" + calendar + ".ics/extra", 404, false},
				{"GET", "/%63alendar/" + calendar + ".ics", 200, false},
				{"GET", "/%2563alendar/" + calendar + ".ics", 404, false},
				{"GET", "/agent/v1/download/not-an-os/not-an-arch?token=" + install, 404, false},
			} {
				var buf bytes.Buffer
				captureCredentialLogs(hs, &buf, format, level)
				r := httptest.NewRequest(tc.method, tc.path, nil)
				before := *r.URL
				w := httptest.NewRecorder()
				hs.h.ServeHTTP(w, r)
				if w.Code != tc.status {
					t.Fatalf("%s %s %s: status=%d want=%d", format, level, tc.method, w.Code, tc.status)
				}
				if *r.URL != before {
					t.Fatal("logging changed the request URL")
				}
				if tc.script && !strings.Contains(w.Body.String(), install) {
					t.Fatal("install script lost the real credential")
				}
				assertNoLogTokens(t, &buf, install, calendar)
				if (level == slog.LevelDebug || tc.status >= 400) && buf.Len() == 0 {
					t.Fatal("request log missing")
				}
				if tc.status >= 400 || level == slog.LevelDebug {
					if !strings.Contains(buf.String(), "request_id") || !strings.Contains(buf.String(), "status") || !strings.Contains(buf.String(), "method") {
						t.Fatal("request diagnostics lost")
					}
				}
			}
		}
	}
	if ok, err := hs.srv.Core.ValidNodeToken(context.Background(), install); err != nil || !ok {
		t.Fatal("script/error requests consumed install token")
	}
}

func TestSlowCredentialRequestLogs(t *testing.T) {
	hs, install, calendar := credentialLogHarness(t)
	for _, format := range []string{"json", "text"} {
		var buf bytes.Buffer
		captureCredentialLogs(hs, &buf, format, slog.LevelInfo)
		hs.srv.logRequest(httptest.NewRequest("GET", "/calendar/"+calendar+".ics", nil), &reqInfo{id: "request-review"}, 200, 3*time.Second)
		assertNoLogTokens(t, &buf, calendar)
		if !strings.Contains(buf.String(), "/calendar/[redacted].ics") || !strings.Contains(buf.String(), "3000") {
			t.Fatal("slow request diagnostics lost")
		}
		buf.Reset()
		hs.srv.logRequest(httptest.NewRequest("GET", "/agent/v1/install/"+install, nil), &reqInfo{}, 200, 10*time.Second)
		if buf.Len() != 0 {
			t.Fatal("successful agent request changed log level")
		}
	}
}

func TestCredentialFailuresThroughMiddleware(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			hs, install, calendar := credentialLogHarness(t)
			var buf bytes.Buffer
			captureCredentialLogs(hs, &buf, format, slog.LevelInfo)
			nodes := hs.srv.Nodes
			hs.srv.Nodes = nil // force a panic after the request reaches the node path
			w := httptest.NewRecorder()
			hs.h.ServeHTTP(w, httptest.NewRequest("GET", "/agent/v1/install/"+install, nil))
			hs.srv.Nodes = nodes
			if w.Code != 500 || !strings.Contains(buf.String(), "/agent/v1/install/[redacted]") {
				t.Fatal("install panic recovery context lost")
			}
			assertNoLogTokens(t, &buf, install)
			broken, err := db.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			_ = broken.Close()
			buf.Reset()
			hs.srv.Core.DB = broken // a valid calendar URL fails while the DB is unavailable
			w = httptest.NewRecorder()
			hs.h.ServeHTTP(w, httptest.NewRequest("GET", "/calendar/"+calendar+".ics", nil))
			hs.srv.Core.DB = hs.db
			if w.Code != 500 || !strings.Contains(buf.String(), "/calendar/[redacted].ics") {
				t.Fatal("calendar failure context lost")
			}
			assertNoLogTokens(t, &buf, calendar)
			buf.Reset()
			w = httptest.NewRecorder()
			hs.h.ServeHTTP(w, httptest.NewRequest("GET", "/calendar/"+calendar+".ics", nil))
			if w.Code != 200 || !strings.Contains(w.Body.String(), "BEGIN:VCALENDAR") {
				t.Fatal("calendar no longer works after DB recovery")
			}
			if ok, err := hs.srv.Core.ValidNodeToken(context.Background(), install); err != nil || !ok {
				t.Fatal("logging consumed the install token")
			}
		})
	}
}

func TestCredentialErrorsAndPanicsAreRedacted(t *testing.T) {
	hs, install, calendar := credentialLogHarness(t)
	st, err := hs.srv.Settings.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "text"} {
		for _, kind := range []string{"server", "api", "user", "render-missing", "render-error", "panic"} {
			t.Run(format+"/"+kind, func(t *testing.T) {
				var buf bytes.Buffer
				captureCredentialLogs(hs, &buf, format, slog.LevelInfo)
				r := httptest.NewRequest("GET", "/calendar/"+calendar+".ics?token="+install, nil)
				ri := &reqInfo{id: "request-review", settings: st}
				r = r.WithContext(context.WithValue(r.Context(), keyReq, ri))
				failure := fmt.Errorf("request %s with credential %s and escaped %s failed", r.URL.RequestURI(), install, encodedLogToken(calendar))
				w := httptest.NewRecorder()
				switch kind {
				case "server":
					hs.srv.serverError(w, r, failure)
				case "api":
					hs.srv.apiFailErr(w, r, failure, "")
				case "user":
					hs.srv.userError(r, failure)
				case "render-missing":
					hs.srv.renderStatus(w, r, 200, "missing", &Page{})
				case "render-error":
					tpl := template.Must(template.New("layout").Funcs(template.FuncMap{"fail": func() (string, error) { return "", failure }}).Parse("{{fail}}"))
					hs.srv.pages["log-error"] = tpl
					hs.srv.renderStatus(w, r, 200, "log-error", &Page{})
				case "panic":
					hs.srv.middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(failure) })).ServeHTTP(w, r)
					if w.Code != 500 {
						t.Fatal("panic not recovered")
					}
				}
				assertNoLogTokens(t, &buf, install, calendar)
				if buf.Len() == 0 || !strings.Contains(buf.String(), "/calendar/[redacted].ics") {
					t.Fatal("error context lost")
				}
				if kind != "render-missing" && !strings.Contains(buf.String(), redactedLogDetail) {
					t.Fatal("unsafe free-form diagnostic value")
				}
			})
		}
	}
}

func TestCredentialLogMetadataAndOrdinaryErrors(t *testing.T) {
	hs, _, _ := credentialLogHarness(t)
	var buf bytes.Buffer
	captureCredentialLogs(hs, &buf, "json", slog.LevelInfo)
	r := httptest.NewRequest("GET", "/targets/999", nil)
	hs.srv.logRequest(r, &reqInfo{id: "review-id", ip: "192.0.2.1"}, 404, 3*time.Second)
	var record struct {
		Path, Method, IP string
		RequestID        string `json:"request_id"`
		Status, MS       int
	}
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.Path != "/targets/999" || record.Method != "GET" || record.IP != "192.0.2.1" || record.RequestID != "review-id" || record.Status != 404 || record.MS != 3000 {
		t.Fatalf("metadata: %+v", record)
	}
	buf.Reset()
	hs.srv.serverError(httptest.NewRecorder(), r, errors.New("ordinary diagnostic detail"))
	if !strings.Contains(buf.String(), "ordinary diagnostic detail") {
		t.Fatal("ordinary error detail lost")
	}
}

// Reading a script still leaves its one-time token available for enrolment;
// redaction affects logs only, including the generated response's real token.
func TestRedactedInstallLogDoesNotChangeEnrolment(t *testing.T) {
	hs, install, _ := credentialLogHarness(t)
	var buf bytes.Buffer
	captureCredentialLogs(hs, &buf, "json", slog.LevelDebug)
	w := httptest.NewRecorder()
	hs.h.ServeHTTP(w, httptest.NewRequest("GET", "/agent/v1/install/"+install, nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), install) {
		t.Fatal("install script changed")
	}
	n, credential, err := hs.srv.Core.EnrolNode(context.Background(), install, core.Enrolment{Facts: core.NodeFacts{Hostname: "test-node"}})
	if err != nil || credential == "" || n.State != core.NodePending {
		t.Fatal("enrolment changed", err)
	}
	if ok, err := hs.srv.Core.ValidNodeToken(context.Background(), install); err != nil || ok {
		t.Fatal("token was not consumed at enrolment")
	}
	assertNoLogTokens(t, &buf, install, credential)
}

// A credential-bearing panic must not invoke a custom Stringer at all.
type sensitiveLogStringer struct{}

func (sensitiveLogStringer) String() string { panic("Stringer must not run") }
func TestSensitiveLogValueDoesNotInvokeStringer(t *testing.T) {
	r := httptest.NewRequest("GET", "/calendar/secret.ics", nil)
	if !strings.Contains(fmt.Sprint(safeLogError(r, sensitiveLogStringer{})), redactedLogDetail) {
		t.Fatal("missing redaction")
	}
}
