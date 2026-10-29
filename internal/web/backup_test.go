package web

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/authz"
)

const testPassphrase = "correct horse battery"

// multipartForm builds the restore form in the browser's field order, the
// file last.
func multipartForm(t *testing.T, fields [][2]string, file []byte) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, f := range fields {
		mw.WriteField(f[0], f[1])
	}
	fw, err := mw.CreateFormFile("file", "tlswatch.backup")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write(file)
	mw.Close()
	return &buf, mw.FormDataContentType()
}

func (hs *harness) upload(path string, role authz.Role, c *http.Cookie, fields [][2]string, file []byte) *httptest.ResponseRecorder {
	body, ct := multipartForm(hs.t, fields, file)
	req := httptest.NewRequest("POST", path, body)
	req.Header.Set("Content-Type", ct)
	if s, ok := hs.sess[role]; ok {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.cookie})
	}
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, req)
	return rec
}

func (hs *harness) download() []byte {
	hs.t.Helper()
	rec := hs.do(authz.Admin, "POST", "/settings/backup", url.Values{"passphrase": {testPassphrase}, "passphrase2": {testPassphrase}}, true)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/octet-stream" ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		hs.t.Fatalf("download: %d %v", rec.Code, rec.Header())
	}
	return rec.Body.Bytes()
}

func (hs *harness) count(q string) int {
	hs.t.Helper()
	var n int
	if err := hs.db.R.QueryRow(q).Scan(&n); err != nil {
		hs.t.Fatal(err)
	}
	return n
}

// deadlineWriter stands in for the server's connection: it records the
// deadlines a handler sets through http.ResponseController.
type deadlineWriter struct {
	httptest.ResponseRecorder
	read, write time.Time
}

func (w *deadlineWriter) SetReadDeadline(t time.Time) error  { w.read = t; return nil }
func (w *deadlineWriter) SetWriteDeadline(t time.Time) error { w.write = t; return nil }

// The backup transfer deadlines reach the connection through the status
// wrapper the middleware puts around every response; without Unwrap the
// server's 60 s read and 150 s write timeouts would cut a large backup off.
func TestBackupDeadlinesReachTheConnection(t *testing.T) {
	hs := newHarness(t)
	conn := &deadlineWriter{}
	req := httptest.NewRequest("POST", "/settings/backup", strings.NewReader(url.Values{"passphrase": {testPassphrase}, "passphrase2": {testPassphrase}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	admin := hs.sess[authz.Admin]
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: admin.cookie})
	req.Header.Set("X-CSRF-Token", admin.csrf)
	start := hs.srv.now()
	hs.h.ServeHTTP(conn, req)
	if conn.Code != http.StatusOK {
		t.Fatalf("download: %d %s", conn.Code, conn.Body.String())
	}
	if got := conn.write.Sub(start); got < transferTime || got > transferTime+time.Minute {
		t.Fatalf("write deadline %s after the request, want %s", got, transferTime)
	}
	rc := http.NewResponseController(&statusWriter{ResponseWriter: conn})
	if err := rc.SetReadDeadline(start.Add(transferTime)); err != nil {
		t.Fatalf("read deadline through the wrapper: %v", err)
	}
	if !conn.read.Equal(start.Add(transferTime)) {
		t.Fatalf("read deadline %s, want %s", conn.read, start.Add(transferTime))
	}
}

func TestBackupDownloadAndRestore(t *testing.T) {
	hs := newHarness(t)
	if rec := hs.do(authz.Admin, "GET", "/settings/backup", nil, false); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Download backup") {
		t.Fatalf("page: %d", rec.Code)
	}
	if rec := hs.do(authz.Admin, "POST", "/settings/backup", url.Values{"passphrase": {"short"}, "passphrase2": {"short"}}, true); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "at least 12") {
		t.Fatalf("short passphrase: %d", rec.Code)
	}
	file := hs.download()

	// Changes after the backup are undone by the restore.
	if _, err := hs.db.W.Exec("DELETE FROM targets"); err != nil {
		t.Fatal(err)
	}
	admin := hs.sess[authz.Admin]
	fields := func(pass, confirm string) [][2]string {
		return [][2]string{{"csrf", admin.csrf}, {"passphrase", pass}, {"confirm", confirm}}
	}
	if rec := hs.upload("/settings/backup/restore", authz.Admin, nil, [][2]string{{"csrf", "wrong"}, {"passphrase", testPassphrase}, {"confirm", "1"}}, file); rec.Code != http.StatusForbidden {
		t.Fatalf("bad CSRF: %d", rec.Code)
	}
	if rec := hs.upload("/settings/backup/restore", authz.Admin, nil, fields(testPassphrase, ""), file); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Confirm") {
		t.Fatalf("unconfirmed: %d", rec.Code)
	}
	if rec := hs.upload("/settings/backup/restore", authz.Admin, nil, fields("wrong passphrase!", "1"), file); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "passphrase is wrong") {
		t.Fatalf("wrong passphrase: %d %s", rec.Code, rec.Body.String())
	}
	if hs.count("SELECT COUNT(*) FROM targets") != 0 {
		t.Fatal("a refused restore changed the database")
	}
	rec := hs.upload("/settings/backup/restore", authz.Admin, nil, fields(testPassphrase, "1"), file)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("restore: %d %s", rec.Code, rec.Body.String())
	}
	if hs.count("SELECT COUNT(*) FROM targets") != 1 {
		t.Fatal("target not restored")
	}
	if hs.count("SELECT COUNT(*) FROM sessions") != 0 {
		t.Fatal("sessions survived the restore")
	}
	if hs.count("SELECT COUNT(*) FROM audit WHERE action = 'backup.restore' AND user_email = 'admin@example.test'") != 1 {
		t.Fatal("restore not audited")
	}
	// The old session no longer works.
	if rec := hs.do(authz.Admin, "GET", "/settings/backup", nil, false); rec.Code != http.StatusSeeOther {
		t.Fatalf("session after restore: %d", rec.Code)
	}
}

func TestSetupRestore(t *testing.T) {
	src := newHarness(t)
	file := src.download()

	hs := newHarnessUsers(t, false)
	page := hs.signedOut("GET", "/setup", nil, nil)
	if !strings.Contains(page.Body.String(), "Or restore a backup") {
		t.Fatal("no restore on the setup screen")
	}
	var csrfC *http.Cookie
	for _, c := range page.Result().Cookies() {
		if c.Name == csrfCookie {
			csrfC = c
		}
	}
	if rec := hs.upload("/setup/restore", "", nil, [][2]string{{"csrf", csrfC.Value}, {"passphrase", testPassphrase}}, file); rec.Code != http.StatusForbidden {
		t.Fatalf("without the CSRF cookie: %d", rec.Code)
	}
	rec := hs.upload("/setup/restore", "", csrfC, [][2]string{{"csrf", csrfC.Value}, {"passphrase", testPassphrase}}, file)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("setup restore: %d %s", rec.Code, rec.Body.String())
	}
	if hs.count("SELECT COUNT(*) FROM users WHERE role = 'admin'") != 1 || hs.count("SELECT COUNT(*) FROM targets") != 1 {
		t.Fatal("not restored")
	}
	// Once accounts exist, the setup screen no longer restores.
	rec = hs.upload("/setup/restore", "", csrfC, [][2]string{{"csrf", csrfC.Value}, {"passphrase", testPassphrase}}, file)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" || hs.count("SELECT COUNT(*) FROM audit WHERE action = 'backup.restore'") != 1 {
		t.Fatalf("second setup restore: %d", rec.Code)
	}
}
