//go:build upgrade

package upgradetest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	email    = "admin@example.nl"
	password = "upgrade test passphrase 7319"
	secret   = "upgrade-hook-secret"
)

// hook records the webhook deliveries whose signature checks.
type hook struct {
	mu     sync.Mutex
	bodies []string
}

func (h *hook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	if r.Header.Get("X-TLSWatch-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	h.mu.Lock()
	h.bodies = append(h.bodies, string(body))
	h.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (h *hook) count() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.bodies) }

// instance is one tlswatch process on the shared database, with a browser
// session.
type instance struct {
	t      *testing.T
	cmd    *exec.Cmd
	base   string
	client *http.Client
}

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func start(t *testing.T, bin, dir string) *instance {
	t.Helper()
	addr := freePort(t)
	cmd := exec.Command(bin, "serve")
	cmd.Env = append(os.Environ(), "TLSWATCH_DB="+filepath.Join(dir, "tlswatch.db"), "TLSWATCH_LISTEN="+addr,
		"TLSWATCH_ALLOW_LOCAL=true", "TLSWATCH_LOG_JSON=false")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	in := &instance{t: t, cmd: cmd, base: "http://" + addr, client: &http.Client{Jar: jar, Timeout: 90 * time.Second}}
	t.Cleanup(in.stop)
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get(in.base + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return in
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not become healthy: %v", bin, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (in *instance) stop() {
	if in.cmd.ProcessState != nil {
		return
	}
	_ = in.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = in.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = in.cmd.Process.Kill()
		<-done
	}
}

func (in *instance) get(path string) string {
	in.t.Helper()
	resp, err := in.client.Get(in.base + path)
	if err != nil {
		in.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		in.t.Fatalf("GET %s: %d", path, resp.StatusCode)
	}
	return string(b)
}

var (
	formRe     = regexp.MustCompile(`(?s)<form\b([^>]*)>(.*?)</form>`)
	actionRe   = regexp.MustCompile(`action="([^"]*)"`)
	inputRe    = regexp.MustCompile(`<input\b[^>]*>`)
	selectRe   = regexp.MustCompile(`(?s)<select\b([^>]*)>(.*?)</select>`)
	optionRe   = regexp.MustCompile(`<option\b[^>]*>`)
	textareaRe = regexp.MustCompile(`(?s)<textarea\b([^>]*)>(.*?)</textarea>`)
	attrRe     = regexp.MustCompile(`\b(name|value|type)="([^"]*)"`)
)

func attrs(tag string) map[string]string {
	m := map[string]string{}
	for _, a := range attrRe.FindAllStringSubmatch(tag, -1) {
		m[a[1]] = html.UnescapeString(a[2])
	}
	m["checked"] = fmt.Sprint(strings.Contains(tag, " checked"))
	m["selected"] = fmt.Sprint(strings.Contains(tag, " selected"))
	m["disabled"] = fmt.Sprint(strings.Contains(tag, " disabled"))
	return m
}

// submit fills the form posting to action on page as a browser would (its
// hidden fields, defaults, checked boxes and selected options), sets the
// fields given, posts it and returns the page it ends on.
func (in *instance) submit(page, action string, set url.Values) string {
	in.t.Helper()
	body := in.get(page)
	var form string
	for _, f := range formRe.FindAllStringSubmatch(body, -1) {
		if a := actionRe.FindStringSubmatch(f[1]); a != nil && html.UnescapeString(a[1]) == action {
			form = f[2]
			break
		}
	}
	if form == "" {
		in.t.Fatalf("no form posting to %s on %s", action, page)
	}
	v := url.Values{}
	for _, tag := range inputRe.FindAllString(form, -1) {
		a := attrs(tag)
		if a["name"] == "" || a["disabled"] == "true" {
			continue
		}
		if (a["type"] == "checkbox" || a["type"] == "radio") && a["checked"] != "true" {
			continue
		}
		v.Add(a["name"], a["value"])
	}
	for _, s := range selectRe.FindAllStringSubmatch(form, -1) {
		name := attrs("<select" + s[1] + ">")["name"]
		var first, chosen string
		for i, o := range optionRe.FindAllString(s[2], -1) {
			a := attrs(o)
			if a["disabled"] == "true" {
				continue
			}
			if i == 0 || first == "" {
				first = a["value"]
			}
			if a["selected"] == "true" {
				chosen = a["value"]
			}
		}
		if chosen == "" {
			chosen = first
		}
		v.Set(name, chosen)
	}
	for _, ta := range textareaRe.FindAllStringSubmatch(form, -1) {
		v.Set(attrs("<textarea" + ta[1] + ">")["name"], html.UnescapeString(ta[2]))
	}
	for k, vals := range set {
		v[k] = vals
	}
	req, _ := http.NewRequest(http.MethodPost, in.base+action, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", in.base)
	resp, err := in.client.Do(req)
	if err != nil {
		in.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || strings.Contains(string(b), `class="notice crit"`) {
		in.t.Fatalf("POST %s: %d\n%s", action, resp.StatusCode, noticeOf(string(b)))
	}
	return string(b)
}

func noticeOf(page string) string {
	if i := strings.Index(page, `class="notice`); i >= 0 {
		return page[i:min(len(page), i+400)]
	}
	return page[:min(len(page), 400)]
}

func waitFor(t *testing.T, what string, d time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func TestUpgradeFromOldestRelease(t *testing.T) {
	old := os.Getenv("TLSWATCH_UPGRADE_FROM")
	if old == "" {
		t.Skip("TLSWATCH_UPGRADE_FROM names the old release binary")
	}
	dir := t.TempDir()
	cur := filepath.Join(dir, "tlswatch-current")
	build := exec.Command("go", "build", "-o", cur, "./cmd/tlswatch")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	// The configuration test offers old versions and suites on purpose.
	target.Config.ErrorLog = log.New(io.Discard, "", 0)
	target.StartTLS()
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "https://")
	h := &hook{}
	hookSrv := httptest.NewServer(h)
	defer hookSrv.Close()

	// The old release: an admin, a target, a webhook channel with a
	// signing secret (stored sealed), a check and the alert it sends.
	o := start(t, old, dir)
	o.submit("/setup", "/setup", url.Values{"email": {email}, "name": {"Admin"}, "password": {password}, "password2": {password}})
	o.submit("/targets/bulk-add", "/targets/bulk-add", url.Values{"hosts": {targetAddr + " Upgrade target"}})
	if !strings.Contains(o.get("/targets"), "Upgrade target") {
		t.Fatal("the old release did not add the target")
	}
	o.submit("/settings/channels?new=webhook", "/settings/channels", url.Values{"name": {"Hook"}, "url": {hookSrv.URL + "/alerts"},
		"secret": {secret}, "min_severity": {"info"}})
	o.submit("/targets/1", "/targets/1/check", nil)
	waitFor(t, "the old release's alert", 90*time.Second, func() bool { return h.count() > 0 })
	alerted := h.count()
	o.stop()

	// This build on the same database.
	n := start(t, cur, dir)
	n.submit("/login", "/login", url.Values{"email": {email}, "password": {password}})
	if p := n.get("/targets"); !strings.Contains(p, "Upgrade target") {
		t.Fatal("the target is gone after the upgrade")
	}
	if p := n.get("/targets/1"); !strings.Contains(p, targetAddr) {
		t.Fatal("the target page lost its endpoint")
	}
	if p := n.get("/findings"); !strings.Contains(p, "Upgrade target") {
		t.Fatal("the open finding is gone after the upgrade")
	}
	if p := n.get("/settings/channels"); !strings.Contains(p, "Hook") {
		t.Fatal("the channel is gone after the upgrade")
	}
	// The sealed signing secret still opens: a test message arrives signed.
	n.submit("/settings/channels", "/settings/channels/1/test", nil)
	waitFor(t, "the test message after the upgrade", 30*time.Second, func() bool { return h.count() > alerted })
	// And the upgraded instance checks again.
	n.submit("/targets/1", "/targets/1/check", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, n.base+"/healthz", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz after the upgrade: %v", err)
	}
	resp.Body.Close()
}
