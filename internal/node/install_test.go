package node

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// stub writes an executable shell script into dir.
func stub(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestInstallScripts runs the install script, then the uninstall script,
// against a server, with the system commands (id, uname, systemctl,
// useradd, chown, userdel) stubbed and every file under a temporary root.
// The served binary is a stand-in that writes the credential on enrol.
func TestInstallScripts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell")
	}
	for _, tool := range []string{"sh", "curl", "awk", "install"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not found")
		}
	}
	e := setup(t)
	root, bin, tmp := t.TempDir(), t.TempDir(), t.TempDir()
	fake := filepath.Join(tmp, "tlswatch")
	stub(t, tmp, "tlswatch", `[ "$1 $2" = "node enrol" ] || exit 9
printf 'cred-%s\n' "$6" >"$8/credential"
echo "Enrolled with $4"`)
	e.disp.Executable = func() (string, error) { return fake, nil }
	log := filepath.Join(tmp, "calls.log")
	stub(t, bin, "id", `case "$1" in -u) echo 0 ;; -gn) echo tlswatch-node ;; *) [ -e "`+tmp+`/user" ] ;; esac`)
	stub(t, bin, "uname", `case "$1" in -s) echo Linux ;; -m) echo x86_64 ;; esac`)
	stub(t, bin, "systemctl", `echo "systemctl $*" >>"`+log+`"; [ "$1" != is-active ]`)
	stub(t, bin, "useradd", `echo "useradd $*" >>"`+log+`"; touch "`+tmp+`/user"`)
	stub(t, bin, "userdel", `echo "userdel $*" >>"`+log+`"; rm -f "`+tmp+`/user"`)
	stub(t, bin, "chown", `echo "chown $*" >>"`+log+`"`)
	env := append(os.Environ(), "TLSWATCH_INSTALL_ROOT="+root, "PATH="+bin+":"+os.Getenv("PATH"))

	_, tok, err := e.core.CreateNode(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	// The stub uname says linux/amd64; the script asks for the platform
	// this test server serves from its own binary instead.
	installer := func(tok string) string {
		return strings.Replace(InstallScript(e.srv.URL, tok), `URL="$SERVER/agent/v1/download/$OS/$ARCH"`,
			`URL="$SERVER/agent/v1/download/`+OwnPlatform()+`"`, 1)
	}
	script := installer(tok)
	cmd := exec.Command("sh", "-s")
	cmd.Stdin, cmd.Env = strings.NewReader(script), env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install script: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Connected to "+e.srv.URL) {
		t.Errorf("no closing line:\n%s", out)
	}
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		return string(b)
	}
	if got := read("/var/lib/tlswatch-node/credential"); got != "cred-"+tok+"\n" {
		t.Errorf("credential: %q", got)
	}
	if got := read("/var/lib/tlswatch-node/bin/tlswatch"); !strings.Contains(got, "node enrol") {
		t.Errorf("binary not installed: %q", got)
	}
	if got := read("/etc/tlswatch-node.env"); !strings.Contains(got, "TLSWATCH_NODE_SERVER="+e.srv.URL) {
		t.Errorf("env file: %q", got)
	}
	unit := read("/etc/systemd/system/tlswatch-node.service")
	for _, want := range []string{"User=tlswatch-node", "ExecStart=/var/lib/tlswatch-node/bin/tlswatch node", "Restart=always",
		"NoNewPrivileges=yes", "ProtectSystem=strict", "ReadWritePaths=/var/lib/tlswatch-node"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %s:\n%s", want, unit)
		}
	}
	if dst, err := os.Readlink(filepath.Join(root, "/usr/local/bin/tlswatch")); err != nil || dst != "/var/lib/tlswatch-node/bin/tlswatch" {
		t.Errorf("link: %q %v", dst, err)
	}
	if fi, err := os.Stat(filepath.Join(root, "/var/lib/tlswatch-node")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("data directory mode: %v %v", fi, err)
	}
	calls, _ := os.ReadFile(log)
	for _, want := range []string{"useradd --system", "chown -R tlswatch-node:tlswatch-node", "systemctl enable tlswatch-node.service", "systemctl restart tlswatch-node.service"} {
		if !strings.Contains(string(calls), want) {
			t.Errorf("no %q in:\n%s", want, calls)
		}
	}

	// A corrupt download is refused.
	_, tok2, _ := e.core.CreateNode(context.Background(), "admin")
	bad := strings.Replace(installer(tok2), `[ "$GOT" = "$WANT" ]`, `[ "$GOT" = "0$WANT" ]`, 1)
	cmd = exec.Command("sh", "-s")
	cmd.Stdin, cmd.Env = strings.NewReader(bad), env
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "corrupt") {
		t.Errorf("a checksum mismatch was not refused:\n%s", out)
	}

	cmd = exec.Command("sh", "-s")
	cmd.Stdin, cmd.Env = strings.NewReader(UninstallScript(e.srv.URL)), env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("uninstall script: %v\n%s", err, out)
	}
	for _, p := range []string{"/var/lib/tlswatch-node", "/etc/tlswatch-node.env", "/etc/systemd/system/tlswatch-node.service", "/usr/local/bin/tlswatch"} {
		if _, err := os.Lstat(filepath.Join(root, p)); err == nil {
			t.Errorf("%s left behind", p)
		}
	}
	calls, _ = os.ReadFile(log)
	if !strings.Contains(string(calls), "systemctl disable --now tlswatch-node.service") || !strings.Contains(string(calls), "userdel tlswatch-node") {
		t.Errorf("uninstall calls:\n%s", calls)
	}
}
