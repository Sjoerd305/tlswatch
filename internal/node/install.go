package node

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed install.sh
var installScript string

//go:embed uninstall.sh
var uninstallScript string

// Install paths, shared by the install script and uninstall.
const (
	InstallData = "/var/lib/tlswatch-node"
	installEnv  = "/etc/tlswatch-node.env"
	installUnit = "/etc/systemd/system/tlswatch-node.service"
	installLink = "/usr/local/bin/tlswatch"
	installUser = "tlswatch-node"
	serviceName = "tlswatch-node.service"
)

// Image is the container image a node can run from.
const Image = "ghcr.io/sjoerd305/tlswatch"

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// InstallScript is the install script for one token: a fixed template with
// the server URL and the token filled in.
func InstallScript(server, token string) string {
	return strings.NewReplacer("@SERVER_Q@", shellQuote(server), "@TOKEN_Q@", shellQuote(token), "@SERVER@", server).Replace(installScript)
}

// UninstallScript removes a node installed by the script. It needs no
// token, so it also works when the node's binary is gone or broken.
func UninstallScript(server string) string {
	return strings.ReplaceAll(uninstallScript, "@SERVER@", server)
}

// UninstallCommands are the ways to remove a node from its machine: the
// binary's own subcommand, and the script served by the server.
func UninstallCommands(server string) (binary, script string) {
	return "sudo tlswatch node uninstall", fmt.Sprintf("curl -fsSL %s%s/uninstall | sudo sh", server, Prefix)
}

// Commands are the ways to install a node, as the Add node screen shows them.
type Commands struct {
	Script string // the one command, on a host with systemd; sudo runs the shell, not curl
	Docker string
	Manual string // without systemd or without root
}

// InstallCommands returns the commands for a token on a server of version.
// The Docker command pins the image tag of the server's version, so the
// customer's image routine keeps the node on it.
func InstallCommands(server, token, version string) Commands {
	tag := "latest"
	if IsRelease(version) {
		tag = version
	}
	script := fmt.Sprintf("curl -fsSL %s%s/install/%s | sudo sh", server, Prefix, token)
	return Commands{
		Script: script,
		Docker: fmt.Sprintf("docker run -d --name tlswatch-node --restart unless-stopped -v tlswatch-node:/data %s:%s node -server %s -token %s",
			Image, tag, server, token),
		Manual: fmt.Sprintf("curl -fsSL -D headers -o tlswatch %s%s/download/linux/amd64\n"+
			"tr -d '\\r' <headers | awk 'tolower($1)==\"x-tlswatch-sha256:\" {print $2 \"  tlswatch\"}' | sha256sum -c && chmod +x tlswatch\n"+
			"./tlswatch node enrol -server %s -token %s -data ./tlswatch-node\n"+
			"./tlswatch node -server %s -data ./tlswatch-node", server, Prefix, server, token, server),
	}
}

// Uninstall stops the node's service and removes what the install script
// put in place: the unit, the settings file, the link, the data directory
// with the credential, and the system user.
func Uninstall(out func(string)) error {
	if os.Geteuid() != 0 {
		return errors.New("run this as root: sudo tlswatch node uninstall")
	}
	run := func(name string, args ...string) {
		if p, err := exec.LookPath(name); err == nil {
			// #nosec G204 -- fixed commands with fixed arguments
			if b, err := exec.Command(p, args...).CombinedOutput(); err != nil {
				out(fmt.Sprintf("%s %s: %v %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(b))))
			}
		}
	}
	run("systemctl", "disable", "--now", serviceName)
	for _, p := range []string{installUnit, installEnv} {
		if err := os.Remove(p); err == nil {
			out("removed " + p)
		}
	}
	run("systemctl", "daemon-reload")
	if dst, err := os.Readlink(installLink); err == nil && strings.HasPrefix(filepath.Clean(dst), InstallData+"/") {
		if err := os.Remove(installLink); err == nil {
			out("removed " + installLink)
		}
	}
	if err := os.RemoveAll(InstallData); err != nil {
		return err
	}
	out("removed " + InstallData)
	if exec.Command("id", installUser).Run() == nil { // #nosec G204 -- fixed command
		run("userdel", installUser)
		out("removed the user " + installUser)
	}
	out("The node is removed from this machine. Delete it in tlswatch under Settings › Nodes.")
	return nil
}
