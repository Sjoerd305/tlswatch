package node

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// InContainer reports whether the node runs in a container: the image sets
// TLSWATCH_CONTAINER, and Docker, Podman and Kubernetes leave traces.
func InContainer() bool {
	if os.Getenv("TLSWATCH_CONTAINER") == "1" || os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// GatherFacts collects the system facts: hostname, operating system,
// kernel, architecture, container or not, version, interfaces with their
// addresses, the IPv6 route and the clock. They identify the machine to
// the admin and help support; they are sent to the server only.
func GatherFacts(version string, container bool) Facts {
	host, _ := os.Hostname()
	f := core.NodeFacts{Hostname: host, OS: osName(), Kernel: kernel(), Arch: runtime.GOOS + "/" + runtime.GOARCH,
		Container: container, Version: version, IPv6Route: probe.HasIPv6Route(), Kinds: Kinds}
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		var list []string
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() {
				list = append(list, n.String())
			}
		}
		if len(list) > 0 {
			f.Interfaces = append(f.Interfaces, core.NodeInterface{Name: i.Name, Addrs: list})
		}
	}
	return Facts{NodeFacts: f, Time: time.Now()}
}

// osName is the PRETTY_NAME of /etc/os-release, or the name and version.
func osName() string {
	fh, err := os.Open("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	defer fh.Close()
	kv := map[string]string{}
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			kv[k] = strings.Trim(v, `"'`)
		}
	}
	if sc.Err() != nil {
		return runtime.GOOS
	}
	switch {
	case kv["PRETTY_NAME"] != "":
		return kv["PRETTY_NAME"]
	case kv["NAME"] != "":
		return strings.TrimSpace(kv["NAME"] + " " + kv["VERSION_ID"])
	}
	return runtime.GOOS
}

// kernel is the running kernel's release, on Linux.
func kernel() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
