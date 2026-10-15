package node

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

// DefaultReleases is where the release assets of other platforms live.
const DefaultReleases = "https://github.com/sjoerd305/tlswatch/releases/download"

// Platforms are the platforms releases are built for.
var Platforms = []string{"linux/amd64", "linux/arm64", "darwin/arm64"}

// binaryCache remembers the SHA-256 of the server's own executable and the
// checksums of its release.
type binaryCache struct {
	mu      sync.Mutex
	path    string
	modTime time.Time
	sum     string
	sums    map[string]string // release asset name → SHA-256
	sumsAt  time.Time
}

// OwnPlatform is the platform the server can serve from its own binary.
func OwnPlatform() string { return runtime.GOOS + "/" + runtime.GOARCH }

// ServesPlatform reports whether nodes on a platform can download the
// binary: the server's own always, the others from its release.
func (d *Dispatcher) ServesPlatform(p string) bool {
	if p == OwnPlatform() {
		return true
	}
	return IsRelease(d.Version) && slices.Contains(Platforms, p)
}

// download serves the node binary: the server's own executable when the
// platform matches, so a same-architecture network needs nothing from the
// internet, and otherwise a redirect to the release asset of the server's
// version. The SHA-256 goes along in a header either way.
func (d *Dispatcher) download(w http.ResponseWriter, r *http.Request, goos, arch string) {
	p := goos + "/" + arch
	if p == OwnPlatform() {
		path, sum, err := d.ownBinary()
		if err != nil {
			d.Log.Error("node download", "err", err)
			http.Error(w, "the server cannot read its own executable", http.StatusInternalServerError)
			return
		}
		f, err := os.Open(path) // #nosec G304 -- the server's own executable
		if err != nil {
			http.Error(w, "the server cannot read its own executable", http.StatusInternalServerError)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			http.Error(w, "the server cannot read its own executable", http.StatusInternalServerError)
			return
		}
		w.Header().Set(HeaderSHA256, sum)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="tlswatch"`)
		http.ServeContent(w, r, "tlswatch", st.ModTime(), f)
		return
	}
	if !d.ServesPlatform(p) {
		msg := fmt.Sprintf("This server runs %s and can serve only that platform", OwnPlatform())
		if !IsRelease(d.Version) {
			msg += "; it is a development build, so there is no release to fetch other platforms from"
		}
		http.Error(w, msg+".", http.StatusNotFound)
		return
	}
	asset := fmt.Sprintf("tlswatch-%s-%s-%s", d.Version, goos, arch)
	sum, err := d.releaseSum(r.Context(), asset)
	if err != nil {
		d.Log.Error("node download: release checksums", "err", err)
		http.Error(w, "the server could not fetch the checksums of release "+d.Version, http.StatusBadGateway)
		return
	}
	w.Header().Set(HeaderSHA256, sum)
	http.Redirect(w, r, d.releases()+"/"+d.Version+"/"+asset, http.StatusFound)
}

func (d *Dispatcher) releases() string {
	if d.Releases != "" {
		return strings.TrimSuffix(d.Releases, "/")
	}
	return DefaultReleases
}

// ownBinary returns the path and SHA-256 of the running executable.
func (d *Dispatcher) ownBinary() (string, string, error) {
	exe := d.Executable
	if exe == nil {
		exe = os.Executable
	}
	path, err := exe()
	if err != nil {
		return "", "", err
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", "", err
	}
	c := &d.binary
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.path == path && c.modTime.Equal(st.ModTime()) && c.sum != "" {
		return path, c.sum, nil
	}
	sum, err := fileSHA256(path)
	if err != nil {
		return "", "", err
	}
	c.path, c.modTime, c.sum = path, st.ModTime(), sum
	return path, sum, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- a path the caller chose
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// releaseSum looks a release asset up in the release's SHA256SUMS, fetched
// once an hour at most.
func (d *Dispatcher) releaseSum(ctx context.Context, asset string) (string, error) {
	c := &d.binary
	c.mu.Lock()
	defer c.mu.Unlock()
	if sum, ok := c.sums[asset]; ok && time.Since(c.sumsAt) < time.Hour {
		return sum, nil
	}
	client := d.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.releases()+"/"+d.Version+"/SHA256SUMS", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("SHA256SUMS: %s", resp.Status)
	}
	sums := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 2 {
			sums[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	c.sums, c.sumsAt = sums, time.Now()
	sum, ok := sums[asset]
	if !ok {
		return "", fmt.Errorf("%s is not in SHA256SUMS", asset)
	}
	return sum, nil
}
