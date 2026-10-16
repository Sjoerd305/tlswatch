package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// Platforms are the platforms releases are built for. "linux/arm" is the
// 32-bit ARMv7 build: a node asks for runtime.GOARCH, which has no variant
// in it, so the release asset is named linux-arm too.
var Platforms = []string{"linux/amd64", "linux/arm64", "linux/arm", "darwin/amd64", "darwin/arm64"}

// binaryCache remembers the SHA-256 of the server's own executable and the
// checksums of its release.
type binaryCache struct {
	mu      sync.Mutex
	path    string
	modTime time.Time
	sum     string
	sums    map[string]string // release asset name → SHA-256, from a signed SHA256SUMS
	text    []byte            // that SHA256SUMS as fetched
	sig     []byte            // and its signature, as fetched
	sumsAt  time.Time
	failErr error // the last failed fetch of SHA256SUMS
	failAt  time.Time
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

// download serves the node binary. On a release, the binary a node gets is
// always one listed in the release's signed SHA256SUMS: the server's own
// executable when its checksum is in there (a same-architecture network
// then needs nothing from the internet), otherwise a redirect to the
// release asset. The node checks the signature itself (see releaseSums), so
// the server is a carrier, not an authority. A development build serves
// its own executable, which a node accepts only when told to.
func (d *Dispatcher) download(w http.ResponseWriter, r *http.Request, goos, arch string) {
	p := goos + "/" + arch
	if !d.ServesPlatform(p) {
		msg := fmt.Sprintf("This server runs %s and can serve only that platform", OwnPlatform())
		if !IsRelease(d.Version) {
			msg += "; it is a development build, so there is no release to fetch other platforms from"
		}
		http.Error(w, msg+".", http.StatusNotFound)
		return
	}
	asset := fmt.Sprintf("tlswatch-%s-%s-%s", d.Version, goos, arch)
	own := ""
	if p == OwnPlatform() {
		path, sum, err := d.ownBinary()
		if err != nil {
			d.Log.Error("node download", "err", err)
			http.Error(w, "the server cannot read its own executable", http.StatusInternalServerError)
			return
		}
		own = path
		if IsRelease(d.Version) {
			want, err := d.releaseSum(r.Context(), asset)
			if err != nil {
				d.sumsError(w, err)
				return
			}
			if want != sum {
				// Built from the same tag, but not the released bytes
				// (a container image, a local build): the node gets the
				// released binary, which is what the signature covers.
				own = ""
			}
		}
		if own != "" {
			d.serveFile(w, r, own, sum)
			return
		}
	}
	sum, err := d.releaseSum(r.Context(), asset)
	if err != nil {
		d.sumsError(w, err)
		return
	}
	w.Header().Set(HeaderSHA256, sum)
	http.Redirect(w, r, d.releases()+"/"+d.Version+"/"+asset, http.StatusFound)
}

// sumsError answers a download whose checksum could not be established.
func (d *Dispatcher) sumsError(w http.ResponseWriter, err error) {
	if errors.Is(err, errNoAsset) {
		http.Error(w, "Release "+d.Version+" has no build for this platform: "+err.Error(), http.StatusNotFound)
		return
	}
	d.Log.Error("node download: release checksums", "err", err)
	http.Error(w, "the server could not fetch the signed checksums of release "+d.Version, http.StatusBadGateway)
}

// serveFile sends the server's own executable with its checksum.
func (d *Dispatcher) serveFile(w http.ResponseWriter, r *http.Request, path, sum string) {
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
}

// releaseSums serves the signed SHA256SUMS of the server's release with
// its signature in HeaderSumsSignature, for a node to verify before it
// replaces its binary. A development build has none: 404.
func (d *Dispatcher) releaseSums(w http.ResponseWriter, r *http.Request) {
	if !IsRelease(d.Version) {
		http.Error(w, "This server is a development build; it has no signed release checksums.", http.StatusNotFound)
		return
	}
	if _, err := d.releaseSum(r.Context(), ""); err != nil {
		d.sumsError(w, err)
		return
	}
	c := &d.binary
	c.mu.Lock()
	text, sig := c.text, c.sig
	c.mu.Unlock()
	w.Header().Set(HeaderSumsSignature, strings.TrimSpace(string(sig)))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(text)
}

// errNoAsset is an asset missing from a valid SHA256SUMS.
var errNoAsset = errors.New("not in SHA256SUMS")

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
// with its signature once an hour at most and accepted only when the
// release key signed it. An empty asset only loads the file.
func (d *Dispatcher) releaseSum(ctx context.Context, asset string) (string, error) {
	c := &d.binary
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sums == nil || time.Since(c.sumsAt) >= time.Hour {
		// A failed fetch is remembered for a minute: this is reachable
		// without a credential, and must not become a way to make the
		// server hammer GitHub.
		if c.failErr != nil && time.Since(c.failAt) < time.Minute {
			return "", c.failErr
		}
		text, sig, err := d.fetchSums(ctx)
		if err == nil {
			c.sums, err = VerifySums(text, sig, d.ReleaseKey)
		}
		if err != nil {
			c.failErr, c.failAt = err, time.Now()
			return "", err
		}
		c.text, c.sig, c.sumsAt, c.failErr = text, sig, time.Now(), nil
	}
	if asset == "" {
		return "", nil
	}
	sum, ok := c.sums[asset]
	if !ok {
		return "", fmt.Errorf("%s is %w", asset, errNoAsset)
	}
	return sum, nil
}

// fetchSums downloads SHA256SUMS and SHA256SUMS.sig of the server's release.
func (d *Dispatcher) fetchSums(ctx context.Context) (text, sig []byte, err error) {
	client := d.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	get := func(name string, limit int64) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.releases()+"/"+d.Version+"/"+name, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: %s", name, resp.Status)
		}
		return io.ReadAll(io.LimitReader(resp.Body, limit))
	}
	if text, err = get("SHA256SUMS", maxSums); err != nil {
		return nil, nil, err
	}
	if sig, err = get("SHA256SUMS.sig", 1024); err != nil {
		return nil, nil, err
	}
	return text, sig, nil
}
