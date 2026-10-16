package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// A self-update leaves two files in the data directory: the marker while
// the new binary has not reached the server yet, and, after a rollback, the
// reason, which the old binary reports on its polls until one succeeds.
const (
	markerFile   = "update.json"
	rollbackFile = "update-failed.json" // why the last update was rolled back or went nowhere
)

type marker struct {
	From string    `json:"from"`
	To   string    `json:"to"`
	At   time.Time `json:"at"`
}

func readMarker(data string) (marker, bool) {
	var m marker
	b, err := os.ReadFile(filepath.Join(data, markerFile)) // #nosec G304 -- the node's own data directory
	if err != nil || json.Unmarshal(b, &m) != nil {
		return m, false
	}
	return m, true
}

func readRollback(data string) string {
	var r struct {
		Reason string `json:"reason"`
	}
	b, err := os.ReadFile(filepath.Join(data, rollbackFile)) // #nosec G304 -- the node's own data directory
	if err != nil || json.Unmarshal(b, &r) != nil {
		return ""
	}
	return r.Reason
}

// clearUpdateFiles runs after a successful poll: the binary in place
// works, and a reported rollback or failure has reached the server.
func clearUpdateFiles(data string) {
	_ = os.Remove(filepath.Join(data, markerFile))
	_ = os.Remove(filepath.Join(data, rollbackFile))
}

func (c *Client) executable() (string, error) {
	exe := c.Executable
	if exe == nil {
		exe = os.Executable
	}
	p, err := exe()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

// update replaces the binary with the server's: it finishes the probes it
// is running and takes no new ones, downloads the binary, verifies its
// SHA-256, writes it next to the running one, renames it into place keeping
// the old one as tlswatch.prev, writes the marker and returns ErrRestart.
// A node in a container is updated by pulling the image instead.
func (c *Client) update(ctx context.Context, version string) error {
	if c.Container {
		c.Log.Warn("the server runs another version; update this container by pulling the image", "server_version", version, "image", Image+":"+version)
		return nil
	}
	switch {
	case c.NoUpdate:
		c.updateFailed("this node does not update itself (-no-self-update); update it by hand")
		return nil
	case c.Insecure:
		c.updateFailed("this node reaches the server over plain http (-insecure) and does not replace its binary over it")
		return nil
	}
	c.Log.Info("updating to the server's version", "from", c.Version, "to", version)
	c.running.Wait()
	exe, err := c.executable()
	if err != nil {
		c.updateFailed("cannot find the running binary: " + err.Error())
		return nil
	}
	if err := c.replace(ctx, exe, version); err != nil {
		c.updateFailed(err.Error())
		return nil
	}
	b, _ := json.Marshal(marker{From: c.Version, To: version, At: time.Now()})
	if err := os.WriteFile(filepath.Join(c.Data, markerFile), b, 0o600); err != nil {
		c.Log.Error("update: marker not written; rollback is not possible", "err", err)
	}
	c.Log.Info("binary replaced; restarting", "to", version)
	return ErrRestart
}

// expectedSum is the checksum the downloaded binary must have. For a
// release it comes from the release's SHA256SUMS, served by the server with
// a signature the node checks against the release key built into it: the
// server cannot make the node run anything the release key did not sign.
// For a development build there is no signature; the server's own checksum
// header is taken only when the node was started to allow that.
func (c *Client) expectedSum(ctx context.Context, version string) (string, error) {
	if !IsRelease(version) {
		return "", nil // decided after the download, from its headers
	}
	sums, err := c.signedSums(ctx)
	if err != nil {
		return "", err
	}
	asset := fmt.Sprintf("tlswatch-%s-%s-%s", version, runtime.GOOS, runtime.GOARCH)
	want, ok := sums[asset]
	if !ok {
		return "", fmt.Errorf("%s is not in the signed checksums of release %s", asset, version)
	}
	return want, nil
}

// unsignedSum takes the checksum of a development build from the download
// itself, which only a node started to allow that does.
func (c *Client) unsignedSum(version string, resp *http.Response) (string, error) {
	if !c.AllowUnsigned {
		return "", fmt.Errorf("%s is a development build without signed checksums; this node takes only signed releases (start it with -allow-unsigned-update to follow development builds)", version)
	}
	want := strings.ToLower(resp.Header.Get(HeaderSHA256))
	if resp.Request != nil && resp.Request.Response != nil {
		// Redirected to a release asset: the checksum came with the
		// server's answer.
		for r := resp.Request.Response; r != nil && want == ""; r = r.Request.Response {
			want = strings.ToLower(r.Header.Get(HeaderSHA256))
		}
	}
	if want == "" {
		return "", errors.New("the server sent no checksum")
	}
	return want, nil
}

// signedSums fetches the release's SHA256SUMS from the server and verifies
// its signature.
func (c *Client) signedSums(ctx context.Context) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Server+Prefix+"/release/sums", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(HeaderVersion, c.Version)
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signed checksums: %s", serverError(resp))
	}
	text, err := io.ReadAll(io.LimitReader(resp.Body, maxSums+1))
	if err != nil {
		return nil, err
	}
	return VerifySums(text, []byte(resp.Header.Get(HeaderSumsSignature)), c.ReleaseKey)
}

func (c *Client) replace(ctx context.Context, exe, version string) error {
	// For a release the expected checksum is known, and signed, before a
	// byte is downloaded.
	want, err := c.expectedSum(ctx, version)
	if err != nil {
		return err
	}
	url := c.Server + Prefix + "/download/" + runtime.GOOS + "/" + runtime.GOARCH
	dctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(dctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set(HeaderVersion, c.Version)
	client := *c.client()
	client.Timeout = 0 // the context bounds the download
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(serverError(resp))
	}
	if want == "" {
		if want, err = c.unsignedSum(version, resp); err != nil {
			return err
		}
	}
	next := exe + ".new"
	f, err := os.OpenFile(next, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755) // #nosec G302 G304 -- the node's own binary
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(next)
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		_ = os.Remove(next)
		return fmt.Errorf("checksum mismatch: got %s, expected %s", got, want)
	}
	prev := exe + ".prev"
	_ = os.Remove(prev)
	if err := os.Link(exe, prev); err != nil {
		if err := copyFile(exe, prev); err != nil {
			_ = os.Remove(next)
			return fmt.Errorf("keep the old binary: %w", err)
		}
	}
	return os.Rename(next, exe)
}

func copyFile(from, to string) error {
	in, err := os.Open(from) // #nosec G304 -- the node's own binary
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755) // #nosec G302 G304
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// updateFailed records why an update went nowhere, so the next poll
// reports it and the server ends the update with that reason instead of
// waiting out UpdateWindow.
func (c *Client) updateFailed(reason string) {
	c.Log.Error("update failed; staying on this version", "err", reason)
	b, _ := json.Marshal(map[string]string{"reason": reason})
	_ = os.WriteFile(filepath.Join(c.Data, rollbackFile), b, 0o600)
}

// watchUpdate rolls an update back when the new binary has not completed
// a poll within UpdateWindow of the update: tlswatch.prev goes back in
// place, the reason is kept for the server, and the process restarts.
func (c *Client) watchUpdate(ctx context.Context, m marker, polled <-chan struct{}, restart chan<- error) {
	if m.From == c.Version {
		// The old binary is running: the swap did not happen or was
		// undone by hand.
		clearUpdateFiles(c.Data)
		return
	}
	wait := time.Until(m.At.Add(UpdateWindow))
	select {
	case <-polled:
		c.Log.Info("update complete", "from", m.From, "to", c.Version)
		return
	case <-ctx.Done():
		return
	case <-time.After(max(wait, 0)):
	}
	reason := fmt.Sprintf("%s could not reach the server within five minutes and was rolled back", c.Version)
	exe, err := c.executable()
	if err == nil {
		err = os.Rename(exe+".prev", exe)
	}
	if err != nil {
		c.Log.Error("rollback failed", "err", err)
		return
	}
	b, _ := json.Marshal(map[string]string{"reason": reason})
	_ = os.WriteFile(filepath.Join(c.Data, rollbackFile), b, 0o600)
	_ = os.Remove(filepath.Join(c.Data, markerFile))
	c.Log.Error("update rolled back", "from", m.From, "to", c.Version)
	restart <- ErrRestart
}
