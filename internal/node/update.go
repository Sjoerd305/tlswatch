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
	rollbackFile = "update-failed.json"
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

// clearUpdateFiles runs after the first successful poll: the binary in
// place works, and a reported rollback has reached the server.
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
	c.Log.Info("updating to the server's version", "from", c.Version, "to", version)
	c.running.Wait()
	exe, err := c.executable()
	if err != nil {
		c.Log.Error("update: cannot find the running binary", "err", err)
		return nil
	}
	if err := c.replace(ctx, exe); err != nil {
		c.Log.Error("update failed; staying on this version", "err", err)
		return nil
	}
	b, _ := json.Marshal(marker{From: c.Version, To: version, At: time.Now()})
	if err := os.WriteFile(filepath.Join(c.Data, markerFile), b, 0o600); err != nil {
		c.Log.Error("update: marker not written; rollback is not possible", "err", err)
	}
	c.Log.Info("binary replaced; restarting", "to", version)
	return ErrRestart
}

func (c *Client) replace(ctx context.Context, exe string) error {
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
	want := strings.ToLower(resp.Header.Get(HeaderSHA256))
	if resp.Request != nil && resp.Request.Response != nil {
		// Redirected to a release asset: the checksum came with the
		// server's answer.
		for r := resp.Request.Response; r != nil && want == ""; r = r.Request.Response {
			want = strings.ToLower(r.Header.Get(HeaderSHA256))
		}
	}
	if want == "" {
		return errors.New("the server sent no checksum")
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
