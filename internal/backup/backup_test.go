package backup

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/secret"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

func init() { argonMemory, argonTime, argonThreads = 64, 1, 1 }

const pass = "correct horse battery"

func key(t *testing.T, c byte) *secret.Key {
	t.Helper()
	k, err := secret.New(bytes.Repeat([]byte{c}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func fileDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "tlswatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func exec(t *testing.T, d *db.DB, q string, args ...any) {
	t.Helper()
	if _, err := d.W.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

// source is an instance with an admin, a session, a target and a channel
// whose credentials are sealed under k.
func source(t *testing.T, k *secret.Key, role string) *db.DB {
	t.Helper()
	d := fileDB(t)
	exec(t, d, "INSERT INTO users(email, role, method, created_at) VALUES('a@example.test', ?, 'local', 1)", role)
	exec(t, d, "INSERT INTO sessions(hash, user_id, csrf, created_at, last_seen) VALUES('h', 1, 'c', 1, 1)")
	exec(t, d, "INSERT INTO channels(name, kind, settings, created_at, updated_at) VALUES('mail', 'smtp', ?, 1, 1)", k.Seal([]byte(`{"password":"pw"}`)))
	exec(t, d, "INSERT INTO targets(name, host, port, created_at, updated_at) VALUES('t', 'example.org', 443, 1, 1)")
	return d
}

func write(t *testing.T, d *db.DB, k *secret.Key) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(context.Background(), &buf, d, k, pass, "test", time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRoundTripOtherInstance(t *testing.T) {
	ctx := context.Background()
	ka, kb := key(t, 'a'), key(t, 'b')
	file := write(t, source(t, ka, "admin"), ka)
	if bytes.Contains(file, []byte("example.org")) || bytes.Contains(file, []byte("SQLite")) {
		t.Fatal("the backup is not encrypted")
	}

	dst := fileDB(t)
	res, err := Open(ctx, bytes.NewReader(file), dst, kb, pass)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	if res.Manifest == nil || res.Manifest.Version != "test" || res.Manifest.Created != 1000 {
		t.Fatalf("manifest %+v", res.Manifest)
	}
	if err := dst.Restore(ctx, res.Path, nil); err != nil {
		t.Fatal(err)
	}
	var host string
	if err := dst.R.QueryRow("SELECT host FROM targets").Scan(&host); err != nil || host != "example.org" {
		t.Fatalf("target: %q %v", host, err)
	}
	var sessions int
	dst.R.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&sessions)
	if sessions != 0 {
		t.Fatalf("%d sessions survived the restore", sessions)
	}
	var blob []byte
	if err := dst.R.QueryRow("SELECT settings FROM channels").Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if pt, err := kb.Open(blob); err != nil || string(pt) != `{"password":"pw"}` {
		t.Fatalf("credentials not re-sealed under the new key: %q %v", pt, err)
	}
	// Still writable through the same pools.
	exec(t, dst, "INSERT INTO audit(at, user_email, action, object, details) VALUES(1, 'x', 'y', 'z', '')")
}

func TestWrongPassphraseAndDamage(t *testing.T) {
	ctx := context.Background()
	k := key(t, 'a')
	file := write(t, source(t, k, "admin"), k)
	dst := fileDB(t)
	for name, c := range map[string]struct {
		data []byte
		pass string
	}{
		"wrong passphrase": {file, "wrong passphrase!"},
		"cut off":          {file[:len(file)-20], pass},
		"altered":          {flip(file, 200), pass},
	} {
		_, err := Open(ctx, bytes.NewReader(c.data), dst, k, c.pass)
		if !errors.Is(err, ErrPassphrase) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Open(ctx, strings.NewReader("hello"), dst, k, pass); !isUser(err) {
		t.Errorf("not a backup: %v", err)
	}
	if _, err := Open(ctx, bytes.NewReader(file), dst, k, ""); !isUser(err) {
		t.Errorf("no passphrase: %v", err)
	}
}

func flip(b []byte, i int) []byte {
	c := append([]byte(nil), b...)
	c[i] ^= 1
	return c
}

func isUser(err error) bool {
	_, ok := usererr.Message(err)
	return err != nil && ok
}

func TestPlainCopy(t *testing.T) {
	ctx := context.Background()
	k := key(t, 'a')
	src := source(t, k, "admin")
	path := filepath.Join(t.TempDir(), "copy.db")
	if err := src.Backup(ctx, path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dst := fileDB(t)
	res, err := Open(ctx, bytes.NewReader(data), dst, k, "")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	if res.Manifest != nil {
		t.Fatal("a plain copy has no manifest")
	}
	if err := dst.Restore(ctx, res.Path, nil); err != nil {
		t.Fatal(err)
	}
	var blob []byte
	dst.R.QueryRow("SELECT settings FROM channels").Scan(&blob)
	if _, err := k.Open(blob); err != nil {
		t.Fatal("credentials of a plain copy changed")
	}
}

func TestRefusesWithoutAdmin(t *testing.T) {
	k := key(t, 'a')
	file := write(t, source(t, k, "viewer"), k)
	_, err := Open(context.Background(), bytes.NewReader(file), fileDB(t), k, pass)
	if !isUser(err) || !strings.Contains(err.Error(), "admin") {
		t.Fatalf("got %v", err)
	}
}

func TestRefusesNewerSchema(t *testing.T) {
	k := key(t, 'a')
	src := source(t, k, "admin")
	exec(t, src, "PRAGMA user_version = 9999")
	path := filepath.Join(t.TempDir(), "copy.db")
	if err := src.Backup(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	_, err := Open(context.Background(), bytes.NewReader(data), fileDB(t), k, "")
	if !isUser(err) || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("got %v", err)
	}
}

func TestGuardCancelsRestore(t *testing.T) {
	ctx := context.Background()
	k := key(t, 'a')
	file := write(t, source(t, k, "admin"), k)
	dst := fileDB(t)
	res, err := Open(ctx, bytes.NewReader(file), dst, k, pass)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	stop := errors.New("stop")
	if err := dst.Restore(ctx, res.Path, func(context.Context, *sql.Conn) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("got %v", err)
	}
	var n int
	dst.R.QueryRow("SELECT COUNT(*) FROM targets").Scan(&n)
	if n != 0 {
		t.Fatal("restored despite the guard")
	}
}
