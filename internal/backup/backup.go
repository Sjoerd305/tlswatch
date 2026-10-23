// Package backup writes and reads the backup file of the web UI: a copy of
// the database, encrypted with a passphrase, that restores the whole
// instance.
//
// The stored credentials in the copy are re-sealed from the instance key
// under a key derived from the passphrase, so the file restores on any
// instance and the instance key itself never leaves the server. On restore
// they are re-sealed under the key of the instance that restores.
//
// File format: a header (magic, Argon2id parameters, salt), then a stream
// of AES-256-GCM chunks over a tar archive with manifest.json and
// tlswatch.db. Each chunk is a 4-byte big-endian length and the sealed
// chunk; the nonce counts the chunks, and the header plus a last-chunk flag
// are the additional data, so a reordered, cut-off or altered file fails.
package backup

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/secret"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// MinPassphrase is the minimum number of characters in a passphrase.
const MinPassphrase = 12

const (
	magic     = "tlswatch-backup\x01"
	saltLen   = 16
	headerLen = len(magic) + 4 + 4 + 1 + saltLen
	chunkSize = 64 << 10
	dbName    = "tlswatch.db"
	manName   = "manifest.json"
)

// sqliteMagic starts every SQLite file, such as the copy `tlswatch backup`
// writes.
const sqliteMagic = "SQLite format 3\x00"

// Argon2id cost of the passphrase. Variables only so tests can lower it.
var (
	argonMemory  uint32 = 64 * 1024
	argonTime    uint32 = 3
	argonThreads uint8  = 2
)

// The most a backup file may ask for: four times the memory this version
// uses, 256 MiB.
const (
	maxArgonMemory  = 256 * 1024 // KiB
	maxArgonTime    = 8
	maxArgonThreads = 4
)

// ErrPassphrase is returned when the file does not open with the
// passphrase given (or was altered).
var ErrPassphrase = usererr.New("The backup could not be decrypted: the passphrase is wrong or the file is damaged")

// Manifest describes the backup.
type Manifest struct {
	Format  int    `json:"format"`
	Version string `json:"version"` // tlswatch version that wrote it
	Schema  int    `json:"schema"`
	Created int64  `json:"created"`
}

// keys derived from the passphrase: one for the stream, one that seals the
// credentials inside the database copy.
type keys struct {
	stream  cipher.AEAD
	secrets *secret.Key
}

func derive(pass string, salt []byte, t, m uint32, p uint8) (keys, error) {
	master := argon2.IDKey([]byte(pass), salt, t, m, p, 32)
	sub := func(purpose string) []byte {
		h := hmac.New(sha256.New, master)
		h.Write([]byte("tlswatch backup " + purpose))
		return h.Sum(nil)
	}
	block, err := aes.NewCipher(sub("stream"))
	if err != nil {
		return keys{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return keys{}, err
	}
	sk, err := secret.New(sub("secrets"))
	return keys{stream: aead, secrets: sk}, err
}

// CheckPassphrase validates a new passphrase.
func CheckPassphrase(pass, confirm string) error {
	if len([]rune(pass)) < MinPassphrase {
		return usererr.New(fmt.Sprintf("Choose a passphrase of at least %d characters", MinPassphrase))
	}
	if pass != confirm {
		return usererr.New("The passphrases do not match")
	}
	return nil
}

// Write writes an encrypted backup of d to w. The copy is made in a
// temporary directory next to the database and removed afterwards.
func Write(ctx context.Context, w io.Writer, d *db.DB, instance *secret.Key, pass, version string, now time.Time) error {
	if len([]rune(pass)) < MinPassphrase {
		return usererr.New(fmt.Sprintf("Choose a passphrase of at least %d characters", MinPassphrase))
	}
	dir, err := d.TempDir()
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, dbName)
	if err := d.Backup(ctx, path); err != nil {
		return err
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	k, err := derive(pass, salt, argonTime, argonMemory, argonThreads)
	if err != nil {
		return err
	}
	if err := reseal(ctx, path, instance, k.secrets); err != nil {
		return err
	}

	hdr := make([]byte, 0, headerLen)
	hdr = append(hdr, magic...)
	hdr = binary.BigEndian.AppendUint32(hdr, argonTime)
	hdr = binary.BigEndian.AppendUint32(hdr, argonMemory)
	hdr = append(hdr, argonThreads)
	hdr = append(hdr, salt...)
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	ew := &encWriter{w: w, aead: k.stream, hdr: hdr, buf: make([]byte, 0, chunkSize)}
	tw := tar.NewWriter(ew)
	man, _ := json.Marshal(Manifest{Format: 1, Version: version, Schema: db.SchemaVersion(), Created: now.Unix()})
	if err := tw.WriteHeader(&tar.Header{Name: manName, Mode: 0o600, Size: int64(len(man)), ModTime: now}); err != nil {
		return err
	}
	if _, err := tw.Write(man); err != nil {
		return err
	}
	f, err := os.Open(path) // #nosec G304 -- our own temporary file
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: dbName, Mode: 0o600, Size: fi.Size(), ModTime: now}); err != nil {
		return err
	}
	if _, err := io.Copy(tw, f); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return ew.Close()
}

// reseal re-seals the stored credentials of the database at path from one
// key to another. Credentials that from cannot open are left as they are:
// they were unreadable before and are marked so after the restore.
func reseal(ctx context.Context, path string, from, to *secret.Key) error {
	d, err := db.OpenExisting(path)
	if err != nil {
		return err
	}
	defer d.Close()
	tx, err := d.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, _, err := notify.Reencrypt(ctx, tx, from, to); err != nil {
		return err
	}
	// An unreadable setting is left as it is, like a channel, and shown
	// as such; an unreadable install token is dropped.
	if _, _, err := config.Reencrypt(ctx, tx, from, to); err != nil {
		return err
	}
	if _, err := core.ReencryptNodeTokens(ctx, tx, from, to); err != nil {
		return err
	}
	// An unreadable TOTP secret is dropped: its user signs in with the
	// password and sets TOTP up again.
	if _, _, err := auth.ReencryptTOTP(ctx, tx, from, to); err != nil {
		return err
	}
	return tx.Commit()
}

type encWriter struct {
	w    io.Writer
	aead cipher.AEAD
	hdr  []byte
	buf  []byte
	n    uint64
}

func (e *encWriter) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		if len(e.buf) == chunkSize {
			if err := e.flush(false); err != nil {
				return total - len(p), err
			}
		}
		k := min(chunkSize-len(e.buf), len(p))
		e.buf = append(e.buf, p[:k]...)
		p = p[k:]
	}
	return total, nil
}

// Close writes the last chunk, which may be empty.
func (e *encWriter) Close() error { return e.flush(true) }

func (e *encWriter) flush(last bool) error {
	sealed := e.aead.Seal(nil, nonce(e.n), e.buf, aad(e.hdr, last))
	e.n++
	e.buf = e.buf[:0]
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(sealed))) // #nosec G115 -- at most chunkSize plus the tag
	if _, err := e.w.Write(l[:]); err != nil {
		return err
	}
	_, err := e.w.Write(sealed)
	return err
}

func nonce(n uint64) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint64(b[4:], n)
	return b
}

func aad(hdr []byte, last bool) []byte {
	a := append([]byte(nil), hdr...)
	if last {
		return append(a, 1)
	}
	return append(a, 0)
}

type decReader struct {
	r    io.Reader
	aead cipher.AEAD
	hdr  []byte
	buf  []byte
	n    uint64
	done bool
}

func (d *decReader) Read(p []byte) (int, error) {
	for len(d.buf) == 0 {
		if d.done {
			return 0, io.EOF
		}
		if err := d.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

func (d *decReader) next() error {
	var l [4]byte
	if _, err := io.ReadFull(d.r, l[:]); err != nil {
		return cutOff(err)
	}
	size := binary.BigEndian.Uint32(l[:])
	if size > chunkSize+uint32(d.aead.Overhead()) { // #nosec G115 -- small constant
		return ErrPassphrase
	}
	sealed := make([]byte, size)
	if _, err := io.ReadFull(d.r, sealed); err != nil {
		return cutOff(err)
	}
	for _, last := range []bool{false, true} {
		if pt, err := d.aead.Open(nil, nonce(d.n), sealed, aad(d.hdr, last)); err == nil {
			d.n++
			d.buf, d.done = pt, last
			return nil
		}
	}
	return ErrPassphrase
}

// cutOff reports a file that ends before its last chunk as damaged.
func cutOff(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrPassphrase
	}
	return err
}

// Restore is a database file ready to be restored.
type Restore struct {
	Path     string    // the database, migrated and with its credentials sealed under the instance key
	Manifest *Manifest // nil for a plain database copy
	dir      string
}

// Close removes the temporary files.
func (r *Restore) Close() error { return os.RemoveAll(r.dir) }

// Open reads an upload: a backup file from Write (which needs the
// passphrase) or a plain database copy from `tlswatch backup`, whose
// credentials must already be sealed under the instance key. It checks
// the database, migrates it, re-seals the credentials under the instance
// key and ends every session in it. The caller restores Path and closes
// the result.
func Open(ctx context.Context, r io.Reader, d *db.DB, instance *secret.Key, pass string) (*Restore, error) {
	dir, err := d.TempDir()
	if err != nil {
		return nil, err
	}
	res := &Restore{Path: filepath.Join(dir, dbName), dir: dir}
	if err := res.read(ctx, bufio.NewReader(r), instance, pass); err != nil {
		_ = res.Close()
		return nil, err
	}
	return res, nil
}

func (res *Restore) read(ctx context.Context, br *bufio.Reader, instance *secret.Key, pass string) error {
	head, _ := br.Peek(len(magic))
	switch string(head) {
	case sqliteMagic:
		if err := writeFile(res.Path, br); err != nil {
			return err
		}
		return prepare(ctx, res.Path, nil, instance)
	case magic:
	default:
		return usererr.New("This is not a tlswatch backup")
	}
	hdr := make([]byte, headerLen)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return usererr.New("This is not a tlswatch backup")
	}
	p := hdr[len(magic):]
	t, m, threads := binary.BigEndian.Uint32(p), binary.BigEndian.Uint32(p[4:]), p[8]
	// The file chooses the cost of its key, and the setup screen takes an
	// upload before anyone signs in: the cap keeps a hostile header from
	// exhausting a small host, with room above what this version writes.
	if t == 0 || t > maxArgonTime || m < 8 || m > maxArgonMemory || threads == 0 || threads > maxArgonThreads {
		return usererr.New("This backup uses settings this version of tlswatch does not read")
	}
	if pass == "" {
		return usererr.New("Enter the passphrase of the backup")
	}
	k, err := derive(pass, p[9:], t, m, threads)
	if err != nil {
		return err
	}
	dec := &decReader{r: br, aead: k.stream, hdr: hdr}
	tr := tar.NewReader(dec)
	var man *Manifest
	haveDB := false
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return readErr(err)
		}
		switch h.Name {
		case manName:
			b, err := io.ReadAll(io.LimitReader(tr, 64<<10))
			if err != nil {
				return ErrPassphrase
			}
			man = &Manifest{}
			if err := json.Unmarshal(b, man); err != nil || man.Format != 1 {
				return usererr.New("This backup was written by a version of tlswatch that this one does not read")
			}
		case dbName:
			if err := writeFile(res.Path, tr); err != nil {
				return readErr(err)
			}
			haveDB = true
		default:
			return usererr.New("The backup contains an unexpected file: " + h.Name)
		}
	}
	if man == nil || !haveDB {
		return usererr.New("The backup is incomplete")
	}
	// Up to the last chunk and not a byte more: anything after it is not
	// what the backup wrote.
	if _, err := io.Copy(io.Discard, dec); err != nil {
		return readErr(err)
	}
	if n, _ := io.CopyN(io.Discard, br, 1); n > 0 {
		return usererr.New("The backup is damaged: there is data after its end")
	}
	res.Manifest = man
	return prepare(ctx, res.Path, k.secrets, instance)
}

// readErr turns an error from reading the archive into one for the user,
// keeping others (such as an upload over the size limit) as they are.
func readErr(err error) error {
	switch {
	case errors.Is(err, ErrPassphrase):
		return ErrPassphrase
	case errors.Is(err, tar.ErrHeader), errors.Is(err, io.ErrUnexpectedEOF):
		return usererr.New("The backup is damaged")
	}
	return err
}

func writeFile(path string, r io.Reader) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- our own temporary file
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// prepare checks and migrates the database at path, re-seals its
// credentials from sealed (nil: already under the instance key) to the
// instance key and ends its sessions.
func prepare(ctx context.Context, path string, sealed, instance *secret.Key) error {
	d, err := db.OpenExisting(path)
	if err != nil {
		return err
	}
	err = check(ctx, d)
	_ = d.Close()
	if err != nil {
		return err
	}
	// Migrate in a pass of its own: Open refuses a newer schema.
	m, err := db.Open(path)
	if err != nil {
		// Logged by the caller as a server error; the text of a migration
		// failure is for the operator's log, not the browser.
		return fmt.Errorf("migrate the backup: %w", err)
	}
	defer m.Close()
	var admins int
	if err := m.R.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role = 'admin' AND enabled = 1").Scan(&admins); err != nil {
		return err
	}
	if admins == 0 {
		return usererr.New("The backup has no enabled admin; restoring it would lock everyone out of the settings")
	}
	// Nobody stays signed in, and no invite or password link or API token
	// from before the backup comes back to life: one revoked since would.
	for _, q := range []string{"DELETE FROM sessions", "DELETE FROM tokens", "DELETE FROM api_tokens"} {
		if _, err := m.W.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	if sealed != nil {
		if err := reseal(ctx, path, sealed, instance); err != nil {
			return err
		}
	}
	return nil
}

// check refuses a file that is not a sound tlswatch database this version
// can run.
func check(ctx context.Context, d *db.DB) error {
	var res string
	if err := d.R.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&res); err != nil || res != "ok" {
		return usererr.New("The database in the backup is damaged")
	}
	var v int
	if err := d.R.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	if v > db.SchemaVersion() {
		return usererr.New(fmt.Sprintf("The backup was made by a newer version of tlswatch (schema %d; this one runs %d). Upgrade first", v, db.SchemaVersion()))
	}
	var tables int
	if err := d.R.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('users', 'targets', 'settings')").Scan(&tables); err != nil {
		return err
	}
	if v < 1 || tables != 3 {
		return usererr.New("This database is not a tlswatch database")
	}
	return nil
}
