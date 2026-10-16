// Package db opens the SQLite database and runs the embedded migrations.
//
// Writes go through a pool limited to one connection, which serialises them;
// reads use a separate pool and run concurrently thanks to WAL mode.
package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"modernc.org/sqlite" // also registers the "sqlite" driver
)

//go:embed migrations/*.sql
var migrations embed.FS

// DB holds the writer and reader pools for one SQLite file.
type DB struct {
	W    *sql.DB // single connection, all writes
	R    *sql.DB // concurrent reads
	Path string
}

// Open opens (and creates) the database at path and applies pending
// migrations. The path ":memory:" opens a private in-memory database shared
// by both pools, for tests.
func Open(path string) (*DB, error) { return open(path, true) }

// OpenExisting opens the database at path as it is: no migrations, and an
// error when the file does not exist. For the backup command, which must
// not change the database it copies.
func OpenExisting(path string) (*DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	return open(path, false)
}

func open(path string, migrate bool) (*DB, error) {
	var dsnW, dsnR string
	// temp_store(MEMORY): sorts and VACUUM need no temporary files, which
	// the scratch image has nowhere to put.
	pragmas := "_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_pragma=temp_store(MEMORY)"
	if path == ":memory:" {
		name := "mem" + strconv.FormatUint(uint64(randUint()), 36)
		dsnW = "file:" + name + "?mode=memory&cache=shared&" + pragmas
		dsnR = dsnW
	} else {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
		u := "file:" + url.PathEscape(path) + "?"
		dsnW = u + pragmas + "&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_txlock=immediate"
		dsnR = u + pragmas + "&_pragma=journal_mode(WAL)&mode=ro"
	}
	_, statErr := os.Stat(path)
	fresh := path != ":memory:" && errors.Is(statErr, os.ErrNotExist)
	w, err := sql.Open("sqlite", dsnW)
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	if err := w.Ping(); err != nil {
		w.Close()
		return nil, fmt.Errorf("open database: %w", err)
	}
	if fresh {
		// The driver creates the file under the umask; it holds password
		// hashes and sealed credentials, so only the owner reads it. The
		// WAL and shm files take the main file's mode.
		if err := os.Chmod(path, 0o600); err != nil {
			w.Close()
			return nil, fmt.Errorf("open database: %w", err)
		}
	}
	d := &DB{W: w, Path: path}
	if migrate {
		if err := d.Migrate(context.Background()); err != nil {
			w.Close()
			return nil, err
		}
	}
	r, err := sql.Open("sqlite", dsnR)
	if err != nil {
		w.Close()
		return nil, err
	}
	if path == ":memory:" {
		// Shared-cache in-memory databases need the writer to keep the
		// database alive; reads share its single connection to avoid
		// table-lock errors.
		r.Close()
		r = w
	} else {
		r.SetMaxOpenConns(8)
	}
	d.R = r
	return d, nil
}

// Close closes both pools.
func (d *DB) Close() error {
	var err error
	if d.R != d.W {
		err = d.R.Close()
	}
	return errors.Join(err, d.W.Close())
}

// Ping checks that the database answers.
func (d *DB) Ping(ctx context.Context) error {
	var one int
	return d.R.QueryRowContext(ctx, "SELECT 1").Scan(&one)
}

// SchemaVersion is the highest migration embedded in this binary.
func SchemaVersion() int {
	files, _ := fs.Glob(migrations, "migrations/*.sql")
	max := 0
	for _, f := range files {
		if v := migrationVersion(f); v > max {
			max = v
		}
	}
	return max
}

func migrationVersion(name string) int {
	base := filepath.Base(name)
	n, _ := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
	return n
}

// Migrate applies pending migrations, forward only, each in its own
// transaction. It refuses a database written by a newer version of
// tlswatch. Migrations run with foreign keys off, as SQLite's procedure for
// rebuilding a table prescribes: with them on, dropping the old copy of a
// table would cascade into the rows that reference it. PRAGMA foreign_keys
// is ignored inside a transaction, so it is switched on the pinned
// connection around each one, and a foreign_key_check before the commit
// catches a migration that left a dangling reference.
func (d *DB) Migrate(ctx context.Context) error {
	var current int
	if err := d.W.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		return err
	}
	if latest := SchemaVersion(); current > latest {
		return fmt.Errorf("database schema version %d is newer than this binary supports (%d); upgrade tlswatch", current, latest)
	}
	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Slice(files, func(i, j int) bool { return migrationVersion(files[i]) < migrationVersion(files[j]) })
	conn, err := d.W.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, f := range files {
		v := migrationVersion(f)
		if v <= current {
			continue
		}
		body, err := migrations.ReadFile(f)
		if err != nil {
			return err
		}
		if err := d.applyMigration(ctx, conn, filepath.Base(f), string(body), v); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) applyMigration(ctx context.Context, conn *sql.Conn, name, body string, v int) error {
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		return err
	}
	defer conn.ExecContext(ctx, "PRAGMA foreign_keys = ON")
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, body); err != nil {
		return fmt.Errorf("migration %s: %w", name, err)
	}
	var table string
	if err := tx.QueryRowContext(ctx, "SELECT \"table\" FROM pragma_foreign_key_check LIMIT 1").Scan(&table); err == nil {
		return fmt.Errorf("migration %s: dangling foreign key in %s", name, table)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("migration %s: foreign key check: %w", name, err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", v)); err != nil {
		return err
	}
	return tx.Commit()
}

// Backup writes a consistent copy of the database to path (VACUUM INTO),
// safe while the server runs.
func (d *DB) Backup(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	if _, err := d.W.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
		return err
	}
	// The copy holds what the database holds: owner-only, like it.
	return os.Chmod(path, 0o600)
}

// TempDir creates a private temporary directory next to the database, on
// the same volume (the container image has no /tmp). The caller removes it.
func (d *DB) TempDir() (string, error) {
	dir := filepath.Dir(d.Path)
	if d.Path == ":memory:" {
		dir = os.TempDir()
	}
	return os.MkdirTemp(dir, ".tlswatch-tmp-")
}

// Restore replaces the whole database with the one at path, in place and
// while the server runs: SQLite's backup API copies it page by page over the
// writer connection in one step, so readers see either the old database or
// the new one. The caller checks and migrates the file first. A non-nil
// guard runs first on the writer connection, which no other write can use
// until the restore ends; an error from it cancels the restore.
func (d *DB) Restore(ctx context.Context, path string, guard func(context.Context, *sql.Conn) error) error {
	c, err := d.W.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if guard != nil {
		if err := guard(ctx, c); err != nil {
			return err
		}
	}
	return c.Raw(func(dc any) error {
		r, ok := dc.(interface {
			NewRestore(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("the SQLite driver cannot restore")
		}
		b, err := r.NewRestore("file:" + url.PathEscape(path) + "?mode=ro")
		if err != nil {
			return fmt.Errorf("restore: %w", err)
		}
		if _, err := b.Step(-1); err != nil {
			b.Finish()
			return fmt.Errorf("restore: %w", err)
		}
		return b.Finish()
	})
}
