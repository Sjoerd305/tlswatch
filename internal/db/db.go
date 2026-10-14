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

	_ "modernc.org/sqlite" // registers the "sqlite" driver
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
	pragmas := "_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)"
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
	w, err := sql.Open("sqlite", dsnW)
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	if err := w.Ping(); err != nil {
		w.Close()
		return nil, fmt.Errorf("open database: %w", err)
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

// Migrate applies pending migrations, forward only. It refuses a database
// written by a newer version of tlswatch.
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
	for _, f := range files {
		v := migrationVersion(f)
		if v <= current {
			continue
		}
		body, err := migrations.ReadFile(f)
		if err != nil {
			return err
		}
		tx, err := d.W.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", filepath.Base(f), err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", v)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Backup writes a consistent copy of the database to path (VACUUM INTO),
// safe while the server runs.
func (d *DB) Backup(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	_, err := d.W.ExecContext(ctx, "VACUUM INTO ?", path)
	return err
}
