package db

import (
	"context"
	"path/filepath"
	"testing"
)

// OpenExisting, used by the backup command, neither creates nor migrates.
func TestOpenExistingDoesNotMigrate(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenExisting(filepath.Join(dir, "missing.db")); err == nil {
		t.Fatal("opened a database that does not exist")
	}
	path := filepath.Join(dir, "old.db")
	d, err := open(path, false) // creates an empty file at schema version 0
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	d, err = OpenExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var v int
	if err := d.W.QueryRowContext(context.Background(), "PRAGMA user_version").Scan(&v); err != nil || v != 0 {
		t.Fatalf("schema version %d after OpenExisting: %v", v, err)
	}
}

func TestMigrateToLatest(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "new.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var v int
	_ = d.W.QueryRow("PRAGMA user_version").Scan(&v)
	if v != SchemaVersion() || v < 3 {
		t.Fatalf("schema version %d, latest %d", v, SchemaVersion())
	}
}
