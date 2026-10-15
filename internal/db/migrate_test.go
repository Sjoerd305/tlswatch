package db

import (
	"context"
	"path/filepath"
	"testing"
)

// Migration 0007 rebuilds the channels table. With foreign keys on, dropping
// the old table would cascade into target_channels and alerts; the runner
// switches them off around each migration, so the rows must survive.
func TestRebuildKeepsReferencingRows(t *testing.T) {
	ctx := context.Background()
	d, err := Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	exec := func(q string, args ...any) {
		if _, err := d.W.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec("INSERT INTO channels(id, name, kind, settings, created_at, updated_at) VALUES(1, 'c', 'slack', x'00', 1, 1)")
	exec("INSERT INTO targets(id, name, host, port, created_at, updated_at) VALUES(1, 't', 'example.org', 443, 1, 1)")
	exec("INSERT INTO target_channels(target_id, channel_id) VALUES(1, 1)")
	exec("INSERT INTO alerts(channel_id, event, created_at, next_attempt) VALUES(1, 'test', 1, 1)")

	body, err := migrations.ReadFile("migrations/0007_channel_kinds.sql")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.W.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = d.applyMigration(ctx, conn, "0007", string(body), SchemaVersion())
	conn.Close() // the writer pool has one connection; release it for the checks
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"channels", "target_channels", "alerts"} {
		var n int
		if err := d.W.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s has %d rows after the rebuild: %v", table, n, err)
		}
	}
	// Foreign keys are back on: deleting the channel cascades as before.
	var fk int
	if err := d.W.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign_keys=%d after the migration: %v", fk, err)
	}
	exec("DELETE FROM channels WHERE id = 1")
	var n int
	if err := d.W.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts").Scan(&n); err != nil || n != 0 {
		t.Fatalf("alerts after deleting the channel: %d, %v", n, err)
	}
	// A new kind is accepted; the CHECK is gone.
	exec("INSERT INTO channels(name, kind, settings, created_at, updated_at) VALUES('w', 'webhook', x'00', 1, 1)")
}
