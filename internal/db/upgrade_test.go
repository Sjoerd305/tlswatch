package db

import (
	"context"
	"io/fs"
	"path/filepath"
	"sort"
	"testing"
)

// openAt creates a database migrated up to version v only.
func openAt(t *testing.T, v int) *DB {
	t.Helper()
	d, err := open(filepath.Join(t.TempDir(), "old.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	files, _ := fs.Glob(migrations, "migrations/*.sql")
	sort.Slice(files, func(i, j int) bool { return migrationVersion(files[i]) < migrationVersion(files[j]) })
	ctx := context.Background()
	conn, err := d.W.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, f := range files {
		if n := migrationVersion(f); n <= v {
			body, _ := migrations.ReadFile(f)
			if err := d.applyMigration(ctx, conn, f, string(body), n); err != nil {
				t.Fatal(err)
			}
		}
	}
	return d
}

// An installation on schema 7 with history upgrades to the latest: the two
// rebuilds of findings (0008, 0010) keep every finding and its alerts, the
// foreign keys still cascade afterwards, and the new constraints hold.
func TestUpgradeKeepsFindingsAndAlerts(t *testing.T) {
	ctx := context.Background()
	d := openAt(t, 7)
	exec := func(q string, args ...any) error {
		_, err := d.W.ExecContext(ctx, q, args...)
		return err
	}
	must := func(q string, args ...any) {
		t.Helper()
		if err := exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	must("INSERT INTO channels(id, name, kind, settings, created_at, updated_at) VALUES(1, 'mail', 'smtp', x'00', 1, 1)")
	must("INSERT INTO targets(id, name, host, port, created_at, updated_at) VALUES(1, 't', 'example.org', 443, 1, 1)")
	must("INSERT INTO observations(target_id, check_id, address, checked_at, status) VALUES(1, 'c1', '192.0.2.1', 1, 'ok')")
	must("INSERT INTO findings(id, target_id, kind, severity, opened_at, ack_by, ack_at) VALUES(7, 1, 'expiring', 'warning', 1, 'Alex', 2)")
	must("INSERT INTO findings(id, target_id, kind, severity, opened_at, resolved_at) VALUES(8, 1, 'expiring', 'critical', 1, 5)")
	must("INSERT INTO alerts(finding_id, channel_id, event, created_at, next_attempt, state) VALUES(7, 1, 'open', 1, 1, 'sent')")
	must("INSERT INTO alerts(finding_id, channel_id, event, created_at, next_attempt, state) VALUES(8, 1, 'recover', 1, 1, 'sent')")

	if err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var v int
	_ = d.W.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v)
	if v != SchemaVersion() {
		t.Fatalf("schema %d", v)
	}
	count := func(q string) int {
		var n int
		if err := d.W.QueryRowContext(ctx, q).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	if n := count("SELECT COUNT(*) FROM findings WHERE target_id = 1 AND ack_by = 'Alex'"); n != 1 {
		t.Fatalf("acknowledged finding after the upgrade: %d", n)
	}
	if n := count("SELECT COUNT(*) FROM alerts"); n != 2 {
		t.Fatalf("alerts after the upgrade: %d", n)
	}
	if n := count("SELECT COUNT(*) FROM pragma_foreign_key_check"); n != 0 {
		t.Fatalf("dangling references after the upgrade: %d", n)
	}
	// The change counter's triggers are back on the rebuilt table.
	before := count("SELECT n FROM changes")
	must("UPDATE findings SET details = 'x' WHERE id = 7")
	if count("SELECT n FROM changes") == before {
		t.Fatal("findings trigger lost in the rebuild")
	}
	// One open finding per target and kind, still.
	if err := exec("INSERT INTO findings(target_id, kind, severity, opened_at) VALUES(1, 'expiring', 'warning', 9)"); err == nil {
		t.Fatal("a second open expiring finding on one target was accepted")
	}
	// Exactly one owner.
	if err := exec("INSERT INTO findings(kind, severity, opened_at) VALUES('expiring', 'warning', 9)"); err == nil {
		t.Fatal("a finding without an owner was accepted")
	}
	must("INSERT INTO domains(id, name, created_at, updated_at) VALUES(1, 'example.org', 1, 1)")
	if err := exec("INSERT INTO findings(target_id, domain_id, kind, severity, opened_at) VALUES(1, 1, 'x', 'warning', 9)"); err == nil {
		t.Fatal("a finding with two owners was accepted")
	}
	// One open finding per issuance on a watch, several per watch.
	must("INSERT INTO findings(domain_id, kind, severity, opened_at, fingerprint) VALUES(1, 'unexpected_certificate', 'warning', 9, '1')")
	must("INSERT INTO findings(domain_id, kind, severity, opened_at, fingerprint) VALUES(1, 'unexpected_certificate', 'warning', 9, '2')")
	if err := exec("INSERT INTO findings(domain_id, kind, severity, opened_at, fingerprint) VALUES(1, 'unexpected_certificate', 'warning', 9, '2')"); err == nil {
		t.Fatal("two open findings for one issuance")
	}
	// Deleting the target cascades through the rebuilt tables.
	must("DELETE FROM targets WHERE id = 1")
	if n := count("SELECT COUNT(*) FROM findings WHERE target_id IS NOT NULL") + count("SELECT COUNT(*) FROM alerts") + count("SELECT COUNT(*) FROM observations"); n != 0 {
		t.Fatalf("%d rows left after deleting the target", n)
	}
	must("DELETE FROM domains WHERE id = 1")
	if n := count("SELECT COUNT(*) FROM findings"); n != 0 {
		t.Fatalf("%d domain findings left after deleting the watch", n)
	}
}

// A node referenced by targets cannot be deleted at the database level, and
// its observations keep their history when it goes.
func TestNodeReferences(t *testing.T) {
	ctx := context.Background()
	d, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	must := func(q string) {
		t.Helper()
		if _, err := d.W.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	must("INSERT INTO nodes(id, state, created_at, updated_at) VALUES(1, 'confirmed', 1, 1)")
	must("INSERT INTO targets(id, name, host, port, created_at, updated_at, node_id) VALUES(1, 't', 'example.org', 443, 1, 1, 1)")
	must("INSERT INTO observations(target_id, check_id, address, checked_at, status, node_id) VALUES(1, 'c', '192.0.2.1', 1, 'ok', 1)")
	if _, err := d.W.ExecContext(ctx, "DELETE FROM nodes WHERE id = 1"); err == nil {
		t.Fatal("deleted a node that a target uses")
	}
	must("UPDATE targets SET node_id = NULL")
	must("DELETE FROM nodes WHERE id = 1")
	var n int
	_ = d.W.QueryRowContext(ctx, "SELECT COUNT(*) FROM observations WHERE node_id IS NULL").Scan(&n)
	if n != 1 {
		t.Fatalf("observation after its node went: %d", n)
	}
}
