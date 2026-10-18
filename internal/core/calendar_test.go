package core

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestFoldAndEscapeICS(t *testing.T) {
	long := "SUMMARY:" + escapeICS(strings.Repeat("é, x; y\\ ", 20)+"\nnext")
	folded := foldICS(long)
	if !strings.HasSuffix(folded, "\r\n") || strings.Contains(long, "\n") {
		t.Fatalf("not one escaped line: %q", long)
	}
	var joined strings.Builder
	for i, l := range strings.Split(strings.TrimSuffix(folded, "\r\n"), "\r\n") {
		if len(l) > 75 || !utf8.ValidString(l) {
			t.Fatalf("line %d: %d octets, valid %v", i, len(l), utf8.ValidString(l))
		}
		if i > 0 {
			if !strings.HasPrefix(l, " ") {
				t.Fatalf("continuation without a space: %q", l)
			}
			l = l[1:]
		}
		joined.WriteString(l)
	}
	if joined.String() != long || !strings.Contains(long, `é\, x\; y\\ `) || !strings.HasSuffix(long, `\nnext`) {
		t.Fatalf("unfolded %q", joined.String())
	}
}

// A feed of a disabled user opens nothing.
func TestCalendarOfDisabledUser(t *testing.T) {
	e := newEnv(t)
	res, err := e.svc.DB.W.Exec("INSERT INTO users(email, role, method, created_at) VALUES('v@example.nl', 'viewer', 'local', 1)")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	_, token, err := e.svc.CreateCalendar(e.ctx, uid, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CalendarByToken(e.ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.DB.W.Exec("UPDATE users SET enabled = 0 WHERE id = ?", uid); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CalendarByToken(e.ctx, token); err != ErrNotFound {
		t.Fatalf("disabled user: %v", err)
	}
}
