package core

import (
	"context"
	"fmt"
	"strings"
)

// AuditEntry is one change in the tool itself.
type AuditEntry struct {
	ID      int64
	At      int64
	User    string
	Action  string
	Object  string
	Details string
}

// AuditLog lists audit entries, newest first, optionally filtered by a
// substring over user, action and object.
func (s *Service) AuditLog(ctx context.Context, filter string, limit int) ([]AuditEntry, error) {
	q := "SELECT id, at, user_email, action, object, details FROM audit"
	var args []any
	if f := strings.TrimSpace(filter); f != "" {
		q += " WHERE user_email LIKE ? OR action LIKE ? OR object LIKE ? OR details LIKE ?"
		like := "%" + strings.ReplaceAll(strings.ReplaceAll(f, "%", ""), "_", "") + "%"
		args = append(args, like, like, like, like)
	}
	q += " ORDER BY id DESC"
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	rows, err := s.DB.R.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.ID, &a.At, &a.User, &a.Action, &a.Object, &a.Details); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
