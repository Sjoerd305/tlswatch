package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// pruneBatch is how many rows one prune statement deletes, so checks and
// sign-ins get the writer between batches.
const pruneBatch = 5000

// Prune removes history older than the retention period. The current state
// of every target is kept regardless of age.
func (s *Service) Prune(ctx context.Context) error {
	st := s.CurrentSettings(ctx)
	cut := s.now().Add(-time.Duration(st.Defaults.RetentionDays) * 24 * time.Hour).Unix()
	batched := []string{
		// Keep each target's latest check.
		`DELETE FROM observations WHERE id IN (SELECT id FROM observations WHERE checked_at < ?1
			AND check_id NOT IN (SELECT last_check_id FROM targets) LIMIT ?2)`,
		"DELETE FROM alerts WHERE id IN (SELECT id FROM alerts WHERE created_at < ?1 AND state != 'pending' LIMIT ?2)",
		"DELETE FROM findings WHERE id IN (SELECT id FROM findings WHERE resolved_at > 0 AND resolved_at < ?1 LIMIT ?2)",
		"DELETE FROM audit WHERE id IN (SELECT id FROM audit WHERE at < ?1 LIMIT ?2)",
		"DELETE FROM tokens WHERE expires_at < ?1",
		// Issuances age out with the rest, except one with an open finding.
		`DELETE FROM issuances WHERE id IN (SELECT id FROM issuances WHERE first_seen < ?1
			AND CAST(id AS TEXT) NOT IN (SELECT fingerprint FROM findings WHERE domain_id IS NOT NULL AND resolved_at = 0) LIMIT ?2)`,
	}
	for _, q := range batched {
		for {
			res, err := s.DB.W.ExecContext(ctx, q, cut, pruneBatch)
			if err != nil {
				return fmt.Errorf("prune: %w", err)
			}
			if n, _ := res.RowsAffected(); n < pruneBatch {
				break
			}
		}
	}
	if err := s.pruneCertificates(ctx, cut); err != nil {
		return fmt.Errorf("prune certificates: %w", err)
	}
	return nil
}

// pruneCertificates removes certificates not seen since cut that no
// remaining observation, current state or pin refers to. The references are
// collected in one pass over the observations on the read pool; the delete
// checks last_seen again, so a certificate seen meanwhile stays.
func (s *Service) pruneCertificates(ctx context.Context, cut int64) error {
	rows, err := s.DB.R.QueryContext(ctx, `SELECT fingerprint FROM certificates WHERE last_seen < ?
		AND fingerprint NOT IN (SELECT current_fp FROM targets) AND fingerprint NOT IN (SELECT pinned_fp FROM targets)`, cut)
	if err != nil {
		return err
	}
	candidates := map[string]bool{}
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			rows.Close()
			return err
		}
		candidates[fp] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(candidates) == 0 {
		return err
	}
	rows, err = s.DB.R.QueryContext(ctx, "SELECT leaf_fp, chain FROM observations")
	if err != nil {
		return err
	}
	for rows.Next() {
		var leaf, chain string
		if err := rows.Scan(&leaf, &chain); err != nil {
			rows.Close()
			return err
		}
		delete(candidates, leaf)
		var refs []string
		_ = json.Unmarshal([]byte(chain), &refs)
		for _, ref := range refs {
			delete(candidates, strings.TrimPrefix(ref, "root:"))
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for fp := range candidates {
		if _, err := s.DB.W.ExecContext(ctx, "DELETE FROM certificates WHERE fingerprint = ? AND last_seen < ?", fp, cut); err != nil {
			return err
		}
	}
	return nil
}
