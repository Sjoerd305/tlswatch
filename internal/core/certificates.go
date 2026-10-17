package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

const certCols = `fingerprint, subject, subject_cn, issuer, issuer_cn, issuer_org, serial, not_before, not_after, sans,
	key_type, key_bits, sig_alg, is_ca, self_signed, pem, first_seen, last_seen`

// certListCols are certCols without the PEM, for lists: only the download
// needs it, and it is most of a row's size.
const certListCols = `fingerprint, subject, subject_cn, issuer, issuer_cn, issuer_org, serial, not_before, not_after, sans,
	key_type, key_bits, sig_alg, is_ca, self_signed, '' AS pem, first_seen, last_seen`

func scanCert(r interface{ Scan(...any) error }) (Certificate, error) {
	var c Certificate
	var sans string
	err := r.Scan(&c.Fingerprint, &c.Subject, &c.SubjectCN, &c.Issuer, &c.IssuerCN, &c.IssuerOrg, &c.Serial, &c.NotBefore, &c.NotAfter,
		&sans, &c.KeyType, &c.KeyBits, &c.SigAlg, &c.IsCA, &c.SelfSigned, &c.PEM, &c.FirstSeen, &c.LastSeen)
	if err == nil {
		_ = json.Unmarshal([]byte(sans), &c.SANs)
	}
	return c, err
}

// Certificate returns one certificate by fingerprint.
func (s *Service) Certificate(ctx context.Context, fp string) (Certificate, error) {
	c, err := scanCert(s.DB.R.QueryRowContext(ctx, "SELECT "+certCols+" FROM certificates WHERE fingerprint = ?", strings.ToLower(fp)))
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

func storeCert(ctx context.Context, tx *sql.Tx, info probe.CertInfo, now int64) error {
	sans, _ := json.Marshal(info.SANs)
	_, err := tx.ExecContext(ctx, `INSERT INTO certificates(`+certCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(fingerprint) DO UPDATE SET last_seen = excluded.last_seen`,
		info.Fingerprint, info.Subject, info.SubjectCN, info.Issuer, info.IssuerCN, info.IssuerOrg, info.Serial,
		info.NotBefore.Unix(), info.NotAfter.Unix(), string(sans), info.KeyType, info.KeyBits, info.SigAlg,
		info.IsCA, info.SelfSigned, info.PEM, now, now)
	return err
}

// Observation is one probe of one address.
type Observation struct {
	ID          int64
	CheckID     string
	Address     string
	CheckedAt   int64
	Status      string
	TLSVersion  string
	Cipher      string
	LeafFP      string
	Chain       []string
	Verified    bool
	VerifyError string
	Error       string
	DurationMS  int64
}

// LastCheck returns the observations of a target's most recent check.
func (s *Service) LastCheck(ctx context.Context, targetID int64) ([]Observation, error) {
	rows, err := s.DB.R.QueryContext(ctx, `SELECT id, check_id, address, checked_at, status, tls_version, cipher, leaf_fp, chain, verified, verify_error, error, duration_ms
		FROM observations WHERE target_id = ?1 AND check_id = (SELECT last_check_id FROM targets WHERE id = ?1) ORDER BY id`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Observation
	for rows.Next() {
		var o Observation
		var chain string
		if err := rows.Scan(&o.ID, &o.CheckID, &o.Address, &o.CheckedAt, &o.Status, &o.TLSVersion, &o.Cipher, &o.LeafFP, &chain, &o.Verified, &o.VerifyError, &o.Error, &o.DurationMS); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(chain), &o.Chain)
		out = append(out, o)
	}
	return out, rows.Err()
}

// ChainLink is one certificate in a served chain.
type ChainLink struct {
	Certificate
	Role    string // leaf, intermediate, root
	InStore bool   // root added from the trust store or bundle
	Weak    bool
	Worst   bool // the link that expires first
	// Stale: an expired root the server still sends after a chain that
	// verifies without it; clients ignore it and it can be dropped.
	Stale bool
}

// Chain resolves an observation's chain to certificates.
func (s *Service) Chain(ctx context.Context, o Observation) []ChainLink {
	var out []ChainLink
	for i, ref := range o.Chain {
		fp, inStore := strings.CutPrefix(ref, "root:")
		c, err := s.Certificate(ctx, fp)
		if err != nil {
			continue
		}
		l := ChainLink{Certificate: c, InStore: inStore}
		switch {
		case i == 0:
			l.Role = "leaf"
		case c.SelfSigned:
			l.Role = "root"
		default:
			l.Role = "intermediate"
		}
		// A root's own signature is never checked; its key is.
		l.Weak = isWeak(c) && !(c.SelfSigned && c.IsCA) || c.KeyType == "RSA" && c.KeyBits < 2048
		out = append(out, l)
	}
	markWorst(out)
	return out
}

// MarkStale flags the expired roots sent after a chain that verified, when
// no expired finding says the chain needs them, and moves Worst past them.
func MarkStale(links []ChainLink, verified bool, now int64) {
	if !verified {
		return
	}
	for i := range links {
		l := &links[i]
		l.Stale = i > 0 && l.Role == "root" && !l.InStore && l.NotAfter < now
	}
	markWorst(links)
}

// markWorst flags the presented link that expires first.
func markWorst(out []ChainLink) {
	worst := -1
	for i := range out {
		out[i].Worst = false
		l := out[i]
		if l.InStore || l.Stale {
			continue
		}
		if worst < 0 || l.NotAfter < out[worst].NotAfter {
			worst = i
		}
	}
	if worst >= 0 {
		out[worst].Worst = true
	}
}

func isWeak(c Certificate) bool {
	sa := strings.ToUpper(c.SigAlg)
	return strings.Contains(sa, "SHA1") || strings.Contains(sa, "SHA-1") || strings.Contains(sa, "MD5") || strings.Contains(sa, "MD2") ||
		(c.KeyType == "RSA" && c.KeyBits < 2048)
}

// HistoryEntry is a certificate seen on a target.
type HistoryEntry struct {
	Certificate
	First, Last int64
	Current     bool
}

// History lists the leaf certificates seen on a target, newest first.
func (s *Service) History(ctx context.Context, t Target) ([]HistoryEntry, error) {
	rows, err := s.DB.R.QueryContext(ctx, `SELECT leaf_fp, MIN(checked_at), MAX(checked_at) FROM observations
		WHERE target_id = ? AND leaf_fp != '' GROUP BY leaf_fp ORDER BY MAX(checked_at) DESC, MIN(checked_at) DESC`, t.ID)
	if err != nil {
		return nil, err
	}
	type row struct {
		fp          string
		first, last int64
	}
	var rs []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.fp, &r.first, &r.last); err != nil {
			rows.Close()
			return nil, err
		}
		rs = append(rs, r)
	}
	rows.Close()
	var out []HistoryEntry
	for _, r := range rs {
		c, err := s.Certificate(ctx, r.fp)
		if err != nil {
			continue
		}
		out = append(out, HistoryEntry{Certificate: c, First: r.first, Last: r.last, Current: r.fp == t.CurrentFP})
	}
	return out, nil
}

// Served is a place a certificate is currently served.
type Served struct {
	TargetID   int64
	TargetName string
	HostPort   string
	Address    string
	Status     string
	CheckedAt  int64
	Current    bool // the target's current certificate
	Addresses  int  // addresses of the target in its last check
}

// InventoryItem is one row of the certificate inventory.
type InventoryItem struct {
	Certificate
	Served  []Served
	Targets int
	Stale   bool // served on only some addresses of a target
	Chain   []ChainLink
}

// served returns where leaf certificates are served now, per fingerprint:
// the addresses of every target's latest check. A non-empty fp limits it to
// that certificate.
func (s *Service) served(ctx context.Context, fp string) (map[string][]Served, error) {
	rows, err := s.DB.R.QueryContext(ctx, `SELECT o.leaf_fp, o.target_id, t.name, t.host, t.port, o.address, o.status, o.checked_at, t.current_fp, t.address_count
		FROM targets t JOIN observations o ON o.check_id = t.last_check_id AND o.target_id = t.id
		WHERE o.leaf_fp != '' AND (?1 = '' OR o.leaf_fp = ?1)
		ORDER BY t.name, o.address`, fp)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]Served{}
	for rows.Next() {
		var leaf, cur string
		var sv Served
		var host string
		var port int
		if err := rows.Scan(&leaf, &sv.TargetID, &sv.TargetName, &host, &port, &sv.Address, &sv.Status, &sv.CheckedAt, &cur, &sv.Addresses); err != nil {
			return nil, err
		}
		sv.HostPort = Target{Host: host, Port: port}.HostPort()
		sv.Current = cur == leaf
		out[leaf] = append(out[leaf], sv)
	}
	return out, rows.Err()
}

// ServedOn returns where one certificate is served now.
func (s *Service) ServedOn(ctx context.Context, fp string) ([]Served, error) {
	m, err := s.served(ctx, fp)
	return m[fp], err
}

// Inventory returns every leaf certificate seen, with where it is served now.
func (s *Service) Inventory(ctx context.Context) ([]InventoryItem, error) {
	served, err := s.served(ctx, "")
	if err != nil {
		return nil, err
	}
	crow, err := s.DB.R.QueryContext(ctx, "SELECT "+certListCols+" FROM certificates WHERE fingerprint IN (SELECT DISTINCT leaf_fp FROM observations WHERE leaf_fp != '') ORDER BY not_after")
	if err != nil {
		return nil, err
	}
	defer crow.Close()
	var out []InventoryItem
	for crow.Next() {
		c, err := scanCert(crow)
		if err != nil {
			return nil, err
		}
		it := InventoryItem{Certificate: c, Served: served[c.Fingerprint]}
		tg := map[int64]int{}
		for _, sv := range it.Served {
			tg[sv.TargetID]++
			if !sv.Current {
				it.Stale = true
			}
		}
		it.Targets = len(tg)
		out = append(out, it)
	}
	return out, crow.Err()
}

// InventoryChain returns the chain under which a certificate was last served.
func (s *Service) InventoryChain(ctx context.Context, fp string) []ChainLink {
	var o Observation
	var chain string
	err := s.DB.R.QueryRowContext(ctx, "SELECT chain, verified FROM observations WHERE leaf_fp = ? ORDER BY id DESC LIMIT 1", fp).Scan(&chain, &o.Verified)
	if err != nil {
		return nil
	}
	_ = json.Unmarshal([]byte(chain), &o.Chain)
	return s.Chain(ctx, o)
}
