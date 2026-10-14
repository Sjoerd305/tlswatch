package core

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/sjoerd305/tlswatch/internal/probe"
)

// Bundle is an uploaded set of private roots and intermediates.
type Bundle struct {
	ID        int64
	Name      string
	PEM       string
	Certs     []probe.CertInfo
	CreatedAt int64
	UpdatedAt int64
	Targets   int
}

type bundleCache struct {
	mu    sync.Mutex
	pools map[int64]*x509.CertPool
}

// ParseBundle parses a PEM bundle; it rejects private keys and requires at
// least one certificate.
func ParseBundle(data string) ([]*x509.Certificate, error) {
	rest := []byte(data)
	var certs []*x509.Certificate
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if strings.Contains(b.Type, "PRIVATE KEY") {
			return nil, errors.New("The bundle contains a private key; upload only certificates")
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, errors.New("A certificate in the bundle could not be parsed: " + err.Error())
		}
		certs = append(certs, c)
	}
	if strings.Contains(string(rest), "PRIVATE KEY") {
		return nil, errors.New("The bundle contains a private key; upload only certificates")
	}
	if len(certs) == 0 {
		return nil, errors.New("No PEM certificates found")
	}
	return certs, nil
}

// Bundles lists the CA bundles.
func (s *Service) Bundles(ctx context.Context) ([]Bundle, error) {
	rows, err := s.DB.R.QueryContext(ctx, `SELECT b.id, b.name, b.pem, b.created_at, b.updated_at,
		(SELECT COUNT(*) FROM targets t WHERE t.bundle_id = b.id) FROM ca_bundles b ORDER BY b.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Bundle
	for rows.Next() {
		var b Bundle
		if err := rows.Scan(&b.ID, &b.Name, &b.PEM, &b.CreatedAt, &b.UpdatedAt, &b.Targets); err != nil {
			return nil, err
		}
		certs, _ := ParseBundle(b.PEM)
		for _, c := range certs {
			b.Certs = append(b.Certs, probe.Describe(c))
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// SaveBundle creates (ID 0) or replaces a bundle.
func (s *Service) SaveBundle(ctx context.Context, id int64, name, data string) (int64, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, errors.New("Name is required")
	}
	certs, err := ParseBundle(data)
	if err != nil {
		return 0, err
	}
	var fps []string
	var buf strings.Builder
	for _, c := range certs {
		fps = append(fps, probe.Fingerprint(c))
		buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	fj, _ := json.Marshal(fps)
	now := s.now().Unix()
	if id == 0 {
		res, err := s.DB.W.ExecContext(ctx, "INSERT INTO ca_bundles(name, pem, fingerprints, created_at, updated_at) VALUES(?,?,?,?,?)", name, buf.String(), string(fj), now, now)
		if err != nil {
			return 0, uniqueBundle(err)
		}
		id, _ = res.LastInsertId()
	} else {
		if _, err := s.DB.W.ExecContext(ctx, "UPDATE ca_bundles SET name=?, pem=?, fingerprints=?, updated_at=? WHERE id=?", name, buf.String(), string(fj), now, id); err != nil {
			return 0, uniqueBundle(err)
		}
	}
	s.bundles.mu.Lock()
	delete(s.bundles.pools, id)
	s.bundles.mu.Unlock()
	return id, nil
}

func uniqueBundle(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return errors.New("A bundle with this name already exists")
	}
	return err
}

// ErrBundleInUse is returned when deleting a bundle that targets use.
var ErrBundleInUse = errors.New("The bundle is used by targets; switch them to another trust mode first")

// DeleteBundle removes a bundle; it refuses while targets use it. The check
// and the delete are one statement, so a target saved meanwhile cannot be
// left pointing at nothing.
func (s *Service) DeleteBundle(ctx context.Context, id int64) error {
	res, err := s.DB.W.ExecContext(ctx, "DELETE FROM ca_bundles WHERE id = ?1 AND NOT EXISTS (SELECT 1 FROM targets WHERE bundle_id = ?1)", id)
	if err != nil {
		return err
	}
	s.bundles.mu.Lock()
	delete(s.bundles.pools, id)
	s.bundles.mu.Unlock()
	if n, _ := res.RowsAffected(); n == 0 {
		var exists bool
		if err := s.DB.R.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM ca_bundles WHERE id = ?)", id).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrBundleInUse
		}
		return ErrNotFound
	}
	return nil
}

// BundlePool returns the certificate pool of a bundle. A missing bundle is
// an error: an empty pool would report every chain as untrusted.
func (s *Service) BundlePool(ctx context.Context, id int64) (*x509.CertPool, error) {
	s.bundles.mu.Lock()
	p, ok := s.bundles.pools[id]
	s.bundles.mu.Unlock()
	if ok {
		return p, nil
	}
	var data string
	err := s.DB.R.QueryRowContext(ctx, "SELECT pem FROM ca_bundles WHERE id = ?", id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("CA bundle %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	certs, err := ParseBundle(data)
	if err != nil {
		return nil, err
	}
	p = x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	s.bundles.mu.Lock()
	if s.bundles.pools == nil {
		s.bundles.pools = map[int64]*x509.CertPool{}
	}
	s.bundles.pools[id] = p
	s.bundles.mu.Unlock()
	return p, nil
}

func sortTagCounts(ts []TagCount) {
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].Count != ts[j].Count {
			return ts[i].Count > ts[j].Count
		}
		return ts[i].Tag < ts[j].Tag
	})
}
