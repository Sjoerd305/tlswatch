package core

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/crl"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// CRLEvery is how often one CRL URL is fetched at most. The hour of slack
// keeps a daily fetch on a daily check that starts a few seconds early.
const CRLEvery = 24 * time.Hour

const crlSlack = time.Hour

// CRLPruneAfter is how long a CRL no served leaf names is kept: every URL
// still named is fetched daily, so one not tried for this long is unused.
const CRLPruneAfter = 7 * 24 * time.Hour

// KindCRL is the node job kind that fetches a CRL; a node lists it in its
// facts when it can.
const KindCRL = "crl"

// CanFetchCRL reports whether a node runs a version that fetches CRLs.
func (n Node) CanFetchCRL() bool {
	for _, k := range n.Facts.Kinds {
		if k == KindCRL {
			return true
		}
	}
	return false
}

// NodeCRLFetch fetches a CRL on a node (node.Dispatcher.FetchCRL).
type NodeCRLFetch func(ctx context.Context, nodeID int64, url string) ([]byte, error)

// CRL is the cached state of one CRL URL.
type CRL struct {
	ID          int64
	URL         string
	IssuerKey   string
	ThisUpdate  int64
	NextUpdate  int64
	FetchedAt   int64 // last fetch that verified; 0: never
	AttemptedAt int64
	FailStreak  int
	Error       string
	Entries     int
	Size        int64
	NodeID      int64
	NodeName    string
}

const crlCols = `c.id, c.url, c.issuer_key, c.this_update, c.next_update, c.fetched_at, c.attempted_at, c.fail_streak, c.error,
	c.entries, c.size, COALESCE(c.node_id, 0), COALESCE(n.name, '')`

func scanCRL(r interface{ Scan(...any) error }) (CRL, error) {
	var c CRL
	err := r.Scan(&c.ID, &c.URL, &c.IssuerKey, &c.ThisUpdate, &c.NextUpdate, &c.FetchedAt, &c.AttemptedAt, &c.FailStreak, &c.Error,
		&c.Entries, &c.Size, &c.NodeID, &c.NodeName)
	return c, err
}

// CRLByURL returns the cached state of one CRL URL.
func (s *Service) CRLByURL(ctx context.Context, url string) (CRL, error) {
	c, err := scanCRL(s.DB.R.QueryRowContext(ctx, "SELECT "+crlCols+" FROM crls c LEFT JOIN nodes n ON n.id = c.node_id WHERE c.url = ?", url))
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

// CRLEntry is a serial a CRL lists.
type CRLEntry struct {
	RevokedAt int64
	Reason    string
}

// crlEntry looks a serial up in a cached CRL.
func (s *Service) crlEntry(ctx context.Context, crlID int64, serial string) (CRLEntry, bool, error) {
	var e CRLEntry
	err := s.DB.R.QueryRowContext(ctx, "SELECT revoked_at, reason FROM crl_entries WHERE crl_id = ? AND serial = ?", crlID, serial).
		Scan(&e.RevokedAt, &e.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return e, false, nil
	}
	return e, err == nil, err
}

// crlSerial is a certificate's serial as certificates.serial holds it.
func crlSerial(c *x509.Certificate) string { return fmt.Sprintf("%X", c.SerialNumber) }

// crlRef is one CRL a check needs: the URL a served leaf names and the
// issuer that must have signed it.
type crlRef struct {
	url    string
	issuer *x509.Certificate
}

// crlRefs returns the CRLs of the leaves r served, one per URL.
func crlRefs(r probe.Result) []crlRef {
	var out []crlRef
	seen := map[string]bool{}
	for _, a := range r.Addresses {
		if !a.OK || len(a.Chain) == 0 {
			continue
		}
		u := crl.URL(a.Chain[0])
		if u == "" || seen[u] {
			continue
		}
		if issuer := probe.Issuer(a); issuer != nil {
			seen[u] = true
			out = append(out, crlRef{url: u, issuer: issuer})
		}
	}
	return out
}

// crlLocks serialises the fetches of one URL, so targets sharing a CA's
// CRL that are checked at once fetch it once.
type crlLocks struct {
	mu sync.Mutex
	m  map[string]*sync.Mutex
}

func (l *crlLocks) lock(url string) func() {
	l.mu.Lock()
	if l.m == nil {
		l.m = map[string]*sync.Mutex{}
	}
	m, ok := l.m[url]
	if !ok {
		m = &sync.Mutex{}
		l.m[url] = m
	}
	l.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// RefreshCRLs fetches the CRLs named by the leaves r served whose cached
// copy was last tried a day ago or more, verifies each against the leaf's
// issuer from the served chain and caches the serials it lists. The
// server fetches, also for node targets, since a CRL URL is public by
// design; a node target verified against a CA bundle is a private CA whose
// CRL may be reachable only inside the network, so onNode fetches it
// there. Failures are recorded on the CRL and logged, never returned: the
// check goes on with what is cached.
func (s *Service) RefreshCRLs(ctx context.Context, t Target, r probe.Result, onNode NodeCRLFetch) {
	refs := crlRefs(r)
	if len(refs) == 0 {
		return
	}
	st := s.CurrentSettings(ctx)
	fetch, nodeID := s.serverCRLFetch(st.General.AllowLocal), int64(0)
	if t.NodeID != 0 && t.Trust == probe.TrustBundle && onNode != nil {
		nodeID = t.NodeID
		fetch = func(ctx context.Context, url string) ([]byte, error) { return onNode(ctx, nodeID, url) }
	}
	for _, ref := range refs {
		if err := s.refreshCRL(ctx, ref, fetch, nodeID); err != nil && ctx.Err() == nil && s.Log != nil {
			s.Log.Error("crl", "url", ref.url, "err", err)
		}
	}
}

// serverCRLFetch fetches from this server through the CRL client, which
// refuses loopback and link-local addresses as targets are refused.
func (s *Service) serverCRLFetch(allowLocal bool) func(context.Context, string) ([]byte, error) {
	client := s.CRLClient
	if client == nil {
		var allow func(net.IP) error
		if !allowLocal {
			allow = func(ip net.IP) error {
				if probe.IsLocalIP(ip) {
					return errors.New("loopback and link-local addresses are not fetched")
				}
				return nil
			}
		}
		client = crl.NewClient(allow)
	}
	return func(ctx context.Context, url string) ([]byte, error) { return crl.Fetch(ctx, client, url) }
}

func (s *Service) refreshCRL(ctx context.Context, ref crlRef, fetch func(context.Context, string) ([]byte, error), nodeID int64) error {
	unlock := s.crls.lock(ref.url)
	defer unlock()
	key := probe.KeyID(ref.issuer)
	old, err := s.CRLByURL(ctx, ref.url)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return err
	case s.now().Sub(time.Unix(old.AttemptedAt, 0)) < CRLEvery-crlSlack:
		return nil
	}
	data, err := fetch(ctx, ref.url)
	if ctx.Err() != nil {
		return ctx.Err() // stopped, not failed
	}
	var rl *x509.RevocationList
	if err == nil {
		rl, err = crl.Check(data, ref.issuer, ref.url)
	}
	if err == nil && old.FetchedAt > 0 && old.IssuerKey == key && rl.ThisUpdate.Unix() < old.ThisUpdate {
		err = fmt.Errorf("issued %s, older than the copy held", rl.ThisUpdate.UTC().Format(time.DateOnly))
	}
	if err != nil {
		if s.Log != nil {
			s.Log.Warn("crl not usable", "url", ref.url, "node_id", nodeID, "err", err)
		}
		return s.crlFailed(ctx, ref.url, key, nodeID, err)
	}
	return s.storeCRL(ctx, ref.url, key, nodeID, rl, len(data))
}

// crlFailed records a fetch that failed; the serials held stay. A URL
// never fetched takes the issuer of this attempt, so revocation_unknown
// can name it.
func (s *Service) crlFailed(ctx context.Context, url, key string, nodeID int64, cause error) error {
	_, err := s.DB.W.ExecContext(ctx, `INSERT INTO crls(url, issuer_key, attempted_at, fail_streak, error, node_id) VALUES(?,?,?,1,?,?)
		ON CONFLICT(url) DO UPDATE SET attempted_at = excluded.attempted_at, fail_streak = fail_streak + 1, error = excluded.error,
			node_id = excluded.node_id, issuer_key = CASE WHEN fetched_at = 0 THEN excluded.issuer_key ELSE issuer_key END`,
		url, key, s.now().Unix(), Clip(cause.Error(), TextMax), nullID(nodeID))
	return err
}

// storeCRL caches a verified CRL. One with the same issue time as the copy
// held only marks the fetch; another replaces the serials.
func (s *Service) storeCRL(ctx context.Context, url, key string, nodeID int64, rl *x509.RevocationList, size int) error {
	now := s.now().Unix()
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id, thisUpdate int64
	var oldKey string
	err = tx.QueryRowContext(ctx, "SELECT id, this_update, issuer_key FROM crls WHERE url = ?", url).Scan(&id, &thisUpdate, &oldKey)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	same := err == nil && thisUpdate == rl.ThisUpdate.Unix() && oldKey == key
	if _, err := tx.ExecContext(ctx, `INSERT INTO crls(url, issuer_key, this_update, next_update, fetched_at, attempted_at, fail_streak, error, entries, size, node_id)
		VALUES(?,?,?,?,?,?,0,'',?,?,?)
		ON CONFLICT(url) DO UPDATE SET issuer_key = excluded.issuer_key, this_update = excluded.this_update, next_update = excluded.next_update,
			fetched_at = excluded.fetched_at, attempted_at = excluded.attempted_at, fail_streak = 0, error = '', entries = excluded.entries,
			size = excluded.size, node_id = excluded.node_id`,
		url, key, rl.ThisUpdate.Unix(), rl.NextUpdate.Unix(), now, now, len(rl.RevokedCertificateEntries), size, nullID(nodeID)); err != nil {
		return err
	}
	if !same {
		if err := tx.QueryRowContext(ctx, "SELECT id FROM crls WHERE url = ?", url).Scan(&id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM crl_entries WHERE crl_id = ?", id); err != nil {
			return err
		}
		ins, err := tx.PrepareContext(ctx, "INSERT OR REPLACE INTO crl_entries(crl_id, serial, revoked_at, reason) VALUES(?,?,?,?)")
		if err != nil {
			return err
		}
		defer ins.Close()
		for _, e := range rl.RevokedCertificateEntries {
			if _, err := ins.ExecContext(ctx, id, fmt.Sprintf("%X", e.SerialNumber), e.RevocationTime.Unix(), crl.Reason(e.ReasonCode)); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// crlStatus says what the cached CRLs hold of each leaf r served, by
// fingerprint, for the checks. A CRL verified against another issuer key
// than the leaf's says nothing of it.
func (s *Service) crlStatus(ctx context.Context, r probe.Result) (map[string]check.CRLStatus, error) {
	out := map[string]check.CRLStatus{}
	for _, a := range r.Addresses {
		if !a.OK || len(a.Chain) == 0 {
			continue
		}
		leaf := a.Chain[0]
		fp := probe.Fingerprint(leaf)
		u := crl.URL(leaf)
		if _, done := out[fp]; done || u == "" {
			continue
		}
		issuer := probe.Issuer(a)
		if issuer == nil {
			continue
		}
		c, err := s.CRLByURL(ctx, u)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if c.IssuerKey != probe.KeyID(issuer) {
			continue
		}
		st := check.CRLStatus{URL: u}
		if c.FailStreak >= check.UnknownAfter {
			st.Unknown = c.Error
		}
		if c.FetchedAt > 0 {
			e, listed, err := s.crlEntry(ctx, c.ID, crlSerial(leaf))
			if err != nil {
				return nil, err
			}
			if listed {
				st.Revoked, st.RevokedAt, st.Reason = true, time.Unix(e.RevokedAt, 0), e.Reason
			}
		}
		out[fp] = st
	}
	return out, nil
}

// Revocation is what the target page shows of its current leaf's
// revocation status.
type Revocation struct {
	URL     string // the CRL distribution point; "" when the leaf names none
	CRL     *CRL   // nil: not fetched yet
	Listed  bool
	Entry   CRLEntry
	Stapled string // the OCSP status the current leaf's address stapled, "" for none
}

// TargetRevocation returns the revocation status of a target's current
// leaf from the cache and its last check.
func (s *Service) TargetRevocation(ctx context.Context, t Target, last []Observation) (Revocation, error) {
	var rv Revocation
	for _, o := range last {
		if o.LeafFP == t.CurrentFP && o.OCSP != "" {
			rv.Stapled = o.OCSP
			break
		}
	}
	if t.CurrentFP == "" {
		return rv, nil
	}
	c, err := s.Certificate(ctx, t.CurrentFP)
	if err != nil {
		return rv, err
	}
	b, _ := pem.Decode([]byte(c.PEM))
	if b == nil {
		return rv, nil
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return rv, nil
	}
	if rv.URL = crl.URL(leaf); rv.URL == "" {
		return rv, nil
	}
	cached, err := s.CRLByURL(ctx, rv.URL)
	if errors.Is(err, ErrNotFound) {
		return rv, nil
	}
	if err != nil {
		return rv, err
	}
	rv.CRL = &cached
	if cached.FetchedAt > 0 {
		rv.Entry, rv.Listed, err = s.crlEntry(ctx, cached.ID, crlSerial(leaf))
	}
	return rv, err
}

// pruneCRLs removes the CRLs no served leaf has named for CRLPruneAfter.
func (s *Service) pruneCRLs(ctx context.Context) error {
	_, err := s.DB.W.ExecContext(ctx, "DELETE FROM crls WHERE attempted_at < ?", s.now().Add(-CRLPruneAfter).Unix())
	return err
}
