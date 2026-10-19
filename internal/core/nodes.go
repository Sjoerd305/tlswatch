package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/secret"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// Node states.
const (
	NodeEnrolling = "enrolling" // an install token is out, no credential yet
	NodePending   = "pending"   // enrolled, waiting for an admin to confirm its facts
	NodeConfirmed = "confirmed" // may take targets
)

// NodeTokenTTL is how long an install token, and an unconfirmed node, live.
const NodeTokenTTL = time.Hour

// Errors of the node dispatcher, shared with the scheduler.
var (
	// ErrNodeOffline: the node has not polled within the offline window,
	// or is disabled or unconfirmed; its targets are held, not failed.
	ErrNodeOffline = errors.New("the node is offline")
	// ErrNodeNoResult: the node leased the job twice and never answered.
	ErrNodeNoResult = errors.New("no result from the node")
	// ErrNodesPaused: a restore runs and the dispatcher dropped the job.
	ErrNodesPaused = errors.New("nodes are paused while a backup is restored")
)

// ErrNodeInUse refuses to delete a node that targets are probed from.
var ErrNodeInUse = usererr.New("Targets are still probed from this node; move them first")

// NodeFacts are what a node reports about the machine it runs on, for
// identification and support.
type NodeFacts struct {
	Hostname   string          `json:"hostname"`
	OS         string          `json:"os"`
	Kernel     string          `json:"kernel"`
	Arch       string          `json:"arch"` // GOOS/GOARCH
	Container  bool            `json:"container"`
	Version    string          `json:"version"`
	Interfaces []NodeInterface `json:"interfaces"`
	IPv6Route  bool            `json:"ipv6_route"`
	// Kinds are the job kinds the node runs; empty for nodes from before
	// the list, which run probe, cancel and update.
	Kinds []string `json:"kinds,omitempty"`
	// ClockOffsetMS is the node's clock minus the server's, computed by
	// the server when the facts arrive.
	ClockOffsetMS int64 `json:"clock_offset_ms"`
	// Limits are what the node allows itself to probe; nil for nodes from
	// before the report.
	Limits *NodeLimits `json:"limits,omitempty"`
}

// NodeLimits are the node-side bounds on what it probes, reported so an
// admin sees whether a node is restricted. They are set on the node only;
// the server shows them and cannot change them.
type NodeLimits struct {
	Allow      []string `json:"allow"` // CIDRs; empty means any address
	AllowLocal bool     `json:"allow_local"`
	// From is where the allowlist was read: NodeLimitsFlag or
	// NodeLimitsEnv.
	From string `json:"from"`
	// EnvFile is the environment file systemd started the node with, when
	// it did.
	EnvFile string `json:"env_file,omitempty"`
}

// Where a node's allowlist was read.
const (
	NodeLimitsFlag = "flag" // the -allow flag
	NodeLimitsEnv  = "env"  // TLSWATCH_NODE_ALLOW
)

// AllowText is the allowlist for the audit log.
func (l *NodeLimits) AllowText() string {
	switch {
	case l == nil:
		return "unreported"
	case len(l.Allow) == 0:
		return "any"
	}
	return strings.Join(l.Allow, ",")
}

// NodeInterface is one non-loopback interface with its addresses (CIDR).
type NodeInterface struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
}

// Limits on what a node may report: facts and headers come from a machine
// the server does not control, and they are stored, audited and shown.
const (
	ShortMax      = 128 // hostname, OS, kernel, arch, version, interface name
	TextMax       = 300 // an error message
	addrMax       = 64  // addresses per interface
	interfacesMax = 64
	allowMax      = 256 // allowlist entries
)

// Clip cuts s to at most n bytes, on a rune boundary, and drops control
// characters other than the tab.
func Clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && cut < len(s) && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// Clipped returns the facts within the limits.
func (f NodeFacts) Clipped() NodeFacts {
	f.Hostname, f.OS, f.Kernel, f.Arch, f.Version = Clip(f.Hostname, ShortMax), Clip(f.OS, ShortMax), Clip(f.Kernel, ShortMax), Clip(f.Arch, ShortMax), Clip(f.Version, ShortMax)
	if len(f.Interfaces) > interfacesMax {
		f.Interfaces = f.Interfaces[:interfacesMax]
	}
	out := make([]NodeInterface, 0, len(f.Interfaces))
	for _, i := range f.Interfaces {
		i.Name = Clip(i.Name, ShortMax)
		if len(i.Addrs) > addrMax {
			i.Addrs = i.Addrs[:addrMax]
		}
		addrs := make([]string, 0, len(i.Addrs))
		for _, a := range i.Addrs {
			addrs = append(addrs, Clip(a, ShortMax))
		}
		i.Addrs = addrs
		out = append(out, i)
	}
	f.Interfaces = out
	if len(f.Kinds) > interfacesMax {
		f.Kinds = f.Kinds[:interfacesMax]
	}
	for i, k := range f.Kinds {
		f.Kinds[i] = Clip(k, ShortMax)
	}
	if f.Limits != nil {
		l := *f.Limits
		if len(l.Allow) > allowMax {
			l.Allow = l.Allow[:allowMax]
		}
		allow := make([]string, 0, len(l.Allow))
		for _, a := range l.Allow {
			allow = append(allow, Clip(a, ShortMax))
		}
		l.Allow, l.From, l.EnvFile = allow, Clip(l.From, ShortMax), Clip(l.EnvFile, ShortMax)
		f.Limits = &l
	}
	return f
}

// addrSet is every address of the interfaces but the link-local ones,
// sorted, for change detection.
func (f NodeFacts) addrSet() []string {
	var out []string
	for _, i := range f.Interfaces {
		for _, a := range i.Addrs {
			// Link-local addresses come and go with interfaces (container
			// veths, privacy addresses) and say nothing about where the
			// node is.
			if p, err := netip.ParsePrefix(a); err == nil && p.Addr().IsLinkLocalUnicast() {
				continue
			}
			out = append(out, a)
		}
	}
	slices.Sort(out)
	return out
}

// Node is a probe worker inside another network.
type Node struct {
	ID            int64
	Name          string
	State         string
	CreatedAt     int64
	CreatedBy     string
	EnrolledAt    int64
	ConfirmedAt   int64
	ConfirmedBy   string
	LastSeen      int64
	Version       string
	Protocol      int
	Address       string // as the server sees it
	PoolSize      int
	Enabled       bool
	Notes         string
	Facts         NodeFacts
	FactsAt       int64
	TokenExpires  int64
	HasCredential bool

	UpdateRequested int64  // an admin pressed Update
	UpdateStarted   int64  // an update job was sent and has not come back yet
	UpdateFrom      string // versions of the running or last update
	UpdateTo        string
	UpdateFailed    string // why the last update failed; empty once one succeeds

	Targets int // targets probed from the node
}

// Label is the node's name, its hostname while it has none, or its number.
func (n Node) Label() string {
	switch {
	case n.Name != "":
		return n.Name
	case n.Facts.Hostname != "":
		return n.Facts.Hostname
	}
	return fmt.Sprintf("node %d", n.ID)
}

// Assignable reports whether targets may be probed from the node.
func (n Node) Assignable() bool { return n.State == NodeConfirmed }

const nodeCols = `n.id, n.name, n.state, n.created_at, n.created_by, n.enrolled_at, n.confirmed_at, n.confirmed_by, n.last_seen,
	n.version, n.protocol, n.address, n.pool_size, n.enabled, n.notes, n.facts, n.facts_at, n.token_expires, n.credential_hash != '',
	n.update_requested, n.update_started, n.update_from, n.update_to, n.update_failed,
	(SELECT COUNT(*) FROM targets t WHERE t.node_id = n.id)`

func scanNode(r interface{ Scan(...any) error }) (Node, error) {
	var n Node
	var facts string
	err := r.Scan(&n.ID, &n.Name, &n.State, &n.CreatedAt, &n.CreatedBy, &n.EnrolledAt, &n.ConfirmedAt, &n.ConfirmedBy, &n.LastSeen,
		&n.Version, &n.Protocol, &n.Address, &n.PoolSize, &n.Enabled, &n.Notes, &facts, &n.FactsAt, &n.TokenExpires, &n.HasCredential,
		&n.UpdateRequested, &n.UpdateStarted, &n.UpdateFrom, &n.UpdateTo, &n.UpdateFailed, &n.Targets)
	if err != nil {
		return n, err
	}
	_ = json.Unmarshal([]byte(facts), &n.Facts)
	return n, nil
}

// Nodes lists every node: pending ones first, then those waiting for their
// install command to run, then the confirmed ones by name.
func (s *Service) Nodes(ctx context.Context) ([]Node, error) {
	rows, err := s.DB.R.QueryContext(ctx, "SELECT "+nodeCols+` FROM nodes n
		ORDER BY CASE n.state WHEN 'pending' THEN 0 WHEN 'enrolling' THEN 1 ELSE 2 END, lower(n.name), n.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// Node returns one node.
func (s *Service) Node(ctx context.Context, id int64) (Node, error) {
	n, err := scanNode(s.DB.R.QueryRowContext(ctx, "SELECT "+nodeCols+" FROM nodes n WHERE n.id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return n, ErrNotFound
	}
	return n, err
}

// NodeByCredential returns the node holding a credential.
func (s *Service) NodeByCredential(ctx context.Context, raw string) (Node, error) {
	if raw == "" {
		return Node{}, ErrNotFound
	}
	n, err := scanNode(s.DB.R.QueryRowContext(ctx, "SELECT "+nodeCols+" FROM nodes n WHERE n.credential_hash = ?", hashSecret(raw)))
	if errors.Is(err, sql.ErrNoRows) {
		return n, ErrNotFound
	}
	return n, err
}

// NodeTargets returns the targets probed from a node.
func (s *Service) NodeTargets(ctx context.Context, id int64) ([]Target, error) {
	return s.queryTargets(ctx, "t.node_id = ?", 0, id)
}

func hashSecret(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func newSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// assignableNodeTx refuses a node that targets may not be probed from.
func assignableNodeTx(ctx context.Context, tx *sql.Tx, id int64) error {
	var state string
	err := tx.QueryRowContext(ctx, "SELECT state FROM nodes WHERE id = ?", id).Scan(&state)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return usererr.New("The chosen node no longer exists")
	case err != nil:
		return err
	case state != NodeConfirmed:
		return usererr.New("The chosen node is not confirmed yet; confirm it under Settings › Nodes first")
	}
	return nil
}

// CreateNode starts the enrolment of a new node: a node in state enrolling
// with a one-time install token valid for NodeTokenTTL. The token is
// returned once and kept as a hash, and sealed for the Add node screen.
func (s *Service) CreateNode(ctx context.Context, user string) (int64, string, error) {
	now := s.now()
	tok := newSecret()
	res, err := s.DB.W.ExecContext(ctx, `INSERT INTO nodes(state, token_hash, token_sealed, token_expires, created_at, created_by, updated_at)
		VALUES(?,?,?,?,?,?,?)`, NodeEnrolling, hashSecret(tok), s.sealToken(tok), now.Add(NodeTokenTTL).Unix(), now.Unix(), user, now.Unix())
	if err != nil {
		return 0, "", err
	}
	id, err := res.LastInsertId()
	return id, tok, err
}

// RenewNodeToken revokes a node's credential at once and gives it a new
// install token; running the install command with it enrols the machine
// again, after which an admin confirms it as for a new node.
func (s *Service) RenewNodeToken(ctx context.Context, id int64) (string, error) {
	now := s.now()
	tok := newSecret()
	res, err := s.DB.W.ExecContext(ctx, `UPDATE nodes SET credential_hash = '', token_hash = ?, token_sealed = ?, token_expires = ?, updated_at = ?
		WHERE id = ?`, hashSecret(tok), s.sealToken(tok), now.Add(NodeTokenTTL).Unix(), now.Unix(), id)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	return tok, nil
}

func (s *Service) sealToken(tok string) []byte {
	if s.Key == nil {
		return nil
	}
	return s.Key.Seal(tokenContext, []byte(tok))
}

// tokenContext names where install tokens live, for Seal.
const tokenContext = "nodes.token_sealed"

// ReencryptNodeTokens re-seals the unspent install tokens from old to new
// within tx, for a key rotation or a restore. A token old cannot open is
// dropped: its node shows no install command until a new token is made.
func ReencryptNodeTokens(ctx context.Context, tx *sql.Tx, old, new *secret.Key) (n int, err error) {
	rows, err := tx.QueryContext(ctx, "SELECT id, token_sealed FROM nodes WHERE token_sealed IS NOT NULL")
	if err != nil {
		return 0, err
	}
	type row struct {
		id   int64
		blob []byte
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.blob); err != nil {
			rows.Close()
			return 0, err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, r := range all {
		pt, err := old.Open(tokenContext, r.blob)
		if err != nil {
			if _, err := tx.ExecContext(ctx, "UPDATE nodes SET token_sealed = NULL WHERE id = ?", r.id); err != nil {
				return n, err
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, "UPDATE nodes SET token_sealed = ? WHERE id = ?", new.Seal(tokenContext, pt), r.id); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// NodeToken returns a node's unspent install token, or "" when it has none,
// it expired, or it cannot be read back.
func (s *Service) NodeToken(ctx context.Context, id int64) (string, error) {
	var sealed []byte
	var expires int64
	err := s.DB.R.QueryRowContext(ctx, "SELECT token_sealed, token_expires FROM nodes WHERE id = ? AND token_hash != ''", id).Scan(&sealed, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil || expires <= s.now().Unix() || s.Key == nil || len(sealed) == 0 {
		return "", err
	}
	pt, err := s.Key.Open(tokenContext, sealed)
	if err != nil {
		return "", nil
	}
	return string(pt), nil
}

// ValidNodeToken reports whether an install token is unspent and
// unexpired, for serving its install script.
func (s *Service) ValidNodeToken(ctx context.Context, token string) (bool, error) {
	if token == "" {
		return false, nil
	}
	var n int
	err := s.DB.R.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes WHERE token_hash = ? AND token_expires > ?", hashSecret(token), s.now().Unix()).Scan(&n)
	return n > 0, err
}

// NodesArriving reports whether an enrolment is under way: an unspent,
// unexpired install token, or a machine waiting for confirmation. The live
// pages poll quickly meanwhile, so the Add node screen shows the machine
// as it enrols.
func (s *Service) NodesArriving(ctx context.Context) (bool, error) {
	var n int
	err := s.DB.R.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes WHERE (token_hash != '' AND token_expires > ?) OR state = ?",
		s.now().Unix(), NodePending).Scan(&n)
	return n > 0, err
}

// Enrolment is what a node sends with its install token.
type Enrolment struct {
	Facts    NodeFacts
	Pool     int
	Version  string
	Protocol int
	Address  string // as the server sees it
}

// ErrBadToken refuses an unknown, spent or expired install token.
var ErrBadToken = errors.New("the install token is unknown, spent or expired")

// EnrolNode spends an install token: the node gets a credential, returned
// once and kept as a hash, and waits in state pending for an admin to
// confirm the facts it reported.
func (s *Service) EnrolNode(ctx context.Context, token string, e Enrolment) (Node, string, error) {
	now := s.now().Unix()
	cred := newSecret()
	e.Facts = e.Facts.Clipped()
	e.Version = Clip(e.Version, ShortMax)
	facts, _ := json.Marshal(e.Facts)
	pool := e.Pool
	if pool < 1 || pool > 64 {
		pool = 4
	}
	res, err := s.DB.W.ExecContext(ctx, `UPDATE nodes SET state = ?, credential_hash = ?, token_hash = '', token_sealed = NULL, token_expires = 0,
		enrolled_at = ?, last_seen = ?, version = ?, protocol = ?, address = ?, pool_size = ?, facts = ?, facts_at = ?,
		update_started = 0, update_requested = 0, updated_at = ?
		WHERE token_hash = ? AND token_hash != '' AND token_expires > ?`,
		NodePending, hashSecret(cred), now, now, e.Version, e.Protocol, e.Address, pool, string(facts), now, now, hashSecret(token), now)
	if err != nil {
		return Node{}, "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Node{}, "", ErrBadToken
	}
	n, err := s.NodeByCredential(ctx, cred)
	if err != nil {
		return n, "", err
	}
	s.Audit(ctx, "", "node.enrol", nodeObject(n), fmt.Sprintf("hostname=%s address=%s os=%s version=%s", e.Facts.Hostname, e.Address, e.Facts.OS, e.Version))
	return n, cred, nil
}

func nodeObject(n Node) string { return fmt.Sprintf("node %d %s", n.ID, n.Label()) }

// ConfirmNode accepts a pending node under a name; it may take targets now.
func (s *Service) ConfirmNode(ctx context.Context, id int64, name, user string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return usererr.New("Give the node a name")
	}
	if len(name) > 80 {
		return usererr.New("The name is limited to 80 characters")
	}
	now := s.now().Unix()
	res, err := s.DB.W.ExecContext(ctx, "UPDATE nodes SET state = ?, name = ?, confirmed_at = ?, confirmed_by = ?, updated_at = ? WHERE id = ? AND state = ?",
		NodeConfirmed, name, now, user, now, id, NodePending)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return usererr.New("The node is not waiting for confirmation")
	}
	return nil
}

// RejectNode refuses a pending node, revoking its credential: a node that
// was never confirmed is deleted, one that was (and enrolled again) keeps
// its targets and waits for another install command.
func (s *Service) RejectNode(ctx context.Context, id int64) error {
	n, err := s.Node(ctx, id)
	if err != nil {
		return err
	}
	confirmed := usererr.New("The node is already confirmed")
	if n.State == NodeConfirmed {
		return confirmed
	}
	// The state is checked again in the write: a Confirm in between wins,
	// and the node is not deleted or revoked under it.
	var res sql.Result
	if n.ConfirmedAt == 0 {
		res, err = s.DB.W.ExecContext(ctx, "DELETE FROM nodes WHERE id = ? AND state != ? AND confirmed_at = 0", id, NodeConfirmed)
	} else {
		res, err = s.DB.W.ExecContext(ctx, "UPDATE nodes SET state = ?, credential_hash = '', updated_at = ? WHERE id = ? AND state != ?",
			NodeConfirmed, s.now().Unix(), id, NodeConfirmed)
	}
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return confirmed
	}
	return nil
}

// SaveNode changes a node's name and notes.
func (s *Service) SaveNode(ctx context.Context, id int64, name, notes string) error {
	name, notes = strings.TrimSpace(name), strings.TrimSpace(strings.ReplaceAll(notes, "\r\n", "\n"))
	switch {
	case name == "":
		return usererr.New("Give the node a name")
	case len(name) > 80:
		return usererr.New("The name is limited to 80 characters")
	case len(notes) > 4000:
		return usererr.New("Notes are limited to 4000 characters")
	}
	res, err := s.DB.W.ExecContext(ctx, "UPDATE nodes SET name = ?, notes = ?, updated_at = ? WHERE id = ?", name, notes, s.now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetNodeEnabled enables or disables a node. A disabled node receives no
// jobs and holds its targets as when offline, without a finding: an open
// node_offline finding resolves without a recovery notice.
func (s *Service) SetNodeEnabled(ctx context.Context, id int64, enabled bool) error {
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now().Unix()
	res, err := tx.ExecContext(ctx, "UPDATE nodes SET enabled = ?, updated_at = ? WHERE id = ?", enabled, now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if !enabled {
		if _, err := tx.ExecContext(ctx, "UPDATE findings SET resolved_at = ? WHERE node_id = ? AND resolved_at = 0", now, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteNode removes a node with its findings. It is refused while targets
// are probed from it, unless move is set: then they move to this server
// first, as when their "Probe from" is changed.
func (s *Service) DeleteNode(ctx context.Context, id int64, move bool) error {
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM targets WHERE node_id = ?", id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		if !move {
			return ErrNodeInUse
		}
		if err := newVantageTx(ctx, tx, "node_id = ?", id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE targets SET node_id = NULL, updated_at = ? WHERE node_id = ?", s.now().Unix(), id); err != nil {
			return err
		}
	}
	res, err := tx.ExecContext(ctx, "DELETE FROM nodes WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// TouchNode records a request from a node: when, its version and protocol,
// and the address the server sees it from. A failed update is forgotten
// once the node runs another version than the one it failed from: it was
// updated some other way (reinstalled, or a container pulled).
func (s *Service) TouchNode(ctx context.Context, id int64, seen time.Time, version string, protocol int, addr string) error {
	_, err := s.DB.W.ExecContext(ctx, `UPDATE nodes SET last_seen = ?1, version = ?2, protocol = ?3, address = ?4,
		update_failed = CASE WHEN update_started = 0 AND update_from != ?2 THEN '' ELSE update_failed END WHERE id = ?5`,
		seen.Unix(), version, protocol, addr, id)
	return err
}

// SaveNodeFacts stores the facts a node reported. A changed hostname, set
// of addresses or allowlist goes to the audit log with the old and new values, so a
// node that moved or was cloned shows.
func (s *Service) SaveNodeFacts(ctx context.Context, n Node, f NodeFacts) error {
	f = f.Clipped()
	b, _ := json.Marshal(f)
	if _, err := s.DB.W.ExecContext(ctx, "UPDATE nodes SET facts = ?, facts_at = ? WHERE id = ?", string(b), s.now().Unix(), n.ID); err != nil {
		return err
	}
	old := n.Facts
	var changes []string
	if old.Hostname != f.Hostname {
		changes = append(changes, fmt.Sprintf("hostname %s → %s", old.Hostname, f.Hostname))
	}
	if oa, na := old.addrSet(), f.addrSet(); !slices.Equal(oa, na) {
		changes = append(changes, fmt.Sprintf("addresses %s → %s", strings.Join(oa, ","), strings.Join(na, ",")))
	}
	// A node that reported before and now probes more, or less, shows; the
	// first report after an update does not count as a change.
	if old.Limits != nil {
		if oa, na := old.Limits.AllowText(), f.Limits.AllowText(); oa != na {
			changes = append(changes, fmt.Sprintf("allowlist %s → %s", oa, na))
		}
		if f.Limits != nil && old.Limits.AllowLocal != f.Limits.AllowLocal {
			changes = append(changes, fmt.Sprintf("local addresses %t → %t", old.Limits.AllowLocal, f.Limits.AllowLocal))
		}
	}
	if len(changes) > 0 {
		s.Audit(ctx, "", "node.facts", nodeObject(n), strings.Join(changes, "; "))
	}
	return nil
}

// ExpireNodes removes what enrolment left behind after NodeTokenTTL: a
// new node whose install command never ran, or that was never confirmed,
// is deleted with its credential; a confirmed node's unspent token is
// dropped, and one that enrolled again but was not confirmed has its new
// credential revoked.
func (s *Service) ExpireNodes(ctx context.Context) error {
	now := s.now().Unix()
	cut := s.now().Add(-NodeTokenTTL).Unix()
	_, err := s.DB.W.ExecContext(ctx, `DELETE FROM nodes WHERE confirmed_at = 0 AND
		((state = 'enrolling' AND token_expires <= ?) OR (state = 'pending' AND enrolled_at <= ?))
		AND NOT EXISTS (SELECT 1 FROM targets t WHERE t.node_id = nodes.id)`, now, cut)
	if err != nil {
		return err
	}
	if _, err := s.DB.W.ExecContext(ctx, `UPDATE nodes SET token_hash = '', token_sealed = NULL, token_expires = 0
		WHERE token_hash != '' AND token_expires <= ? AND confirmed_at > 0`, now); err != nil {
		return err
	}
	_, err = s.DB.W.ExecContext(ctx, `UPDATE nodes SET state = 'confirmed', credential_hash = ''
		WHERE state = 'pending' AND confirmed_at > 0 AND enrolled_at <= ?`, cut)
	return err
}

// RequestNodeUpdate asks for a node to be updated to the server's version
// on its next turn; id 0 asks for every node.
func (s *Service) RequestNodeUpdate(ctx context.Context, id int64) error {
	now := s.now().Unix()
	if id == 0 {
		_, err := s.DB.W.ExecContext(ctx, "UPDATE nodes SET update_requested = ?, update_failed = '' WHERE state = 'confirmed'", now)
		return err
	}
	res, err := s.DB.W.ExecContext(ctx, "UPDATE nodes SET update_requested = ?, update_failed = '' WHERE id = ?", now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// StartNodeUpdate records that an update job went out to a node.
func (s *Service) StartNodeUpdate(ctx context.Context, n Node, to string) error {
	_, err := s.DB.W.ExecContext(ctx, "UPDATE nodes SET update_started = ?, update_from = ?, update_to = ?, update_requested = 0 WHERE id = ?",
		s.now().Unix(), n.Version, to, n.ID)
	if err == nil {
		s.Audit(ctx, "", "node.update", nodeObject(n), fmt.Sprintf("from=%s to=%s", n.Version, to))
	}
	return err
}

// EndNodeUpdate records the outcome of a node's update: failure is empty
// when it came back on the new version.
func (s *Service) EndNodeUpdate(ctx context.Context, n Node, failure string) error {
	failure = Clip(failure, TextMax)
	_, err := s.DB.W.ExecContext(ctx, "UPDATE nodes SET update_started = 0, update_failed = ? WHERE id = ?", failure, n.ID)
	if err != nil {
		return err
	}
	if failure != "" {
		s.Audit(ctx, "", "node.update_failed", nodeObject(n), fmt.Sprintf("from=%s to=%s: %s", n.UpdateFrom, n.UpdateTo, failure))
	} else {
		s.Audit(ctx, "", "node.updated", nodeObject(n), fmt.Sprintf("from=%s to=%s", n.UpdateFrom, n.Version))
	}
	return nil
}

// NodeOverdue reports whether a target probed from the node is overdue by
// more than its own interval.
func (s *Service) NodeOverdue(ctx context.Context, id int64) (bool, error) {
	ts, err := s.queryTargets(ctx, "t.node_id = ? AND t.enabled = 1 AND t.next_check > 0", 0, id)
	if err != nil {
		return false, err
	}
	st := s.CurrentSettings(ctx)
	now := s.now().Unix()
	for _, t := range ts {
		if now > t.NextCheck+int64(t.Effective(st.Defaults).IntervalS) {
			return true, nil
		}
	}
	return false, nil
}

// NodeOffline opens, updates or escalates the node_offline finding of a
// node that has not been seen since lastSeen: a warning, critical once one
// of its targets is overdue by more than its interval. Alerts go to every
// enabled channel whose floor the severity meets.
func (s *Service) NodeOffline(ctx context.Context, n Node, lastSeen time.Time) error {
	overdue, err := s.NodeOverdue(ctx, n.ID)
	if err != nil {
		return err
	}
	cf := check.Finding{Kind: check.NodeOffline, Severity: check.Warning}
	if lastSeen.IsZero() {
		cf.Details = "The node has not contacted the server since it started"
	} else {
		cf.Details = fmt.Sprintf("No contact since %s", lastSeen.In(s.CurrentSettings(ctx).Location()).Format("2006-01-02 15:04"))
	}
	// Only enabled targets wait; a disabled one is not checked anyway.
	var waiting int
	if err := s.DB.R.QueryRowContext(ctx, "SELECT COUNT(*) FROM targets WHERE node_id = ? AND enabled = 1", n.ID).Scan(&waiting); err != nil {
		return err
	}
	if waiting > 0 {
		cf.Details += "; " + plural(waiting, "1 target waits", fmt.Sprintf("%d targets wait", waiting)) + " for it"
	}
	if overdue {
		cf.Severity = check.Critical
		cf.Details += ", one is overdue by more than its interval"
	}
	st := s.CurrentSettings(ctx)
	chans, err := s.Channels.Enabled(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	al := s.nodeAlerter(tx, st, n, chans, now)
	old, err := scanFinding(tx.QueryRowContext(ctx, "SELECT "+findingCols+" FROM findings f WHERE f.node_id = ? AND f.kind = ? AND f.resolved_at = 0", n.ID, string(check.NodeOffline)))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, err := tx.ExecContext(ctx, `INSERT INTO findings(node_id, kind, severity, opened_at, details, last_alert_at) VALUES(?,?,?,?,?,?)`,
			n.ID, string(cf.Kind), string(cf.Severity), now.Unix(), cf.Details, now.Unix())
		if err != nil {
			return err
		}
		f := Finding{NodeID: n.ID, Kind: cf.Kind, Severity: cf.Severity, Details: cf.Details, OpenedAt: now.Unix()}
		f.ID, _ = res.LastInsertId()
		if err := al.send(ctx, f, notify.EventOpen); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		if _, err := tx.ExecContext(ctx, "UPDATE findings SET severity = ?, details = ? WHERE id = ?", string(cf.Severity), cf.Details, old.ID); err != nil {
			return err
		}
		if cf.Severity.Rank() > old.Severity.Rank() {
			old.Severity, old.Details = cf.Severity, cf.Details
			if err := al.send(ctx, old, notify.EventEscalate); err != nil {
				return err
			}
			// An acknowledgement covers the severity it was given for.
			if _, err := tx.ExecContext(ctx, "UPDATE findings SET last_alert_at = ?, ack_by = '', ack_at = 0, ack_until = 0, ack_comment = '' WHERE id = ?", now.Unix(), old.ID); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if al.queued > 0 {
		s.wake()
	}
	return nil
}

// NodeOnline resolves the node_offline finding of a node that polled
// again, with a recovery notice to the channels that had the alert.
func (s *Service) NodeOnline(ctx context.Context, n Node) error {
	f, err := scanFinding(s.DB.R.QueryRowContext(ctx, "SELECT "+findingCols+" FROM findings f WHERE f.node_id = ? AND f.kind = ? AND f.resolved_at = 0", n.ID, string(check.NodeOffline)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	now := s.now()
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE findings SET resolved_at = ? WHERE id = ? AND resolved_at = 0", now.Unix(), f.ID); err != nil {
		return err
	}
	al := s.nodeAlerter(tx, s.CurrentSettings(ctx), n, nil, now)
	if err := al.recover(ctx, f); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if al.queued > 0 {
		s.wake()
	}
	return nil
}

// remindNode queues a reminder for an open node finding whose reminder
// interval (from Settings › Defaults) has passed.
func (s *Service) remindNode(ctx context.Context, st config.Settings, f Finding, now time.Time) (int, error) {
	every := st.Defaults.RemindWarnS
	if f.Severity == check.Critical {
		every = st.Defaults.RemindCritS
	}
	if every <= 0 || f.LastAlertAt+int64(every) > now.Unix() {
		return 0, nil
	}
	n, err := s.Node(ctx, f.NodeID)
	if err != nil || !n.Enabled {
		return 0, nil
	}
	chans, err := s.Channels.Enabled(ctx)
	if err != nil {
		return 0, err
	}
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	al := s.nodeAlerter(tx, st, n, chans, now)
	if err := al.send(ctx, f, notify.EventRemind); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE findings SET last_alert_at = ? WHERE id = ?", now.Unix(), f.ID); err != nil {
		return 0, err
	}
	return al.queued, tx.Commit()
}

// nodeAlerter starts an alerter for a node finding.
func (s *Service) nodeAlerter(tx *sql.Tx, st config.Settings, n Node, chans []notify.Channel, now time.Time) *alerter {
	base := notify.AlertData{Node: true, TargetName: n.Label(), HostPort: "node " + n.Label(), Address: n.Address, Loc: st.Location()}
	if st.General.BaseURL != "" {
		base.Link = fmt.Sprintf("%s/settings/nodes/%d", st.General.BaseURL, n.ID)
	}
	return &alerter{tx: tx, chans: chans, now: now, base: base}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
