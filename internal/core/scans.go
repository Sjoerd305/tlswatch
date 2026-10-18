package core

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// Scan states.
const (
	ScanRunning = "running"
	ScanDone    = "done"
	ScanFailed  = "failed"
)

// ScanKeep is how long a scan and its results are kept. They are a list to
// pick targets from, not inventory.
const ScanKeep = 7 * 24 * time.Hour

// KindScan is the node job kind of a scan; a node lists it in its facts
// when it can run one.
const KindScan = "scan"

// Scan is one discovery scan of address ranges and ports.
type Scan struct {
	ID         int64
	CreatedAt  int64
	CreatedBy  string
	NodeID     int64 // 0: this server
	NodeName   string
	Ranges     []string
	Ports      []int
	Rate       int
	State      string
	Total      int // connects planned
	Probed     int
	Refused    int // addresses refused without a connect
	Error      string
	FinishedAt int64
	Found      int // endpoints that answered with TLS
}

// Percent is the share of the planned connects made or refused.
func (s Scan) Percent() int {
	if s.Total == 0 {
		return 100
	}
	return min(100, (s.Probed+s.Refused*len(s.Ports))*100/s.Total)
}

// ScanResult is one TLS endpoint a scan found, with the target that
// already covers it, if any.
type ScanResult struct {
	ID          int64
	Address     string
	Port        int
	Protocol    probe.Protocol
	TLSVersion  string
	Fingerprint string
	SubjectCN   string
	SANs        []string
	Issuer      string
	NotAfter    int64
	SelfSigned  bool
	TargetID    int64 // a target on this address and port, 0 for none
	TargetName  string
}

// HostPort is address:port with an IPv6 address bracketed.
func (r ScanResult) HostPort() string { return net.JoinHostPort(r.Address, strconv.Itoa(r.Port)) }

// ScanInput is a scan as an operator asks for it.
type ScanInput struct {
	Ranges string // CIDRs or addresses, separated by commas, spaces or lines
	Ports  string // empty: probe.DefaultScanPorts
	Rate   int    // 0: probe.DefaultScanRate
	NodeID int64
}

// privateRanges are the ranges a scan may cover without the public
// discovery setting: RFC 1918, the shared address space of RFC 6598 and
// the unique local addresses of RFC 4193.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fc00::/7"),
}

// localRanges are loopback, link-local and unspecified, refused unless
// local addresses are allowed as targets.
var localRanges = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("::/128"),
}

func within(p netip.Prefix, ranges []netip.Prefix) bool {
	return slices.ContainsFunc(ranges, func(r netip.Prefix) bool { return r.Bits() <= p.Bits() && r.Contains(p.Addr()) })
}

func overlaps(p netip.Prefix, ranges []netip.Prefix) bool {
	return slices.ContainsFunc(ranges, func(r netip.Prefix) bool { return r.Overlaps(p) })
}

// ParseScanRanges reads the ranges of a scan: CIDRs or single addresses.
// Without public, each must lie in a private range; without local, none
// may touch loopback or link-local. Together they hold at most
// probe.MaxScanAddresses addresses.
func ParseScanRanges(s string, public, local bool) ([]netip.Prefix, []netip.Addr, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		p, err := netip.ParsePrefix(f)
		if err != nil {
			a, aerr := netip.ParseAddr(f)
			if aerr != nil {
				return nil, nil, usererr.New(fmt.Sprintf("%q is not a CIDR or an address", f))
			}
			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), max(p.Bits()-96, 0))
		}
		p = p.Masked()
		if !local && overlaps(p, localRanges) {
			return nil, nil, usererr.New(fmt.Sprintf("%s covers loopback or link-local addresses, which Settings › General does not allow as targets", p))
		}
		if !public && !within(p, privateRanges) {
			return nil, nil, usererr.New(fmt.Sprintf("%s is not a private range; scanning public addresses needs Settings › General › Allow discovery of public addresses", p))
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, nil, usererr.New("Enter at least one range, such as 10.20.0.0/24")
	}
	addrs := probe.ScanAddresses(out)
	if len(addrs) > probe.MaxScanAddresses {
		return nil, nil, usererr.New(fmt.Sprintf("A scan covers at most %d addresses, a /20; split the ranges over several scans", probe.MaxScanAddresses))
	}
	return out, addrs, nil
}

// ParseScanPorts reads the ports of a scan; empty is probe.DefaultScanPorts.
func ParseScanPorts(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return slices.Clone(probe.DefaultScanPorts), nil
	}
	var out []int
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > 65535 {
			return nil, usererr.New(fmt.Sprintf("%q is not a port", f))
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	if len(out) > probe.MaxScanPorts {
		return nil, usererr.New(fmt.Sprintf("A scan tries at most %d ports", probe.MaxScanPorts))
	}
	return out, nil
}

// ErrScanBusy refuses a second scan from the same node or the server.
var ErrScanBusy = usererr.New("A scan is already running from there; wait for it to finish")

// CanScan reports whether a node can run scans: it lists the job kind in
// its facts. Nodes from before discovery do not.
func (n Node) CanScan() bool { return slices.Contains(n.Facts.Kinds, KindScan) }

// CreateScan validates a scan, records it as running and returns it with
// the addresses to probe. One scan runs per node, and one from the server.
func (s *Service) CreateScan(ctx context.Context, in ScanInput, user string) (Scan, []netip.Addr, error) {
	st := s.CurrentSettings(ctx)
	prefixes, addrs, err := ParseScanRanges(in.Ranges, st.General.PublicDiscovery, st.General.AllowLocal)
	if err != nil {
		return Scan{}, nil, err
	}
	ports, err := ParseScanPorts(in.Ports)
	if err != nil {
		return Scan{}, nil, err
	}
	rate := in.Rate
	if rate == 0 {
		rate = probe.DefaultScanRate
	}
	if rate < 1 || rate > probe.MaxScanRate {
		return Scan{}, nil, usererr.New(fmt.Sprintf("The rate must be 1 to %d connects per second", probe.MaxScanRate))
	}
	sc := Scan{CreatedAt: s.now().Unix(), CreatedBy: user, NodeID: in.NodeID, Ports: ports, Rate: rate, State: ScanRunning,
		Total: len(addrs) * len(ports)}
	for _, p := range prefixes {
		sc.Ranges = append(sc.Ranges, p.String())
	}
	if in.NodeID != 0 {
		n, err := s.Node(ctx, in.NodeID)
		if errors.Is(err, ErrNotFound) || err == nil && !n.Assignable() {
			return Scan{}, nil, usererr.New("Choose a confirmed node, or This server")
		}
		if err != nil {
			return Scan{}, nil, err
		}
		if !n.CanScan() {
			return Scan{}, nil, usererr.New(fmt.Sprintf("Node %s runs a version that cannot scan; update it under Settings › Nodes first", n.Label()))
		}
		sc.NodeName = n.Label()
	}
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return Scan{}, nil, err
	}
	defer tx.Rollback()
	var busy int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM scans WHERE state = ? AND COALESCE(node_id, 0) = ?", ScanRunning, in.NodeID).Scan(&busy); err != nil {
		return Scan{}, nil, err
	}
	if busy > 0 {
		return Scan{}, nil, ErrScanBusy
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO scans(created_at, created_by, node_id, node_name, ranges, ports, rate, state, total)
		VALUES(?,?,?,?,?,?,?,?,?)`, sc.CreatedAt, user, nullID(in.NodeID), sc.NodeName, strings.Join(sc.Ranges, ","), joinInts(ports), rate, ScanRunning, sc.Total)
	if err != nil {
		return Scan{}, nil, err
	}
	sc.ID, _ = res.LastInsertId()
	if err := tx.Commit(); err != nil {
		return Scan{}, nil, err
	}
	from := "this server"
	if sc.NodeName != "" {
		from = "node " + sc.NodeName
	}
	s.Audit(ctx, user, "scan.start", fmt.Sprintf("scan %d", sc.ID), fmt.Sprintf("ranges=%s ports=%s rate=%d from=%s",
		strings.Join(sc.Ranges, ","), joinInts(ports), rate, from))
	return sc, addrs, nil
}

func joinInts(ns []int) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
}

const scanCols = `s.id, s.created_at, s.created_by, COALESCE(s.node_id, 0), s.node_name, s.ranges, s.ports, s.rate, s.state, s.total,
	s.probed, s.refused, s.error, s.finished_at, (SELECT COUNT(*) FROM scan_results r WHERE r.scan_id = s.id)`

func scanScan(r interface{ Scan(...any) error }) (Scan, error) {
	var sc Scan
	var ranges, ports string
	err := r.Scan(&sc.ID, &sc.CreatedAt, &sc.CreatedBy, &sc.NodeID, &sc.NodeName, &ranges, &ports, &sc.Rate, &sc.State, &sc.Total,
		&sc.Probed, &sc.Refused, &sc.Error, &sc.FinishedAt, &sc.Found)
	if ranges != "" {
		sc.Ranges = strings.Split(ranges, ",")
	}
	for _, p := range strings.Split(ports, ",") {
		if n, err := strconv.Atoi(p); err == nil {
			sc.Ports = append(sc.Ports, n)
		}
	}
	return sc, err
}

// Scan returns one scan.
func (s *Service) Scan(ctx context.Context, id int64) (Scan, error) {
	sc, err := scanScan(s.DB.R.QueryRowContext(ctx, "SELECT "+scanCols+" FROM scans s WHERE s.id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return sc, ErrNotFound
	}
	return sc, err
}

// Scans returns the scans of the last ScanKeep, newest first.
func (s *Service) Scans(ctx context.Context) ([]Scan, error) {
	rows, err := s.DB.R.QueryContext(ctx, "SELECT "+scanCols+" FROM scans s ORDER BY s.id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Scan
	for rows.Next() {
		sc, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// RecordScan stores the endpoints a part of a scan found and adds its
// connects and refusals to the progress.
func (s *Service) RecordScan(ctx context.Context, id int64, res probe.ScanResult) error {
	tx, err := s.DB.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, h := range res.Hits {
		if len(h.Chain) == 0 {
			continue
		}
		info := probe.Describe(h.Chain[0])
		sans, _ := json.Marshal(info.SANs)
		issuer := info.IssuerOrg
		if issuer == "" {
			issuer = info.IssuerCN
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO scan_results(scan_id, address, port, protocol, tls_version, fingerprint, subject_cn, sans, issuer, not_after, self_signed)
			VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, h.IP, h.Port, string(h.Protocol), h.TLSVersion, info.Fingerprint, Clip(info.SubjectCN, ShortMax*2),
			string(sans), Clip(issuer, ShortMax*2), info.NotAfter.Unix(), info.SelfSigned); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE scans SET probed = probed + ?, refused = refused + ? WHERE id = ?", res.Probed, res.Refused, id); err != nil {
		return err
	}
	return tx.Commit()
}

// FinishScan ends a scan: done, or failed with the reason.
func (s *Service) FinishScan(ctx context.Context, id int64, failure string) error {
	state := ScanDone
	if failure != "" {
		state = ScanFailed
	}
	_, err := s.DB.W.ExecContext(ctx, "UPDATE scans SET state = ?, error = ?, finished_at = ? WHERE id = ?", state, Clip(failure, TextMax), s.now().Unix(), id)
	return err
}

// FailRunningScans ends the scans a stopped server left running; what they
// found so far stays.
func (s *Service) FailRunningScans(ctx context.Context) error {
	_, err := s.DB.W.ExecContext(ctx, "UPDATE scans SET state = ?, error = 'stopped by a restart of the server', finished_at = ? WHERE state = ?",
		ScanFailed, s.now().Unix(), ScanRunning)
	return err
}

// ScanResults returns what a scan found, by address and port, each with
// the target that already covers it: one whose host is the address, or
// whose last check reached it, on the same port.
func (s *Service) ScanResults(ctx context.Context, id int64) ([]ScanResult, error) {
	covered := map[string]Target{}
	rows, err := s.DB.R.QueryContext(ctx, `SELECT t.id, t.name, t.host, t.port, COALESCE(o.address, '') FROM targets t
		LEFT JOIN observations o ON o.check_id = t.last_check_id AND o.target_id = t.id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t Target
		var addr string
		if err := rows.Scan(&t.ID, &t.Name, &t.Host, &t.Port, &addr); err != nil {
			rows.Close()
			return nil, err
		}
		covered[t.Host+"|"+strconv.Itoa(t.Port)] = t
		if addr != "" {
			covered[addr+"|"+strconv.Itoa(t.Port)] = t
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = s.DB.R.QueryContext(ctx, `SELECT id, address, port, protocol, tls_version, fingerprint, subject_cn, sans, issuer, not_after, self_signed
		FROM scan_results WHERE scan_id = ?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanResult
	for rows.Next() {
		var r ScanResult
		var proto, sans string
		if err := rows.Scan(&r.ID, &r.Address, &r.Port, &proto, &r.TLSVersion, &r.Fingerprint, &r.SubjectCN, &sans, &r.Issuer, &r.NotAfter, &r.SelfSigned); err != nil {
			return nil, err
		}
		r.Protocol = probe.Protocol(proto)
		_ = json.Unmarshal([]byte(sans), &r.SANs)
		if t, ok := covered[r.Address+"|"+strconv.Itoa(r.Port)]; ok {
			r.TargetID, r.TargetName = t.ID, t.Name
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b ScanResult) int {
		x, errx := netip.ParseAddr(a.Address)
		y, erry := netip.ParseAddr(b.Address)
		if c := x.Compare(y); errx == nil && erry == nil && c != 0 {
			return c
		}
		return a.Port - b.Port
	})
	return out, nil
}

// pruneScans removes scans older than ScanKeep with their results.
func (s *Service) pruneScans(ctx context.Context) error {
	_, err := s.DB.W.ExecContext(ctx, "DELETE FROM scans WHERE created_at < ? AND state != ?", s.now().Add(-ScanKeep).Unix(), ScanRunning)
	return err
}
