// Package caa looks up CAA records (RFC 8659) and judges whether they
// permit a CA to issue for a name. A CAA record set names the CAs allowed
// to issue; a Certificate Transparency issuance by another CA is either a
// CA that ignored CAA or a record that changed after the issuance, and
// tlswatch shows both. The lookup asks the system's resolver directly,
// since Go's resolver has no CAA queries.
package caa

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TypeCAA is the CAA resource record type.
const TypeCAA = dnsmessage.Type(257)

// Record is one CAA resource record.
type Record struct {
	Flags uint8  `json:"flags"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// Critical reports the issuer-critical flag.
func (r Record) Critical() bool { return r.Flags&0x80 != 0 }

// String is the record in zone-file form: 0 issue "letsencrypt.org".
func (r Record) String() string { return fmt.Sprintf("%d %s %q", r.Flags, r.Tag, r.Value) }

// Set is the relevant record set of a name: the first non-empty set found
// climbing from the name towards the root, and the name it was found at.
// An empty set means no CAA record anywhere: any CA may issue.
type Set struct {
	Name    string   `json:"name,omitempty"`
	Records []Record `json:"records,omitempty"`
}

// Empty reports that no CAA record applies.
func (s Set) Empty() bool { return len(s.Records) == 0 }

// Equal reports whether two sets hold the same records at the same name,
// in any order.
func (s Set) Equal(o Set) bool {
	if !strings.EqualFold(s.Name, o.Name) || len(s.Records) != len(o.Records) {
		return false
	}
	for _, r := range s.Records {
		if !slices.Contains(o.Records, r) {
			return false
		}
	}
	return true
}

// Lines lists the records in zone-file form, sorted.
func (s Set) Lines() []string {
	var out []string
	for _, r := range s.Records {
		out = append(out, r.String())
	}
	slices.Sort(out)
	return out
}

// Resolver answers the CAA records of exactly one name: none when the
// name has none or does not exist; an error when the answer is unusable.
type Resolver interface {
	CAA(ctx context.Context, name string) ([]Record, error)
}

// Lookup returns the relevant record set of name: the CAA records of the
// name itself, else of its parent, and so on up to the top-level domain
// (RFC 8659, 3). A wildcard's "*." is not part of the climb.
func Lookup(ctx context.Context, r Resolver, name string) (Set, error) {
	name = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(name), "*."), ".")
	for n := name; n != ""; {
		recs, err := r.CAA(ctx, n)
		if err != nil {
			return Set{}, fmt.Errorf("CAA of %s: %w", n, err)
		}
		if len(recs) > 0 {
			return Set{Name: n, Records: recs}, nil
		}
		_, parent, ok := strings.Cut(n, ".")
		if !ok {
			break
		}
		n = parent
	}
	return Set{}, nil
}

// Verdicts of Permits.
const (
	Permitted = "permitted"
	Forbidden = "forbidden"
)

// Permits reports whether set allows a CA known by any of ids (its issuer
// domain names) to issue for a name, a wildcard name or not (RFC 8659,
// 4.2 and 4.3), and when not, why. An empty set, or one without issue or
// issuewild properties, permits every CA. An unknown property flagged
// critical forbids issuance.
func Permits(set Set, ids []string, wildcard bool) (bool, string) {
	var issue, wild []string
	hasIssue, hasWild := false, false
	for _, r := range set.Records {
		switch strings.ToLower(r.Tag) {
		case "issue":
			hasIssue = true
			issue = append(issue, issuerDomain(r.Value))
		case "issuewild":
			hasWild = true
			wild = append(wild, issuerDomain(r.Value))
		case "iodef", "contactemail", "contactphone", "issuemail", "issuevmc":
		default:
			if r.Critical() {
				return false, fmt.Sprintf("the record at %s has a critical property %q tlswatch does not know", set.Name, r.Tag)
			}
		}
	}
	allowed, prop := issue, "issue"
	if wildcard && hasWild {
		allowed, prop = wild, "issuewild"
	} else if !hasIssue {
		return true, ""
	}
	for _, a := range allowed {
		for _, id := range ids {
			if a != "" && strings.EqualFold(a, id) {
				return true, ""
			}
		}
	}
	var named []string
	for _, a := range allowed {
		if a != "" {
			named = append(named, a)
		}
	}
	if len(named) == 0 {
		return false, fmt.Sprintf("the CAA record at %s allows no CA (%s \";\")", set.Name, prop)
	}
	return false, fmt.Sprintf("the CAA record at %s allows only %s", set.Name, strings.Join(named, ", "))
}

// issuerDomain is the issuer domain name of an issue property value, the
// part before any parameters: "letsencrypt.org; validationmethods=dns-01"
// is letsencrypt.org; ";" is none.
func issuerDomain(v string) string {
	d, _, _ := strings.Cut(v, ";")
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// System asks the name servers of /etc/resolv.conf, over UDP and over TCP
// when the answer was truncated.
type System struct {
	// Servers overrides the name servers, as host:port; tests set it.
	Servers []string
	Timeout time.Duration
}

// servers returns the configured name servers, or the local one.
func (s System) servers() []string {
	if len(s.Servers) > 0 {
		return s.Servers
	}
	var out []string
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "nameserver" {
				host := f[1]
				if i := strings.IndexByte(host, '%'); i >= 0 {
					host = host[:i] // a zone index is the interface's business
				}
				out = append(out, net.JoinHostPort(host, "53"))
			}
		}
	}
	if len(out) == 0 {
		out = []string{"127.0.0.1:53"}
	}
	return out
}

// CAA asks each name server in turn until one answers.
func (s System) CAA(ctx context.Context, name string) ([]Record, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	var last error
	for _, srv := range s.servers() {
		recs, err := query(ctx, srv, name, timeout)
		if err == nil {
			return recs, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

// errTruncated asks for the query again over TCP.
var errTruncated = errors.New("truncated")

func query(ctx context.Context, server, name string, timeout time.Duration) ([]Record, error) {
	q, id, err := build(name)
	if err != nil {
		return nil, err
	}
	recs, err := exchange(ctx, "udp", server, q, id, timeout)
	if errors.Is(err, errTruncated) {
		recs, err = exchange(ctx, "tcp", server, q, id, timeout)
	}
	return recs, err
}

func build(name string) ([]byte, uint16, error) {
	n, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil, 0, fmt.Errorf("%q is not a DNS name", name)
	}
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, 0, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: TypeCAA, Class: dnsmessage.ClassINET}); err != nil {
		return nil, 0, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, 0, err
	}
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, 0, err
	}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		return nil, 0, err
	}
	msg, err := b.Finish()
	return msg, id, err
}

func exchange(ctx context.Context, network, server string, q []byte, id uint16, timeout time.Duration) ([]Record, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	var resp []byte
	if network == "tcp" {
		msg := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
		if _, err := conn.Write(append(msg, q...)); err != nil {
			return nil, err
		}
		var l [2]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return nil, err
		}
		resp = make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, err
		}
	} else {
		if _, err := conn.Write(q); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return nil, err
			}
			// A reply with another ID is a stray datagram, not ours.
			if n >= 2 && binary.BigEndian.Uint16(buf[:2]) == id {
				resp = buf[:n]
				break
			}
		}
	}
	return parse(resp, id)
}

// parse reads the CAA records of a reply. NXDOMAIN and an empty answer are
// no records; any other failure is an error, since a CA must not issue on
// one either.
func parse(resp []byte, id uint16) ([]Record, error) {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return nil, fmt.Errorf("unreadable DNS answer: %w", err)
	}
	if h.ID != id {
		return nil, errors.New("DNS answer for another query")
	}
	if h.Truncated {
		return nil, errTruncated
	}
	switch h.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, nil
	default:
		return nil, fmt.Errorf("the resolver answered %s", strings.TrimPrefix(h.RCode.String(), "RCode"))
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	var out []Record
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, err
		}
		if rh.Type != TypeCAA {
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
			continue
		}
		res, err := p.UnknownResource()
		if err != nil {
			return nil, err
		}
		rec, err := decode(res.Data)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

// decode reads the RDATA of a CAA record: flags, tag length, tag, value.
func decode(b []byte) (Record, error) {
	if len(b) < 2 || len(b) < 2+int(b[1]) {
		return Record{}, errors.New("malformed CAA record")
	}
	tl := int(b[1])
	return Record{Flags: b[0], Tag: string(b[2 : 2+tl]), Value: string(b[2+tl:])}, nil
}

// encode is decode's reverse, for tests and fakes.
func encode(r Record) []byte {
	out := []byte{r.Flags, byte(len(r.Tag))}
	out = append(out, r.Tag...)
	return append(out, r.Value...)
}

// Static answers from a map of names to records, for tests and for a
// fixed set of answers; a name it does not hold has none.
type Static map[string][]Record

// CAA returns the records held for name.
func (s Static) CAA(_ context.Context, name string) ([]Record, error) {
	return s[strings.ToLower(strings.TrimSuffix(name, "."))], nil
}
