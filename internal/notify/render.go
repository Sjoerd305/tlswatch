package notify

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// Alert events.
const (
	EventOpen     = "open"
	EventEscalate = "escalate"
	EventRemind   = "remind"
	EventRecover  = "recover"
	EventTest     = "test"
	EventDigest   = "digest"
)

// AlertData holds the fields of one alert message.
type AlertData struct {
	Event      string
	Severity   string // info, warning, critical
	Kind       string // finding kind, e.g. "expiring"
	KindLabel  string
	TargetName string
	HostPort   string
	Details    string
	DaysLeft   *int
	// HoursLeft replaces DaysLeft in the text under a week ("31 h").
	HoursLeft   *int
	NotAfter    time.Time
	SubjectCN   string
	IssuerCN    string
	Fingerprint string
	Address     string
	Link        string
	OpenedAt    time.Time
	Loc         *time.Location
	// Node marks a finding on a node: TargetName is the node's name and
	// HostPort reads "node <name>". Domain marks one on a domain watch.
	Node   bool
	Domain bool
}

// left is the time left as text: "31 h", "1 day", "12 days"; "" when
// unknown.
func left(a AlertData) string {
	switch {
	case a.HoursLeft != nil:
		return fmt.Sprintf("%d h", *a.HoursLeft)
	case a.DaysLeft == nil:
		return ""
	case *a.DaysLeft == 1:
		return "1 day"
	}
	return fmt.Sprintf("%d days", *a.DaysLeft)
}

// phrase describes the problem in the subject line.
func phrase(a AlertData) string {
	switch a.Kind {
	case "expiring":
		if l := left(a); l != "" {
			return "expires in " + l
		}
		return "expires soon"
	case "renewal_overdue":
		return "renewal overdue"
	case "distrusted_ca":
		return "chain roots in a distrusted CA"
	case "revoked":
		return "certificate revoked"
	case "expired":
		return "certificate expired"
	case "chain_untrusted":
		return "chain not trusted"
	case "self_signed":
		return "serves a self-signed certificate"
	case "hostname_mismatch":
		return "hostname mismatch"
	case "weak_signature":
		return "weak signature or key"
	case "certificate_changed":
		return "certificate changed"
	case "issuer_changed":
		return "issuer changed"
	case "inconsistent":
		return "addresses serve different certificates"
	case "tls_unavailable":
		return "STARTTLS not offered"
	case "unreachable":
		return "unreachable"
	case "dns_failed":
		return "DNS lookup failed"
	case "node_offline":
		return "offline"
	case "unexpected_certificate":
		return "unexpected certificate issued"
	case "ct_source_failed":
		return "Certificate Transparency source not answering"
	case "certificate_issued":
		return "certificate issued"
	case "caa_violation":
		return "certificate issued against the CAA record"
	}
	return a.Kind
}

// Render builds the message for one alert. The subject starts with the
// severity in brackets so mail rules can route it.
func Render(a AlertData) Message {
	loc := a.Loc
	if loc == nil {
		loc = time.UTC
	}
	tag := a.Severity
	subject := fmt.Sprintf("%s %s", a.HostPort, phrase(a))
	switch a.Event {
	case EventEscalate:
		subject += ", escalated"
	case EventRemind:
		subject += ", still open since " + a.OpenedAt.In(loc).Format("2 Jan")
	case EventRecover:
		tag = "resolved"
		subject = fmt.Sprintf("%s %s resolved", a.HostPort, strings.ToLower(a.KindLabel))
	}
	// One list of fields feeds the plain text and the HTML part.
	var rows []kv
	add := func(label, value string, mono bool) {
		if value != "" {
			rows = append(rows, kv{label, value, mono})
		}
	}
	if a.Node {
		add("Node", a.TargetName, false)
	} else if a.Domain {
		add("Domain", a.TargetName, false)
	} else {
		add("Target", fmt.Sprintf("%s (%s)", a.TargetName, a.HostPort), false)
	}
	if a.Event == EventRecover {
		add("Resolved", a.KindLabel, false)
	} else {
		add("Finding", fmt.Sprintf("%s, %s", a.KindLabel, a.Severity), false)
	}
	add("Details", a.Details, false)
	if !a.NotAfter.IsZero() {
		exp := a.NotAfter.In(loc).Format("2006-01-02 15:04 MST")
		if l := left(a); l != "" {
			exp += " (" + l + " left)"
		}
		add("Expires", exp, true)
	}
	add("Subject", a.SubjectCN, false)
	add("Issuer", a.IssuerCN, false)
	if len(a.Fingerprint) >= 16 {
		add("SHA-256", a.Fingerprint[:16]+"…", true)
	}
	add("Address", a.Address, true)
	if !a.OpenedAt.IsZero() && a.Event != EventOpen {
		add("Open since", a.OpenedAt.In(loc).Format("2006-01-02 15:04"), true)
	}
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "%-12s %s\n", r.K+":", r.V)
	}
	if a.Link != "" {
		b.WriteString("\n" + a.Link + "\n")
	}

	view := &alertView{Tag: tag, Event: eventLabel(a, loc), Title: subject, Rows: rows}
	if a.DaysLeft != nil && a.Event != EventRecover {
		view.Countdown, view.CountdownNote = countdown(*a.DaysLeft, a.HoursLeft, a.NotAfter.In(loc))
	}
	html := renderHTML(emailDoc{Kind: "alert", Title: subject, Preheader: a.Details, Label: "Alert", Link: a.Link, Alert: view})
	return Message{Subject: tagged(tag, subject), Body: b.String(), HTML: html}
}

// eventLabel says what kind of alert this is, above the title.
func eventLabel(a AlertData, loc *time.Location) string {
	switch a.Event {
	case EventEscalate:
		return "Escalated to " + a.Severity
	case EventRemind:
		return "Reminder, open since " + a.OpenedAt.In(loc).Format("2 Jan 2006")
	case EventRecover:
		return "Resolved"
	}
	return "New finding on " + a.TargetName
}

// countdown is the large figure of an expiry alert and the note beside it.
func countdown(days int, hours *int, notAfter time.Time) (string, string) {
	date := ""
	if !notAfter.IsZero() {
		date = notAfter.Format("2 Jan 2006")
	}
	switch {
	case days < 0:
		return "Expired", "on " + date
	case hours != nil && *hours == 1:
		return "1", "hour left · expires " + date
	case hours != nil:
		return fmt.Sprint(*hours), "hours left · expires " + date
	case days == 1:
		return "1", "day left · expires " + date
	}
	return fmt.Sprint(days), "days left · expires " + date
}

// Subject tags, worst first: Render starts every subject with one, which
// mail rules route on, and Combine orders a batch by it. Messages in the
// outbox are stored rendered, so the tag is how a batch learns severity.
var subjectTags = []string{"critical", "warning", "info", "resolved"}

func tagged(tag, subject string) string { return "[" + tag + "] " + subject }

// tagRank is the position of the subject's tag in subjectTags; an untagged
// subject ranks as info.
func tagRank(subject string) int {
	for i, t := range subjectTags {
		if strings.HasPrefix(subject, "["+t+"]") {
			return i
		}
	}
	return slices.Index(subjectTags, "info")
}

// MaxBatchLines caps a collapsed message.
const MaxBatchLines = 50

// Combine collapses several alerts for one channel into one message, one
// line per alert, worst severity first.
func Combine(msgs []Message, link string) Message {
	if len(msgs) == 1 {
		return msgs[0]
	}
	sorted := append([]Message(nil), msgs...)
	sort.SliceStable(sorted, func(i, j int) bool { return tagRank(sorted[i].Subject) < tagRank(sorted[j].Subject) })
	worst := subjectTags[tagRank(sorted[0].Subject)]
	var b strings.Builder
	for i, m := range sorted {
		if i == MaxBatchLines {
			fmt.Fprintf(&b, "… and %d more\n", len(sorted)-MaxBatchLines)
			break
		}
		b.WriteString(m.Subject + "\n")
	}
	if link != "" {
		b.WriteString("\n" + link + "\n")
	}
	subject := fmt.Sprintf("%d alerts from tlswatch", len(msgs))
	view := &batchView{Title: subject, Count: len(msgs)}
	for i, m := range sorted {
		if i == MaxBatchLines {
			view.More = len(sorted) - MaxBatchLines
			break
		}
		view.Rows = append(view.Rows, batchRow{Tag: subjectTag(m.Subject), Text: untagged(m.Subject)})
	}
	html := renderHTML(emailDoc{Kind: "batch", Title: subject, Preheader: untagged(sorted[0].Subject), Label: "Alerts", Link: link,
		LinkText: "Open findings in tlswatch", Batch: view})
	return Message{Subject: tagged(worst, subject), Body: b.String(), HTML: html}
}

// TestMessage is the sample sent by a channel's Test button.
func TestMessage(channel, link string) Message {
	body := fmt.Sprintf("This is a test message from tlswatch for the channel %q.\nIf you can read it, alerts will arrive here.\n", channel)
	if link != "" {
		body += "\n" + link + "\n"
	}
	html := renderHTML(emailDoc{Kind: "test", Title: "tlswatch test message", Preheader: "Alerts will arrive here.", Label: "Test",
		Link: link, Test: &testView{Channel: channel}})
	return Message{Subject: tagged("info", "tlswatch test message"), Body: body, HTML: html}
}

// DigestData is the content of the weekly digest.
type DigestData struct {
	Date     string // "Monday 19 October 2026"
	Findings []DigestFinding
	Expiring []DigestExpiry
	Failed   []DigestFailure
	Grades   []DigestGrade // targets whose configuration grade dropped this week
	Issued   []DigestIssuance
	Distrust []DigestDistrust // events taking effect in the next 90 days
	Link     string
}

// DigestDistrust is a root-program distrust event ahead, with the targets
// whose certificates it will affect.
type DigestDistrust struct {
	Date, CA, Phrase, Link string
	Targets                []string // "name (host:port)"
}

// DigestIssuance is a certificate issued for a watched domain this week.
type DigestIssuance struct {
	Domain, Names, Issuer, State, Date string
}

// DigestGrade is a target whose configuration grade dropped.
type DigestGrade struct {
	Name, HostPort, Details string
}

// acknowledged counts the open findings an operator has acknowledged.
func (d DigestData) acknowledged() int {
	n := 0
	for _, f := range d.Findings {
		if f.AckBy != "" {
			n++
		}
	}
	return n
}

// DigestFinding is an open finding in the digest.
type DigestFinding struct {
	Severity, HostPort, Kind, Details, AckBy string
}

// DigestExpiry is a certificate expiring within 30 days.
type DigestExpiry struct {
	Date           string
	Days           int
	Tag            string // critical or warning, for the colour of Days
	Name, HostPort string
}

// DigestFailure is a target whose last check failed.
type DigestFailure struct {
	Name, HostPort, Error string
}

// RenderDigest builds the weekly digest; tag is the subject tag (the worst
// open severity, or info).
func RenderDigest(d DigestData, tag string) Message {
	var b strings.Builder
	fmt.Fprintf(&b, "tlswatch weekly digest, %s\n\n", d.Date)
	acked := d.acknowledged()
	if acked > 0 {
		fmt.Fprintf(&b, "Open findings (%d, %d acknowledged)\n", len(d.Findings), acked)
	} else {
		fmt.Fprintf(&b, "Open findings (%d)\n", len(d.Findings))
	}
	for _, f := range d.Findings {
		ack := ""
		if f.AckBy != "" {
			ack = " (acknowledged by " + f.AckBy + ")"
		}
		fmt.Fprintf(&b, "  [%s] %s %s: %s%s\n", f.Severity, f.HostPort, f.Kind, f.Details, ack)
	}
	none := func(n int) {
		if n == 0 {
			b.WriteString("  none\n")
		}
	}
	none(len(d.Findings))
	fmt.Fprintf(&b, "\nExpiring in the next 30 days (%d)\n", len(d.Expiring))
	for _, e := range d.Expiring {
		fmt.Fprintf(&b, "  %s  %4d d  %s (%s)\n", e.Date, e.Days, e.Name, e.HostPort)
	}
	none(len(d.Expiring))
	fmt.Fprintf(&b, "\nFailed their last check (%d)\n", len(d.Failed))
	for _, f := range d.Failed {
		fmt.Fprintf(&b, "  %s (%s): %s\n", f.Name, f.HostPort, f.Error)
	}
	none(len(d.Failed))
	if len(d.Grades) > 0 {
		fmt.Fprintf(&b, "\nConfiguration grade dropped this week (%d)\n", len(d.Grades))
		for _, g := range d.Grades {
			fmt.Fprintf(&b, "  %s (%s): %s\n", g.Name, g.HostPort, g.Details)
		}
	}
	if len(d.Issued) > 0 {
		fmt.Fprintf(&b, "\nIssued for your domains this week (%d)\n", len(d.Issued))
		for _, i := range d.Issued {
			fmt.Fprintf(&b, "  %s  %-10s %s by %s (%s)\n", i.Date, i.State, i.Names, i.Issuer, i.Domain)
		}
	}
	if len(d.Distrust) > 0 {
		fmt.Fprintf(&b, "\nDistrust taking effect in the next 90 days (%d)\n", len(d.Distrust))
		for _, e := range d.Distrust {
			affects := "no target affected"
			if len(e.Targets) > 0 {
				affects = "affects " + strings.Join(e.Targets, ", ")
			}
			fmt.Fprintf(&b, "  %s  %s: %s; %s\n", e.Date, e.CA, e.Phrase, affects)
		}
	}
	if d.Link != "" {
		b.WriteString("\n" + d.Link + "\n")
	}
	subject := fmt.Sprintf("tlswatch weekly digest: %d open, %d expiring within 30 days", len(d.Findings), len(d.Expiring))

	figure := func(n int, tag string) string {
		if n == 0 {
			return "ok"
		}
		return tag
	}
	worstOpen := "ok"
	if len(d.Findings) > 0 {
		worstOpen = tag
	}
	view := &digestView{DigestData: d, Calm: len(d.Findings)+len(d.Expiring)+len(d.Failed) == 0, Tiles: []tile{
		{K: "Open findings", N: len(d.Findings), Tag: worstOpen},
		{K: "Expiring ≤ 30 d", N: len(d.Expiring), Tag: figure(len(d.Expiring), "warning")},
		{K: "Failed checks", N: len(d.Failed), Tag: figure(len(d.Failed), "critical")},
	}}
	if acked > 0 {
		view.Tiles = append(view.Tiles, tile{K: "Acknowledged", N: acked, Tag: "ok"})
	}
	html := renderHTML(emailDoc{Kind: "digest", Title: subject, Preheader: subject, Label: "Weekly digest", Link: d.Link, Digest: view})
	return Message{Subject: tagged(tag, subject), Body: b.String(), HTML: html}
}
