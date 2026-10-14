package notify

import (
	"fmt"
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
	Event       string
	Severity    string // info, warning, critical
	Kind        string // finding kind, e.g. "expiring"
	KindLabel   string
	TargetName  string
	HostPort    string
	Details     string
	DaysLeft    *int
	NotAfter    time.Time
	SubjectCN   string
	IssuerCN    string
	Fingerprint string
	Address     string
	Link        string
	OpenedAt    time.Time
	Loc         *time.Location
}

// phrase describes the problem in the subject line.
func phrase(kind string, days *int) string {
	switch kind {
	case "expiring":
		if days != nil {
			if *days == 1 {
				return "expires in 1 day"
			}
			return fmt.Sprintf("expires in %d days", *days)
		}
		return "expires soon"
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
	}
	return kind
}

// Render builds the message for one alert. The subject starts with the
// severity in brackets so mail rules can route it.
func Render(a AlertData) Message {
	loc := a.Loc
	if loc == nil {
		loc = time.UTC
	}
	tag := a.Severity
	subject := fmt.Sprintf("%s %s", a.HostPort, phrase(a.Kind, a.DaysLeft))
	switch a.Event {
	case EventEscalate:
		subject += ", escalated"
	case EventRemind:
		subject += ", still open since " + a.OpenedAt.In(loc).Format("2 Jan")
	case EventRecover:
		tag = "resolved"
		subject = fmt.Sprintf("%s %s resolved", a.HostPort, strings.ToLower(a.KindLabel))
	}
	var b strings.Builder
	line := func(label, value string) {
		if value != "" {
			fmt.Fprintf(&b, "%-12s %s\n", label+":", value)
		}
	}
	line("Target", fmt.Sprintf("%s (%s)", a.TargetName, a.HostPort))
	if a.Event == EventRecover {
		line("Resolved", a.KindLabel)
	} else {
		line("Finding", fmt.Sprintf("%s, %s", a.KindLabel, a.Severity))
	}
	line("Details", a.Details)
	if !a.NotAfter.IsZero() {
		exp := a.NotAfter.In(loc).Format("2006-01-02 15:04 MST")
		if a.DaysLeft != nil {
			exp += fmt.Sprintf(" (%d days left)", *a.DaysLeft)
		}
		line("Expires", exp)
	}
	line("Subject", a.SubjectCN)
	line("Issuer", a.IssuerCN)
	if len(a.Fingerprint) >= 16 {
		line("SHA-256", a.Fingerprint[:16]+"…")
	}
	line("Address", a.Address)
	if !a.OpenedAt.IsZero() && a.Event != EventOpen {
		line("Open since", a.OpenedAt.In(loc).Format("2006-01-02 15:04"))
	}
	if a.Link != "" {
		b.WriteString("\n" + a.Link + "\n")
	}
	return Message{Subject: "[" + tag + "] " + subject, Body: b.String()}
}

// MaxBatchLines caps a collapsed message.
const MaxBatchLines = 50

// Combine collapses several alerts for one channel into one message, one
// line per alert, worst severity first.
func Combine(msgs []Message, link string) Message {
	if len(msgs) == 1 {
		return msgs[0]
	}
	rank := func(s string) int {
		switch {
		case strings.HasPrefix(s, "[critical]"):
			return 0
		case strings.HasPrefix(s, "[warning]"):
			return 1
		case strings.HasPrefix(s, "[resolved]"):
			return 3
		}
		return 2
	}
	sorted := append([]Message(nil), msgs...)
	sort.SliceStable(sorted, func(i, j int) bool { return rank(sorted[i].Subject) < rank(sorted[j].Subject) })
	worst := "info"
	switch rank(sorted[0].Subject) {
	case 0:
		worst = "critical"
	case 1:
		worst = "warning"
	case 3:
		worst = "resolved"
	}
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
	return Message{Subject: fmt.Sprintf("[%s] %d alerts from tlswatch", worst, len(msgs)), Body: b.String()}
}

// TestMessage is the sample sent by a channel's Test button.
func TestMessage(channel, link string) Message {
	body := fmt.Sprintf("This is a test message from tlswatch for the channel %q.\nIf you can read it, alerts will arrive here.\n", channel)
	if link != "" {
		body += "\n" + link + "\n"
	}
	return Message{Subject: "[info] tlswatch test message", Body: body}
}
