package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sjoerd305/tlswatch/internal/config"
)

// Calendar is a secret calendar feed of a user: an ICS URL with one event
// per served certificate on its expiry date, optionally only for the
// targets with one tag. The token is stored as a hash, like a session's.
type Calendar struct {
	ID       int64
	UserID   int64
	Tag      string
	Created  int64
	LastUsed int64
}

// calendarUsedEvery is how often a feed's last use is written: calendar
// clients poll every few minutes, and the list needs no more.
const calendarUsedEvery = time.Hour

// CreateCalendar makes a feed for a user and returns it with its token,
// which is shown once and then only its hash is kept.
func (s *Service) CreateCalendar(ctx context.Context, userID int64, tag string) (Calendar, string, error) {
	c := Calendar{UserID: userID, Tag: strings.ToLower(strings.TrimSpace(tag)), Created: s.now().Unix()}
	token := newSecret()
	res, err := s.DB.W.ExecContext(ctx, "INSERT INTO calendars(user_id, hash, tag, created_at) VALUES(?,?,?,?)", userID, hashSecret(token), c.Tag, c.Created)
	if err != nil {
		return c, "", err
	}
	c.ID, err = res.LastInsertId()
	return c, token, err
}

// Calendars lists a user's feeds, newest first.
func (s *Service) Calendars(ctx context.Context, userID int64) ([]Calendar, error) {
	rows, err := s.DB.R.QueryContext(ctx, "SELECT id, user_id, tag, created_at, last_used_at FROM calendars WHERE user_id = ? ORDER BY id DESC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Calendar
	for rows.Next() {
		var c Calendar
		if err := rows.Scan(&c.ID, &c.UserID, &c.Tag, &c.Created, &c.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteCalendar revokes one of a user's feeds.
func (s *Service) DeleteCalendar(ctx context.Context, userID, id int64) (Calendar, error) {
	var c Calendar
	err := s.DB.R.QueryRowContext(ctx, "SELECT id, user_id, tag, created_at, last_used_at FROM calendars WHERE id = ? AND user_id = ?", id, userID).
		Scan(&c.ID, &c.UserID, &c.Tag, &c.Created, &c.LastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	_, err = s.DB.W.ExecContext(ctx, "DELETE FROM calendars WHERE id = ? AND user_id = ?", id, userID)
	return c, err
}

// CalendarByToken returns the feed a token opens. A feed of a disabled or
// deleted user opens nothing.
func (s *Service) CalendarByToken(ctx context.Context, token string) (Calendar, error) {
	var c Calendar
	err := s.DB.R.QueryRowContext(ctx, `SELECT c.id, c.user_id, c.tag, c.created_at, c.last_used_at FROM calendars c JOIN users u ON u.id = c.user_id
		WHERE c.hash = ? AND u.enabled = 1`, hashSecret(token)).Scan(&c.ID, &c.UserID, &c.Tag, &c.Created, &c.LastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	if now := s.now(); now.Sub(time.Unix(c.LastUsed, 0)) >= calendarUsedEvery {
		if _, err := s.DB.W.ExecContext(ctx, "UPDATE calendars SET last_used_at = ? WHERE id = ?", now.Unix(), c.ID); err != nil {
			return c, err
		}
	}
	return c, nil
}

// calEvent is one all-day event of a feed.
type calEvent struct {
	uid, summary, description, url string
	day                            time.Time
}

// CalendarICS renders a feed: an all-day event per certificate an enabled
// target serves, on its expiry date, and for renewal-managed targets one
// on the renewal point. The UID is the certificate's fingerprint, so a
// renewal moves the event instead of adding one.
func (s *Service) CalendarICS(ctx context.Context, c Calendar) ([]byte, error) {
	st := s.CurrentSettings(ctx)
	loc := st.Location()
	ts, err := s.Targets(ctx)
	if err != nil {
		return nil, err
	}
	type served struct {
		cert    *Certificate
		targets []Target
		renewAt time.Time // the earliest renewal point of its renewal-managed targets
	}
	byFP := map[string]*served{}
	var order []string
	for _, t := range ts {
		if !t.Enabled || t.Cert == nil || c.Tag != "" && !slices.Contains(t.Tags, c.Tag) {
			continue
		}
		sv, ok := byFP[t.Cert.Fingerprint]
		if !ok {
			sv = &served{cert: t.Cert}
			byFP[t.Cert.Fingerprint] = sv
			order = append(order, t.Cert.Fingerprint)
		}
		sv.targets = append(sv.targets, t)
		if t.RenewalManaged && t.Cert.NotAfter > t.Cert.NotBefore {
			pct := t.Effective(st.Defaults).RenewalPct
			life := time.Duration(t.Cert.NotAfter-t.Cert.NotBefore) * time.Second
			at := time.Unix(t.Cert.NotBefore, 0).Add(life * time.Duration(pct) / 100)
			if sv.renewAt.IsZero() || at.Before(sv.renewAt) {
				sv.renewAt = at
			}
		}
	}
	var events []calEvent
	for _, fp := range order {
		sv := byFP[fp]
		var names, lines []string
		for _, t := range sv.targets {
			names = append(names, t.Name)
			lines = append(lines, fmt.Sprintf("%s (%s)", t.Name, t.HostPort()))
		}
		cn := sv.cert.SubjectCN
		link := ""
		if len(sv.targets) == 1 {
			link = s.TargetLink(st, sv.targets[0].ID)
		}
		desc := fmt.Sprintf("%s, issued by %s, expires %s.\nServed by: %s\nSHA-256 %s", cn, sv.cert.IssuerName(),
			time.Unix(sv.cert.NotAfter, 0).In(loc).Format("2006-01-02 15:04 MST"), strings.Join(lines, ", "), fp)
		events = append(events, calEvent{uid: fp + "@tlswatch", day: time.Unix(sv.cert.NotAfter, 0).In(loc), url: link,
			summary: fmt.Sprintf("Certificate expires: %s (%s)", cn, strings.Join(names, ", ")), description: desc})
		if !sv.renewAt.IsZero() {
			events = append(events, calEvent{uid: "renew-" + fp + "@tlswatch", day: sv.renewAt.In(loc), url: link,
				summary:     fmt.Sprintf("Renewal due: %s (%s)", cn, strings.Join(names, ", ")),
				description: "The renewal point of " + strings.Join(names, ", ") + ": the ACME client should have replaced the certificate by now.\n" + desc})
		}
	}
	return renderICS(calendarName(c), events, s.now()), nil
}

func calendarName(c Calendar) string {
	if c.Tag != "" {
		return "tlswatch expiries · " + c.Tag
	}
	return "tlswatch expiries"
}

// renderICS writes an iCalendar document (RFC 5545) with CRLF line ends
// and lines folded at 75 octets.
func renderICS(name string, events []calEvent, now time.Time) []byte {
	var b strings.Builder
	line := func(s string) { b.WriteString(foldICS(s)) }
	line("BEGIN:VCALENDAR")
	line("VERSION:2.0")
	line("PRODID:-//tlswatch//expiry calendar//EN")
	line("CALSCALE:GREGORIAN")
	line("METHOD:PUBLISH")
	line("X-WR-CALNAME:" + escapeICS(name))
	line("REFRESH-INTERVAL;VALUE=DURATION:PT1H")
	stamp := now.UTC().Format("20060102T150405Z")
	for _, e := range events {
		line("BEGIN:VEVENT")
		line("UID:" + e.uid)
		line("DTSTAMP:" + stamp)
		line("DTSTART;VALUE=DATE:" + e.day.Format("20060102"))
		line("DTEND;VALUE=DATE:" + e.day.AddDate(0, 0, 1).Format("20060102"))
		line("SUMMARY:" + escapeICS(e.summary))
		line("DESCRIPTION:" + escapeICS(e.description))
		if e.url != "" {
			line("URL:" + e.url)
		}
		line("TRANSP:TRANSPARENT")
		line("END:VEVENT")
	}
	line("END:VCALENDAR")
	return []byte(b.String())
}

// escapeICS escapes a TEXT value.
func escapeICS(s string) string {
	r := strings.NewReplacer(`\`, `\\`, ";", `\;`, ",", `\,`, "\r\n", `\n`, "\n", `\n`, "\r", "")
	return r.Replace(s)
}

// foldICS ends a content line with CRLF, folding it into lines of at most
// 75 octets, continuation lines starting with a space, without splitting
// a UTF-8 character.
func foldICS(s string) string {
	var b strings.Builder
	limit := 75
	for len(s) > limit {
		cut := limit
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		b.WriteString(s[:cut])
		b.WriteString("\r\n ")
		s = s[cut:]
		limit = 74 // the leading space counts
	}
	b.WriteString(s)
	b.WriteString("\r\n")
	return b.String()
}

// CalendarURL is the address of a feed's token under the base URL.
func CalendarURL(st config.Settings, base, token string) string {
	if st.General.BaseURL != "" {
		base = st.General.BaseURL
	}
	return strings.TrimRight(base, "/") + "/calendar/" + token + ".ics"
}
