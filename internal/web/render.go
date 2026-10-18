package web

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/ct"
	"github.com/sjoerd305/tlswatch/internal/probe"
	assets "github.com/sjoerd305/tlswatch/web"
)

// Notice is a bar at the top of the content.
type Notice struct {
	Kind string // ok, warn, crit, info
	Text string
	Link string // optional copyable link shown under the text
}

// Page is the data every page template receives.
type Page struct {
	Title    string
	Nav      string
	User     *auth.User
	CSRF     string
	Theme    string
	Counts   core.NavCounts
	Now      time.Time
	Loc      *time.Location
	Notices  []Notice
	Settings config.Settings
	Version  string
	Assets   string // versioned URL prefix of the static files
	Data     any
	// Path is the request's path and query, for forms that return to it.
	Path string
	// SettingsNav is the active settings sub-page.
	SettingsNav string
	// Live pages refresh themselves when Stamp changes on the server.
	Live  bool
	Stamp string
	// Demo is demo mode: the chrome says so, and has no account menu.
	Demo bool
}

// Can reports whether the signed-in user may perform an action.
func (p *Page) Can(a string) bool {
	return p.User != nil && authz.Allowed(p.User.Role, authz.Action(a))
}

func (s *Server) loadTemplates() error {
	funcs := s.funcs()
	base, err := template.New("base").Funcs(funcs).ParseFS(assets.FS, "templates/layout.html", "templates/partials.html")
	if err != nil {
		return err
	}
	files, err := fs.Glob(assets.FS, "templates/pages/*.html")
	if err != nil {
		return err
	}
	s.pages = map[string]*template.Template{}
	for _, f := range files {
		t, err := base.Clone()
		if err != nil {
			return err
		}
		if _, err := t.ParseFS(assets.FS, f); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		s.pages[strings.TrimSuffix(path.Base(f), ".html")] = t
	}
	s.pages["_partials"] = base
	return nil
}

// fill completes the common page fields.
func (s *Server) fill(w http.ResponseWriter, r *http.Request, p *Page) {
	ri := info(r)
	p.Now = s.now()
	p.Settings = ri.settings
	p.Loc = ri.settings.Location()
	p.Version = s.Version
	p.Demo = s.Demo
	p.Assets = "/static/" + assetVersion(s.Version)
	p.Path = r.URL.RequestURI()
	p.Theme = "system"
	if c, err := r.Cookie(themeCookie); err == nil {
		switch c.Value {
		case "light", "dark":
			p.Theme = c.Value
		}
	}
	if ri.session != nil {
		u := ri.session.User
		p.User = &u
		p.CSRF = ri.session.CSRF
		if u.Theme != "" {
			p.Theme = u.Theme
		}
		p.Counts = s.Core.Nav(r.Context())
		if p.Live {
			p.Stamp = s.stamp(r.Context())
		}
		// The reminder is for the home screen only, not every page.
		if p.Nav == "overview" && u.Role == authz.Admin && ri.settings.General.BaseURL == "" {
			p.Notices = append(p.Notices, Notice{Kind: "info", Text: "Set the public URL under Settings › General so alerts link back to tlswatch."})
		}
		if p.Nav == "overview" {
			p.Notices = append(p.Notices, s.offlineNotices(r.Context(), p.Loc, p.Now)...)
		}
	} else {
		p.CSRF = s.preCSRF(w, r)
	}
	if n := s.flash(w, r); n != nil {
		p.Notices = append([]Notice{*n}, p.Notices...)
	}
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, p *Page) {
	s.renderStatus(w, r, http.StatusOK, name, p)
}

func (s *Server) renderStatus(w http.ResponseWriter, r *http.Request, status int, name string, p *Page) {
	t, ok := s.pages[name]
	if !ok {
		s.Log.Error("render: unknown page", "page", name, "path", r.URL.Path)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	s.fill(w, r, p)
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		s.Log.Error("render", "page", name, "path", r.URL.Path, "err", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// fragment renders a named partial for the JSON API.
func (s *Server) fragment(r *http.Request, name string, data any) (string, error) {
	var buf bytes.Buffer
	err := s.pages["_partials"].ExecuteTemplate(&buf, name, data)
	return buf.String(), err
}

// frag is the data passed to partials: the page context plus one item.
type frag struct {
	P    *Page
	Item any
}

// fragPage is the page context for a fragment of the JSON API: what the
// partials use, without the navigation counts or the flash notice of a full
// page.
func (s *Server) fragPage(r *http.Request) *Page {
	ri := info(r)
	p := &Page{Now: s.now(), Settings: ri.settings, Loc: ri.settings.Location(), Version: s.Version}
	if ri.session != nil {
		u := ri.session.User
		p.User, p.CSRF = &u, ri.session.CSRF
	}
	return p
}

func (s *Server) funcs() template.FuncMap {
	return template.FuncMap{
		"frag": func(p *Page, item any) frag { return frag{P: p, Item: item} },
		"date": func(loc *time.Location, unix int64) string {
			if unix == 0 {
				return "—"
			}
			return time.Unix(unix, 0).In(loc).Format("2006-01-02")
		},
		"datetime": func(loc *time.Location, unix int64) string {
			if unix == 0 {
				return "—"
			}
			return time.Unix(unix, 0).In(loc).Format("2006-01-02 15:04")
		},
		"clock": func(loc *time.Location, unix int64) string {
			if unix == 0 {
				return "—"
			}
			return time.Unix(unix, 0).In(loc).Format("15:04")
		},
		// when is a compact relative time: "04:14" today, "13 Oct" this year.
		"when": func(loc *time.Location, now time.Time, unix int64) string { return when(loc, now, unix, false) },
		// whenTime adds the time of day to older dates: "13 Oct 04:14".
		"whenTime": func(loc *time.Location, now time.Time, unix int64) string { return when(loc, now, unix, true) },
		"days":     func(now time.Time, unix int64) int { return check.DaysLeft(time.Unix(unix, 0), now) },
		"left":     newTimeLeft,
		// pct is a lifetime percentage as a placeholder shows it.
		"pct": func(n int) string {
			if n == 0 {
				return "off"
			}
			return fmt.Sprintf("%d %%", n)
		},
		// threshold is a threshold as help text names it: "30 d or 33 %".
		"threshold": func(days, pct int) string {
			if pct == 0 {
				return fmt.Sprintf("%d d", days)
			}
			return fmt.Sprintf("%d d or %d %%", days, pct)
		},
		"renewalPoint": func() int { return check.DefaultRenewalPoint },
		"daysPtr": func(p *int) string {
			if p == nil {
				return "—"
			}
			return fmt.Sprint(*p)
		},
		"intv": func(p *int) int {
			if p == nil {
				return 0
			}
			return *p
		},
		"isnil":       func(p *int) bool { return p == nil },
		"used":        func(now time.Time, nb, na int64) int { return core.LifetimeUsed(nb, na, now) },
		"statusClass": core.StatusClass,
		"statusLabel": core.StatusLabel,
		"short": func(fp string) string {
			if len(fp) > 8 {
				return fp[:8]
			}
			return fp
		},
		"fpfmt":  formatFP,
		"join":   strings.Join,
		"lower":  strings.ToLower,
		"kinds":  func() []check.Kind { return check.Kinds },
		"roles":  func() []authz.Role { return authz.Roles },
		"hasTag": func(tags []string, t string) bool { return contains(tags, t) },
		"hasID": func(ids []int64, id int64) bool {
			for _, v := range ids {
				if v == id {
					return true
				}
			}
			return false
		},
		"duration": durationLabel,
		"div":      func(a, b int) int { return a / b },
		"ctLabel":  ct.Label,
		"add":      func(a, b int) int { return a + b },
		"sub":      func(a, b int) int { return a - b },
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
		"weekday": func(d int) string { return time.Weekday(d).String() },
		"seq": func(a, b int) []int {
			var out []int
			for i := a; i <= b; i++ {
				out = append(out, i)
			}
			return out
		},
		"kindLabel": func(k string) string { return check.Kind(k).Label() },
		"sevClass":  func(s string) string { return check.Severity(s).Class() },
		"sevShort":  func(s string) string { return check.Severity(s).Short() },
		"plural": func(n int, one, many string) string {
			if n == 1 {
				return one
			}
			return many
		},
		"defaultPort": func(p probe.Protocol) int { return probe.DefaultPort(p) },
		// waiting: the target's node is offline, so it shows "Waiting for node".
		"waiting":    s.waiting,
		"gradeClass": check.GradeClass,
		"since":      func(now time.Time, unix int64) string { return sinceLabel(now, unix) },
		"offset":     offsetLabel,
		"hostport":   func(host string, port int) string { return core.Target{Host: host, Port: port}.HostPort() },
	}
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func when(loc *time.Location, now time.Time, unix int64, withTime bool) string {
	if unix == 0 {
		return "—"
	}
	t := time.Unix(unix, 0).In(loc)
	n := now.In(loc)
	switch {
	case t.Year() == n.Year() && t.YearDay() == n.YearDay():
		if withTime {
			return "today " + t.Format("15:04")
		}
		return t.Format("15:04")
	case t.Year() == n.Year():
		if withTime {
			return t.Format("2 Jan 15:04")
		}
		return t.Format("2 Jan")
	}
	return t.Format("2 Jan 06")
}

// formatFP groups a hex fingerprint in pairs, uppercased.
func formatFP(fp string) string {
	fp = strings.ToUpper(fp)
	var b strings.Builder
	for i := 0; i < len(fp); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		end := i + 2
		if end > len(fp) {
			end = len(fp)
		}
		b.WriteString(fp[i:end])
	}
	return b.String()
}

// durationLabel renders seconds as "24 h", "7 d" or "never".
func durationLabel(secs int) string {
	switch {
	case secs <= 0:
		return "never"
	case secs%86400 == 0:
		return fmt.Sprintf("%d d", secs/86400)
	case secs%3600 == 0:
		return fmt.Sprintf("%d h", secs/3600)
	}
	return fmt.Sprintf("%d min", secs/60)
}

// sinceLabel is how long ago a moment was: "just now", "12 min ago",
// "3 h ago", "4 d ago".
func sinceLabel(now time.Time, unix int64) string {
	if unix == 0 {
		return "never"
	}
	d := now.Sub(time.Unix(unix, 0))
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d d ago", int(d.Hours()/24))
}

// offsetLabel renders a clock offset in milliseconds: "+0.3 s".
func offsetLabel(ms int64) string {
	if ms > -500 && ms < 500 {
		return "in sync"
	}
	return fmt.Sprintf("%+.1f s", float64(ms)/1000)
}

// timeLeft is the time until an expiry as a days column shows it: whole
// days, or hours under check.HoursUnder days.
type timeLeft struct{ Days, Hours int }

func newTimeLeft(now time.Time, unix int64) timeLeft {
	na := time.Unix(unix, 0)
	return timeLeft{Days: check.DaysLeft(na, now), Hours: int(na.Sub(now) / time.Hour)}
}

func (l timeLeft) String() string {
	if l.Days < check.HoursUnder {
		return fmt.Sprintf("%d h", l.Hours)
	}
	return fmt.Sprint(l.Days)
}

// Short is the compact text beside a date: "31 h", "12 d".
func (l timeLeft) Short() string {
	if l.Days < check.HoursUnder {
		return fmt.Sprintf("%d h", l.Hours)
	}
	return fmt.Sprintf("%d d", l.Days)
}

// Long is the countdown text: "31 h", "1 day", "12 days".
func (l timeLeft) Long() string {
	switch {
	case l.Days < check.HoursUnder:
		return fmt.Sprintf("%d h", l.Hours)
	case l.Days == 1:
		return "1 day"
	}
	return fmt.Sprintf("%d days", l.Days)
}
