package web

import (
	"html"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/sjoerd305/tlswatch/internal/core"
)

// Sort is a list's order, from the URL: ?sort=key&dir=desc. Every list has
// a default column whose ascending order is the list's own (the targets by
// expiry, the findings by severity); that order shows as the default column
// sorted ascending, and a click on it reverses the list.
//
// The TypeScript sorts the rendered rows the same way from the data-sort-*
// attributes that sortAttrs writes, and puts the choice in the URL, so a
// reload or a live refresh renders the same order from here.
type Sort struct {
	Key  string
	Desc bool
	def  string
	path string
	q    url.Values
}

// sortFrom reads the sort from the request; keys are the sortable columns
// and def the default among them. An unknown key means the default.
func sortFrom(r *http.Request, def string, keys ...string) Sort {
	q := r.URL.Query()
	s := Sort{Key: q.Get("sort"), Desc: q.Get("dir") == "desc", def: def, path: r.URL.Path, q: q}
	if !slices.Contains(keys, s.Key) {
		s.Key, s.Desc = def, false
	}
	return s
}

// Default reports whether the list is in its own order.
func (s Sort) Default() bool { return s.Key == s.def && !s.Desc }

// Href is the link that sorts by key: the active column flips its
// direction, another column starts ascending. The other parameters (filter,
// chips, selection) stay.
func (s Sort) Href(key string) string {
	q := url.Values{}
	for k, v := range s.q {
		q[k] = v
	}
	q.Del("page")
	desc := key == s.Key && !s.Desc
	q.Del("sort")
	q.Del("dir")
	if key != s.def || desc {
		q.Set("sort", key)
	}
	if desc {
		q.Set("dir", "desc")
	}
	if enc := q.Encode(); enc != "" {
		return "?" + enc
	}
	return s.path
}

// Dir is the aria-sort value of a column: ascending, descending or empty.
func (s Sort) Dir(key string) string {
	if key != s.Key {
		return ""
	}
	if s.Desc {
		return "descending"
	}
	return "ascending"
}

// sortVal is a cell's value for sorting: a number or a text, or none.
type sortVal struct {
	n   float64
	s   string
	num bool
	ok  bool
}

func num(v float64) sortVal { return sortVal{n: v, num: true, ok: true} }

// numIf is a number that is missing when ok is false (no certificate yet).
func numIf(ok bool, v float64) sortVal { return sortVal{n: v, num: true, ok: ok} }

func txt(v string) sortVal { return sortVal{s: v, ok: v != ""} }

func (v sortVal) compare(w sortVal) int {
	if v.num {
		switch {
		case v.n < w.n:
			return -1
		case v.n > w.n:
			return 1
		}
		return 0
	}
	return strings.Compare(strings.ToLower(v.s), strings.ToLower(w.s))
}

func (v sortVal) text() string {
	if v.num {
		return strconv.FormatFloat(v.n, 'f', -1, 64)
	}
	return v.s
}

// sortRows orders rows by the active column. Rows without a value go last
// whichever the direction; equal rows keep the list's own order.
func sortRows[T any](s Sort, rows []T, val func(T, string) sortVal) {
	if s.Default() {
		return
	}
	slices.SortStableFunc(rows, func(a, b T) int {
		va, vb := val(a, s.Key), val(b, s.Key)
		if va.ok != vb.ok {
			if va.ok {
				return -1
			}
			return 1
		}
		if !va.ok {
			return 0
		}
		c := va.compare(vb)
		if s.Desc {
			c = -c
		}
		return c
	})
}

// sortAttrs renders a row's values as data-sort-<key> attributes for the
// TypeScript sort; a missing value gets no attribute.
func sortAttrs(keys []string, val func(string) sortVal) template.HTMLAttr {
	var b strings.Builder
	for _, k := range keys {
		if v := val(k); v.ok {
			b.WriteString(` data-sort-` + k + `="` + html.EscapeString(v.text()) + `"`)
		}
	}
	return template.HTMLAttr(b.String()) // #nosec G203 -- keys are literals, values escaped
}

// statusRank orders target statuses from most to least urgent.
func statusRank(status string) int {
	switch status {
	case core.StatusCritical:
		return 0
	case core.StatusWarning, core.StatusChanged:
		return 1
	case core.StatusAcknowledged:
		return 2
	case core.StatusHealthy:
		return 3
	case core.StatusUnreachable:
		return 4
	case core.StatusPending:
		return 5
	}
	return 6
}
