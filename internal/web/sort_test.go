package web

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/core"
)

func TestSortFromAndHref(t *testing.T) {
	r := httptest.NewRequest("GET", "/targets?q=badssl&sort=name&dir=desc", nil)
	s := sortFrom(r, "days", targetSortKeys...)
	if s.Key != "name" || !s.Desc || s.Default() {
		t.Fatalf("sort: %+v", s)
	}
	// The active column flips, another starts ascending, the default drops
	// the parameters; the filter stays.
	cases := map[string]string{
		"name":   "?q=badssl&sort=name",
		"host":   "?q=badssl&sort=host",
		"days":   "?q=badssl",
		"status": "?q=badssl&sort=status",
	}
	for key, want := range cases {
		if got := s.Href(key); got != want {
			t.Errorf("Href(%s) = %s, want %s", key, got, want)
		}
	}
	if s.Dir("name") != "descending" || s.Dir("host") != "" {
		t.Errorf("dir: %s %s", s.Dir("name"), s.Dir("host"))
	}
	// An unknown column is the default; its link reverses the list.
	r = httptest.NewRequest("GET", "/targets?sort=bogus", nil)
	s = sortFrom(r, "days", targetSortKeys...)
	if !s.Default() || s.Href("days") != "?dir=desc&sort=days" || s.Dir("days") != "ascending" {
		t.Fatalf("default: %+v href %s dir %s", s, s.Href("days"), s.Dir("days"))
	}
	if s.Href("name") != "?sort=name" {
		t.Fatalf("name: %s", s.Href("name"))
	}
}

func TestSortRowsAndAttrs(t *testing.T) {
	rows := []targetRow{
		{T: core.Target{Name: "b", Status: core.StatusHealthy, NotAfter: 300}},
		{T: core.Target{Name: "a", Status: core.StatusCritical}},
		{T: core.Target{Name: "C", Status: core.StatusWarning, NotAfter: 100}},
	}
	names := func() string {
		var out []string
		for _, r := range rows {
			out = append(out, r.T.Name)
		}
		return strings.Join(out, "")
	}
	s := Sort{Key: "name", def: "days"}
	sortRows(s, rows, targetRow.sortVal)
	if names() != "abC" {
		t.Fatalf("by name: %s", names())
	}
	s = Sort{Key: "days", Desc: true, def: "days"}
	sortRows(s, rows, targetRow.sortVal)
	if names() != "bCa" { // a has no certificate and stays last
		t.Fatalf("by days desc: %s", names())
	}
	s = Sort{Key: "status", def: "days"}
	sortRows(s, rows, targetRow.sortVal)
	if names() != "aCb" {
		t.Fatalf("by status: %s", names())
	}
	s = Sort{Key: "days", def: "days"}
	before := names()
	sortRows(s, rows, targetRow.sortVal)
	if names() != before {
		t.Fatalf("the default order must not re-sort: %s", names())
	}
	attrs := string(rows[0].SortAttrs())
	if !strings.Contains(attrs, ` data-sort-name="a"`) || !strings.Contains(attrs, ` data-sort-status="0"`) || strings.Contains(attrs, "data-sort-days") {
		t.Fatalf("attrs: %s", attrs)
	}
	quoted := targetRow{T: core.Target{Name: `x" onclick="y`}}
	if a := string(quoted.SortAttrs()); strings.Contains(a, `onclick="`) {
		t.Fatalf("unescaped: %s", a)
	}
}

func TestGroupFindings(t *testing.T) {
	rows := []findingRow{
		{Finding: core.Finding{ID: 1, Kind: check.LegacyProtocol}},
		{Finding: core.Finding{ID: 2, Kind: check.Expired}},
		{Finding: core.Finding{ID: 3, Kind: check.LegacyProtocol}},
	}
	groups := groupFindings(rows)
	if len(groups) != 2 || groups[0].Kind != check.Expired || len(groups[1].Rows) != 2 || groups[1].Rows[1].ID != 3 {
		t.Fatalf("groups: %+v", groups)
	}
}
