package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/sjoerd305/tlswatch/internal/core"
)

func scaleRequest(s *Server, ri *reqInfo, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r = r.WithContext(context.WithValue(r.Context(), keyReq, ri))
	w := httptest.NewRecorder()
	if strings.HasPrefix(path, "/api/") {
		s.apiTargets(w, r)
	} else {
		s.targets(w, r)
	}
	return w
}

// Compare the database implementation with the old Go filter/sort contract,
// including non-ASCII folding, literal LIKE metacharacters, missing values,
// node labels, status aliases, exact tags and matches across field boundaries.
func TestTargetDatabaseFilterAndSortParity(t *testing.T) {
	s, _ := targetScaleFixture(t, 237)
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO nodes(id,name,state,created_at,updated_at) VALUES(7,'Équipe','confirmed',1,1)`,
		`UPDATE targets SET name='ÄPI 100%_队', status='changed',tags='prod,site:ams',node_id=7 WHERE id=1`,
		`UPDATE targets SET name='',grade='',pq='',not_after=0,current_fp='',tls_version='',last_check=0 WHERE id=2`,
		`UPDATE targets SET host='2001:db8::1',status='disabled',enabled=0,current_fp='',not_after=0 WHERE id=3`,
		`UPDATE targets SET pq='yes' WHERE id%3=0`,
		`UPDATE certificates SET issuer_org='Émetteur' WHERE serial='1'`,
		`UPDATE certificates SET self_signed=1 WHERE serial='2'`,
	} {
		if _, err := s.Core.DB.W.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.Core.Targets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	queries := []string{"", "status=warning", "status=changed", "status=disabled", "tag=prod", "tag=production", "tag=prod,site:ams", "grade=none", "pq=untested", "pq=yes", "node=server", "node=7", "node=07", "q=äpi", "q=100%25_", "q=émetteur", "q=équipe", "q=self-signed", "q=%5B2001:db8::1%5D:443", "q=production+site:ams", "q=no-match", "q=%27+OR+1%3D1--", "tag=%27+OR+1%3D1--", "node=7+OR+1%3D1", "tag=production&pq=yes&grade=A", "status=warning&node=7&q=äpi"}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			q, _ := url.ParseQuery(query)
			f := targetFilterFrom(q)
			var want []int64
			for _, tg := range all {
				if f.matches(tg, "") {
					want = append(want, tg.ID)
				}
			}
			slices.Sort(want)
			var got []int64
			var after int64
			for {
				page, err := s.Core.TargetPage(ctx, f.coreFilter(), after, 7)
				if err != nil {
					t.Fatal(err)
				}
				more := len(page) > 7
				if more {
					page = page[:7]
				}
				for _, tg := range page {
					got = append(got, tg.ID)
					after = tg.ID
				}
				if !more {
					break
				}
				if len(got) > len(all) {
					t.Fatal("cursor did not advance")
				}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("IDs %v, want %v", got, want)
			}
			facets, err := s.Core.TargetFacetCounts(ctx, f.coreFilter())
			if err != nil {
				t.Fatal(err)
			}
			if facets.Total != len(all) || facets.Matching != len(want) {
				t.Fatalf("counts %+v, matching=%d", facets, len(want))
			}
			for _, g := range []struct {
				key    string
				counts map[string]core.FacetCount
				token  func(core.Target) []string
			}{
				{"status", facets.Status, func(t core.Target) []string { return []string{chipStatus(t.Status)} }},
				{"tag", facets.Tags, func(t core.Target) []string { return t.Tags }},
				{"grade", facets.Grade, func(t core.Target) []string { return []string{gradeToken(t)} }},
				{"pq", facets.PQ, func(t core.Target) []string { return []string{pqToken(t)} }},
				{"node", facets.Node, func(t core.Target) []string { return []string{nodeToken(t)} }},
			} {
				expected := map[string]core.FacetCount{}
				for _, tg := range all {
					for _, value := range g.token(tg) {
						v := expected[value]
						v.Total++
						if f.matches(tg, g.key) {
							v.Matching++
						}
						expected[value] = v
					}
				}
				if fmt.Sprint(g.counts) != fmt.Sprint(expected) {
					t.Errorf("%s facets %v want %v", g.key, g.counts, expected)
				}
			}
		})
	}
	for _, key := range targetSortKeys {
		for _, desc := range []bool{false, true} {
			t.Run(fmt.Sprintf("sort/%s/%t", key, desc), func(t *testing.T) {
				rows := make([]targetRow, len(all))
				for i, tg := range all {
					rows[i] = targetRow{T: tg, Now: s.now()}
				}
				sortRows(Sort{Key: key, Desc: desc, def: "days"}, rows, targetRow.sortVal)
				var got []int64
				for offset := 0; offset < len(all); offset += 37 {
					page, err := s.Core.TargetListPage(ctx, core.TargetFilter{}, key, desc, offset, 37, s.now())
					if err != nil {
						t.Fatal(err)
					}
					for _, tg := range page {
						got = append(got, tg.ID)
					}
				}
				for i, row := range rows {
					if got[i] != row.T.ID {
						t.Fatalf("at %d got %d want %d", i, got[i], row.T.ID)
					}
				}
			})
		}
	}
}

func TestTargetPagesBoundRowsAndKeepFilters(t *testing.T) {
	s, ri := targetScaleFixture(t, 237)
	for _, path := range []string{"/targets", "/targets?page=2", "/targets?page=3", "/targets?page=999999999", "/targets?group=tag", "/targets?q=no-match"} {
		w := scaleRequest(s, ri, path)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		n := strings.Count(w.Body.String(), `<tr id="target-`)
		limit := 100
		if strings.Contains(path, "group=") {
			limit = 200
		}
		if strings.Contains(path, "no-match") {
			limit = 0
		}
		if n > limit {
			t.Fatalf("%s rendered %d rows", path, n)
		}
		if limit > 0 && n == 0 {
			t.Fatalf("%s rendered no rows", path)
		}
	}
	w := scaleRequest(s, ri, "/targets?page=2&sort=name&tag=production&pq=untested&q=Target")
	for _, want := range []string{`name="tag" value="production"`, `name="pq" value="untested"`, `name="sort" value="name"`, `Page 2 of 3`, `Select all targets on this page`, `page=3`, `q=Target`, `href="/targets?pq=untested&amp;q=Target&amp;sort=name&amp;tag=production"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, path := range []string{"/targets?page=-1", "/targets?page=bad", "/targets?page=0"} {
		if w := scaleRequest(s, ri, path); w.Code != 400 {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
	// Reset a page when sorting or changing a chip; keep the other filters.
	r := httptest.NewRequest("GET", "/targets?page=3&tag=production&q=Target", nil)
	if strings.Contains(chipHref(r, "pq", "yes"), "page=") || strings.Contains(sortFrom(r, "days", targetSortKeys...).Href("name"), "page=") {
		t.Error("filter/sort retained a stale page")
	}
	// Walk the actual JSON cursor contract and cover every ID exactly once.
	seen := map[int64]bool{}
	cursor := ""
	for {
		w := scaleRequest(s, ri, "/api/v2/targets?limit=31&cursor="+cursor)
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		var page struct {
			Data []struct {
				ID int64 `json:"id"`
			}
			Next *string `json:"next_cursor"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Data) > 31 {
			t.Fatal("oversized page")
		}
		for _, tg := range page.Data {
			if seen[tg.ID] {
				t.Fatal("duplicate cursor ID")
			}
			seen[tg.ID] = true
		}
		if page.Next == nil {
			break
		}
		cursor = *page.Next
		if len(seen) > 237 {
			t.Fatal("unbounded cursor")
		}
	}
	if len(seen) != 237 {
		t.Fatalf("walk saw %d targets", len(seen))
	}
	// Invalid parameters are rejected before any database work.
	_ = s.Core.DB.Close()
	for _, query := range []string{"limit=0", "limit=501", "limit=x", "cursor=!!!", "cursor=" + base64.RawURLEncoding.EncodeToString([]byte("-1")), "cursor=" + base64.RawURLEncoding.EncodeToString([]byte("99999999999999999999"))} {
		if w := scaleRequest(s, ri, "/api/v2/targets?"+query); w.Code != 400 {
			t.Errorf("%s: %d", query, w.Code)
		}
	}
}

func TestTargetListsBeyondSQLiteParameterLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("large inventory regression")
	}
	s, ri := targetScaleFixture(t, 33000)
	// Use a distinct fingerprint per target, so deduplication alone cannot
	// hide a parameter-limit regression in full-list/export callers.
	if _, err := s.Core.DB.W.Exec(`UPDATE targets SET current_fp=printf('%064x',id)`); err != nil {
		t.Fatal(err)
	}
	all, err := s.Core.Targets(context.Background())
	if err != nil || len(all) != 33000 {
		t.Fatalf("full list: %d %v", len(all), err)
	}
	for _, path := range []string{"/targets", "/targets?page=330", "/api/v2/targets?limit=1", "/api/v2/targets?limit=500"} {
		w := scaleRequest(s, ri, path)
		if w.Code != 200 {
			t.Errorf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
}

func TestTargetPageChannelLinks(t *testing.T) {
	s, _ := targetScaleFixture(t, 1100)
	for _, q := range []string{
		`INSERT INTO channels(id,name,kind,settings,created_at,updated_at) VALUES(1,'one','smtp',x'00',1,1),(2,'two','smtp',x'00',1,1)`,
		`INSERT INTO target_channels(target_id,channel_id) SELECT id,1 FROM targets WHERE id%2=0`,
		`INSERT INTO target_channels(target_id,channel_id) SELECT id,2 FROM targets WHERE id%3=0`,
	} {
		if _, err := s.Core.DB.W.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.Core.Targets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Core.TargetChannels(context.Background(), all); err != nil {
		t.Fatal(err)
	}
	for _, tg := range all {
		var want []int64
		if tg.ID%2 == 0 {
			want = append(want, 1)
		}
		if tg.ID%3 == 0 {
			want = append(want, 2)
		}
		if !slices.Equal(tg.ChannelIDs, want) {
			t.Fatalf("target %d: channels %v want %v", tg.ID, tg.ChannelIDs, want)
		}
	}
}
