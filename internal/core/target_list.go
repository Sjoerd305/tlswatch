package core

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// TargetFilter is shared by the paginated UI and REST API. Text is a literal,
// Unicode-case-insensitive substring, not a LIKE pattern.
type TargetFilter struct {
	Status, Tag, Text, Node, Grade, PQ string
}

const targetListFrom = targetFrom + " LEFT JOIN certificates c ON c.fingerprint = t.current_fp "
const targetIssuer = "CASE WHEN c.self_signed = 1 THEN 'self-signed' WHEN c.issuer_org != '' THEN c.issuer_org ELSE COALESCE(c.issuer_cn, '') END"

func (f TargetFilter) where(skip string) (string, []any) {
	var clauses []string
	var args []any
	add := func(q string, v any) { clauses = append(clauses, q); args = append(args, v) }
	if f.Status != "" && skip != "status" {
		// StatusChanged shares the warning chip.
		if f.Status == StatusChanged {
			clauses = append(clauses, "0")
		} else if f.Status == "warning" {
			add("t.status IN ('warning', ?)", StatusChanged)
		} else {
			add("t.status = ?", f.Status)
		}
	}
	if f.Tag != "" && skip != "tag" {
		if strings.Contains(f.Tag, ",") {
			clauses = append(clauses, "0")
		} else {
			add("instr(',' || t.tags || ',', ',' || ? || ',') > 0", f.Tag)
		}
	}
	if f.Node != "" && skip != "node" {
		add("CASE WHEN t.node_id IS NULL THEN 'server' ELSE CAST(t.node_id AS TEXT) END = ?", f.Node)
	}
	if f.Grade != "" && skip != "grade" {
		v := f.Grade
		if v == "none" {
			v = ""
		}
		add("t.grade = ?", v)
	}
	if f.PQ != "" && skip != "pq" {
		v := f.PQ
		if v == "untested" {
			v = ""
		}
		add("t.pq = ?", v)
	}
	if text := strings.ToLower(strings.TrimSpace(f.Text)); text != "" {
		// Keep the exact field order and separators of the UI's targetSearch.
		search := "t.name || ' ' || tlswatch_hostport(t.host,t.port) || ' ' || t.servername || ' ' || t.protocol || ' ' || replace(t.tags, ',', ' ') || ' ' || COALESCE(n.name, '') || CASE WHEN c.fingerprint IS NULL THEN '' ELSE ' ' || " + targetIssuer + " || ' ' || c.subject_cn END"
		add("instr(tlswatch_lower("+search+"), ?) > 0", text)
	}
	if len(clauses) == 0 {
		return "1", nil
	}
	return strings.Join(clauses, " AND "), args
}

// TargetPage reads a bounded API page in primary-key order, with one extra
// row to detect the next page. Certificate data is loaded only for this page.
func (s *Service) TargetPage(ctx context.Context, f TargetFilter, after int64, limit int) ([]Target, error) {
	if limit < 1 || limit > 500 {
		return nil, fmt.Errorf("target page limit must be 1 to 500")
	}
	where, args := f.where("")
	args = append(args, after, limit+1)
	return s.readTargets(ctx, "SELECT "+targetCols+targetListFrom+" WHERE "+where+" AND t.id > ? ORDER BY t.id LIMIT ?", args...)
}

// TargetListPage reads just the requested UI page. Sort keys are allowlisted;
// equal values keep the existing expiry order, with id as the final tie-break.
func (s *Service) TargetListPage(ctx context.Context, f TargetFilter, key string, desc bool, offset, limit int, now time.Time) ([]Target, error) {
	if offset < 0 || limit < 1 || limit > 500 {
		return nil, fmt.Errorf("invalid target page")
	}
	where, args := f.where("")
	base := strings.TrimPrefix(targetOrder, " ORDER BY ") + ", t.id"
	order := base
	dir := " ASC"
	if desc {
		dir = " DESC"
	}
	text := func(v string) string { return "NULLIF(tlswatch_lower(" + v + "), '')" }
	var value string
	switch key {
	case "name":
		value = text("t.name")
	case "host":
		value = text("tlswatch_hostport(t.host,t.port)")
	case "node":
		value = text("COALESCE(n.name, '')")
	case "status":
		value = "CASE t.status WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 WHEN 'changed' THEN 1 WHEN 'healthy' THEN 2 WHEN 'unreachable' THEN 3 WHEN 'pending' THEN 4 ELSE 5 END"
	case "days", "expires":
		value = "NULLIF(t.not_after, 0)"
	case "checked":
		value = "NULLIF(t.last_check, 0)"
	case "tls":
		value = text("t.tls_version")
	case "tags":
		value = text("replace(t.tags, ',', ' ')")
	case "issuer":
		value = text(targetIssuer)
	case "grade":
		value = "CASE t.grade WHEN '' THEN NULL WHEN 'A' THEN -4 WHEN 'B' THEN -3 WHEN 'C' THEN -2 WHEN 'F' THEN -1 ELSE 0 END"
	case "lifetime":
		value = "CASE WHEN c.fingerprint IS NULL THEN NULL WHEN c.not_after <= c.not_before THEN 100 ELSE min(100, max(0, ((? - c.not_before) * 100) / (c.not_after - c.not_before))) END"
		// This placeholder follows the WHERE placeholders and precedes LIMIT.
		args = append(args, now.Unix())
	default:
		key, desc = "days", false
	}
	if key != "days" || desc {
		order = value + dir + " NULLS LAST, " + base
	}
	args = append(args, limit, offset)
	return s.readTargets(ctx, "SELECT "+targetCols+targetListFrom+" WHERE "+where+" ORDER BY "+order+" LIMIT ? OFFSET ?", args...)
}

// FacetCount counts every target in a group and those matching all the other
// filters. This preserves the existing chip behavior without loading targets.
type FacetCount struct{ Total, Matching int }
type TargetFacets struct {
	Status, Tags, Grade, PQ, Node map[string]FacetCount
	Total, Matching               int
}

func (s *Service) TargetFacetCounts(ctx context.Context, f TargetFilter) (TargetFacets, error) {
	var out TargetFacets
	// Materialize only the small facet columns and six match flags once.
	// A text search is folded once per target, rather than once per chip group.
	fields := []string{
		"CASE WHEN t.status = 'changed' THEN 'warning' ELSE t.status END AS status",
		"t.tags AS tags",
		"CASE WHEN t.grade = '' THEN 'none' ELSE t.grade END AS grade",
		"CASE WHEN t.pq = '' THEN 'untested' ELSE t.pq END AS pq",
		"CASE WHEN t.node_id IS NULL THEN 'server' ELSE CAST(t.node_id AS TEXT) END AS node",
	}
	filters := []struct {
		name   string
		filter TargetFilter
	}{
		{"status", TargetFilter{Status: f.Status}}, {"tag", TargetFilter{Tag: f.Tag}},
		{"grade", TargetFilter{Grade: f.Grade}}, {"pq", TargetFilter{PQ: f.PQ}},
		{"node", TargetFilter{Node: f.Node}}, {"text", TargetFilter{Text: f.Text}},
	}
	var args []any
	for _, g := range filters {
		condition, values := g.filter.where("")
		fields = append(fields, "("+condition+") AS "+g.name+"_ok")
		args = append(args, values...)
	}
	var parts []string
	for _, key := range []string{"status", "tag", "grade", "pq", "node", "count"} {
		var conditions []string
		for _, g := range filters {
			if g.name != key {
				conditions = append(conditions, g.name+"_ok")
			}
		}
		value, from, group := key, " FROM base", " GROUP BY "+key
		if key == "tag" {
			value = "tag.value"
			from += ", json_each(tlswatch_tags(tags)) tag"
			group = " GROUP BY tag.value"
		}
		if key == "count" {
			value = "''"
			group = ""
		}
		parts = append(parts, "SELECT '"+key+"', "+value+", COUNT(*), COALESCE(SUM("+strings.Join(conditions, " AND ")+"),0)"+from+group)
	}
	// #nosec G202 -- expressions and identifiers are fixed above; filter values are bound
	q := "WITH base AS MATERIALIZED (SELECT " + strings.Join(fields, ",") + targetListFrom + ") " + strings.Join(parts, " UNION ALL ")
	rows, err := s.DB.R.QueryContext(ctx, q, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	out.Status = map[string]FacetCount{}
	out.Tags = map[string]FacetCount{}
	out.Grade = map[string]FacetCount{}
	out.PQ = map[string]FacetCount{}
	out.Node = map[string]FacetCount{}
	for rows.Next() {
		var kind, key string
		var v FacetCount
		if err := rows.Scan(&kind, &key, &v.Total, &v.Matching); err != nil {
			return out, err
		}
		switch kind {
		case "status":
			out.Status[key] = v
		case "tag":
			out.Tags[key] = v
		case "grade":
			out.Grade[key] = v
		case "pq":
			out.PQ[key] = v
		case "node":
			out.Node[key] = v
		case "count":
			out.Total = v.Total
			out.Matching = v.Matching
		}
	}
	return out, rows.Err()
}
