package web

import (
	"encoding/json"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// The OpenAPI document of the public API, generated from apiRoutes and the
// Go types of the bodies and responses, so it cannot drift from the
// handlers. Served without sign-in: it describes the API, not the data.

func (s *Server) openAPI(w http.ResponseWriter, r *http.Request) {
	b, err := json.MarshalIndent(s.openAPIDocument(), "", "  ")
	if err != nil {
		s.Log.Error("openapi", "err", err)
		apiFail(w, http.StatusInternalServerError, "internal", "The document could not be built.")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(b)
}

var pathParam = regexp.MustCompile(`\{(\w+)\}`)

// openAPIDocument builds the document as nested maps.
func (s *Server) openAPIDocument() map[string]any {
	g := &schemaGen{schemas: map[string]any{}}
	errRef := g.ref(reflect.TypeOf(apiErrorBody{}))
	errResp := func(desc string) map[string]any {
		return map[string]any{"description": desc, "content": map[string]any{"application/json": map[string]any{"schema": errRef}}}
	}
	paths := map[string]any{}
	for _, a := range s.apiRoutes() {
		op := map[string]any{"summary": a.Summary, "operationId": operationID(a), "x-role-action": string(a.Action)}
		var params []any
		for _, m := range pathParam.FindAllStringSubmatch(a.Path, -1) {
			typ := map[string]any{"type": "integer", "format": "int64", "minimum": 1}
			if m[1] == "fp" {
				typ = map[string]any{"type": "string", "pattern": "^[0-9a-f]{64}$"}
			}
			params = append(params, map[string]any{"name": m[1], "in": "path", "required": true, "schema": typ})
		}
		for _, q := range a.Query {
			params = append(params, map[string]any{"name": q.Name, "in": "query", "description": q.Doc, "schema": map[string]any{"type": "string"}})
		}
		if params != nil {
			op["parameters"] = params
		}
		if a.Body != nil {
			op["requestBody"] = map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": g.ref(reflect.TypeOf(a.Body))}}}
		}
		status := a.Status
		if status == 0 {
			status = http.StatusOK
		}
		ok := map[string]any{"description": http.StatusText(status)}
		switch {
		case a.Resp == nil:
		case reflect.TypeOf(a.Resp).Kind() == reflect.String:
			ok["content"] = map[string]any{"application/yaml": map[string]any{"schema": map[string]any{"type": "string"}}}
		case a.List:
			ok["content"] = map[string]any{"application/json": map[string]any{"schema": map[string]any{
				"type":     "object",
				"required": []string{"data", "next_cursor"},
				"properties": map[string]any{
					"data":        map[string]any{"type": "array", "items": g.ref(reflect.TypeOf(a.Resp))},
					"next_cursor": map[string]any{"type": []string{"string", "null"}, "description": "Pass as cursor for the next page; null on the last."},
				},
			}}}
		default:
			ok["content"] = map[string]any{"application/json": map[string]any{"schema": g.ref(reflect.TypeOf(a.Resp))}}
		}
		responses := map[string]any{
			strconv.Itoa(status): ok,
			"401":                errResp("No token, or an invalid, expired or revoked one."),
			"403":                errResp("The token's role does not allow this."),
			"429":                errResp("Rate limited; see Retry-After."),
		}
		if a.Body != nil || len(a.Query) > 0 {
			responses["400"] = errResp("The request is invalid; fields says why, per field.")
		}
		if strings.Contains(a.Path, "{") {
			responses["404"] = errResp("No such object.")
		}
		op["responses"] = responses
		item, _ := paths[a.Path].(map[string]any)
		if item == nil {
			item = map[string]any{}
			paths[a.Path] = item
		}
		item[strings.ToLower(a.Method)] = op
	}
	paths["/api/v2/openapi.json"] = map[string]any{"get": map[string]any{
		"summary": "This document.", "operationId": "openapi", "security": []any{},
		"responses": map[string]any{"200": map[string]any{"description": "OK", "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}}}},
	}}
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   "tlswatch",
			"version": s.Version,
			"description": "The REST API of tlswatch. Authenticate with an API token made under Account, sent as Authorization: Bearer. " +
				"A token has a role no higher than its user's, and every endpoint needs the action named in x-role-action. Lists are paginated with a cursor.",
		},
		"servers":    []any{map[string]any{"url": "/"}},
		"security":   []any{map[string]any{"bearer": []any{}}},
		"paths":      paths,
		"components": map[string]any{"schemas": g.schemas, "securitySchemes": map[string]any{"bearer": map[string]any{"type": "http", "scheme": "bearer"}}},
	}
}

// operationID names an operation from its method and path: GET
// /api/v2/targets/{id} is getTargetsById.
func operationID(a apiRoute) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(a.Method))
	for _, part := range strings.Split(strings.TrimPrefix(a.Path, "/api/v2/"), "/") {
		if m := pathParam.FindStringSubmatch(part); m != nil {
			part = "by_" + m[1]
		}
		for _, w := range strings.Split(part, "_") {
			if w != "" {
				r := []rune(w)
				r[0] = unicode.ToUpper(r[0])
				b.WriteString(string(r))
			}
		}
	}
	return b.String()
}

// schemaGen turns Go types into JSON Schemas under components.schemas.
type schemaGen struct {
	schemas map[string]any
}

var stampType = reflect.TypeOf(stamp(0))

// schemaName is a type's name in the document: apiTargetInput is
// TargetInput.
func schemaName(t reflect.Type) string {
	n := strings.TrimPrefix(t.Name(), "api")
	if n == "" {
		return t.Name()
	}
	r := []rune(n)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func (g *schemaGen) ref(t reflect.Type) map[string]any {
	if t.Kind() == reflect.Struct {
		name := schemaName(t)
		if _, ok := g.schemas[name]; !ok {
			g.schemas[name] = nil // a placeholder against recursion
			g.schemas[name] = g.object(t)
		}
		return map[string]any{"$ref": "#/components/schemas/" + name}
	}
	return g.schema(t)
}

func (g *schemaGen) object(t reflect.Type) map[string]any {
	props := map[string]any{}
	var required []string
	input := strings.HasSuffix(t.Name(), "Input")
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" || !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		p := g.ref(f.Type)
		if f.Type.Kind() == reflect.Pointer {
			p = nullable(g.ref(f.Type.Elem()))
		}
		if doc := f.Tag.Get("doc"); doc != "" {
			if _, isRef := p["$ref"]; isRef {
				p = map[string]any{"allOf": []any{p}, "description": doc}
			} else {
				p["description"] = doc
			}
		}
		props[name] = p
		if !input && !strings.Contains(opts, "omitempty") {
			required = append(required, name)
		}
	}
	o := map[string]any{"type": "object", "properties": props, "additionalProperties": !input}
	if required != nil {
		o["required"] = required
	}
	return o
}

func (g *schemaGen) schema(t reflect.Type) map[string]any {
	if t == stampType {
		return map[string]any{"type": []string{"string", "null"}, "format": "date-time"}
	}
	switch t.Kind() {
	case reflect.Pointer:
		return nullable(g.ref(t.Elem()))
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int64, reflect.Int32:
		return map[string]any{"type": "integer"}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": g.ref(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": g.ref(t.Elem())}
	case reflect.Interface:
		return map[string]any{}
	}
	return map[string]any{}
}

// nullable allows null besides the schema.
func nullable(s map[string]any) map[string]any {
	if typ, ok := s["type"].(string); ok {
		out := map[string]any{}
		for k, v := range s {
			out[k] = v
		}
		out["type"] = []string{typ, "null"}
		return out
	}
	if typ, ok := s["type"].([]string); ok && len(typ) == 2 {
		return s
	}
	return map[string]any{"oneOf": []any{s, map[string]any{"type": "null"}}}
}
