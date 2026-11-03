package web

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite docs/openapi.json from the generated document")

// goldenOpenAPI is the committed copy of the OpenAPI document. The binary
// generates the document from its routes and types; this copy only mirrors
// it, so a change to the public API shows as a diff in the commit that
// makes it, and the document can be read without running an instance.
var goldenOpenAPI = filepath.Join("..", "..", "docs", "openapi.json")

// The committed document matches the generated one. After a deliberate API
// change: go test ./internal/web -run TestOpenAPIGolden -update
func TestOpenAPIGolden(t *testing.T) {
	hs := newHarness(t)
	doc := hs.srv.openAPIDocument()
	// The binary puts its own version here; the copy is not tied to one.
	doc["info"].(map[string]any)["version"] = "dev"
	got, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *updateGolden {
		if err := os.WriteFile(goldenOpenAPI, got, 0o644); err != nil { // #nosec G306 -- documentation
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(goldenOpenAPI)
	if err != nil {
		t.Fatalf("%v; create it with: go test ./internal/web -run TestOpenAPIGolden -update", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("docs/openapi.json differs from the generated document: the public API changed. " +
			"Check the diff is intended, then run: go test ./internal/web -run TestOpenAPIGolden -update")
	}
}
