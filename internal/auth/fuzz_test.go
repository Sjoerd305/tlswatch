package auth

import "testing"

// FuzzParseIDToken feeds the ID token an OpenID Connect provider returns.
func FuzzParseIDToken(f *testing.F) {
	f.Add("eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwiYXVkIjpbImEiLCJiIl19.")
	f.Add("eyJhbGciOiJub25lIn0.eyJhdWQiOiJhIn0.x")
	f.Add("a.b.c")
	f.Add("..")
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = parseIDToken(raw)
	})
}
