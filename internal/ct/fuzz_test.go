package ct

import "testing"

// The CT sources are third-party JSON services; their strings are parsed
// here.

func FuzzDNParts(f *testing.F) {
	f.Add(`C=US, O=Let's Encrypt, CN=R11`)
	f.Add(`CN="Acme, Inc. CA", O="Acme, Inc."`)
	f.Add(`CN=a\,b, O=\`)
	f.Add(`=,=,`)
	f.Fuzz(func(t *testing.T, dn string) {
		dnParts(dn)
	})
}

func FuzzParseCrtShTime(f *testing.F) {
	f.Add("2026-10-24T12:00:00")
	f.Add("2026-10-24T12:00:00.123")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = parseCrtShTime(s)
	})
}

func FuzzParseEntryCert(f *testing.F) {
	f.Add("MAA=")
	f.Add("")
	f.Add("not base64")
	f.Fuzz(func(t *testing.T, data string) {
		parseEntryCert(data)
	})
}
