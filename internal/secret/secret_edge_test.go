package secret

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A key file of the wrong size is an error, never replaced by a new key:
// that would make every stored credential unreadable.
func TestLoadOrCreateRefusesBadFile(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string][]byte{
		"empty":      {},
		"short":      bytes.Repeat([]byte{1}, 31),
		"long":       bytes.Repeat([]byte{1}, 33),
		"bad hex":    []byte(strings.Repeat("zz", 32)),
		"hex plus 1": []byte(strings.Repeat("ab", 32) + "c"),
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if k, created, err := LoadOrCreate(p); err == nil || created || k != nil {
			t.Errorf("%s: key %v, created %v, err %v", name, k != nil, created, err)
		}
		if got, _ := os.ReadFile(p); !bytes.Equal(got, content) {
			t.Errorf("%s: the key file was rewritten", name)
		}
	}
}

// The same 32 bytes, raw or as hex with surrounding whitespace, are the
// same key; another key opens nothing.
func TestKeyFormatsAndIsolation(t *testing.T) {
	dir := t.TempDir()
	raw := bytes.Repeat([]byte{7}, 32)
	rawPath, hexPath := filepath.Join(dir, "raw"), filepath.Join(dir, "hex")
	if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hexPath, []byte("  "+strings.ToUpper(hex.EncodeToString(raw))+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, _, err := LoadOrCreate(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := LoadOrCreate(hexPath)
	if err != nil {
		t.Fatal(err)
	}
	sealed := a.Seal("settings:x", []byte("pw"))
	if pt, err := b.Open("settings:x", sealed); err != nil || string(pt) != "pw" {
		t.Fatalf("hex and raw differ: %q %v", pt, err)
	}
	other, _, _ := Generate()
	if _, err := other.Open("settings:x", sealed); err == nil {
		t.Fatal("another key opened the value")
	}
	if _, err := other.Open("", sealed); err == nil {
		t.Fatal("another key opened the value without a place")
	}
	for _, short := range [][]byte{nil, {1, 2, 3}, sealed[:11]} {
		if _, err := a.Open("settings:x", short); err == nil {
			t.Errorf("%d bytes opened", len(short))
		}
	}
	// Two seals of the same value differ (fresh nonce).
	if bytes.Equal(a.Seal("p", []byte("v")), a.Seal("p", []byte("v"))) {
		t.Fatal("the nonce is reused")
	}
}

// WriteFile never overwrites a key, and creates the file owner-only.
func TestWriteFileRefusesOverwrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "secret.key")
	if err := WriteFile(p, bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, bytes.Repeat([]byte{2}, 32)); err == nil {
		t.Fatal("an existing key was overwritten")
	}
	k, created, err := LoadOrCreate(p)
	if err != nil || created {
		t.Fatalf("reload: %v %v", created, err)
	}
	want, _ := New(bytes.Repeat([]byte{1}, 32))
	if _, err := want.Open("c", k.Seal("c", []byte("x"))); err != nil {
		t.Fatal("the first key was replaced")
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}
