package secret

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateAndSeal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d", "secret.key")
	k, created, err := LoadOrCreate(p)
	if err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	k2, created, err := LoadOrCreate(p)
	if err != nil || created {
		t.Fatalf("reload: %v %v", created, err)
	}
	sealed := k.Seal("t", []byte("hunter2"))
	got, err := k2.Open("t", sealed)
	if err != nil || string(got) != "hunter2" {
		t.Fatalf("open: %q %v", got, err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := k2.Open("t", sealed); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
}

// A value sealed for one place does not open for another, while a value
// sealed by a build before places existed still opens anywhere.
func TestSealContext(t *testing.T) {
	k, _, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	sealed := k.Seal("channels.settings", []byte("pw"))
	if _, err := k.Open("nodes.token_sealed", sealed); err == nil {
		t.Fatal("opened in another place")
	}
	if pt, err := k.Open("channels.settings", sealed); err != nil || string(pt) != "pw" {
		t.Fatalf("own place: %q %v", pt, err)
	}
	legacy := k.Seal("", []byte("old"))
	if pt, err := k.Open("channels.settings", legacy); err != nil || string(pt) != "old" {
		t.Fatalf("legacy value: %q %v", pt, err)
	}
}
