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
	sealed := k.Seal([]byte("hunter2"))
	got, err := k2.Open(sealed)
	if err != nil || string(got) != "hunter2" {
		t.Fatalf("open: %q %v", got, err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := k2.Open(sealed); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
}
