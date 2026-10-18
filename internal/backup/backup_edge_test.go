package backup

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/config"
)

// chunkBounds returns the offsets at which each sealed chunk of a backup
// file starts, after the header.
func chunkBounds(t *testing.T, file []byte) []int {
	t.Helper()
	var out []int
	for off := headerLen; off < len(file); {
		out = append(out, off)
		if off+4 > len(file) {
			t.Fatalf("bad framing at %d", off)
		}
		off += 4 + int(binary.BigEndian.Uint32(file[off:]))
	}
	return out
}

// bigSource is an instance whose backup spans several chunks.
func bigSource(t *testing.T) []byte {
	t.Helper()
	k := key(t, 'a')
	src := source(t, k, "admin")
	exec(t, src, "UPDATE targets SET notes = ?", strings.Repeat("renewal procedure ", 20000))
	return write(t, src, k)
}

// A file cut off at any chunk boundary, or inside the header, does not
// restore: the last chunk is marked, so a download that ended early is
// never mistaken for a whole one.
func TestCutOffAtEveryChunkBoundary(t *testing.T) {
	ctx := context.Background()
	k := key(t, 'a')
	file := bigSource(t)
	bounds := chunkBounds(t, file)
	if len(bounds) < 4 {
		t.Fatalf("only %d chunks; the test wants several", len(bounds))
	}
	dst := fileDB(t)
	for _, cut := range append(bounds[1:], len(file)-1, bounds[1]+3) {
		if _, err := Open(ctx, bytes.NewReader(file[:cut]), dst, k, pass); !errors.Is(err, ErrPassphrase) && !isUser(err) {
			t.Errorf("cut at %d of %d: %v", cut, len(file), err)
		} else if err == nil {
			t.Errorf("cut at %d of %d restored", cut, len(file))
		}
	}
	for _, cut := range []int{len(magic) - 1, len(magic) + 3, headerLen - 1} {
		if _, err := Open(ctx, bytes.NewReader(file[:cut]), dst, k, pass); !isUser(err) {
			t.Errorf("header cut at %d: %v", cut, err)
		}
	}
}

// Reordering or dropping chunks, or changing the key parameters in the
// header, is noticed.
func TestReorderedChunksAndHeaderRefused(t *testing.T) {
	ctx := context.Background()
	k := key(t, 'a')
	file := bigSource(t)
	b := chunkBounds(t, file)
	dst := fileDB(t)
	drop := append(append([]byte(nil), file[:b[1]]...), file[b[2]:]...)
	swap := append(append(append(append([]byte(nil), file[:b[1]]...), file[b[2]:b[3]]...), file[b[1]:b[2]]...), file[b[3]:]...)
	lastOnly := append(append([]byte(nil), file[:b[0]]...), file[b[len(b)-1]:]...)
	params := append([]byte(nil), file...)
	params[len(magic)+3]++ // one more Argon2 pass
	for name, data := range map[string][]byte{"dropped chunk": drop, "swapped chunks": swap, "only the last chunk": lastOnly, "header parameters": params} {
		if _, err := Open(ctx, bytes.NewReader(data), dst, k, pass); err == nil {
			t.Errorf("%s: restored", name)
		} else if !isUser(err) {
			t.Errorf("%s: %v is not a message for the user", name, err)
		}
	}
	huge := append([]byte(nil), file...)
	binary.BigEndian.PutUint32(huge[len(magic)+4:], 1<<20+1)
	if _, err := Open(ctx, bytes.NewReader(huge), dst, k, pass); !isUser(err) || !strings.Contains(err.Error(), "settings") {
		t.Errorf("an Argon2 memory above the cap: %v", err)
	}
}

// One-time links from before the backup do not come back to life, and the
// sealed settings (Google client secret, CT API key) are re-sealed for the
// instance that restores.
func TestRestoreDropsLinksAndReSealsSettings(t *testing.T) {
	ctx := context.Background()
	ka, kb := key(t, 'a'), key(t, 'b')
	src := source(t, ka, "admin")
	exec(t, src, "INSERT INTO tokens(hash, kind, user_id, expires_at, created_at) VALUES('t', 'invite', 1, 99999999999, 1)")
	st := config.NewStore(src, ka)
	if err := st.SaveSignIn(ctx, config.SignIn{GoogleClientID: "cid", GoogleClientSecret: "gsecret"}, false, false); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveCT(ctx, config.CT{Source: "certspotter", IntervalS: 3600, APIKey: "ctkey"}, false); err != nil {
		t.Fatal(err)
	}
	file := write(t, src, ka)
	if bytes.Contains(file, []byte("gsecret")) || bytes.Contains(file, []byte("ctkey")) {
		t.Fatal("a secret is readable in the file")
	}
	dst := fileDB(t)
	res, err := Open(ctx, bytes.NewReader(file), dst, kb, pass)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	if err := dst.Restore(ctx, res.Path, nil); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = dst.R.QueryRow("SELECT COUNT(*) FROM tokens").Scan(&n)
	if n != 0 {
		t.Errorf("%d one-time links survived the restore", n)
	}
	got, err := config.NewStore(dst, kb).Get(ctx)
	if err != nil || got.SignIn.GoogleClientSecret != "gsecret" || got.CT.APIKey != "ctkey" || got.SignIn.SecretUnreadable || got.CT.KeyUnreadable {
		t.Fatalf("sealed settings after the restore: %+v %+v %v", got.SignIn, got.CT, err)
	}
}

// A wrong passphrase costs one key derivation and says so; it is not
// reported as a damaged database.
func TestWrongPassphraseMessage(t *testing.T) {
	k := key(t, 'a')
	file := write(t, source(t, k, "admin"), k)
	_, err := Open(context.Background(), bytes.NewReader(file), fileDB(t), k, strings.ToUpper(pass))
	if !errors.Is(err, ErrPassphrase) || !strings.Contains(err.Error(), "passphrase is wrong") {
		t.Fatalf("got %v", err)
	}
}

// Data after the last chunk is not what the backup wrote.
func TestTrailingBytesRefused(t *testing.T) {
	ctx := context.Background()
	k := key(t, 'a')
	file := write(t, source(t, k, "admin"), k)
	dst := fileDB(t)
	if res, err := Open(ctx, bytes.NewReader(file), dst, k, pass); err != nil {
		t.Fatalf("the backup itself: %v", err)
	} else {
		res.Close()
	}
	if _, err := Open(ctx, bytes.NewReader(append(append([]byte(nil), file...), "extra"...)), dst, k, pass); !isUser(err) {
		t.Fatalf("trailing bytes: %v", err)
	}
}

// A header asking for more memory, passes or threads than the cap is
// refused before any key is derived.
func TestKeyCostCapped(t *testing.T) {
	ctx := context.Background()
	k := key(t, 'a')
	file := write(t, source(t, k, "admin"), k)
	dst := fileDB(t)
	for name, set := range map[string]func(p []byte){
		"512 MiB":    func(p []byte) { binary.BigEndian.PutUint32(p[4:], 512*1024) },
		"9 passes":   func(p []byte) { binary.BigEndian.PutUint32(p, 9) },
		"16 threads": func(p []byte) { p[8] = 16 },
	} {
		f := append([]byte(nil), file...)
		set(f[len(magic):])
		start := time.Now()
		if _, err := Open(ctx, bytes.NewReader(f), dst, k, pass); err == nil || !strings.Contains(err.Error(), "settings this version") || time.Since(start) > time.Second {
			t.Errorf("%s: %v after %v", name, err, time.Since(start))
		}
	}
}
