package node

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
)

// ReleasePublicKey is the Ed25519 key that signs the SHA256SUMS of every
// release (scripts/releasesign). A node replaces its binary only with one
// whose checksum is in a SHA256SUMS this key signed, so a server, or anyone
// who can edit a GitHub release, cannot hand a node a binary of their own.
var ReleasePublicKey = mustPublicKey("fb6a41105b04c9cba82343f71a4ced0e3f42d85dc9808d018e8193eb802296ab")

// HeaderSumsSignature carries the hex Ed25519 signature of a SHA256SUMS
// body served by the server.
const HeaderSumsSignature = "X-Tlswatch-Sums-Signature"

// ErrUnsigned is a SHA256SUMS without a valid signature by the release key.
var ErrUnsigned = errors.New("the release checksums are not signed by the tlswatch release key")

// maxSums bounds a SHA256SUMS file: a handful of lines.
const maxSums = 64 << 10

func mustPublicKey(h string) ed25519.PublicKey {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("release public key: not 32 hex bytes")
	}
	return ed25519.PublicKey(b)
}

// VerifySums checks sig (hex) over the exact bytes of a SHA256SUMS file with
// key (nil: ReleasePublicKey) and returns asset name → SHA-256.
func VerifySums(sums, sig []byte, key ed25519.PublicKey) (map[string]string, error) {
	if key == nil {
		key = ReleasePublicKey
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize || len(sums) > maxSums || !ed25519.Verify(key, sums, raw) {
		return nil, ErrUnsigned
	}
	return parseSums(sums), nil
}

// parseSums reads sha256sum's output: "<hex>  <name>" per line.
func parseSums(b []byte) map[string]string {
	sums := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 2 && len(f[0]) == 64 {
			sums[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
		}
	}
	return sums
}
