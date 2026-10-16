// Command releasesign signs and verifies the SHA256SUMS of a release with
// the Ed25519 release key, whose public half is built into tlswatch
// (internal/node.ReleasePublicKey). Nodes accept a binary only when its
// checksum is in a SHA256SUMS that this key signed.
//
//	go run ./scripts/releasesign -keygen
//	    prints a new private key (hex) on stdout and the matching public key
//	    on stderr; put the private key in the RELEASE_SIGNING_KEY secret and
//	    the public key in internal/node/release.go.
//	go run ./scripts/releasesign -sign SHA256SUMS > SHA256SUMS.sig
//	    signs the file with the key in $RELEASE_SIGNING_KEY.
//	go run ./scripts/releasesign -verify SHA256SUMS SHA256SUMS.sig
//	    checks the signature against the built-in public key, so a release
//	    is never published with a key the binaries do not know.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sjoerd305/tlswatch/internal/node"
)

func main() {
	keygen := flag.Bool("keygen", false, "make a new key pair")
	sign := flag.String("sign", "", "sign this file with $RELEASE_SIGNING_KEY")
	verify := flag.Bool("verify", false, "verify FILE SIG against the built-in public key")
	flag.Parse()
	if err := run(*keygen, *sign, *verify, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "releasesign:", err)
		os.Exit(1)
	}
}

func run(keygen bool, sign string, verify bool, args []string) error {
	switch {
	case keygen:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		fmt.Println(hex.EncodeToString(priv.Seed()))
		fmt.Fprintln(os.Stderr, "public key:", hex.EncodeToString(pub))
		return nil
	case sign != "":
		seed, err := hex.DecodeString(strings.TrimSpace(os.Getenv("RELEASE_SIGNING_KEY")))
		if err != nil || len(seed) != ed25519.SeedSize {
			return fmt.Errorf("RELEASE_SIGNING_KEY must be %d hex characters", 2*ed25519.SeedSize)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		if !priv.Public().(ed25519.PublicKey).Equal(node.ReleasePublicKey) {
			return fmt.Errorf("RELEASE_SIGNING_KEY does not match the public key built into tlswatch")
		}
		b, err := os.ReadFile(sign) // #nosec G304 -- the file the maintainer named
		if err != nil {
			return err
		}
		fmt.Println(hex.EncodeToString(ed25519.Sign(priv, b)))
		return nil
	case verify:
		if len(args) != 2 {
			return fmt.Errorf("usage: releasesign -verify FILE SIG")
		}
		b, err := os.ReadFile(args[0]) // #nosec G304 -- the file the maintainer named
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(args[1]) // #nosec G304 -- the file the maintainer named
		if err != nil {
			return err
		}
		sums, err := node.VerifySums(b, sig, nil)
		if err != nil {
			return err
		}
		fmt.Printf("signature valid; %d asset(s) listed\n", len(sums))
		return nil
	}
	return fmt.Errorf("one of -keygen, -sign FILE or -verify is required")
}
