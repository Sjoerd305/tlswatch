package auth

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/sjoerd305/tlswatch/internal/usererr"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (RFC 9106 second recommended option, scaled down).
// They are variables only so tests can lower the cost.
var (
	argonMemory  uint32 = 64 * 1024
	argonTime    uint32 = 3
	argonThreads uint8  = 2
)

const (
	argonKeyLen  = 32
	argonSaltLen = 16

	// MinPasswordLength is the minimum number of characters in a password.
	MinPasswordLength = 12
)

// HashPassword returns an Argon2id hash in PHC string format.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword checks pw against a PHC string from HashPassword, in
// constant time. Malformed hashes never verify.
func VerifyPassword(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || t == 0 || p == 0 || m > 1<<22 || t > 64 {
		return false
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 128 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want))) // #nosec G115 -- at most 128, checked above
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is verified against when a login names no usable account, so
// the response time does not reveal whether the e-mail exists.
var dummyHash = sync.OnceValue(func() string {
	h, err := HashPassword("tlswatch-dummy-password")
	if err != nil {
		panic(err)
	}
	return h
})

//go:embed leaked.txt
var leakedList string

// Breached is a set of known leaked or common passwords, lowercased.
type Breached struct{ set map[string]struct{} }

// DefaultBreached returns the embedded list, parsed once.
var DefaultBreached = sync.OnceValue(func() *Breached {
	b := &Breached{set: map[string]struct{}{}}
	sc := bufio.NewScanner(strings.NewReader(leakedList))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b.set[strings.ToLower(line)] = struct{}{}
	}
	return b
})

// Contains reports whether pw is on the list, case-insensitively.
func (b *Breached) Contains(pw string) bool {
	if b == nil {
		return false
	}
	_, ok := b.set[strings.ToLower(pw)]
	return ok
}

// Password policy errors, worded for the user.
var (
	ErrPasswordTooShort = usererr.New(fmt.Sprintf("Use at least %d characters.", MinPasswordLength))
	ErrPasswordLeaked   = usererr.New("This password appears in a list of leaked or common passwords. Choose another one.")
	ErrPasswordIsEmail  = usererr.New("The password must not be your e-mail address.")
)

// CheckPasswordPolicy validates a new password for the account email.
func (s *Service) CheckPasswordPolicy(pw, email string) error {
	if utf8.RuneCountInString(pw) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	lower := strings.ToLower(pw)
	email = strings.ToLower(strings.TrimSpace(email))
	if email != "" {
		local, _, _ := strings.Cut(email, "@")
		if lower == email || lower == local {
			return ErrPasswordIsEmail
		}
	}
	if s.Breached.Contains(pw) {
		return ErrPasswordLeaked
	}
	return nil
}
