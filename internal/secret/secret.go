// Package secret holds the instance key: it encrypts secrets at rest with
// AES-256-GCM and derives keys for signing.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Key is the 32-byte instance key.
type Key struct {
	aead cipher.AEAD
	raw  [32]byte
}

// LoadOrCreate reads the key file, or generates one with mode 0600 when it
// does not exist. The file holds 32 raw bytes or 64 hex characters.
func LoadOrCreate(path string) (*Key, bool, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- path from the operator's own environment
	if errors.Is(err, os.ErrNotExist) {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, false, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, false, err
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(raw[:])+"\n"), 0o600); err != nil {
			return nil, false, fmt.Errorf("write secret key: %w", err)
		}
		k, err := New(raw[:])
		return k, true, err
	}
	if err != nil {
		return nil, false, fmt.Errorf("read secret key: %w", err)
	}
	if s := strings.TrimSpace(string(b)); len(s) == 64 {
		if raw, err := hex.DecodeString(s); err == nil {
			k, err := New(raw)
			return k, false, err
		}
	}
	k, err := New(b)
	return k, false, err
}

// New builds a key from 32 raw bytes.
func New(raw []byte) (*Key, error) {
	if len(raw) != 32 {
		return nil, fmt.Errorf("secret key must be 32 bytes or 64 hex characters, got %d bytes", len(raw))
	}
	k := &Key{}
	copy(k.raw[:], raw)
	enc := k.derive("encryption")
	block, err := aes.NewCipher(enc)
	if err != nil {
		return nil, err
	}
	k.aead, err = cipher.NewGCM(block)
	return k, err
}

func (k *Key) derive(purpose string) []byte {
	m := hmac.New(sha256.New, k.raw[:])
	m.Write([]byte("tlswatch " + purpose))
	return m.Sum(nil)
}

// Seal encrypts plaintext; the nonce is prepended.
func (k *Key) Seal(plaintext []byte) []byte {
	nonce := make([]byte, k.aead.NonceSize(), k.aead.NonceSize()+len(plaintext)+k.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return k.aead.Seal(nonce, nonce, plaintext, nil)
}

// Open decrypts what Seal produced.
func (k *Key) Open(sealed []byte) ([]byte, error) {
	n := k.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("ciphertext too short")
	}
	return k.aead.Open(nil, sealed[:n], sealed[n:], nil)
}

// MAC returns a hex HMAC of msg under a key derived for purpose.
func (k *Key) MAC(purpose, msg string) string {
	m := hmac.New(sha256.New, k.derive(purpose))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}
