package probe

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Issuer returns the certificate that signed the address's leaf, from the
// chain as served or as verified; nil when neither holds it.
func Issuer(a Address) *x509.Certificate {
	if len(a.Chain) == 0 {
		return nil
	}
	leaf := a.Chain[0]
	for _, chain := range [][]*x509.Certificate{a.Chain[1:], a.VerifiedChain} {
		for _, c := range chain {
			if !c.Equal(leaf) && bytes.Equal(leaf.RawIssuer, c.RawSubject) && leaf.CheckSignatureFrom(c) == nil {
				return c
			}
		}
	}
	return nil
}

// KeyID identifies an issuer by its public key: the hex SHA-256 of its
// SubjectPublicKeyInfo. A CRL verified against one key says nothing about
// leaves of another.
func KeyID(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// Statuses of a stapled OCSP response.
const (
	StapleGood    = "good"
	StapleRevoked = "revoked"
	StapleUnknown = "unknown" // the responder does not know the certificate
	StapleInvalid = "invalid" // unreadable, or not signed for this leaf by its issuer
)

// Staple is what a stapled OCSP response says.
type Staple struct {
	Status    string // "" when nothing was stapled
	RevokedAt time.Time
	Reason    int // the RFC 5280 reason code when revoked
}

// StapleOf reads the OCSP response the address stapled, checked against
// the leaf's issuer from the chain. Only a response signed for the leaf
// counts; its age does not matter to a revocation.
func StapleOf(a Address) Staple {
	if len(a.OCSP) == 0 || len(a.Chain) == 0 {
		return Staple{}
	}
	issuer := Issuer(a)
	if issuer == nil {
		return Staple{Status: StapleInvalid}
	}
	r, err := ocsp.ParseResponseForCert(a.OCSP, a.Chain[0], issuer)
	if err != nil {
		return Staple{Status: StapleInvalid}
	}
	switch r.Status {
	case ocsp.Good:
		return Staple{Status: StapleGood}
	case ocsp.Revoked:
		return Staple{Status: StapleRevoked, RevokedAt: r.RevokedAt, Reason: r.RevocationReason}
	}
	return Staple{Status: StapleUnknown}
}
