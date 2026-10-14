package probe

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// CertInfo is the display and storage form of one certificate.
type CertInfo struct {
	Fingerprint string
	Subject     string
	SubjectCN   string // the CN, or the first DNS SAN when the CN is empty
	Issuer      string
	IssuerCN    string
	IssuerOrg   string
	Serial      string // uppercase hex
	NotBefore   time.Time
	NotAfter    time.Time
	SANs        []string // DNS names, IPs, e-mail addresses, URIs
	KeyType     string   // RSA, ECDSA, Ed25519
	KeyBits     int
	KeyDesc     string // "RSA 2048", "ECDSA P-256", "Ed25519"
	SigAlg      string // "SHA-256 with RSA"
	IsCA        bool
	SelfSigned  bool
	// WeakSignature: signed with MD2, MD5 or SHA-1, or an RSA key under 2048 bits.
	WeakSignature bool
	PEM           string
}

// Describe extracts the fields tlswatch stores and shows.
func Describe(c *x509.Certificate) CertInfo {
	ci := CertInfo{
		Fingerprint: Fingerprint(c),
		Subject:     c.Subject.String(),
		SubjectCN:   c.Subject.CommonName,
		Issuer:      c.Issuer.String(),
		IssuerCN:    c.Issuer.CommonName,
		NotBefore:   c.NotBefore.UTC(),
		NotAfter:    c.NotAfter.UTC(),
		IsCA:        c.IsCA,
		SigAlg:      sigAlgName(c.SignatureAlgorithm),
		PEM:         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})),
	}
	if c.SerialNumber != nil {
		ci.Serial = fmt.Sprintf("%X", c.SerialNumber)
	}
	if len(c.Issuer.Organization) > 0 {
		ci.IssuerOrg = c.Issuer.Organization[0]
	}
	ci.SANs = append(ci.SANs, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		ci.SANs = append(ci.SANs, ip.String())
	}
	ci.SANs = append(ci.SANs, c.EmailAddresses...)
	for _, u := range c.URIs {
		ci.SANs = append(ci.SANs, u.String())
	}
	if ci.SubjectCN == "" && len(c.DNSNames) > 0 {
		ci.SubjectCN = c.DNSNames[0]
	}
	if ci.IssuerCN == "" && ci.IssuerOrg != "" {
		ci.IssuerCN = ci.IssuerOrg
	}

	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		ci.KeyType, ci.KeyBits = "RSA", k.N.BitLen()
		ci.KeyDesc = fmt.Sprintf("RSA %d", ci.KeyBits)
	case *ecdsa.PublicKey:
		ci.KeyType = "ECDSA"
		if k.Curve != nil {
			ci.KeyBits = k.Curve.Params().BitSize
			ci.KeyDesc = "ECDSA " + k.Curve.Params().Name
		} else {
			ci.KeyDesc = "ECDSA"
		}
	case ed25519.PublicKey:
		ci.KeyType, ci.KeyBits, ci.KeyDesc = "Ed25519", 256, "Ed25519"
	default:
		ci.KeyType = c.PublicKeyAlgorithm.String()
		ci.KeyDesc = ci.KeyType
	}

	ci.SelfSigned = isSelfSigned(c)
	switch c.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		ci.WeakSignature = true
	}
	if ci.KeyType == "RSA" && ci.KeyBits < 2048 {
		ci.WeakSignature = true
	}
	return ci
}

func isSelfSigned(c *x509.Certificate) bool {
	if !bytes.Equal(c.RawSubject, c.RawIssuer) {
		return false
	}
	err := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
	if err == nil {
		return true
	}
	// Go refuses to check SHA-1 and MD5 signatures; fall back to the key
	// identifiers so such certificates are still recognised as self-signed.
	var insecure x509.InsecureAlgorithmError
	if errors.As(err, &insecure) {
		return len(c.AuthorityKeyId) == 0 || bytes.Equal(c.AuthorityKeyId, c.SubjectKeyId)
	}
	return false
}

func sigAlgName(a x509.SignatureAlgorithm) string {
	switch a {
	case x509.MD2WithRSA:
		return "MD2 with RSA"
	case x509.MD5WithRSA:
		return "MD5 with RSA"
	case x509.SHA1WithRSA:
		return "SHA-1 with RSA"
	case x509.SHA256WithRSA:
		return "SHA-256 with RSA"
	case x509.SHA384WithRSA:
		return "SHA-384 with RSA"
	case x509.SHA512WithRSA:
		return "SHA-512 with RSA"
	case x509.SHA256WithRSAPSS:
		return "SHA-256 with RSA-PSS"
	case x509.SHA384WithRSAPSS:
		return "SHA-384 with RSA-PSS"
	case x509.SHA512WithRSAPSS:
		return "SHA-512 with RSA-PSS"
	case x509.DSAWithSHA1:
		return "SHA-1 with DSA"
	case x509.DSAWithSHA256:
		return "SHA-256 with DSA"
	case x509.ECDSAWithSHA1:
		return "SHA-1 with ECDSA"
	case x509.ECDSAWithSHA256:
		return "SHA-256 with ECDSA"
	case x509.ECDSAWithSHA384:
		return "SHA-384 with ECDSA"
	case x509.ECDSAWithSHA512:
		return "SHA-512 with ECDSA"
	case x509.PureEd25519:
		return "Ed25519"
	}
	return a.String()
}
