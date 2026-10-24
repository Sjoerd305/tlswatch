package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"sync/atomic"
	"testing"
	"time"
)

func tlsCert(chain ...*testCert) tls.Certificate {
	return serverConfig(chain...).Certificates[0]
}

func TestOtherCertificateByKeyType(t *testing.T) {
	p := newPKI(t)
	rsa := rsaLeaf(t, p.inter)
	// Go's server picks the first certificate the client supports: ECDSA
	// for the normal probe, RSA for a TLS 1.2 client offering RSA suites.
	cfg := &tls.Config{Certificates: []tls.Certificate{tlsCert(p.leaf, p.inter), tlsCert(rsa, p.inter)}}
	r := req(serve(t, cfg, nil), TLS)
	r.Legacy, r.Trust, r.Roots = true, TrustBundle, p.pool
	a := single(t, Probe(context.Background(), r))
	if !a.OK || !a.OthersChecked || len(a.Others) != 1 {
		t.Fatalf("ok %v checked %v others %+v", a.OK, a.OthersChecked, a.Others)
	}
	o := a.Others[0]
	if o.Via != ViaOtherKey || !o.Chain[0].Equal(rsa.cert) || !o.Verified {
		t.Fatalf("other: via %s leaf %s verified %v %s", o.Via, o.Chain[0].Subject.CommonName, o.Verified, o.VerifyError)
	}

	// The RSA certificate first: the probe gets RSA and asks for ECDSA.
	cfg = &tls.Config{Certificates: []tls.Certificate{tlsCert(rsa, p.inter), tlsCert(p.leaf, p.inter)}}
	r = req(serve(t, cfg, nil), TLS)
	r.Legacy = true
	a = single(t, Probe(context.Background(), r))
	if !a.OthersChecked || len(a.Others) != 1 || !a.Others[0].Chain[0].Equal(p.leaf.cert) {
		t.Fatalf("RSA first: checked %v others %+v", a.OthersChecked, a.Others)
	}
}

func TestOneCertificateHasNoOthers(t *testing.T) {
	p := newPKI(t)
	r := req(serve(t, serverConfig(p.leaf, p.inter), nil), TLS)
	r.Legacy, r.ServerName = true, "good.example"
	a := single(t, Probe(context.Background(), r))
	if !a.OK || !a.OthersChecked || len(a.Others) != 0 {
		t.Fatalf("checked %v others %+v", a.OthersChecked, a.Others)
	}
}

func TestDefaultCertificateWithoutSNI(t *testing.T) {
	p := newPKI(t)
	stale := newCert(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "old.example"},
		DNSNames:    []string{"old.example"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		NotBefore:   time.Now().Add(-400 * 24 * time.Hour),
		NotAfter:    time.Now().Add(-10 * 24 * time.Hour),
	}, p.inter, nil)
	named, def := tlsCert(p.leaf, p.inter), tlsCert(stale, p.inter)
	cfg := &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if h.ServerName == "" {
			return &def, nil
		}
		return &named, nil
	}}
	r := req(serve(t, cfg, nil), TLS)
	r.Legacy, r.ServerName = true, "good.example"
	a := single(t, Probe(context.Background(), r))
	var sni *OtherChain
	for i := range a.Others {
		if a.Others[i].Via == ViaNoSNI {
			sni = &a.Others[i]
		}
	}
	if !a.OthersChecked || sni == nil || !sni.Chain[0].Equal(stale.cert) {
		t.Fatalf("checked %v others %+v", a.OthersChecked, a.Others)
	}
	if !sni.HostnameChecked || sni.HostnameOK {
		t.Fatalf("hostname of the default certificate: checked %v ok %v", sni.HostnameChecked, sni.HostnameOK)
	}

	// An IP literal is never sent in SNI, so there is no other handshake.
	r.ServerName = "127.0.0.1"
	a = single(t, Probe(context.Background(), r))
	for _, o := range a.Others {
		if o.Via == ViaNoSNI {
			t.Fatalf("no-SNI test run for an IP server name: %+v", o)
		}
	}
}

func mustStapleLeaf(t *testing.T, parent *testCert) *testCert {
	t.Helper()
	val, err := asn1.Marshal([]int{5})
	if err != nil {
		t.Fatal(err)
	}
	return newCert(t, &x509.Certificate{
		Subject:         pkix.Name{CommonName: "staple.example"},
		DNSNames:        []string{"staple.example"},
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: oidTLSFeature, Value: val}},
	}, parent, nil)
}

func TestMustStapleExtension(t *testing.T) {
	p := newPKI(t)
	if !MustStaple(mustStapleLeaf(t, p.inter).cert) || MustStaple(p.leaf.cert) {
		t.Fatal("must-staple misread")
	}
	other, _ := asn1.Marshal([]int{17}) // status_request_v2 alone is not must-staple
	c := newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "v2.example"}, ExtraExtensions: []pkix.Extension{{Id: oidTLSFeature, Value: other}}}, p.inter, nil)
	if MustStaple(c.cert) {
		t.Fatal("status_request_v2 read as must-staple")
	}
	garbage := newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "bad.example"}, ExtraExtensions: []pkix.Extension{{Id: oidTLSFeature, Value: []byte{0x02, 0x01, 0x05}}}}, p.inter, nil)
	if MustStaple(garbage.cert) {
		t.Fatal("a malformed extension read as must-staple")
	}
}

// A server that staples from its second handshake on, as nginx does after
// a restart: the probe asks again and gets the staple.
func TestMustStapleRetried(t *testing.T) {
	old := stapleRetryDelay
	stapleRetryDelay = 10 * time.Millisecond
	t.Cleanup(func() { stapleRetryDelay = old })
	p := newPKI(t)
	leaf := mustStapleLeaf(t, p.inter)
	bare, stapled := tlsCert(leaf, p.inter), tlsCert(leaf, p.inter)
	stapled.OCSPStaple = []byte{0x30, 0x03, 0x0a, 0x01, 0x00}
	var n atomic.Int32
	cfg := &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if n.Add(1) == 1 {
			return &bare, nil
		}
		return &stapled, nil
	}}
	a := single(t, Probe(context.Background(), req(serve(t, cfg, nil), TLS)))
	if !a.OK || len(a.OCSP) == 0 || n.Load() != 2 {
		t.Fatalf("staple %x after %d handshakes", a.OCSP, n.Load())
	}

	// A leaf without must-staple is not asked twice.
	n.Store(0)
	plain := tlsCert(p.leaf, p.inter)
	cfg = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { n.Add(1); return &plain, nil }}
	single(t, Probe(context.Background(), req(serve(t, cfg, nil), TLS)))
	if n.Load() != 1 {
		t.Fatalf("%d handshakes for a leaf without must-staple", n.Load())
	}
}
