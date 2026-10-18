package probe

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestStapledResponseRecorded(t *testing.T) {
	p := newPKI(t)
	der, err := ocsp.CreateResponse(p.inter.cert, p.inter.cert, ocsp.Response{Status: ocsp.Good, SerialNumber: p.leaf.cert.SerialNumber,
		ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(24 * time.Hour)}, p.inter.key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := serverConfig(p.leaf, p.inter)
	cfg.Certificates[0].OCSPStaple = der
	r := req(serve(t, cfg, nil), TLS)
	r.Trust, r.Roots = TrustBundle, p.pool
	a := single(t, Probe(context.Background(), r))
	if s := StapleOf(a); s.Status != StapleGood {
		t.Fatalf("staple: %+v (%d bytes)", s, len(a.OCSP))
	}
	if Issuer(a) == nil || !Issuer(a).Equal(p.inter.cert) {
		t.Fatal("issuer not found in the chain")
	}

	// Without a staple nothing is recorded.
	a = single(t, Probe(context.Background(), req(serve(t, serverConfig(p.leaf, p.inter), nil), TLS)))
	if len(a.OCSP) != 0 || StapleOf(a).Status != "" {
		t.Fatalf("no staple: %+v", StapleOf(a))
	}
}
