package probe

import (
	"context"
	"crypto/tls"
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

// The configuration test finds out whether the address negotiates
// post-quantum key exchange; the normal probe records the group.
func TestPostQuantumKeyExchange(t *testing.T) {
	p := newPKI(t)
	r := req(serve(t, serverConfig(p.leaf, p.inter), nil), TLS)
	r.Legacy = true
	a := single(t, Probe(context.Background(), r))
	if a.Group != "X25519MLKEM768" || !a.PQChecked || !a.PQ {
		t.Fatalf("default Go server: group %q checked %v pq %v", a.Group, a.PQChecked, a.PQ)
	}

	classic := serverConfig(p.leaf, p.inter)
	classic.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	r = req(serve(t, classic, nil), TLS)
	r.Legacy = true
	a = single(t, Probe(context.Background(), r))
	if a.Group != "X25519" || !a.PQChecked || a.PQ {
		t.Fatalf("classic server: group %q checked %v pq %v", a.Group, a.PQChecked, a.PQ)
	}
	// Without the configuration test nothing is decided.
	r.Legacy = false
	if a = single(t, Probe(context.Background(), r)); a.PQChecked {
		t.Fatal("tested without the configuration test")
	}
}
