package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/caa"
	"github.com/sjoerd305/tlswatch/internal/check"
)

type failingCAA struct{}

func (failingCAA) CAA(context.Context, string) ([]caa.Record, error) {
	return nil, errors.New("the resolver answered ServerFailure")
}

// caaOf returns the CAA verdict and detail of each issuance by its first name.
func (e *env) caaOf(id int64) map[string]Issuance {
	e.t.Helper()
	list, err := e.svc.Issuances(e.ctx, id, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	m := map[string]Issuance{}
	for _, i := range list {
		m[i.Names[0]] = i
	}
	return m
}

func TestCAAViolation(t *testing.T) {
	e, stub, d, _, _ := ctServed(t)
	// The first poll found no record: the baseline, no event.
	if n := e.count("SELECT COUNT(*) FROM findings WHERE kind = 'caa_changed'"); n != 0 {
		t.Fatalf("%d caa_changed events on the baseline", n)
	}
	e.svc.CAAResolver = caa.Static{
		"example.nl":      {{Tag: "issue", Value: "letsencrypt.org"}, {Tag: "issuewild", Value: ";"}},
		"shop.example.nl": {{Tag: "issue", Value: "sectigo.com"}},
	}
	nb := e.clock.Now().Add(-time.Hour)
	na := nb.Add(days(90))
	le, sectigo := "C=US, O=Let's Encrypt, CN=R11", "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV"
	stub.entry(60, "admin.example.nl", []string{"admin.example.nl"}, sectigo, "6001", nb, na)
	stub.entry(61, "le.example.nl", []string{"le.example.nl"}, le, "6002", nb, na)
	stub.entry(62, "shop.example.nl", []string{"shop.example.nl"}, sectigo, "6003", nb, na)
	stub.entry(63, "*.example.nl", []string{"*.example.nl"}, le, "6004", nb, na)
	stub.entry(64, "odd.example.nl", []string{"odd.example.nl"}, "C=XX, O=Nobody, CN=Nobody CA", "6005", nb, na)
	e.poll()

	got := e.caaOf(d.ID)
	for name, want := range map[string]string{"admin.example.nl": CAAViolation, "le.example.nl": CAAPermitted, "shop.example.nl": CAAPermitted,
		"*.example.nl": CAAViolation, "odd.example.nl": CAAUnknownIssuer} {
		if got[name].CAA != want {
			t.Errorf("%s: %q (%s), want %q", name, got[name].CAA, got[name].CAADetail, want)
		}
	}
	if !strings.Contains(got["admin.example.nl"].CAADetail, "Sectigo Limited issued for admin.example.nl, but the CAA record at example.nl allows only letsencrypt.org") {
		t.Errorf("detail: %s", got["admin.example.nl"].CAADetail)
	}
	if !strings.Contains(got["*.example.nl"].CAADetail, `allows no CA (issuewild ";")`) {
		t.Errorf("wildcard detail: %s", got["*.example.nl"].CAADetail)
	}
	if n := e.count("SELECT COUNT(*) FROM findings WHERE domain_id = ? AND kind = 'caa_violation' AND resolved_at = 0", d.ID); n != 2 {
		t.Fatalf("%d caa_violation findings", n)
	}
	// The record set changed since the baseline: an info event.
	ch, _ := e.svc.RecentChanges(e.ctx, 0, 20)
	found := false
	for _, f := range ch {
		found = found || f.Kind == check.CAAChanged && strings.Contains(f.Details, `none (any CA may issue) → example.nl 0 issue "letsencrypt.org"`)
	}
	if !found {
		t.Fatalf("no caa_changed in recent changes: %+v", ch)
	}
	dm, _ := e.svc.Domain(e.ctx, d.ID)
	if dm.Status() != StatusWarning || dm.CAA.Empty() || dm.CAACheckedAt == 0 {
		t.Fatalf("domain: %s %+v", dm.Status(), dm.CAA)
	}

	// Acknowledging resolves the finding and marks the issuance.
	var fid int64
	if err := e.svc.DB.R.QueryRow("SELECT id FROM findings WHERE kind = 'caa_violation' AND fingerprint = ?", got["admin.example.nl"].ID).Scan(&fid); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Acknowledge(e.ctx, fid, "admin", time.Time{}, "old record"); err != nil {
		t.Fatal(err)
	}
	if e.caaOf(d.ID)["admin.example.nl"].CAA != CAAAcknowledged {
		t.Fatal("issuance not marked acknowledged")
	}

	// Disabling closes the other; enabling opens it again, not the
	// acknowledged one.
	if err := e.svc.SetDomainEnabled(e.ctx, d.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetDomainEnabled(e.ctx, d.ID, true); err != nil {
		t.Fatal(err)
	}
	if n := e.count("SELECT COUNT(*) FROM findings WHERE domain_id = ? AND kind = 'caa_violation' AND resolved_at = 0", d.ID); n != 1 {
		t.Fatalf("%d caa_violation findings after enabling", n)
	}
}

func TestCAALookupFailureJudgesNothing(t *testing.T) {
	e, stub, d, _, _ := ctServed(t)
	e.svc.CAAResolver = failingCAA{}
	nb := e.clock.Now().Add(-time.Hour)
	stub.entry(70, "admin.example.nl", []string{"admin.example.nl"}, "C=GB, O=Sectigo Limited, CN=Sectigo RSA DV", "7001", nb, nb.Add(days(90)))
	e.poll()
	if i := e.caaOf(d.ID)["admin.example.nl"]; i.CAA != CAALookupFailed {
		t.Fatalf("verdict %q", i.CAA)
	}
	if n := e.count("SELECT COUNT(*) FROM findings WHERE kind = 'caa_violation'"); n != 0 {
		t.Fatalf("%d violations on a failed lookup", n)
	}
	if dm, _ := e.svc.Domain(e.ctx, d.ID); !strings.Contains(dm.CAAError, "ServerFailure") {
		t.Fatalf("error not kept: %q", dm.CAAError)
	}
}
