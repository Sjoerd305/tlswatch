package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
	"github.com/sjoerd305/tlswatch/internal/secret"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial int64 = 100

func newCA(t *testing.T, org string) ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: org + " CA", Organization: []string{org}},
		NotBefore: time.Now().Add(-1000 * 24 * time.Hour), NotAfter: time.Now().Add(3000 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return ca{c, key}
}

func (a ca) leaf(t *testing.T, nb, na time.Time, sans ...string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: sans[0]}, DNSNames: sans,
		NotBefore: nb, NotAfter: na, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// served is a successful probe of one address.
func served(ip string, chain ...*x509.Certificate) probe.Address {
	return probe.Address{IP: ip, OK: true, TLSVersion: "TLS 1.3", Cipher: "TLS_AES_128_GCM_SHA256", Chain: chain, Verified: true,
		HostnameChecked: true, HostnameOK: true, Duration: 20 * time.Millisecond}
}

func result(addrs ...probe.Address) probe.Result {
	return probe.Result{Host: "portal.example.nl", Port: 443, Protocol: probe.TLS, StartedAt: time.Now(), Addresses: addrs}
}

func failed(ip string) probe.Address {
	return probe.Address{IP: ip, ErrorKind: probe.ErrConnect, Error: "connection refused"}
}

type env struct {
	t     *testing.T
	ctx   context.Context
	svc   *Service
	clock *clock
	sent  map[string][]notify.Message // per channel name
	mu    sync.Mutex
	disp  *notify.Dispatcher
	chW   int64 // floor warning
	chC   int64 // floor critical
}

type fakeSender struct {
	e    *env
	name string
}

func (f fakeSender) Send(_ context.Context, m notify.Message) error {
	f.e.mu.Lock()
	defer f.e.mu.Unlock()
	f.e.sent[f.name] = append(f.e.sent[f.name], m)
	return nil
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	key, _ := secret.New(make([]byte, 32))
	c := &clock{t: time.Now()}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	chans := &notify.Channels{DB: d, Key: key, Now: c.Now}
	e := &env{t: t, ctx: context.Background(), clock: c, sent: map[string][]notify.Message{}}
	e.disp = &notify.Dispatcher{DB: d, Channels: chans, Now: c.Now, Log: log}
	e.disp.Senders = func(ch notify.Channel) notify.Sender { return fakeSender{e, ch.Name} }
	e.svc = &Service{DB: d, Settings: config.NewStore(d, key), Channels: chans, Dispatcher: e.disp, Now: c.Now, Log: log}
	e.chW, err = chans.Save(e.ctx, notify.Channel{Name: "mail", Kind: notify.KindSMTP, MinSeverity: "warning", Enabled: true,
		SMTP: notify.SMTPSettings{Host: "smtp.example.nl", Port: 587, From: "tlswatch@example.nl", Recipients: []string{"ops@example.nl"}}})
	if err != nil {
		t.Fatal(err)
	}
	e.chC, err = chans.Save(e.ctx, notify.Channel{Name: "telegram", Kind: notify.KindTelegram, MinSeverity: "critical", Enabled: true,
		Telegram: notify.TelegramSettings{Token: "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ", ChatIDs: []string{"-1001"}}})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) target(mut func(*Target)) Target {
	e.t.Helper()
	t := Target{Name: "Portal", Host: "portal.example.nl", Port: 443, Protocol: probe.TLS, ServerName: "portal.example.nl",
		Trust: probe.TrustSystem, AllAddresses: true, AllChannels: true, Enabled: true, RenewalSet: true}
	if mut != nil {
		mut(&t)
	}
	id, err := e.svc.SaveTarget(e.ctx, t, "test")
	if err != nil {
		e.t.Fatal(err)
	}
	got, err := e.svc.Target(e.ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

func (e *env) apply(id int64, r probe.Result) Target {
	e.t.Helper()
	t, err := e.svc.Target(e.ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.svc.Apply(e.ctx, t, r); err != nil {
		e.t.Fatal(err)
	}
	t, _ = e.svc.Target(e.ctx, id)
	return t
}

func (e *env) open(id int64) map[check.Kind]Finding {
	e.t.Helper()
	fs, err := e.svc.Findings(e.ctx, FindingFilter{TargetID: id})
	if err != nil {
		e.t.Fatal(err)
	}
	m := map[check.Kind]Finding{}
	for _, f := range fs {
		m[f.Kind] = f
	}
	return m
}

// flush delivers the outbox after the batch delay.
func (e *env) flush() {
	e.t.Helper()
	e.clock.Add(notify.BatchDelay + time.Second)
	if err := e.disp.Flush(e.ctx); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) take(ch string) []notify.Message {
	e.mu.Lock()
	defer e.mu.Unlock()
	m := e.sent[ch]
	delete(e.sent, ch)
	return m
}

func days(n float64) time.Duration { return time.Duration(n * 24 * float64(time.Hour)) }

func TestExpiryLifecycle(t *testing.T) {
	e := newEnv(t)
	sectigo := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)

	// 40 days left: healthy, nothing open, nothing sent.
	c1 := sectigo.leaf(t, now.Add(-days(325)), now.Add(days(40)+time.Hour), "portal.example.nl")
	tg = e.apply(tg.ID, result(served("192.0.2.1", c1, sectigo.cert)))
	if tg.Status != StatusHealthy || len(e.open(tg.ID)) != 0 {
		t.Fatalf("status %s, findings %v", tg.Status, e.open(tg.ID))
	}

	// 29 days and some hours left: "warning 30" fires (strictly fewer than 30 whole days).
	e.clock.Add(days(11))
	tg = e.apply(tg.ID, result(served("192.0.2.1", c1, sectigo.cert)))
	f, ok := e.open(tg.ID)[check.Expiring]
	if !ok || f.Severity != check.Warning || *f.DaysLeft != 29 {
		t.Fatalf("expiring finding: %+v", f)
	}
	if tg.Status != StatusWarning {
		t.Fatalf("status %s", tg.Status)
	}
	e.flush()
	mail := e.take("mail")
	if len(mail) != 1 || !strings.HasPrefix(mail[0].Subject, "[warning] portal.example.nl:443 expires in 29 days") {
		t.Fatalf("mail: %+v", mail)
	}
	if !strings.Contains(mail[0].HTML, "portal.example.nl:443 expires in 29 days") {
		t.Fatal("queued alert lost its HTML part")
	}
	if tm := e.take("telegram"); len(tm) != 0 {
		t.Fatalf("telegram floor critical got a warning: %+v", tm)
	}

	// Same state again: no new alert (transitions only).
	e.clock.Add(time.Hour)
	e.apply(tg.ID, result(served("192.0.2.1", c1, sectigo.cert)))
	e.flush()
	if m := e.take("mail"); len(m) != 0 {
		t.Fatalf("repeat check alerted: %+v", m)
	}

	// 6 days left: escalates to critical, both channels get it.
	e.clock.Add(days(23))
	tg = e.apply(tg.ID, result(served("192.0.2.1", c1, sectigo.cert)))
	if f := e.open(tg.ID)[check.Expiring]; f.Severity != check.Critical {
		t.Fatalf("not escalated: %+v", f)
	}
	e.flush()
	if m := e.take("mail"); len(m) != 1 || !strings.Contains(m[0].Subject, "escalated") {
		t.Fatalf("mail escalate: %+v", m)
	}
	if m := e.take("telegram"); len(m) != 1 || !strings.HasPrefix(m[0].Subject, "[critical]") {
		t.Fatalf("telegram escalate: %+v", m)
	}

	// Reminder after the critical interval (1 day), not before.
	e.clock.Add(12 * time.Hour)
	if n, _ := e.svc.Remind(e.ctx); n != 0 {
		t.Fatalf("early reminder: %d", n)
	}
	e.clock.Add(13 * time.Hour)
	if n, _ := e.svc.Remind(e.ctx); n != 2 {
		t.Fatalf("reminders queued: %d", n)
	}
	e.flush()
	if m := e.take("mail"); len(m) != 1 || !strings.Contains(m[0].Subject, "still open since") {
		t.Fatalf("reminder: %+v", m)
	}
	e.take("telegram")

	// Acknowledged: no reminders.
	f = e.open(tg.ID)[check.Expiring]
	if _, err := e.svc.Acknowledge(e.ctx, f.ID, "Alex", time.Time{}, "renewal ordered"); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(days(2))
	if n, _ := e.svc.Remind(e.ctx); n != 0 {
		t.Fatalf("acknowledged finding reminded: %d", n)
	}

	// Renewed manually: expiring recovers (to the channels that got it),
	// certificate_changed opens as a warning.
	c2 := sectigo.leaf(t, e.clock.Now(), e.clock.Now().Add(days(365)), "portal.example.nl")
	tg = e.apply(tg.ID, result(served("192.0.2.1", c2, sectigo.cert)))
	open := e.open(tg.ID)
	if _, ok := open[check.Expiring]; ok {
		t.Fatal("expiring still open after renewal")
	}
	ch, ok := open[check.CertificateChanged]
	if !ok || ch.Severity != check.Warning {
		t.Fatalf("certificate_changed: %+v", open)
	}
	if tg.Status != StatusChanged {
		t.Fatalf("status %s", tg.Status)
	}
	e.flush()
	mail = e.take("mail")
	// Recovery and the change notice are collapsed into one message.
	if len(mail) != 1 || !strings.Contains(mail[0].Body, "[resolved] portal.example.nl:443 expiring resolved") || !strings.Contains(mail[0].Body, "certificate changed") {
		t.Fatalf("mail after renewal: %+v", mail)
	}
	if m := e.take("telegram"); len(m) != 1 || !strings.HasPrefix(m[0].Subject, "[resolved]") {
		t.Fatalf("telegram recovery: %+v", m)
	}

	// Confirming the change resolves it.
	if _, err := e.svc.Acknowledge(e.ctx, ch.ID, "Sjoerd", time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	if tg, _ = e.svc.Target(e.ctx, tg.ID); tg.Status != StatusHealthy || len(e.open(tg.ID)) != 0 {
		t.Fatalf("after confirm: %s %v", tg.Status, e.open(tg.ID))
	}
	// And stays resolved on the next check.
	tg = e.apply(tg.ID, result(served("192.0.2.1", c2, sectigo.cert)))
	if len(e.open(tg.ID)) != 0 {
		t.Fatalf("reopened: %v", e.open(tg.ID))
	}
}

func TestExpiredDoesNotRecoverExpiring(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	c := ca.leaf(t, now.Add(-days(360)), now.Add(days(2)), "portal.example.nl")
	e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	e.flush()
	e.take("mail")
	e.take("telegram")
	e.clock.Add(days(3))
	e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	open := e.open(tg.ID)
	if _, ok := open[check.Expired]; !ok {
		t.Fatalf("expired not open: %v", open)
	}
	e.flush()
	for _, m := range e.take("mail") {
		if strings.Contains(m.Subject+m.Body, "resolved") {
			t.Fatalf("expiring 'recovered' when it expired: %s", m.Subject)
		}
	}
}

func TestACMERenewalIsInfo(t *testing.T) {
	e := newEnv(t)
	le := newCA(t, "Let's Encrypt")
	now := e.clock.Now()
	tg := e.target(func(t *Target) { t.RenewalSet = false })
	c1 := le.leaf(t, now.Add(-days(60)), now.Add(days(30)), "portal.example.nl")
	tg = e.apply(tg.ID, result(served("192.0.2.1", c1, le.cert)))
	if !tg.RenewalManaged {
		t.Fatal("renewal managed not derived from the ACME issuer")
	}
	// Managed thresholds are 10/3, so 30 days left is healthy.
	if tg.Status != StatusHealthy {
		t.Fatalf("status %s, %v", tg.Status, e.open(tg.ID))
	}
	c2 := le.leaf(t, now, now.Add(days(90)), "portal.example.nl", "www.portal.example.nl")
	tg = e.apply(tg.ID, result(served("192.0.2.1", c2, le.cert)))
	if len(e.open(tg.ID)) != 0 || tg.Status != StatusHealthy {
		t.Fatalf("ACME renewal opened findings: %v", e.open(tg.ID))
	}
	ch, _ := e.svc.RecentChanges(e.ctx, 0, 10)
	if len(ch) != 1 || ch[0].Severity != check.Info || !strings.Contains(ch[0].Details, "renewed by Let's Encrypt") {
		t.Fatalf("recent changes: %+v", ch)
	}
	e.flush()
	if m := e.take("mail"); len(m) != 0 {
		t.Fatalf("info renewal alerted: %+v", m)
	}
	// The weekly digest lists open findings; the renewal is recorded as
	// resolved and stays out of it.
	if d, err := e.svc.Digest(e.ctx); err != nil {
		t.Fatal(err)
	} else if strings.Contains(d.Body, "renewed by") || strings.Contains(d.HTML, "renewed by") {
		t.Fatalf("info renewal in the digest:\n%s", d.Body)
	}
	// A different CA on an ACME target is a warning, plus issuer_changed.
	other := newCA(t, "Sectigo")
	c3 := other.leaf(t, now, now.Add(days(365)), "portal.example.nl", "www.portal.example.nl")
	e.apply(tg.ID, result(served("192.0.2.1", c3, other.cert)))
	open := e.open(tg.ID)
	if open[check.CertificateChanged].Severity != check.Warning || open[check.IssuerChanged].Severity != check.Warning {
		t.Fatalf("issuer change: %v", open)
	}
}

func TestUnreachableDebounce(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	c := ca.leaf(t, now.Add(-days(10)), now.Add(days(300)), "portal.example.nl")
	e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))

	tg = e.apply(tg.ID, result(failed("192.0.2.1")))
	if _, ok := e.open(tg.ID)[check.Unreachable]; ok {
		t.Fatal("opened after one failure")
	}
	// The finding waits for the debounce, the status does not.
	if tg.Status != StatusUnreachable {
		t.Fatalf("status after one failed check: %s", tg.Status)
	}
	tg = e.apply(tg.ID, result(failed("192.0.2.1")))
	if _, ok := e.open(tg.ID)[check.Unreachable]; !ok || tg.Status != StatusUnreachable {
		t.Fatalf("not opened after two failures: %s", tg.Status)
	}
	e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	if _, ok := e.open(tg.ID)[check.Unreachable]; !ok {
		t.Fatal("closed after one success")
	}
	tg = e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	if _, ok := e.open(tg.ID)[check.Unreachable]; ok || tg.Status != StatusHealthy {
		t.Fatalf("still open after two successes: %s", tg.Status)
	}
}

func TestNeverAnsweredIsNotHealthy(t *testing.T) {
	e := newEnv(t)
	tg := e.target(func(t *Target) { t.Protocol = probe.SMTP; t.Port = 465 })
	r := result(failed("192.0.2.1"))
	r.Protocol, r.Port = probe.SMTP, 465
	tg = e.apply(tg.ID, r)
	if tg.Status != StatusUnreachable {
		t.Fatalf("status %s", tg.Status)
	}
	if !strings.Contains(tg.LastError, "choose protocol tls") {
		t.Fatalf("no port hint in %q", tg.LastError)
	}
}

func TestInconsistentAddresses(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	fresh := ca.leaf(t, now, now.Add(days(300)), "portal.example.nl")
	stale := ca.leaf(t, now.Add(-days(350)), now.Add(days(12)), "portal.example.nl")
	tg = e.apply(tg.ID, result(served("192.0.2.1", fresh, ca.cert), served("2001:db8::1", stale, ca.cert)))
	open := e.open(tg.ID)
	if _, ok := open[check.Inconsistent]; !ok {
		t.Fatalf("inconsistent not opened: %v", open)
	}
	// The earliest expiry across addresses counts.
	if f := open[check.Expiring]; f.DaysLeft == nil || *f.DaysLeft != 11 {
		t.Fatalf("expiring from the stale node: %+v", f)
	}
	// The current certificate is the fresher one on a tie.
	if tg.CurrentFP != probe.Fingerprint(fresh) {
		t.Fatal("current fingerprint is the stale node's")
	}
	inv, _ := e.svc.Inventory(e.ctx)
	stales := 0
	for _, it := range inv {
		if it.Stale {
			stales++
		}
	}
	if stales != 1 {
		t.Fatalf("stale node rows: %d", stales)
	}
}

func TestSelfSignedPinning(t *testing.T) {
	e := newEnv(t)
	now := e.clock.Now()
	self := newCA(t, "pfSense")
	tg := e.target(func(t *Target) { t.Trust = probe.TrustSelfSigned; t.ServerName = "" })
	a := self.cert
	r := result(probe.Address{IP: "192.0.2.9", OK: true, Chain: []*x509.Certificate{a}})
	tg = e.apply(tg.ID, r)
	if tg.PinnedFP != probe.Fingerprint(a) || len(e.open(tg.ID)) != 0 {
		t.Fatalf("pin %q, open %v", tg.PinnedFP, e.open(tg.ID))
	}
	b := newCA(t, "pfSense").cert
	_ = now
	e.apply(tg.ID, result(probe.Address{IP: "192.0.2.9", OK: true, Chain: []*x509.Certificate{b}}))
	f, ok := e.open(tg.ID)[check.CertificateChanged]
	if !ok {
		t.Fatal("pinned change not reported")
	}
	if _, err := e.svc.Acknowledge(e.ctx, f.ID, "op", time.Time{}, "replaced"); err != nil {
		t.Fatal(err)
	}
	tg, _ = e.svc.Target(e.ctx, tg.ID)
	if tg.PinnedFP != probe.Fingerprint(b) {
		t.Fatal("acknowledging did not re-pin")
	}
	e.apply(tg.ID, result(probe.Address{IP: "192.0.2.9", OK: true, Chain: []*x509.Certificate{b}}))
	if len(e.open(tg.ID)) != 0 {
		t.Fatalf("after re-pin: %v", e.open(tg.ID))
	}
}

func TestBatchCollapsesPerChannel(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	for i := 0; i < 60; i++ {
		tg := e.target(func(t *Target) { t.Port = 1000 + i })
		c := ca.leaf(t, now.Add(-days(360)), now.Add(days(3)), "portal.example.nl")
		e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	}
	e.flush()
	mail := e.take("mail")
	if len(mail) != 1 {
		t.Fatalf("expected one collapsed message, got %d", len(mail))
	}
	if !strings.Contains(mail[0].Subject, "60 alerts") || !strings.Contains(mail[0].Body, "and 10 more") {
		t.Fatalf("collapsed: %s\n%s", mail[0].Subject, mail[0].Body)
	}
	if !strings.Contains(mail[0].HTML, "60 alerts from tlswatch") || !strings.Contains(mail[0].HTML, "and 10 more") {
		t.Fatal("collapsed mail has no HTML part")
	}
	// Every alert of the batch records the reference the message went out under.
	var refs, n int
	_ = e.svc.DB.R.QueryRow("SELECT COUNT(DISTINCT ref), COUNT(*) FROM alerts WHERE channel_id = ? AND ref = ?", e.chW, notify.MessageID(mail[0].Ref)).Scan(&refs, &n)
	if mail[0].Ref == "" || refs != 1 || n != 60 {
		t.Fatalf("ref %q on %d alerts", mail[0].Ref, n)
	}
}

func TestRetryBackoffAndFailure(t *testing.T) {
	e := newEnv(t)
	calls := 0
	e.disp.Senders = func(notify.Channel) notify.Sender {
		return senderFunc(func() error { calls++; return io.ErrUnexpectedEOF })
	}
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(func(t *Target) { t.AllChannels = false; t.ChannelIDs = []int64{e.chW} })
	c := ca.leaf(t, now.Add(-days(360)), now.Add(days(20)), "portal.example.nl")
	e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	e.flush()
	if calls != 1 {
		t.Fatalf("calls %d", calls)
	}
	e.flush() // 16 s later: not yet due (1 min backoff)
	if calls != 1 {
		t.Fatalf("retried too early: %d", calls)
	}
	for i := 0; i < 40; i++ {
		e.clock.Add(time.Hour)
		_ = e.disp.Flush(e.ctx)
	}
	var state string
	_ = e.svc.DB.R.QueryRow("SELECT state FROM alerts ORDER BY id DESC LIMIT 1").Scan(&state)
	if state != "failed" {
		t.Fatalf("state after 24 h of retries: %s", state)
	}
	if calls < 20 || calls > 30 {
		t.Fatalf("attempts over 24 h: %d", calls)
	}
}

// A channel whose settings cannot be decrypted (the secret key changed) does
// not stop checks or the other channels; its alerts fail visibly.
func TestUnreadableChannelDoesNotStopChecks(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.DB.W.Exec("UPDATE channels SET settings = x'00' WHERE id = ?", e.chC); err != nil {
		t.Fatal(err)
	}
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	c := ca.leaf(t, now.Add(-days(360)), now.Add(days(3)), "portal.example.nl")
	tg = e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	if _, ok := e.open(tg.ID)[check.Expiring]; !ok {
		t.Fatal("check not stored")
	}
	e.flush()
	if len(e.take("mail")) != 1 {
		t.Fatal("readable channel not served")
	}
	chans, err := e.svc.Channels.List(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range chans {
		if ch.ID == e.chC && (ch.Unreadable == "" || ch.LastState != "retrying" || !strings.Contains(ch.LastError, "decrypt")) {
			t.Fatalf("unreadable channel: %+v", ch)
		}
	}
}

// A probe result for a target disabled or moved to another endpoint while
// it was being probed is discarded.
func TestApplyDiscardsStaleTarget(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	expiring := result(served("192.0.2.1", ca.leaf(t, now.Add(-days(360)), now.Add(days(3)), "portal.example.nl"), ca.cert))

	tg := e.target(nil)
	if err := e.svc.SetEnabled(e.ctx, tg.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Apply(e.ctx, tg, expiring); !errors.Is(err, ErrStale) {
		t.Fatalf("disabled meanwhile: %v", err)
	}
	if len(e.open(tg.ID)) != 0 {
		t.Fatal("findings opened on a disabled target")
	}

	tg = e.target(func(t *Target) { t.Port = 8443 })
	moved := tg
	moved.Host = "new.example.nl"
	if _, err := e.svc.SaveTarget(e.ctx, moved, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Apply(e.ctx, tg, expiring); !errors.Is(err, ErrStale) {
		t.Fatalf("host changed meanwhile: %v", err)
	}
	if got, _ := e.svc.Target(e.ctx, tg.ID); got.CurrentFP != "" {
		t.Fatal("old endpoint's certificate stored as current")
	}
}

// A Telegram chat that fails does not make the retry repeat the message to
// the chats that got it, and a rate limit's retry_after is honoured.
func TestTelegramRetrySkipsReachedChats(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	got := map[string]int{}
	limited := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		defer mu.Unlock()
		chat := r.Form.Get("chat_id")
		if chat == "-1002" && limited {
			limited = false
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"ok":false,"description":"Too Many Requests: retry after 120","parameters":{"retry_after":120}}`))
			return
		}
		got[chat]++
		_, _ = fmt.Fprintf(w, `{"ok":true,"result":{"message_id":%d}}`, 100+got[chat])
	}))
	defer srv.Close()
	tg, err := e.svc.Channels.Save(e.ctx, notify.Channel{Name: "ops", Kind: notify.KindTelegram, MinSeverity: "warning", Enabled: true,
		Telegram: notify.TelegramSettings{Token: "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ", ChatIDs: []string{"-1001", "-1002"}}})
	if err != nil {
		t.Fatal(err)
	}
	e.disp.Senders = func(ch notify.Channel) notify.Sender {
		return &notify.TelegramSender{S: ch.Telegram, BaseURL: srv.URL}
	}
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	target := e.target(func(t *Target) { t.AllChannels = false; t.ChannelIDs = []int64{tg} })
	e.apply(target.ID, result(served("192.0.2.1", ca.leaf(t, now.Add(-days(360)), now.Add(days(3)), "portal.example.nl"), ca.cert)))

	e.flush()
	var delivered string
	var next int64
	_ = e.svc.DB.R.QueryRow("SELECT delivered, next_attempt FROM alerts WHERE channel_id = ?", tg).Scan(&delivered, &next)
	if delivered != "-1001" || got["-1001"] != 1 || got["-1002"] != 0 {
		t.Fatalf("first attempt: delivered %q, got %v", delivered, got)
	}
	if wait := next - e.clock.Now().Unix(); wait < 119 {
		t.Fatalf("retry in %d s, retry_after was 120", wait)
	}
	e.clock.Add(2 * time.Minute)
	if err := e.disp.Flush(e.ctx); err != nil {
		t.Fatal(err)
	}
	if got["-1001"] != 1 || got["-1002"] != 1 {
		t.Fatalf("after retry: %v", got)
	}
	// The alert records Telegram's message ID for each chat.
	var ref string
	_ = e.svc.DB.R.QueryRow("SELECT ref FROM alerts WHERE channel_id = ?", tg).Scan(&ref)
	if ref != "-1001:101,-1002:101" {
		t.Fatalf("ref %q", ref)
	}
}

func TestDeleteBundle(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Internal")
	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))
	id, err := e.svc.SaveBundle(e.ctx, 0, "internal", pemData)
	if err != nil {
		t.Fatal(err)
	}
	tg := e.target(func(t *Target) { t.Trust = probe.TrustBundle; t.BundleID = id })
	if err := e.svc.DeleteBundle(e.ctx, id); !errors.Is(err, ErrBundleInUse) {
		t.Fatalf("delete in use: %v", err)
	}
	if err := e.svc.DeleteTarget(e.ctx, tg.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteBundle(e.ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteBundle(e.ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if _, err := e.svc.BundlePool(e.ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pool of a deleted bundle: %v", err)
	}
}

type senderFunc func() error

func (f senderFunc) Send(context.Context, notify.Message) error { return f() }

func TestNextCheckSlotIsStable(t *testing.T) {
	iv := 24 * time.Hour
	base := time.Date(2026, 10, 14, 15, 0, 0, 0, time.UTC)
	a := NextCheck(7, iv, base)
	b := NextCheck(7, iv, a.Add(3*time.Second))
	if b.Sub(a) != iv {
		t.Fatalf("slot drifted: %v then %v", a, b)
	}
	if a.Before(base.Add(iv/2)) || a.After(base.Add(iv+iv/2)) {
		t.Fatalf("next check out of range: %v", a)
	}
	if Slot(7, iv) == Slot(8, iv) {
		t.Fatal("targets share a slot")
	}
}

func TestPruneKeepsCurrentState(t *testing.T) {
	e := newEnv(t)
	oldCA, ca := newCA(t, "Old CA"), newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	old := oldCA.leaf(t, now.Add(-days(10)), now.Add(days(1000)), "portal.example.nl")
	e.apply(tg.ID, result(served("192.0.2.1", old, oldCA.cert)))
	e.clock.Add(days(200))
	c := ca.leaf(t, now.Add(-days(10)), now.Add(days(1000)), "portal.example.nl")
	e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	e.clock.Add(days(200))
	if err := e.svc.Prune(e.ctx); err != nil {
		t.Fatal(err)
	}
	obs, _ := e.svc.LastCheck(e.ctx, tg.ID)
	if len(obs) != 1 || obs[0].LeafFP != probe.Fingerprint(c) {
		t.Fatal("latest check pruned")
	}
	var n int
	_ = e.svc.DB.R.QueryRow("SELECT COUNT(*) FROM observations").Scan(&n)
	if n != 1 {
		t.Fatalf("%d observations left, want the latest only", n)
	}
	for _, kept := range []*x509.Certificate{c, ca.cert} {
		if _, err := e.svc.Certificate(e.ctx, probe.Fingerprint(kept)); err != nil {
			t.Fatalf("%s pruned while the latest check serves it", kept.Subject.CommonName)
		}
	}
	for _, gone := range []*x509.Certificate{old, oldCA.cert} {
		if _, err := e.svc.Certificate(e.ctx, probe.Fingerprint(gone)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s kept: %v", gone.Subject.CommonName, err)
		}
	}
}

// The live-page stamp moves with every change the pages show.
func TestStampChanges(t *testing.T) {
	e := newEnv(t)
	stamp := func() string {
		st, _, err := e.svc.Stamp(e.ctx)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	s0 := stamp()
	tg := e.target(nil)
	s1 := stamp()
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	e.apply(tg.ID, result(served("192.0.2.1", ca.leaf(t, now.Add(-days(360)), now.Add(days(3)), "portal.example.nl"), ca.cert)))
	s2 := stamp()
	f := e.open(tg.ID)[check.Expiring]
	if _, err := e.svc.Acknowledge(e.ctx, f.ID, "test", time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	s3 := stamp()
	e.flush()
	s4 := stamp()
	if s0 == s1 || s1 == s2 || s2 == s3 || s3 == s4 {
		t.Fatalf("stamp did not move: %s %s %s %s %s", s0, s1, s2, s3, s4)
	}
	if stamp() != s4 {
		t.Fatal("stamp moved without a change")
	}
}

func TestStatusOf(t *testing.T) {
	f := func(k check.Kind, sev check.Severity) check.Finding { return check.Finding{Kind: k, Severity: sev} }
	cases := []struct {
		name             string
		enabled, checked bool
		failing          bool
		open             []check.Finding
		want             string
	}{
		{"disabled", false, true, false, nil, StatusDisabled},
		{"never checked", true, false, false, nil, StatusPending},
		{"healthy", true, true, false, nil, StatusHealthy},
		{"failing before the finding opens", true, true, true, nil, StatusUnreachable},
		{"critical outranks unreachable", true, true, false, []check.Finding{f(check.Unreachable, check.Critical), f(check.Expired, check.Critical)}, StatusCritical},
		{"change only", true, true, false, []check.Finding{f(check.CertificateChanged, check.Warning)}, StatusChanged},
		{"change and expiring", true, true, false, []check.Finding{f(check.CertificateChanged, check.Warning), f(check.Expiring, check.Warning)}, StatusWarning},
		{"info only", true, true, false, []check.Finding{f(check.CertificateChanged, check.Info)}, StatusHealthy},
	}
	for _, c := range cases {
		if got := StatusOf(c.enabled, c.checked, c.failing, c.open); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// Apply reports what it changed, for the check log.
func TestApplySummary(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(func(t *Target) { t.AllChannels = false; t.ChannelIDs = []int64{e.chC} })
	c := ca.leaf(t, now.Add(-days(360)), now.Add(days(20)), "portal.example.nl")
	sum, err := e.svc.Apply(e.ctx, tg, result(served("192.0.2.1", c, ca.cert)))
	if err != nil {
		t.Fatal(err)
	}
	// A warning to a channel with a critical floor: opened, not queued.
	if sum.CheckID == "" || sum.Status != StatusWarning || !slices.Equal(sum.Opened, []check.Kind{check.Expiring}) ||
		sum.Queued != 0 || sum.BelowFloor != 1 || sum.Channels != 1 {
		t.Fatalf("summary: %+v", sum)
	}
	tg, _ = e.svc.Target(e.ctx, tg.ID)
	sum, err = e.svc.Apply(e.ctx, tg, result(failed("192.0.2.1")))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sum.Waiting, []check.Kind{check.Unreachable}) || sum.Status != StatusUnreachable {
		t.Fatalf("debounced failure: %+v", sum)
	}
}

// Key rotation re-seals channel settings so the new key reads them.
func TestReencryptChannels(t *testing.T) {
	e := newEnv(t)
	old := e.svc.Channels.Key
	next, _, err := secret.Generate()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := e.svc.DB.W.BeginTx(e.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	n, unreadable, err := notify.Reencrypt(e.ctx, tx, old, next)
	if err != nil || n != 2 || len(unreadable) != 0 {
		t.Fatalf("re-encrypted %d, unreadable %v: %v", n, unreadable, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	rotated := &notify.Channels{DB: e.svc.DB, Key: next}
	c, err := rotated.Get(e.ctx, e.chC)
	if err != nil || c.Telegram.Token != "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		t.Fatalf("after rotation: %+v %v", c.Telegram, err)
	}
	if _, err := e.svc.Channels.Get(e.ctx, e.chC); !errors.Is(err, notify.ErrUnreadable) {
		t.Fatalf("old key still reads the channel: %v", err)
	}
}

func TestMetrics(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	tg := e.target(nil)
	c := ca.leaf(t, now.Add(-days(360)), now.Add(days(3)), "portal.example.nl")
	e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	m, err := e.svc.Metrics(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m.TargetsByStatus[StatusCritical] != 1 || m.OpenBySeverity["critical"] != 1 || m.AlertsByState["pending"] != 2 {
		t.Fatalf("counts: %+v", m)
	}
	if len(m.CertificateTimes) != 1 || m.CertificateTimes[0].Endpoint != "portal.example.nl:443" || m.CertificateTimes[0].NotAfter != c.NotAfter.Unix() {
		t.Fatalf("expiry: %+v", m.CertificateTimes)
	}
}

// The overview counts with aggregate queries and lists the eight enabled
// targets expiring first.
func intp(n int) *int { return &n }

func TestOverview(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	for i := 0; i < 10; i++ {
		tg := e.target(func(t *Target) { t.Port = 1000 + i })
		c := ca.leaf(t, now.Add(-days(300)), now.Add(days(float64(5+20*i))), "portal.example.nl")
		e.apply(tg.ID, result(served("192.0.2.1", c, ca.cert)))
	}
	disabled := e.target(func(t *Target) { t.Port = 2000 })
	if err := e.svc.SetEnabled(e.ctx, disabled.ID, false); err != nil {
		t.Fatal(err)
	}
	// A target with its own low thresholds is healthy at 20 days left and
	// the only one "due within 30 days" under the Healthy tile.
	soon := e.target(func(t *Target) { t.Port = 3000; t.WarnDays, t.CritDays = intp(3), intp(1) })
	e.apply(soon.ID, result(served("192.0.2.1", ca.leaf(t, now.Add(-days(300)), now.Add(days(20)), "portal.example.nl"), ca.cert)))
	o, err := e.svc.Overview(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Days left 5, 25, 45 … : 5 critical, 25 warning, the rest healthy. The
	// critical and warning ones are not "due" under the Healthy tile.
	if o.Total != 12 || o.Critical != 1 || o.Warning != 1 || o.Healthy != 9 || o.Disabled != 1 || o.DueWithin30 != 1 {
		t.Fatalf("counts: total %d crit %d warn %d healthy %d disabled %d due %d", o.Total, o.Critical, o.Warning, o.Healthy, o.Disabled, o.DueWithin30)
	}
	// Every enabled target with a certificate is listed, soonest first.
	if len(o.Targets) != 11 || o.Targets[0].Port != 1000 || o.Targets[1].Port != 3000 || o.Targets[10].Port != 1009 || o.Targets[0].Cert == nil {
		t.Fatalf("listed: %d, first %d", len(o.Targets), o.Targets[0].Port)
	}
	if o.LastCheck == 0 || o.NextCheck == 0 {
		t.Fatalf("times: %d %d", o.LastCheck, o.NextCheck)
	}
}

func TestParseBundleRejectsKeys(t *testing.T) {
	if _, err := ParseBundle("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"); err == nil {
		t.Fatal("private key accepted")
	}
	if _, err := ParseBundle("nothing"); err == nil {
		t.Fatal("empty bundle accepted")
	}
}

func TestParseTags(t *testing.T) {
	got, err := ParseTags("Customer:Example, sip  sip,\tsite:amsterdam")
	if err != nil || strings.Join(got, "|") != "customer:example|sip|site:amsterdam" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ParseTags(strings.Repeat("x", 41)); err == nil {
		t.Fatal("long tag accepted")
	}
}

// The old TLS versions are tested once a day: the finding stands between
// tests, a test that finds them refused resolves it, and moving the target
// or switching the test off forgets the last test.
func TestLegacyProtocolDaily(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	leaf := ca.leaf(t, now, now.Add(days(300)), "portal.example.nl")
	tested := func(versions ...string) probe.Result {
		a := served("192.0.2.1", leaf, ca.cert)
		a.LegacyChecked, a.Legacy = true, versions
		return result(a)
	}
	due := func(tg Target) bool {
		t.Helper()
		got, _ := e.svc.Target(e.ctx, tg.ID)
		req, err := e.svc.ProbeRequest(e.ctx, got, e.svc.CurrentSettings(e.ctx))
		if err != nil {
			t.Fatal(err)
		}
		return req.Legacy
	}

	tg := e.target(nil)
	if !due(tg) {
		t.Fatal("first check does not test the old versions")
	}
	tg = e.apply(tg.ID, tested("TLS 1.0"))
	if f, ok := e.open(tg.ID)[check.LegacyProtocol]; !ok || f.Severity != check.Warning {
		t.Fatalf("legacy_protocol not opened: %+v", e.open(tg.ID))
	}
	if tg.Status != StatusWarning || tg.LegacyChecked == 0 || strings.Join(tg.LegacyAccepted, ",") != "TLS 1.0" {
		t.Fatalf("state: status %s checked %d accepted %v", tg.Status, tg.LegacyChecked, tg.LegacyAccepted)
	}

	e.clock.Add(12 * time.Hour)
	if due(tg) {
		t.Fatal("tested again within a day")
	}
	tg = e.apply(tg.ID, result(served("192.0.2.1", leaf, ca.cert)))
	if _, ok := e.open(tg.ID)[check.LegacyProtocol]; !ok {
		t.Fatal("a check without the test resolved legacy_protocol")
	}

	e.clock.Add(12 * time.Hour)
	if !due(tg) {
		t.Fatal("not tested after a day")
	}
	tg = e.apply(tg.ID, tested())
	if _, ok := e.open(tg.ID)[check.LegacyProtocol]; ok || tg.LegacyAccepted != nil || tg.Status != StatusHealthy {
		t.Fatalf("refused versions did not resolve: status %s accepted %v", tg.Status, tg.LegacyAccepted)
	}

	moved := tg
	moved.Port = 8443
	if _, err := e.svc.SaveTarget(e.ctx, moved, "test"); err != nil {
		t.Fatal(err)
	}
	if !due(tg) {
		t.Fatal("a new port does not test again")
	}
	tg = e.apply(tg.ID, tested("TLS 1.1"))
	off, _ := e.svc.Target(e.ctx, tg.ID)
	off.SkipLegacy = true
	if _, err := e.svc.SaveTarget(e.ctx, off, "test"); err != nil {
		t.Fatal(err)
	}
	if due(tg) {
		t.Fatal("tested while switched off")
	}
	tg = e.apply(tg.ID, result(served("192.0.2.1", leaf, ca.cert)))
	if _, ok := e.open(tg.ID)[check.LegacyProtocol]; ok || tg.LegacyChecked != 0 || !tg.SkipLegacy {
		t.Fatalf("switched off: open %v checked %d", e.open(tg.ID), tg.LegacyChecked)
	}
}
