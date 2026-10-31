package core

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/sjoerd305/tlswatch/internal/check"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/probe"
)

// A schedule's slots: the latest at or before now, due until it has run,
// and the next one after that.
func TestScheduleSlots(t *testing.T) {
	ams, err := time.LoadLocation("Europe/Amsterdam")
	if err != nil {
		t.Skip("no tzdata")
	}
	// Wednesday 21 October 2026, 10:30 in Amsterdam.
	now := time.Date(2026, 10, 21, 10, 30, 0, 0, ams)
	daily := ScanSchedule{Every: ScheduleDaily, Hour: 3, Enabled: true}
	if got := daily.Slot(now); !got.Equal(time.Date(2026, 10, 21, 3, 0, 0, 0, ams)) {
		t.Fatalf("daily slot: %s", got)
	}
	if !daily.Due(now) {
		t.Fatal("a daily schedule that never ran is due")
	}
	daily.LastRun = daily.Slot(now).Unix()
	if daily.Due(now) {
		t.Fatal("ran at its slot, still due")
	}
	if got := daily.NextRun(now); !got.Equal(time.Date(2026, 10, 22, 3, 0, 0, 0, ams)) {
		t.Fatalf("daily next: %s", got)
	}
	early := ScanSchedule{Every: ScheduleDaily, Hour: 12, Enabled: true}
	if got := early.Slot(now); !got.Equal(time.Date(2026, 10, 20, 12, 0, 0, 0, ams)) {
		t.Fatalf("slot before today's hour: %s", got)
	}
	// Weekly on Monday 03:00: the slot is Monday the 19th; next Monday the
	// 26th, across the end of summer time.
	weekly := ScanSchedule{Every: ScheduleWeekly, Weekday: int(time.Monday), Hour: 3, Enabled: true}
	if got := weekly.Slot(now); !got.Equal(time.Date(2026, 10, 19, 3, 0, 0, 0, ams)) {
		t.Fatalf("weekly slot: %s", got)
	}
	weekly.LastRun = weekly.Slot(now).Unix()
	if got := weekly.NextRun(now); !got.Equal(time.Date(2026, 10, 26, 3, 0, 0, 0, ams)) {
		t.Fatalf("weekly next: %s", got)
	}
	// Weekly later today: the slot is a week ago, and it is due.
	later := ScanSchedule{Every: ScheduleWeekly, Weekday: int(time.Wednesday), Hour: 20, Enabled: true}
	if got := later.Slot(now); !got.Equal(time.Date(2026, 10, 14, 20, 0, 0, 0, ams)) {
		t.Fatalf("weekly slot before the hour: %s", got)
	}
	if !later.Due(now) {
		t.Fatal("never ran, not due")
	}
	later.Enabled = false
	if later.Due(now) {
		t.Fatal("a paused schedule is due")
	}
	if w := weekly.When(); w != "weekly on Monday at 03:00" {
		t.Fatalf("when: %q", w)
	}
}

// A scheduled run reports the endpoints no target covers as findings,
// alerted like any warning; a target that covers one, a run that no longer
// sees one, and an acknowledgement each settle it.
func TestScheduledDiscovery(t *testing.T) {
	e := newEnv(t)
	ca := newCA(t, "Sectigo")
	now := e.clock.Now()
	leaf := ca.leaf(t, now.Add(-days(10)), now.Add(days(80)), "intranet.example.nl")
	other := ca.leaf(t, now.Add(-days(10)), now.Add(days(80)), "mail.example.nl")

	id, err := e.svc.SaveScanSchedule(e.ctx, 0, ScanScheduleInput{Name: "Office", Ranges: "10.0.0.0/29", Ports: "443, 587", Every: ScheduleDaily, Hour: 3, Enabled: true}, "op")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SaveScanSchedule(e.ctx, 0, ScanScheduleInput{Ranges: "8.8.8.0/24", Every: ScheduleDaily, Hour: 3, Enabled: true}, "op"); err == nil {
		t.Fatal("a public range was accepted")
	}
	if _, err := e.svc.SaveScanSchedule(e.ctx, 0, ScanScheduleInput{Ranges: "10.0.0.0/29", Every: "month", Hour: 3, Enabled: true}, "op"); err == nil {
		t.Fatal("a monthly schedule was accepted")
	}
	sc, err := e.svc.ScanSchedule(e.ctx, id)
	if err != nil || sc.Label() != "Office" || len(sc.Ports) != 2 || sc.Rate != probe.DefaultScanRate || !sc.Enabled {
		t.Fatalf("schedule: %+v %v", sc, err)
	}
	if due, _ := e.svc.DueScanSchedules(e.ctx); len(due) != 1 {
		t.Fatalf("due: %d", len(due))
	}

	// A run: two endpoints, none covered.
	run := func(hits ...probe.ScanHit) Scan {
		t.Helper()
		sc, _ := e.svc.ScanSchedule(e.ctx, id)
		scan, _, err := e.svc.StartScheduledScan(e.ctx, sc, ScheduleRunner)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.svc.RecordScan(e.ctx, scan.ID, probe.ScanResult{Probed: 16, Hits: hits}); err != nil {
			t.Fatal(err)
		}
		if err := e.svc.FinishScan(e.ctx, scan.ID, ""); err != nil {
			t.Fatal(err)
		}
		if err := e.svc.ReconcileScan(e.ctx, scan.ID); err != nil {
			t.Fatal(err)
		}
		scan, _ = e.svc.Scan(e.ctx, scan.ID)
		return scan
	}
	hit := func(ip string, port int, c *x509.Certificate) probe.ScanHit {
		return probe.ScanHit{IP: ip, Port: port, Protocol: probe.TLS, TLSVersion: "TLS 1.3", Chain: []*x509.Certificate{c}}
	}
	scan := run(hit("10.0.0.1", 443, leaf), hit("10.0.0.2", 443, other))
	if scan.ScheduleID != id || scan.CreatedBy != ScheduleRunner {
		t.Fatalf("run: %+v", scan)
	}
	if due, _ := e.svc.DueScanSchedules(e.ctx); len(due) != 0 {
		t.Fatal("still due after its run")
	}
	open, err := e.svc.Findings(e.ctx, FindingFilter{ScheduleID: id})
	if err != nil || len(open) != 2 {
		t.Fatalf("findings after the run: %d %v", len(open), err)
	}
	f := open[0]
	if f.Kind != check.UnknownEndpoint || f.Severity != check.Warning || f.ScheduleID != id || f.TargetName != "Office" ||
		f.HostPort() != "10.0.0.1:443" || !strings.Contains(f.Details, "intranet.example.nl") || !strings.Contains(f.Details, "Sectigo") {
		t.Fatalf("finding: %+v", f)
	}
	e.flush()
	// Two alerts in the same batch go out as one mail of their subjects;
	// a single alert names the schedule and the endpoint.
	if m := e.take("mail"); len(m) != 1 || !strings.Contains(m[0].Body, "10.0.0.1:443 found by discovery, not in the inventory") || !strings.Contains(m[0].Body, "10.0.0.2:443") {
		t.Fatalf("alerts: %+v", m)
	}
	one := notify.Render(notify.AlertData{Event: notify.EventOpen, Severity: "warning", Kind: string(check.UnknownEndpoint), KindLabel: check.UnknownEndpoint.Label(),
		Discovery: true, TargetName: "Office", HostPort: "10.0.0.1:443", Details: f.Details})
	if !strings.Contains(one.Body, "Scan:        Office") || !strings.Contains(one.Body, "Endpoint:    10.0.0.1:443") || strings.Contains(one.Body, "Target:") {
		t.Fatalf("single alert:\n%s", one.Body)
	}
	if m := e.take("telegram"); len(m) != 0 {
		t.Fatal("a warning reached the critical channel")
	}
	if sc, _ := e.svc.ScanSchedule(e.ctx, id); sc.OpenFindings != 2 || sc.LastScanID != scan.ID || sc.LastRun == 0 {
		t.Fatalf("schedule after the run: %+v", sc)
	}
	if n := e.svc.Nav(e.ctx); n.Findings != 2 {
		t.Fatalf("navigation counts %d findings", n.Findings)
	}

	// The same run again: nothing new, no second alert.
	run(hit("10.0.0.1", 443, leaf), hit("10.0.0.2", 443, other))
	e.flush()
	if m := e.take("mail"); len(m) != 0 {
		t.Fatalf("repeated run alerted: %+v", m)
	}

	// A target on the first endpoint resolves its finding with a notice.
	if _, _, err := e.svc.AddTargets(e.ctx, []Target{{Name: "intranet", Host: "10.0.0.1", Port: 443, Protocol: probe.TLS, Trust: probe.TrustSystem, AllChannels: true, AllAddresses: true, Enabled: true}}, "op"); err != nil {
		t.Fatal(err)
	}
	open, _ = e.svc.Findings(e.ctx, FindingFilter{ScheduleID: id})
	if len(open) != 1 || open[0].HostPort() != "10.0.0.2:443" {
		t.Fatalf("after adding a target: %+v", open)
	}
	e.flush()
	if m := e.take("mail"); len(m) != 1 || !strings.Contains(m[0].Subject, "resolved") {
		t.Fatalf("recovery: %+v", m)
	}

	// Acknowledged: resolved, and not reported by the next run.
	if _, err := e.svc.Acknowledge(e.ctx, open[0].ID, "op", time.Time{}, "printer, fine"); err != nil {
		t.Fatal(err)
	}
	run(hit("10.0.0.1", 443, leaf), hit("10.0.0.2", 443, other), hit("10.0.0.3", 587, other))
	open, _ = e.svc.Findings(e.ctx, FindingFilter{ScheduleID: id})
	if len(open) != 1 || open[0].HostPort() != "10.0.0.3:587" {
		t.Fatalf("after acknowledging: %+v", open)
	}
	e.flush()
	e.take("mail") // the new endpoint's alert

	// Gone from a completed run: resolved. A failed run resolves nothing.
	sch, _ := e.svc.ScanSchedule(e.ctx, id)
	failed, _, err := e.svc.StartScheduledScan(e.ctx, sch, ScheduleRunner)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.FinishScan(e.ctx, failed.ID, "node went away"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ReconcileScan(e.ctx, failed.ID); err != nil {
		t.Fatal(err)
	}
	if open, _ = e.svc.Findings(e.ctx, FindingFilter{ScheduleID: id}); len(open) != 1 {
		t.Fatalf("a failed run resolved findings: %+v", open)
	}
	run(hit("10.0.0.1", 443, leaf))
	if open, _ = e.svc.Findings(e.ctx, FindingFilter{ScheduleID: id}); len(open) != 0 {
		t.Fatalf("an endpoint that is gone stays open: %+v", open)
	}
	e.flush()
	if m := e.take("mail"); len(m) != 1 || !strings.Contains(m[0].Subject, "10.0.0.3:587") || !strings.Contains(m[0].Subject, "resolved") {
		t.Fatalf("recovery of the gone endpoint: %d %s", len(m), firstSubject(m))
	}

	// A busy place: the slot is noted and skipped, not queued.
	busy, _, err := e.svc.CreateScan(e.ctx, ScanInput{Ranges: "10.0.1.0/30"}, "op")
	if err != nil {
		t.Fatal(err)
	}
	sch, _ = e.svc.ScanSchedule(e.ctx, id)
	if _, _, err := e.svc.StartScheduledScan(e.ctx, sch, ScheduleRunner); err == nil {
		t.Fatal("started next to a running scan")
	}
	if sch, _ = e.svc.ScanSchedule(e.ctx, id); !strings.Contains(sch.LastNote, "skipped") {
		t.Fatalf("note: %q", sch.LastNote)
	}
	_ = e.svc.FinishScan(e.ctx, busy.ID, "")

	// Paused: findings resolve quietly; the export carries the schedule.
	run(hit("10.0.0.5", 443, other))
	if err := e.svc.SetScanScheduleEnabled(e.ctx, id, false, "op"); err != nil {
		t.Fatal(err)
	}
	if open, _ = e.svc.Findings(e.ctx, FindingFilter{ScheduleID: id}); len(open) != 0 {
		t.Fatal("pausing left findings open")
	}
	doc, err := e.svc.Export(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"discovery:", "name: Office", "ranges: [10.0.0.0/29]", "ports: [443, 587]", "every: day", "hour: 3", "disabled: true"} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("export lacks %q:\n%s", want, doc)
		}
	}
	plan, err := e.svc.PlanImport(e.ctx, doc)
	if err != nil {
		t.Fatal(err)
	}
	for label, op := range planOps(plan) {
		if op != ImportUnchanged {
			t.Errorf("%s: %s after a round trip", label, op)
		}
	}
	// A changed file: a new schedule, this one removed.
	changed := strings.Replace(string(doc), "hour: 3", "hour: 4", 1)
	plan, err = e.svc.PlanImport(e.ctx, []byte(changed))
	if err != nil {
		t.Fatal(err)
	}
	if plan.CountOf(ImportChanged, "discovery") != 1 {
		t.Fatalf("changed hour not planned: %+v", plan.Changes)
	}
	if err := e.svc.DeleteScanSchedule(e.ctx, id, "op"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ScanSchedule(e.ctx, id); err != ErrNotFound {
		t.Fatalf("after delete: %v", err)
	}
	if a, _ := e.svc.AuditLog(e.ctx, "scan_schedule", 10); len(a) < 3 {
		t.Fatalf("audit: %+v", a)
	}
}

func firstSubject(m []notify.Message) string {
	if len(m) == 0 {
		return ""
	}
	return m[0].Subject
}
