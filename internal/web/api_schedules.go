package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// ---------- Scan schedules ----------

type apiScanSchedule struct {
	ID           int64    `json:"id"`
	Name         string   `json:"name" doc:"A label; empty means the ranges."`
	Ranges       []string `json:"ranges"`
	Ports        []int    `json:"ports"`
	Rate         int      `json:"rate" doc:"Connects per second."`
	NodeID       *int64   `json:"node_id" doc:"The node the scan runs from; null: this server."`
	Every        string   `json:"every" doc:"day or week."`
	Weekday      int      `json:"weekday" doc:"0 Sunday to 6 Saturday; used for week."`
	Hour         int      `json:"hour" doc:"0 to 23, in the instance's time zone."`
	Enabled      bool     `json:"enabled"`
	NextRun      stamp    `json:"next_run" doc:"Null while paused."`
	LastRun      stamp    `json:"last_run"`
	LastScanID   *int64   `json:"last_scan_id" doc:"The last run's scan while it is kept."`
	LastNote     string   `json:"last_note" doc:"Why the last slot ran no scan, else empty."`
	OpenFindings int      `json:"open_findings" doc:"Endpoints found that no target covers."`
	CreatedAt    stamp    `json:"created_at"`
	CreatedBy    string   `json:"created_by"`
	UpdatedAt    stamp    `json:"updated_at"`
}

func (s *Server) toAPISchedule(r *http.Request, sc core.ScanSchedule) apiScanSchedule {
	a := apiScanSchedule{ID: sc.ID, Name: sc.Name, Ranges: nonNil(sc.Ranges), Ports: sc.Ports, Rate: sc.Rate, Every: sc.Every, Weekday: sc.Weekday, Hour: sc.Hour,
		Enabled: sc.Enabled, LastRun: stamp(sc.LastRun), LastNote: sc.LastNote, OpenFindings: sc.OpenFindings,
		CreatedAt: stamp(sc.CreatedAt), CreatedBy: sc.CreatedBy, UpdatedAt: stamp(sc.UpdatedAt)}
	if a.Ports == nil {
		a.Ports = []int{}
	}
	if sc.NodeID != 0 {
		id := sc.NodeID
		a.NodeID = &id
	}
	if sc.LastScanID != 0 {
		id := sc.LastScanID
		a.LastScanID = &id
	}
	if sc.Enabled {
		a.NextRun = stamp(sc.NextRun(s.now().In(info(r).settings.Location())).Unix())
	}
	return a
}

// apiScanScheduleInput is the body of adding or changing a schedule.
type apiScanScheduleInput struct {
	Name    *string   `json:"name,omitempty"`
	Ranges  *[]string `json:"ranges,omitempty" doc:"Required to add: CIDRs or addresses, private unless Settings › General allows public discovery."`
	Ports   *[]int    `json:"ports,omitempty" doc:"At most 16; the discovery defaults when left out."`
	Rate    *int      `json:"rate,omitempty" doc:"1 to 200 connects per second; 50 when left out."`
	NodeID  *int64    `json:"node_id,omitempty" doc:"null: this server."`
	Every   *string   `json:"every,omitempty" doc:"day or week; required to add."`
	Weekday *int      `json:"weekday,omitempty" doc:"0 Sunday to 6 Saturday; Monday when left out."`
	Hour    *int      `json:"hour,omitempty" doc:"0 to 23; 3 when left out."`
	Enabled *bool     `json:"enabled,omitempty"`
}

// scheduleInputOf merges a body into the input of an existing schedule.
func scheduleInputOf(sc core.ScanSchedule, in apiScanScheduleInput, raw map[string]json.RawMessage) (core.ScanScheduleInput, map[string]string) {
	errs := map[string]string{}
	for k, v := range raw {
		if isNull(v) && k != "node_id" && k != "name" {
			errs[k] = "cannot be null"
		}
	}
	out := core.ScanScheduleInput{Name: sc.Name, Ranges: strings.Join(sc.Ranges, " "), Rate: sc.Rate, NodeID: sc.NodeID, Every: sc.Every, Weekday: sc.Weekday, Hour: sc.Hour, Enabled: sc.Enabled}
	ports := make([]string, 0, len(sc.Ports))
	for _, p := range sc.Ports {
		ports = append(ports, fmt.Sprint(p))
	}
	out.Ports = strings.Join(ports, ",")
	if in.Name != nil {
		out.Name = *in.Name
	}
	if in.Ranges != nil {
		out.Ranges = strings.Join(*in.Ranges, " ")
	}
	if in.Ports != nil {
		ps := make([]string, 0, len(*in.Ports))
		for _, p := range *in.Ports {
			ps = append(ps, fmt.Sprint(p))
		}
		out.Ports = strings.Join(ps, ",")
	}
	if in.Rate != nil {
		out.Rate = *in.Rate
	}
	if _, ok := raw["node_id"]; ok {
		out.NodeID = 0
		if in.NodeID != nil {
			out.NodeID = *in.NodeID
		}
	}
	if in.Every != nil {
		out.Every = *in.Every
	}
	if in.Weekday != nil {
		out.Weekday = *in.Weekday
	}
	if in.Hour != nil {
		out.Hour = *in.Hour
	}
	if in.Enabled != nil {
		out.Enabled = *in.Enabled
	}
	return out, errs
}

func (s *Server) apiSchedules(w http.ResponseWriter, r *http.Request) {
	scs, err := s.Core.ScanSchedules(r.Context())
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	writePage(w, r, scs, func(sc core.ScanSchedule) string { return idKey(sc.ID) }, func(sc core.ScanSchedule) any { return s.toAPISchedule(r, sc) })
}

func (s *Server) writeSchedule(w http.ResponseWriter, r *http.Request, status int, id int64) {
	sc, err := s.Core.ScanSchedule(r.Context(), id)
	if err != nil {
		s.apiFailErr(w, r, err, "No such scan schedule.")
		return
	}
	writeJSON(w, status, s.toAPISchedule(r, sc))
}

func (s *Server) apiScheduleGet(w http.ResponseWriter, r *http.Request) {
	if id, ok := s.apiPathID(w, r, "scan schedule"); ok {
		s.writeSchedule(w, r, http.StatusOK, id)
	}
}

// saveSchedule validates and stores; a user-facing error is a 400 on the
// field the message is about.
func (s *Server) saveSchedule(ctx context.Context, id int64, in core.ScanScheduleInput, user string) (int64, map[string]string, error) {
	newID, err := s.Core.SaveScanSchedule(ctx, id, in, user)
	if msg, isUser := usererr.Message(err); isUser {
		field := "ranges"
		switch {
		case strings.Contains(msg, "port"):
			field = "ports"
		case strings.Contains(msg, "rate"):
			field = "rate"
		case strings.Contains(msg, "node"):
			field = "node_id"
		case strings.Contains(msg, "daily"):
			field = "every"
		case strings.Contains(msg, "weekday"):
			field = "weekday"
		case strings.Contains(msg, "hour"):
			field = "hour"
		}
		return 0, map[string]string{field: msg}, nil
	}
	return newID, nil, err
}

func (s *Server) apiScheduleCreate(w http.ResponseWriter, r *http.Request) {
	var in apiScanScheduleInput
	raw, ok := readBody(w, r, &in)
	if !ok {
		return
	}
	start := core.ScanSchedule{Every: core.ScheduleDaily, Weekday: 1, Hour: 3, Enabled: true}
	si, errs := scheduleInputOf(start, in, raw)
	if in.Ranges == nil {
		errs["ranges"] = "required"
	}
	if in.Every == nil {
		errs["every"] = "required"
	}
	if len(errs) > 0 {
		apiInvalid(w, errs)
		return
	}
	id, fields, err := s.saveSchedule(r.Context(), 0, si, apiSession(r).User.Email)
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	if fields != nil {
		apiInvalid(w, fields)
		return
	}
	w.Header().Set("Location", fmt.Sprintf("/api/v2/discovery/schedules/%d", id))
	s.writeSchedule(w, r, http.StatusCreated, id)
}

func (s *Server) apiScheduleUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.apiPathID(w, r, "scan schedule")
	if !ok {
		return
	}
	sc, err := s.Core.ScanSchedule(r.Context(), id)
	if err != nil {
		s.apiFailErr(w, r, err, "No such scan schedule.")
		return
	}
	var in apiScanScheduleInput
	raw, ok := readBody(w, r, &in)
	if !ok {
		return
	}
	si, errs := scheduleInputOf(sc, in, raw)
	if len(errs) > 0 {
		apiInvalid(w, errs)
		return
	}
	if _, fields, err := s.saveSchedule(r.Context(), id, si, apiSession(r).User.Email); err != nil {
		s.apiFailErr(w, r, err, "No such scan schedule.")
		return
	} else if fields != nil {
		apiInvalid(w, fields)
		return
	}
	s.writeSchedule(w, r, http.StatusOK, id)
}

func (s *Server) apiScheduleDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := s.apiPathID(w, r, "scan schedule")
	if !ok {
		return
	}
	if err := s.Core.DeleteScanSchedule(r.Context(), id, apiSession(r).User.Email); err != nil {
		s.apiFailErr(w, r, err, "No such scan schedule.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiScheduleRun(w http.ResponseWriter, r *http.Request) {
	id, ok := s.apiPathID(w, r, "scan schedule")
	if !ok {
		return
	}
	sc, err := s.Core.ScanSchedule(r.Context(), id)
	if err != nil {
		s.apiFailErr(w, r, err, "No such scan schedule.")
		return
	}
	scan, addrs, err := s.Core.StartScheduledScan(r.Context(), sc, apiSession(r).User.Email)
	if errors.Is(err, core.ErrScanBusy) {
		apiFail(w, http.StatusConflict, "conflict", "A scan is already running from there; wait for it to finish.")
		return
	}
	if msg, isUser := usererr.Message(err); isUser {
		apiFail(w, http.StatusConflict, "conflict", msg)
		return
	}
	if err != nil {
		s.apiFailErr(w, r, err, "")
		return
	}
	s.Sched.StartScan(scan, addrs)
	s.writeSchedule(w, r, http.StatusOK, id)
}
