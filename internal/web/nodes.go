package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/node"
)

// nodeRow is a node with its live state and the note on its version.
type nodeRow struct {
	N core.Node
	S node.Status
	// Note says where the node stands with updates: "update available",
	// "updating", "update failed" or "update by pulling the image".
	Note      string
	NoteClass string
	// CanUpdate: Update is offered, since this server can hand out a
	// binary for the node's platform.
	CanUpdate bool
}

// Waiting reports whether the node holds its targets: offline, disabled or
// not confirmed.
func (r nodeRow) Waiting() bool { return r.N.State == core.NodeConfirmed && !r.S.Online }

func (s *Server) nodeRow(n core.Node) nodeRow {
	r := nodeRow{N: n, S: s.Nodes.Status(n.ID)}
	if n.State != core.NodeConfirmed || n.Version == "" {
		return r
	}
	switch {
	case n.UpdateStarted > 0:
		r.Note, r.NoteClass = "updating to "+n.UpdateTo, "info"
	case n.Version == s.Version:
	case n.Facts.Container:
		r.Note, r.NoteClass = "update by pulling the image", "warn"
	case n.Facts.Arch != "" && !s.Nodes.ServesPlatform(n.Facts.Arch):
		// A development build has no release to fetch other platforms
		// from; Update could only fail.
		r.Note, r.NoteClass = "no "+n.Facts.Arch+" binary for "+s.Version, "info"
	case n.UpdateFailed != "":
		r.Note, r.NoteClass, r.CanUpdate = "update failed", "crit", true
	default:
		r.Note, r.NoteClass, r.CanUpdate = "update available", "warn", true
	}
	return r
}

type nodesData struct {
	Rows      []nodeRow
	Auto      bool
	Release   bool // the server runs a release, which nodes follow on their own
	HasBase   bool
	Updating  int // the place of the node updating now, 0 when none
	Of        int // nodes to update in this round
	Outdated  int // nodes on another version that the server can update
	Version   string
	Own       string
	Platforms []string // platforms the server can hand out
}

func (s *Server) settingsNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.Core.Nodes(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	st := info(r).settings
	d := nodesData{Auto: st.Nodes.AutoUpdate, Release: node.IsRelease(s.Version), HasBase: st.General.BaseURL != "",
		Version: s.Version, Own: node.OwnPlatform()}
	for _, p := range node.Platforms {
		if s.Nodes.ServesPlatform(p) {
			d.Platforms = append(d.Platforms, p)
		}
	}
	if !contains(d.Platforms, d.Own) {
		d.Platforms = append([]string{d.Own}, d.Platforms...)
	}
	for _, n := range nodes {
		row := s.nodeRow(n)
		if row.CanUpdate {
			d.Outdated++
		}
		d.Rows = append(d.Rows, row)
	}
	d.Updating, d.Of = s.Nodes.Updating(nodes)
	s.renderStatus(w, r, http.StatusOK, "settings-nodes", &Page{Title: "Settings", Nav: "settings", SettingsNav: "nodes", Data: d, Live: true})
}

// nodeAdd starts a new node: an install token and the command screen.
func (s *Server) nodeAdd(w http.ResponseWriter, r *http.Request) {
	if info(r).settings.General.BaseURL == "" {
		s.back(w, r, "/settings/nodes", "Set the public URL under Settings › General first: the install command needs it to reach this server.", "warn")
		return
	}
	id, _, err := s.Core.CreateNode(r.Context(), user(r).Email)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "node.create", fmt.Sprintf("node %d", id), "install token issued, valid 1 hour")
	http.Redirect(w, r, fmt.Sprintf("/settings/nodes/%d", id), http.StatusSeeOther)
}

func (s *Server) nodesAuto(w http.ResponseWriter, r *http.Request) {
	n := config.Nodes{AutoUpdate: r.PostFormValue("auto_update") == "1"}
	if err := s.Settings.SaveNodes(r.Context(), n); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "settings.nodes", "nodes", fmt.Sprintf("auto_update=%v", n.AutoUpdate))
	msg := "Nodes are updated to the server's version on their own, one at a time."
	if !n.AutoUpdate {
		msg = "Nodes are no longer updated on their own; use Update or Update all."
	}
	s.back(w, r, "/settings/nodes", msg, "ok")
}

func (s *Server) nodesUpdateAll(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.Core.Nodes(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	// Only the nodes this server can hand a binary to.
	for _, n := range nodes {
		if s.nodeRow(n).CanUpdate {
			if err := s.Core.RequestNodeUpdate(r.Context(), n.ID); err != nil {
				s.serverError(w, r, err)
				return
			}
		}
	}
	s.Core.Audit(r.Context(), user(r).Email, "node.update_request", "all nodes", "to="+s.Version)
	s.back(w, r, "/settings/nodes", "Every node on another version is updated in turn, one at a time.", "info")
}

// nodeData is the node page in each of its states: the install command
// while enrolling, the reported facts to confirm while pending, and the
// node with its targets once confirmed.
type nodeData struct {
	Row             nodeRow
	Cmd             *node.Commands
	Targets         []core.Target
	Name            string // the confirm or edit form's value
	Notes           string
	Error           string
	Version         string
	Own             string
	Platforms       []string
	Uninstall       string // the binary's own uninstall command
	UninstallScript string // the served script, for a node whose binary is gone
	Release         bool
}

func (s *Server) loadNode(w http.ResponseWriter, r *http.Request) (core.Node, bool) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such node.")
		return core.Node{}, false
	}
	n, err := s.Core.Node(r.Context(), id)
	if err != nil {
		s.failErr(w, r, err, "No such node. An unconfirmed node is removed an hour after its install command was made.")
		return n, false
	}
	return n, true
}

func (s *Server) nodePage(w http.ResponseWriter, r *http.Request) {
	n, ok := s.loadNode(w, r)
	if !ok {
		return
	}
	s.renderNode(w, r, http.StatusOK, n, nodeData{Name: n.Name, Notes: n.Notes})
}

func (s *Server) renderNode(w http.ResponseWriter, r *http.Request, status int, n core.Node, d nodeData) {
	ctx := r.Context()
	d.Row, d.Version, d.Own, d.Release = s.nodeRow(n), s.Version, node.OwnPlatform(), node.IsRelease(s.Version)
	d.Uninstall, d.UninstallScript = node.UninstallCommands(s.baseURL(r))
	for _, p := range node.Platforms {
		if s.Nodes.ServesPlatform(p) {
			d.Platforms = append(d.Platforms, p)
		}
	}
	if !contains(d.Platforms, d.Own) {
		d.Platforms = append([]string{d.Own}, d.Platforms...)
	}
	if d.Name == "" && n.State == core.NodePending {
		d.Name = n.Facts.Hostname
	}
	if base := info(r).settings.General.BaseURL; base != "" {
		tok, err := s.Core.NodeToken(ctx, n.ID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if tok != "" {
			c := node.InstallCommands(base, tok, s.Version)
			d.Cmd = &c
		}
	}
	var err error
	if d.Targets, err = s.Core.NodeTargets(ctx, n.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	title := n.Label()
	if n.State == core.NodeEnrolling && n.ConfirmedAt == 0 {
		title = "Add node"
	}
	s.renderStatus(w, r, status, "settings-node", &Page{Title: title, Nav: "settings", SettingsNav: "nodes", Data: d, Live: true})
}

func (s *Server) nodeConfirm(w http.ResponseWriter, r *http.Request) {
	n, ok := s.loadNode(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if err := s.Core.ConfirmNode(r.Context(), n.ID, name, user(r).Email); err != nil {
		if msg, ok := s.formError(w, r, err); ok {
			s.renderNode(w, r, http.StatusBadRequest, n, nodeData{Name: name, Error: msg})
		}
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "node.confirm", fmt.Sprintf("node %d %s", n.ID, name),
		fmt.Sprintf("hostname=%s address=%s", n.Facts.Hostname, n.Address))
	s.Nodes.Refresh(r.Context(), n.ID)
	s.Sched.Reload()
	s.back(w, r, fmt.Sprintf("/settings/nodes/%d", n.ID), "Node "+name+" confirmed. Choose it under \"Probe from\" on a target to probe that target from inside its network.", "ok")
}

func (s *Server) nodeReject(w http.ResponseWriter, r *http.Request) {
	n, ok := s.loadNode(w, r)
	if !ok {
		return
	}
	if err := s.Core.RejectNode(r.Context(), n.ID); err != nil {
		s.failErr(w, r, err, "No such node.")
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "node.reject", fmt.Sprintf("node %d %s", n.ID, n.Label()),
		fmt.Sprintf("hostname=%s address=%s; credential revoked", n.Facts.Hostname, n.Address))
	s.Nodes.Refresh(r.Context(), n.ID)
	if n.ConfirmedAt > 0 {
		s.back(w, r, fmt.Sprintf("/settings/nodes/%d", n.ID), "The machine was rejected and its credential revoked. Rotate the credential for a new install command.", "ok")
		return
	}
	s.back(w, r, "/settings/nodes", "The machine was rejected; its credential no longer works.", "ok")
}

func (s *Server) nodeSave(w http.ResponseWriter, r *http.Request) {
	n, ok := s.loadNode(w, r)
	if !ok {
		return
	}
	name, notes := r.PostFormValue("name"), r.PostFormValue("notes")
	if err := s.Core.SaveNode(r.Context(), n.ID, name, notes); err != nil {
		if msg, ok := s.formError(w, r, err); ok {
			s.renderNode(w, r, http.StatusBadRequest, n, nodeData{Name: name, Notes: notes, Error: msg})
		}
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "node.update_details", fmt.Sprintf("node %d %s", n.ID, strings.TrimSpace(name)), "")
	s.Nodes.Refresh(r.Context(), n.ID)
	s.back(w, r, fmt.Sprintf("/settings/nodes/%d", n.ID), "Node saved.", "ok")
}

func (s *Server) nodeRotate(w http.ResponseWriter, r *http.Request) {
	n, ok := s.loadNode(w, r)
	if !ok {
		return
	}
	if info(r).settings.General.BaseURL == "" {
		s.back(w, r, fmt.Sprintf("/settings/nodes/%d", n.ID), "Set the public URL under Settings › General first: the install command needs it.", "warn")
		return
	}
	if _, err := s.Core.RenewNodeToken(r.Context(), n.ID); err != nil {
		s.failErr(w, r, err, "No such node.")
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "node.rotate", fmt.Sprintf("node %d %s", n.ID, n.Label()), "credential revoked, install token issued")
	s.Nodes.Refresh(r.Context(), n.ID)
	s.back(w, r, fmt.Sprintf("/settings/nodes/%d", n.ID), "The old credential is revoked. Run the install command below on the node to enrol it again, then confirm it.", "info")
}

func (s *Server) nodeUpdate(w http.ResponseWriter, r *http.Request) {
	n, ok := s.loadNode(w, r)
	if !ok {
		return
	}
	if row := s.nodeRow(n); !row.CanUpdate {
		msg := n.Label() + " has nothing to update to"
		if row.Note != "" {
			msg += ": " + row.Note
		}
		s.fail(w, r, http.StatusBadRequest, msg+".")
		return
	}
	if err := s.Core.RequestNodeUpdate(r.Context(), n.ID); err != nil {
		s.failErr(w, r, err, "No such node.")
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "node.update_request", fmt.Sprintf("node %d %s", n.ID, n.Label()), fmt.Sprintf("from=%s to=%s", n.Version, s.Version))
	s.Nodes.Refresh(r.Context(), n.ID)
	s.back(w, r, safeNext(r.PostFormValue("next")), fmt.Sprintf("%s is updated to %s at its next poll, after any node updating now.", n.Label(), s.Version), "info")
}

func (s *Server) nodeSetEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	n, ok := s.loadNode(w, r)
	if !ok {
		return
	}
	if err := s.Core.SetNodeEnabled(r.Context(), n.ID, enabled); err != nil {
		s.failErr(w, r, err, "No such node.")
		return
	}
	action, msg := "node.disable", "Node disabled: it receives no jobs and its targets wait, without an alert."
	if enabled {
		action, msg = "node.enable", "Node enabled; its waiting targets are checked when it polls."
	}
	s.Core.Audit(r.Context(), user(r).Email, action, fmt.Sprintf("node %d %s", n.ID, n.Label()), "")
	s.Nodes.Refresh(r.Context(), n.ID)
	s.back(w, r, fmt.Sprintf("/settings/nodes/%d", n.ID), msg, "ok")
}

func (s *Server) nodeEnable(w http.ResponseWriter, r *http.Request)  { s.nodeSetEnabled(w, r, true) }
func (s *Server) nodeDisable(w http.ResponseWriter, r *http.Request) { s.nodeSetEnabled(w, r, false) }

type nodeDeleteData struct {
	N       core.Node
	Targets []core.Target
}

func (s *Server) nodeDeletePage(w http.ResponseWriter, r *http.Request) {
	n, ok := s.loadNode(w, r)
	if !ok {
		return
	}
	ts, err := s.Core.NodeTargets(r.Context(), n.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "settings-node-delete", &Page{Title: "Delete " + n.Label(), Nav: "settings", SettingsNav: "nodes", Data: nodeDeleteData{N: n, Targets: ts}})
}

func (s *Server) nodeDelete(w http.ResponseWriter, r *http.Request) {
	n, ok := s.loadNode(w, r)
	if !ok {
		return
	}
	if r.PostFormValue("confirm") != "yes" {
		http.Redirect(w, r, fmt.Sprintf("/settings/nodes/%d/delete", n.ID), http.StatusSeeOther)
		return
	}
	move := r.PostFormValue("move") == "yes"
	if err := s.Core.DeleteNode(r.Context(), n.ID, move); err != nil {
		if errors.Is(err, core.ErrNodeInUse) {
			http.Redirect(w, r, fmt.Sprintf("/settings/nodes/%d/delete", n.ID), http.StatusSeeOther)
			return
		}
		s.failErr(w, r, err, "No such node.")
		return
	}
	detail := fmt.Sprintf("hostname=%s", n.Facts.Hostname)
	if move && n.Targets > 0 {
		detail += fmt.Sprintf("; %d targets moved to this server", n.Targets)
	}
	s.Core.Audit(r.Context(), user(r).Email, "node.delete", fmt.Sprintf("node %d %s", n.ID, n.Label()), detail)
	s.Nodes.Refresh(r.Context(), n.ID)
	s.Sched.Reload()
	_, script := node.UninstallCommands(s.baseURL(r))
	msg := "Node " + n.Label() + " deleted. To remove it from the machine, run there: " + script
	if move && n.Targets > 0 {
		msg = fmt.Sprintf("Node %s deleted; its %d %s are probed from this server now. To remove it from the machine, run there: %s",
			n.Label(), n.Targets, plural(n.Targets, "target", "targets"), script)
	}
	s.back(w, r, "/settings/nodes", msg, "ok")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// waiting reports whether a target shows "Waiting for node": it is probed
// from a node that is offline, disabled or not confirmed.
func (s *Server) waiting(t core.Target) bool {
	return t.Enabled && t.NodeID != 0 && !s.Nodes.Online(t.NodeID)
}

// offlineNotices are the bars the overview shows while a node is offline.
func (s *Server) offlineNotices(ctx context.Context, loc *time.Location, now time.Time) []Notice {
	nodes, err := s.Core.Nodes(ctx)
	if err != nil {
		return nil
	}
	var out []Notice
	for _, n := range nodes {
		if n.State != core.NodeConfirmed || !n.Enabled {
			continue
		}
		st := s.Nodes.Status(n.ID)
		if st.Online {
			continue
		}
		since := "it has not polled since the server started"
		if !st.LastSeen.IsZero() {
			since = "last seen " + when(loc, now, st.LastSeen.Unix(), true)
		}
		out = append(out, Notice{Kind: "warn", Text: fmt.Sprintf("Node %s is offline (%s); %s for it.",
			n.Label(), since, plural(n.Targets, "its target waits", fmt.Sprintf("its %d targets wait", n.Targets)))})
	}
	return out
}
