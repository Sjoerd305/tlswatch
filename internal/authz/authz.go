// Package authz holds the one role × action decision used by every handler.
package authz

import "fmt"

// Role is a user's single role.
type Role string

const (
	Viewer   Role = "viewer"
	Operator Role = "operator"
	Admin    Role = "admin"
	// Demo is the visitor of an instance in demo mode (TLSWATCH_DEMO): it
	// views the data and nothing else. It is never stored on a user, so
	// Roles and ParseRole leave it out.
	Demo Role = "demo"
)

// Roles lists every role a user can have, least privileged first.
var Roles = []Role{Viewer, Operator, Admin}

// ParseRole validates a role name.
func ParseRole(s string) (Role, error) {
	switch r := Role(s); r {
	case Viewer, Operator, Admin:
		return r, nil
	}
	return "", fmt.Errorf("unknown role %q", s)
}

// Action is something a handler does on behalf of a user.
type Action string

const (
	ViewData         Action = "view"            // targets, certificates, findings, history
	EditTargets      Action = "targets.edit"    // add, edit, disable, delete, check now, check all, test probe
	Acknowledge      Action = "findings.ack"    // acknowledge and unacknowledge findings
	ManageSettings   Action = "settings.manage" // general, sign-in, channels, CA bundles, defaults, digest
	ManageUsers      Action = "users.manage"
	ViewAudit        Action = "audit.view"
	ManageOwnAccount Action = "account.manage" // own name, theme and password
)

// Actions lists every action.
var Actions = []Action{ViewData, EditTargets, Acknowledge, ManageSettings, ManageUsers, ViewAudit, ManageOwnAccount}

var policy = map[Role]map[Action]bool{
	Demo: {
		ViewData: true,
	},
	Viewer: {
		ViewData: true, ManageOwnAccount: true,
	},
	Operator: {
		ViewData: true, ManageOwnAccount: true,
		EditTargets: true, Acknowledge: true,
	},
	Admin: {
		ViewData: true, ManageOwnAccount: true,
		EditTargets: true, Acknowledge: true,
		ManageSettings: true, ManageUsers: true, ViewAudit: true,
	},
}

// Allowed reports whether role r may perform action a. Unknown roles and
// actions are denied.
func Allowed(r Role, a Action) bool {
	return policy[r][a]
}
