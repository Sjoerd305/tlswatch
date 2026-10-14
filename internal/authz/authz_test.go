package authz

import "testing"

func TestMatrix(t *testing.T) {
	want := map[Role][]Action{
		Viewer:   {ViewData, ManageOwnAccount},
		Operator: {ViewData, ManageOwnAccount, EditTargets, Acknowledge},
		Admin:    Actions,
	}
	for _, r := range Roles {
		allowed := map[Action]bool{}
		for _, a := range want[r] {
			allowed[a] = true
		}
		for _, a := range Actions {
			if got := Allowed(r, a); got != allowed[a] {
				t.Errorf("Allowed(%s, %s) = %v, want %v", r, a, got, allowed[a])
			}
		}
	}
}

// Negative suite: every role tried against every action it must not have.
func TestDenied(t *testing.T) {
	denied := map[Role][]Action{
		Viewer:   {EditTargets, Acknowledge, ManageSettings, ManageUsers, ViewAudit},
		Operator: {ManageSettings, ManageUsers, ViewAudit},
	}
	for r, as := range denied {
		for _, a := range as {
			if Allowed(r, a) {
				t.Errorf("%s must not be allowed %s", r, a)
			}
		}
	}
	for _, a := range Actions {
		if Allowed("", a) || Allowed("root", a) {
			t.Errorf("unknown role allowed %s", a)
		}
	}
	for _, r := range Roles {
		if Allowed(r, "") || Allowed(r, "everything") {
			t.Errorf("%s allowed an unknown action", r)
		}
	}
}

func TestParseRole(t *testing.T) {
	for _, r := range Roles {
		if got, err := ParseRole(string(r)); err != nil || got != r {
			t.Errorf("ParseRole(%s) = %v, %v", r, got, err)
		}
	}
	if _, err := ParseRole("Admin"); err == nil {
		t.Error("ParseRole accepted wrong case")
	}
}
