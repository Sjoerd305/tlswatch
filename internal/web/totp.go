package web

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/qr"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// totpIssuer names tlswatch in the authenticator app.
const totpIssuer = "tlswatch"

// methodName names a login method for people.
func (s *Server) methodName(r *http.Request, method string) string {
	switch method {
	case auth.MethodGoogle:
		return "Google"
	case auth.MethodOIDC:
		return info(r).settings.SignIn.OIDCLabel()
	}
	return "a password"
}

type totpData struct {
	Setup auth.TOTPSetup
	QR    template.HTML
	Error string
	// Required is set when the user's role must use TOTP: nothing else
	// opens until it is set up.
	Required bool
}

// totpSetupPage shows a new secret as a QR code to set up TOTP.
func (s *Server) totpSetupPage(w http.ResponseWriter, r *http.Request) {
	u := user(r)
	if u.Method != auth.MethodLocal || u.HasTOTP() {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	setup, err := s.Auth.BeginTOTP(u, totpIssuer)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderTOTPSetup(w, r, http.StatusOK, setup, "")
}

func (s *Server) renderTOTPSetup(w http.ResponseWriter, r *http.Request, status int, setup auth.TOTPSetup, msg string) {
	code, err := qr.Encode(setup.URI)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := totpData{Setup: setup, Error: msg, Required: s.totpDue(info(r)),
		QR: template.HTML(code.SVG("QR code to scan with the authenticator app"))} // #nosec G203 -- drawn by internal/qr, the label escaped
	s.renderStatus(w, r, status, "account-totp", &Page{Title: "Two-factor sign-in", Data: d})
}

// totpConfirm turns TOTP on once the code from the app matches, and shows
// the recovery codes once. The other sessions end.
func (s *Server) totpConfirm(w http.ResponseWriter, r *http.Request) {
	u := user(r)
	if u.Method != auth.MethodLocal || u.HasTOTP() {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	sealed := r.PostFormValue("setup")
	codes, err := s.Auth.ConfirmTOTP(r.Context(), u, sealed, r.PostFormValue("code"))
	if err != nil {
		if errors.Is(err, auth.ErrCodeMismatch) {
			if setup, err2 := s.Auth.ReopenTOTP(u, totpIssuer, sealed); err2 == nil {
				s.renderTOTPSetup(w, r, http.StatusBadRequest, setup, err.Error())
				return
			}
		}
		if msg, ok := usererr.Message(err); ok {
			setup, err := s.Auth.BeginTOTP(u, totpIssuer)
			if err != nil {
				s.serverError(w, r, err)
				return
			}
			s.renderTOTPSetup(w, r, http.StatusBadRequest, setup, msg)
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), u.Email, "user.totp.enable", "user "+u.Email, "TOTP set up; other sessions ended")
	if err := s.Auth.DeleteUserSessions(r.Context(), u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	raw, csrf, err := s.Auth.NewSession(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setSessionCookie(w, r, raw)
	info(r).session.CSRF = csrf // the page below has the new session's forms
	s.showRecoveryCodes(w, r, codes, "Two-factor sign-in is on. Other sessions were signed out.")
}

// showRecoveryCodes renders the account page with new recovery codes.
func (s *Server) showRecoveryCodes(w http.ResponseWriter, r *http.Request, codes []string, notice string) {
	u, err := s.Auth.UserByID(r.Context(), user(r).ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	info(r).session.User = u
	d, err := s.accountData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d.RecoveryCodes = codes
	s.render(w, r, "account", &Page{Title: "Account", Data: d, Notices: []Notice{{Kind: "ok", Text: notice}}})
}

// checkOwnCode checks a code from the user's app (or a recovery code)
// before a change to two-factor sign-in; a wrong one counts towards the
// lockout. It answers the request itself when the code is not accepted.
func (s *Server) checkOwnCode(w http.ResponseWriter, r *http.Request) bool {
	u := user(r)
	if u.Method != auth.MethodLocal || !u.HasTOTP() {
		s.back(w, r, "/account", "Two-factor sign-in is not on for this account.", "crit")
		return false
	}
	_, _, err := s.Auth.LoginCode(r.Context(), u.ID, r.PostFormValue("code"), info(r).ip)
	switch {
	case err == nil:
		return true
	case errors.Is(err, auth.ErrLocked):
		s.back(w, r, "/account", "Too many failed attempts. Try again in 15 minutes.", "crit")
	case errors.Is(err, auth.ErrInvalidCode):
		s.back(w, r, "/account", "The code is incorrect.", "crit")
	default:
		s.serverError(w, r, err)
	}
	return false
}

// totpRecovery replaces the user's recovery codes.
func (s *Server) totpRecovery(w http.ResponseWriter, r *http.Request) {
	if !s.checkOwnCode(w, r) {
		return
	}
	u := user(r)
	codes, err := s.Auth.NewRecoveryCodes(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), u.Email, "user.totp.recovery", "user "+u.Email, "new recovery codes; the old ones no longer work")
	s.showRecoveryCodes(w, r, codes, "New recovery codes made; the old ones no longer work.")
}

// totpDisable turns the user's own TOTP off, unless their role must use it.
func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) {
	u := user(r)
	if info(r).settings.SignIn.TOTPRequired(string(u.Role)) {
		s.back(w, r, "/account", "An administrator requires two-factor sign-in for "+string(u.Role)+"s; it cannot be turned off.", "crit")
		return
	}
	if !s.checkOwnCode(w, r) {
		return
	}
	if err := s.Auth.ResetTOTP(r.Context(), u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), u.Email, "user.totp.disable", "user "+u.Email, "turned off by the user")
	s.back(w, r, "/account", "Two-factor sign-in is off.", "ok")
}

// userTOTPReset lets an admin turn TOTP off for a user who lost their
// phone and recovery codes. Their sessions end; a role that must use TOTP
// sets it up again at the next sign-in.
func (s *Server) userTOTPReset(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such user.")
		return
	}
	u, err := s.Auth.UserByID(r.Context(), id)
	if err != nil || !u.HasTOTP() {
		s.fail(w, r, http.StatusNotFound, "No such user with two-factor sign-in.")
		return
	}
	back := fmt.Sprintf("/settings/users?edit=%d", id)
	if id == user(r).ID {
		s.back(w, r, back, "Turn your own two-factor sign-in off under Account.", "crit")
		return
	}
	if err := s.Auth.ResetTOTP(r.Context(), id); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.Auth.DeleteUserSessions(r.Context(), id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "user.totp.reset", "user "+u.Email, "TOTP and recovery codes removed by admin; sessions ended")
	s.back(w, r, "/settings/users", "Two-factor sign-in reset for "+u.Email+"; their sessions were signed out.", "ok")
}
