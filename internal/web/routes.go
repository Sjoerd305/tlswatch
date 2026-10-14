package web

import (
	"net/http"

	"github.com/sjoerd305/tlswatch/internal/authz"
)

func (s *Server) routes(mux *http.ServeMux) {
	view := func(h http.HandlerFunc) http.HandlerFunc { return s.require(authz.ViewData, h) }
	edit := func(h http.HandlerFunc) http.HandlerFunc { return s.require(authz.EditTargets, h) }
	ack := func(h http.HandlerFunc) http.HandlerFunc { return s.require(authz.Acknowledge, h) }
	admin := func(h http.HandlerFunc) http.HandlerFunc { return s.require(authz.ManageSettings, h) }
	users := func(h http.HandlerFunc) http.HandlerFunc { return s.require(authz.ManageUsers, h) }
	audit := func(h http.HandlerFunc) http.HandlerFunc { return s.require(authz.ViewAudit, h) }
	own := func(h http.HandlerFunc) http.HandlerFunc { return s.require(authz.ManageOwnAccount, h) }

	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /favicon.ico", s.favicon)

	// Signed out.
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /auth/google", s.googleStart)
	mux.HandleFunc("GET /auth/google/callback", s.googleCallback)
	mux.HandleFunc("GET /setup", s.setupPage)
	mux.HandleFunc("POST /setup", s.setup)
	mux.HandleFunc("GET /invite", s.invitePage)
	mux.HandleFunc("POST /invite", s.invite)

	// Pages.
	mux.HandleFunc("GET /{$}", view(s.overview))
	mux.HandleFunc("GET /targets", view(s.targets))
	mux.HandleFunc("GET /targets/new", edit(s.targetNew))
	mux.HandleFunc("POST /targets/new", edit(s.targetSave))
	mux.HandleFunc("GET /targets/{id}", view(s.targetDetail))
	mux.HandleFunc("GET /targets/{id}/edit", edit(s.targetEdit))
	mux.HandleFunc("POST /targets/{id}/edit", edit(s.targetSave))
	mux.HandleFunc("POST /targets/{id}/check", edit(s.targetCheck))
	mux.HandleFunc("POST /targets/{id}/enable", edit(s.targetEnable))
	mux.HandleFunc("POST /targets/{id}/disable", edit(s.targetDisable))
	mux.HandleFunc("GET /targets/{id}/delete", edit(s.targetDeletePage))
	mux.HandleFunc("POST /targets/{id}/delete", edit(s.targetDelete))
	mux.HandleFunc("POST /targets/check-all", edit(s.checkAll))
	mux.HandleFunc("GET /certificates", view(s.certificates))
	mux.HandleFunc("GET /certificates.csv", view(s.certificatesCSV))
	mux.HandleFunc("GET /certificates/{fp}/pem", view(s.certificatePEM))
	mux.HandleFunc("GET /findings", view(s.findings))
	mux.HandleFunc("POST /findings/ack", ack(s.findingAckBulk))
	mux.HandleFunc("POST /findings/{id}/ack", ack(s.findingAck))
	mux.HandleFunc("POST /findings/{id}/unack", ack(s.findingUnack))

	// Settings.
	mux.HandleFunc("GET /settings", admin(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/settings/general", http.StatusSeeOther)
	}))
	mux.HandleFunc("GET /settings/general", admin(s.settingsGeneral))
	mux.HandleFunc("POST /settings/general", admin(s.settingsGeneralSave))
	mux.HandleFunc("GET /settings/signin", admin(s.settingsSignIn))
	mux.HandleFunc("POST /settings/signin", admin(s.settingsSignInSave))
	mux.HandleFunc("GET /settings/channels", admin(s.settingsChannels))
	mux.HandleFunc("POST /settings/channels", admin(s.channelSave))
	mux.HandleFunc("POST /settings/channels/{id}/test", admin(s.channelTest))
	mux.HandleFunc("POST /settings/channels/{id}/delete", admin(s.channelDelete))
	mux.HandleFunc("GET /settings/bundles", admin(s.settingsBundles))
	mux.HandleFunc("POST /settings/bundles", admin(s.bundleSave))
	mux.HandleFunc("POST /settings/bundles/{id}/delete", admin(s.bundleDelete))
	mux.HandleFunc("GET /settings/defaults", admin(s.settingsDefaults))
	mux.HandleFunc("POST /settings/defaults", admin(s.settingsDefaultsSave))
	mux.HandleFunc("POST /settings/digest/send", admin(s.digestSend))
	mux.HandleFunc("GET /settings/users", users(s.settingsUsers))
	mux.HandleFunc("POST /settings/users", users(s.userCreate))
	mux.HandleFunc("POST /settings/users/{id}", users(s.userUpdate))
	mux.HandleFunc("POST /settings/users/{id}/link", users(s.userLink))
	mux.HandleFunc("POST /settings/users/{id}/password", users(s.userPassword))
	mux.HandleFunc("POST /settings/users/{id}/unlock", users(s.userUnlock))
	mux.HandleFunc("POST /settings/users/{id}/delete", users(s.userDelete))
	mux.HandleFunc("GET /settings/audit", audit(s.settingsAudit))
	mux.HandleFunc("GET /settings/audit.csv", audit(s.auditCSV))
	mux.HandleFunc("GET /settings/about", admin(s.settingsAbout))
	mux.HandleFunc("GET /account", own(s.account))
	mux.HandleFunc("POST /account", own(s.accountSave))
	mux.HandleFunc("POST /account/password", own(s.accountPassword))

	// JSON API for the TypeScript modules.
	mux.HandleFunc("POST /api/v1/targets/{id}/check", edit(s.apiTargetCheck))
	mux.HandleFunc("POST /api/v1/targets/check-all", edit(s.apiCheckAll))
	mux.HandleFunc("POST /api/v1/targets/test", edit(s.apiTargetTest))
	mux.HandleFunc("GET /api/v1/findings/{id}/panel", view(s.apiFindingPanel))
	mux.HandleFunc("GET /api/v1/stamp", view(s.apiStamp))
	mux.HandleFunc("GET /api/v1/certificates/{fp}/chain", view(s.apiCertChain))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.fail(w, r, http.StatusNotFound, "There is nothing at this address.")
	})
}
