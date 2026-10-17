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
	mux.HandleFunc("POST /setup/restore", s.setupRestore)
	mux.HandleFunc("GET /invite", s.invitePage)
	mux.HandleFunc("POST /invite", s.invite)

	// Pages.
	mux.HandleFunc("GET /{$}", view(s.overview))
	mux.HandleFunc("GET /targets", view(s.targets))
	mux.HandleFunc("GET /targets/new", edit(s.targetNew))
	mux.HandleFunc("POST /targets/new", edit(s.targetSave))
	mux.HandleFunc("GET /targets/bulk-add", edit(s.bulkAddPage))
	mux.HandleFunc("POST /targets/bulk-add", edit(s.bulkAdd))
	mux.HandleFunc("POST /targets/bulk", edit(s.bulkSelect))
	mux.HandleFunc("GET /targets/bulk-edit", edit(s.bulkEditPage))
	mux.HandleFunc("POST /targets/bulk-edit", edit(s.bulkEdit))
	mux.HandleFunc("GET /targets/{id}", view(s.targetDetail))
	mux.HandleFunc("GET /targets/{id}/edit", edit(s.targetEdit))
	mux.HandleFunc("POST /targets/{id}/edit", edit(s.targetSave))
	mux.HandleFunc("POST /targets/{id}/check", edit(s.targetCheck))
	mux.HandleFunc("POST /targets/{id}/enable", edit(s.targetEnable))
	mux.HandleFunc("POST /targets/{id}/disable", edit(s.targetDisable))
	mux.HandleFunc("GET /targets/{id}/delete", edit(s.targetDeletePage))
	mux.HandleFunc("POST /targets/{id}/delete", edit(s.targetDelete))
	mux.HandleFunc("POST /targets/check-all", edit(s.checkAll))
	mux.HandleFunc("GET /domains", view(s.domains))
	mux.HandleFunc("GET /domains/new", edit(s.domainNew))
	mux.HandleFunc("POST /domains/new", edit(s.domainSave))
	mux.HandleFunc("GET /domains/{id}", view(s.domainDetail))
	mux.HandleFunc("GET /domains/{id}/edit", edit(s.domainEdit))
	mux.HandleFunc("POST /domains/{id}/edit", edit(s.domainSave))
	mux.HandleFunc("POST /domains/{id}/enable", edit(s.domainEnable))
	mux.HandleFunc("POST /domains/{id}/disable", edit(s.domainDisable))
	mux.HandleFunc("POST /domains/{id}/poll", edit(s.domainPoll))
	mux.HandleFunc("GET /domains/{id}/delete", edit(s.domainDeletePage))
	mux.HandleFunc("POST /domains/{id}/delete", edit(s.domainDelete))
	mux.HandleFunc("POST /domains/{id}/issuances/{iid}/unexpected", edit(s.issuanceUnexpected))
	mux.HandleFunc("POST /domains/{id}/issuances/{iid}/ack", ack(s.issuanceAck))
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
	mux.HandleFunc("GET /settings/ct", admin(s.settingsCT))
	mux.HandleFunc("POST /settings/ct", admin(s.settingsCTSave))
	mux.HandleFunc("POST /settings/ct/test", admin(s.settingsCTTest))
	mux.HandleFunc("GET /settings/channels", admin(s.settingsChannels))
	mux.HandleFunc("POST /settings/channels", admin(s.channelSave))
	mux.HandleFunc("POST /settings/channels/{id}/test", admin(s.channelTest))
	mux.HandleFunc("POST /settings/channels/{id}/delete", admin(s.channelDelete))
	mux.HandleFunc("GET /settings/nodes", admin(s.settingsNodes))
	mux.HandleFunc("POST /settings/nodes", admin(s.nodeAdd))
	mux.HandleFunc("POST /settings/nodes/auto", admin(s.nodesAuto))
	mux.HandleFunc("POST /settings/nodes/update-all", admin(s.nodesUpdateAll))
	mux.HandleFunc("GET /settings/nodes/{id}", admin(s.nodePage))
	mux.HandleFunc("POST /settings/nodes/{id}", admin(s.nodeSave))
	mux.HandleFunc("POST /settings/nodes/{id}/confirm", admin(s.nodeConfirm))
	mux.HandleFunc("POST /settings/nodes/{id}/reject", admin(s.nodeReject))
	mux.HandleFunc("POST /settings/nodes/{id}/rotate", admin(s.nodeRotate))
	mux.HandleFunc("POST /settings/nodes/{id}/update", admin(s.nodeUpdate))
	mux.HandleFunc("POST /settings/nodes/{id}/enable", admin(s.nodeEnable))
	mux.HandleFunc("POST /settings/nodes/{id}/disable", admin(s.nodeDisable))
	mux.HandleFunc("GET /settings/nodes/{id}/delete", admin(s.nodeDeletePage))
	mux.HandleFunc("POST /settings/nodes/{id}/delete", admin(s.nodeDelete))
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
	mux.HandleFunc("GET /settings/backup", admin(s.settingsBackup))
	mux.HandleFunc("POST /settings/backup", admin(s.backupDownload))
	mux.HandleFunc("POST /settings/backup/restore", admin(s.backupRestore))
	mux.HandleFunc("GET /settings/about", admin(s.settingsAbout))
	mux.HandleFunc("GET /account", own(s.account))
	mux.HandleFunc("POST /account", own(s.accountSave))
	if s.Demo {
		mux.HandleFunc("POST /account/theme", view(s.accountTheme))
	} else {
		mux.HandleFunc("POST /account/theme", own(s.accountTheme))
	}
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
