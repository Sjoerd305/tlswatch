package web

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/config"
	"github.com/sjoerd305/tlswatch/internal/core"
	"github.com/sjoerd305/tlswatch/internal/db"
	"github.com/sjoerd305/tlswatch/internal/notify"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request, status int, name, sub, title string, data any) {
	s.renderStatus(w, r, status, name, &Page{Title: title, Nav: "settings", SettingsNav: sub, Data: data})
}

// General.

type generalData struct {
	G       config.General
	Derived string
	Error   string
	Zones   []string
}

func (s *Server) settingsGeneral(w http.ResponseWriter, r *http.Request) {
	st := info(r).settings
	s.settingsPage(w, r, http.StatusOK, "settings-general", "general", "Settings", generalData{G: st.General, Derived: s.baseURL(r), Zones: commonZones})
}

var commonZones = []string{"UTC", "Europe/Amsterdam", "Europe/London", "Europe/Berlin", "America/New_York", "America/Chicago", "America/Los_Angeles", "Asia/Tokyo", "Australia/Sydney"}

func (s *Server) settingsGeneralSave(w http.ResponseWriter, r *http.Request) {
	g := config.General{
		BaseURL:         strings.TrimSpace(r.PostFormValue("base_url")),
		BehindProxy:     r.PostFormValue("behind_proxy") == "1",
		AllowLocal:      r.PostFormValue("allow_local") == "1",
		PublicDiscovery: r.PostFormValue("public_discovery") == "1",
		TimeZone:        strings.TrimSpace(r.PostFormValue("time_zone")),
		Metrics:         r.PostFormValue("metrics") == "1",
	}
	// The token stays unless the admin asks for a new one; SaveGeneral
	// makes the first.
	if cur := info(r).settings.General; r.PostFormValue("metrics_rotate") != "1" {
		g.MetricsToken = cur.MetricsToken
	}
	if err := s.Settings.SaveGeneral(r.Context(), g); err != nil {
		if msg, ok := s.formError(w, r, err); ok {
			s.settingsPage(w, r, http.StatusBadRequest, "settings-general", "general", "Settings", generalData{G: g, Derived: s.baseURL(r), Error: msg, Zones: commonZones})
		}
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "settings.general", "general", fmt.Sprintf("base_url=%s behind_proxy=%v allow_local=%v public_discovery=%v time_zone=%s metrics=%v metrics_token=%s", g.BaseURL, g.BehindProxy, g.AllowLocal, g.PublicDiscovery, g.TimeZone, g.Metrics, map[bool]string{true: "rotated", false: "kept"}[r.PostFormValue("metrics_rotate") == "1"]))
	s.back(w, r, "/settings/general", "General settings saved.", "ok")
}

// Sign-in.

type signInData struct {
	S          config.SignIn
	HasSecret  bool
	HasOIDCKey bool
	Redirect   string
	// OIDCRedirect is the generic provider's callback URL.
	OIDCRedirect string
	Error        string
	// Section is the card the error belongs to.
	Section string
}

func (s *Server) signInData(r *http.Request, si config.SignIn) signInData {
	st := info(r).settings
	return signInData{S: si, HasSecret: st.HasGoogleSecret(), HasOIDCKey: st.SignIn.OIDCClientSecret != "",
		Redirect: s.baseURL(r) + "/auth/google/callback", OIDCRedirect: s.baseURL(r) + "/auth/oidc/callback"}
}

func (s *Server) settingsSignIn(w http.ResponseWriter, r *http.Request) {
	s.settingsPage(w, r, http.StatusOK, "settings-signin", "signin", "Settings", s.signInData(r, info(r).settings.SignIn))
}

// settingsSignInSave saves one card of the page: section is totp, google
// or oidc, and the others stay as they are.
func (s *Server) settingsSignInSave(w http.ResponseWriter, r *http.Request) {
	si := info(r).settings.SignIn
	// The secrets in the settings are the stored ones (or the
	// environment's); only a typed one is saved.
	si.GoogleClientSecret, si.OIDCClientSecret = "", ""
	var clearGoogle, clearOIDC bool
	var object, detail string
	section := r.PostFormValue("section")
	switch section {
	case "totp":
		si.TOTPRoles = nil
		for _, v := range r.PostForm["totp_roles"] {
			if role, err := authz.ParseRole(v); err == nil && !slices.Contains(si.TOTPRoles, string(role)) {
				si.TOTPRoles = append(si.TOTPRoles, string(role))
			}
		}
		object, detail = "two-factor sign-in", "required for="+strings.Join(si.TOTPRoles, ",")
	case "google":
		si.GoogleClientID = strings.TrimSpace(r.PostFormValue("google_client_id"))
		si.GoogleClientSecret = strings.TrimSpace(r.PostFormValue("google_client_secret"))
		si.GoogleDomain = strings.ToLower(strings.TrimSpace(r.PostFormValue("google_domain")))
		clearGoogle = r.PostFormValue("clear_secret") == "1"
		object, detail = "google sign-in", fmt.Sprintf("client_id=%s domain=%s", si.GoogleClientID, si.GoogleDomain)
		if si.GoogleClientSecret != "" {
			detail += " secret=[changed]"
		}
		if clearGoogle {
			detail += " secret=[removed]"
		}
	case "oidc":
		si.OIDCName = strings.TrimSpace(r.PostFormValue("oidc_name"))
		si.OIDCIssuer = strings.TrimSpace(r.PostFormValue("oidc_issuer"))
		si.OIDCClientID = strings.TrimSpace(r.PostFormValue("oidc_client_id"))
		si.OIDCClientSecret = strings.TrimSpace(r.PostFormValue("oidc_client_secret"))
		si.OIDCScopes = strings.Join(strings.Fields(r.PostFormValue("oidc_scopes")), " ")
		si.OIDCDomain = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(r.PostFormValue("oidc_domain")), "@"))
		si.OIDCRoleClaim = strings.TrimSpace(r.PostFormValue("oidc_role_claim"))
		si.OIDCAdminGroups = strings.Join(config.SplitGroups(r.PostFormValue("oidc_admin_groups")), ", ")
		si.OIDCOperatorGroups = strings.Join(config.SplitGroups(r.PostFormValue("oidc_operator_groups")), ", ")
		si.OIDCViewerGroups = strings.Join(config.SplitGroups(r.PostFormValue("oidc_viewer_groups")), ", ")
		si.OIDCCreateUsers = r.PostFormValue("oidc_create_users") == "1"
		clearOIDC = r.PostFormValue("clear_oidc_secret") == "1"
		object = "openid connect sign-in"
		detail = fmt.Sprintf("name=%s issuer=%s client_id=%s scopes=%s domain=%s role_claim=%s admin=%s operator=%s viewer=%s create_users=%v",
			si.OIDCName, si.OIDCIssuer, si.OIDCClientID, si.OIDCScopes, si.OIDCDomain, si.OIDCRoleClaim, si.OIDCAdminGroups, si.OIDCOperatorGroups, si.OIDCViewerGroups, si.OIDCCreateUsers)
		if si.OIDCClientSecret != "" {
			detail += " secret=[changed]"
		}
		if clearOIDC {
			detail += " secret=[removed]"
		}
	default:
		s.fail(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	if err := s.Settings.SaveSignIn(r.Context(), si, clearGoogle, clearOIDC); err != nil {
		if msg, ok := s.formError(w, r, err); ok {
			d := s.signInData(r, si)
			d.Error, d.Section = msg, section
			s.settingsPage(w, r, http.StatusBadRequest, "settings-signin", "signin", "Settings", d)
		}
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "settings.signin", object, detail)
	s.back(w, r, "/settings/signin", "Sign-in settings saved.", "ok")
}

// Channels.

type channelsData struct {
	Channels []notify.Channel
	Edit     *notify.Channel
	Error    string
}

func (s *Server) settingsChannels(w http.ResponseWriter, r *http.Request) {
	chans, err := s.Core.Channels.List(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := channelsData{Channels: chans}
	q := r.URL.Query()
	switch {
	case q.Get("new") == notify.KindSMTP:
		d.Edit = &notify.Channel{Kind: notify.KindSMTP, MinSeverity: "warning", Enabled: true, SMTP: notify.SMTPSettings{Port: 587, Encryption: "starttls"}}
	case q.Get("new") == notify.KindNtfy:
		d.Edit = &notify.Channel{Kind: notify.KindNtfy, MinSeverity: "critical", Enabled: true, Ntfy: notify.NtfySettings{Server: notify.DefaultNtfyServer}}
	case notify.KnownKind(q.Get("new")):
		// Chat channels default to critical only, as the mailbox takes the rest.
		d.Edit = &notify.Channel{Kind: q.Get("new"), MinSeverity: "critical", Enabled: true}
	case q.Get("edit") != "":
		id, _ := strconv.ParseInt(q.Get("edit"), 10, 64)
		for i := range chans {
			if chans[i].ID == id {
				c := chans[i]
				d.Edit = &c
			}
		}
	}
	s.settingsPage(w, r, http.StatusOK, "settings-channels", "channels", "Settings", d)
}

func (s *Server) channelSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	v := r.PostForm
	c := notify.Channel{
		Name: strings.TrimSpace(v.Get("name")), Kind: v.Get("kind"), MinSeverity: v.Get("min_severity"),
		Enabled: v.Get("enabled") == "1",
	}
	c.ID, _ = strconv.ParseInt(v.Get("id"), 10, 64)
	switch c.Kind {
	case notify.KindTelegram:
		c.Telegram = notify.TelegramSettings{Token: strings.TrimSpace(v.Get("token")), ChatIDs: splitList(v.Get("chat_ids"))}
	case notify.KindSlack:
		c.Slack = notify.SlackSettings{WebhookURL: strings.TrimSpace(v.Get("webhook_url"))}
	case notify.KindDiscord:
		c.Discord = notify.DiscordSettings{WebhookURL: strings.TrimSpace(v.Get("webhook_url"))}
	case notify.KindNtfy:
		c.Ntfy = notify.NtfySettings{Server: strings.TrimSpace(v.Get("server")), Topic: strings.TrimSpace(v.Get("topic")), Token: strings.TrimSpace(v.Get("token"))}
	case notify.KindWebhook:
		c.Webhook = notify.WebhookSettings{URL: strings.TrimSpace(v.Get("url")), Secret: strings.TrimSpace(v.Get("secret"))}
	case notify.KindTeams:
		c.Teams = notify.TeamsSettings{WebhookURL: strings.TrimSpace(v.Get("webhook_url"))}
	case notify.KindMatrix:
		c.Matrix = notify.MatrixSettings{Homeserver: strings.TrimSpace(v.Get("homeserver")), RoomID: strings.TrimSpace(v.Get("room_id")), Token: strings.TrimSpace(v.Get("token"))}
	case notify.KindPagerDuty:
		c.PagerDuty = notify.PagerDutySettings{RoutingKey: strings.TrimSpace(v.Get("routing_key")), Region: v.Get("region")}
	default:
		c.Kind = notify.KindSMTP
		port, _ := strconv.Atoi(strings.TrimSpace(v.Get("port")))
		if port == 0 {
			port = map[string]int{"tls": 465, "none": 25}[v.Get("encryption")]
			if port == 0 {
				port = 587
			}
		}
		c.SMTP = notify.SMTPSettings{
			Host: strings.TrimSpace(v.Get("host")), Port: port, Encryption: v.Get("encryption"),
			Username: strings.TrimSpace(v.Get("username")), Password: v.Get("password"),
			From: strings.TrimSpace(v.Get("from")), Recipients: splitList(v.Get("recipients")),
			InsecureSkipVerify: v.Get("insecure_skip_verify") == "1",
		}
	}
	id, err := s.Core.Channels.Save(r.Context(), c)
	if err != nil {
		if msg, ok := s.formError(w, r, err); ok {
			chans, _ := s.Core.Channels.List(r.Context())
			c.ClearSecrets()
			s.settingsPage(w, r, http.StatusBadRequest, "settings-channels", "channels", "Settings", channelsData{Channels: chans, Edit: &c, Error: msg})
		}
		return
	}
	action := "channel.update"
	if c.ID == 0 {
		action = "channel.create"
	}
	detail := fmt.Sprintf("kind=%s floor=%s enabled=%v", c.Kind, c.MinSeverity, c.Enabled)
	if c.HasSecret() {
		detail += " credentials=[changed]"
	}
	s.Core.Audit(r.Context(), user(r).Email, action, fmt.Sprintf("channel %d %s", id, c.Name), detail)
	s.back(w, r, "/settings/channels", "Channel "+c.Name+" saved.", "ok")
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Server) channelTest(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such channel.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 70*time.Second)
	defer cancel()
	err = s.Dispatch.SendTest(ctx, id, s.baseURL(r)+"/")
	s.Core.Audit(r.Context(), user(r).Email, "channel.test", fmt.Sprintf("channel %d", id), fmt.Sprintf("ok=%v", err == nil))
	if err != nil {
		s.back(w, r, "/settings/channels", "Test message failed: "+err.Error(), "crit")
		return
	}
	s.back(w, r, "/settings/channels", "Test message sent.", "ok")
}

func (s *Server) channelDelete(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such channel.")
		return
	}
	c, err := s.Core.Channels.Get(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		s.fail(w, r, http.StatusNotFound, "No such channel.")
		return
	}
	if err != nil && !errors.Is(err, notify.ErrUnreadable) {
		s.serverError(w, r, err)
		return
	}
	if err := s.Core.Channels.Delete(r.Context(), id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "channel.delete", fmt.Sprintf("channel %d %s", id, c.Name), "")
	s.back(w, r, "/settings/channels", "Channel "+c.Name+" deleted.", "ok")
}

// CA bundles.

type bundlesData struct {
	Bundles []core.Bundle
	Name    string
	PEM     string
	Error   string
	Edit    int64
}

func (s *Server) settingsBundles(w http.ResponseWriter, r *http.Request) {
	bs, err := s.Core.Bundles(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := bundlesData{Bundles: bs}
	if id, err := strconv.ParseInt(r.URL.Query().Get("edit"), 10, 64); err == nil {
		for _, b := range bs {
			if b.ID == id {
				d.Edit, d.Name, d.PEM = b.ID, b.Name, b.PEM
			}
		}
	}
	s.settingsPage(w, r, http.StatusOK, "settings-bundles", "bundles", "Settings", d)
}

func (s *Server) bundleSave(w http.ResponseWriter, r *http.Request) {
	// The middleware read the form and capped its size.
	name := r.FormValue("name")
	data := r.FormValue("pem")
	if f, h, err := r.FormFile("file"); err == nil {
		if h.Size > 2<<20 {
			_ = f.Close()
			s.fail(w, r, http.StatusRequestEntityTooLarge, "The upload is too large (2 MB at most).")
			return
		}
		b, _ := io.ReadAll(f)
		_ = f.Close()
		if len(b) > 0 {
			data = string(b)
		}
	}
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	nid, err := s.Core.SaveBundle(r.Context(), id, name, data)
	if err != nil {
		if msg, ok := s.formError(w, r, err); ok {
			bs, _ := s.Core.Bundles(r.Context())
			s.settingsPage(w, r, http.StatusBadRequest, "settings-bundles", "bundles", "Settings", bundlesData{Bundles: bs, Name: name, PEM: data, Error: msg, Edit: id})
		}
		return
	}
	action := "bundle.update"
	if id == 0 {
		action = "bundle.create"
	}
	s.Core.Audit(r.Context(), user(r).Email, action, fmt.Sprintf("bundle %d %s", nid, name), "")
	s.back(w, r, "/settings/bundles", "CA bundle "+name+" saved.", "ok")
}

func (s *Server) bundleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such bundle.")
		return
	}
	switch err := s.Core.DeleteBundle(r.Context(), id); {
	case errors.Is(err, core.ErrBundleInUse):
		s.back(w, r, "/settings/bundles", err.Error(), "crit")
		return
	case errors.Is(err, core.ErrNotFound):
		s.fail(w, r, http.StatusNotFound, "No such bundle.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "bundle.delete", fmt.Sprintf("bundle %d", id), "")
	s.back(w, r, "/settings/bundles", "CA bundle deleted.", "ok")
}

// Defaults.

type defaultsData struct {
	D        config.Defaults
	Channels []notify.Channel
	Error    string
}

func (s *Server) settingsDefaults(w http.ResponseWriter, r *http.Request) {
	chans, _ := s.Core.Channels.List(r.Context())
	s.settingsPage(w, r, http.StatusOK, "settings-defaults", "defaults", "Settings", defaultsData{D: info(r).settings.Defaults, Channels: chans})
}

func (s *Server) settingsDefaultsSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	v := r.PostForm
	cur := info(r).settings
	// Non-numeric input is an error, not 0: for retries, reminders and the
	// digest day and hour, 0 is a valid value.
	var bad []string
	n := func(k string) int {
		x, err := strconv.Atoi(strings.TrimSpace(v.Get(k)))
		if err != nil {
			bad = append(bad, k)
		}
		return x
	}
	// An empty percentage means days only.
	pct := func(k string) int {
		if strings.TrimSpace(v.Get(k)) == "" {
			return 0
		}
		v.Set(k, trimPct(v.Get(k)))
		return n(k)
	}
	d := config.Defaults{
		Manual:        config.Thresholds{WarnDays: n("manual_warn"), CritDays: n("manual_crit"), WarnPct: pct("manual_warn_pct"), CritPct: pct("manual_crit_pct")},
		Managed:       config.Thresholds{WarnDays: n("managed_warn"), CritDays: n("managed_crit"), WarnPct: pct("managed_warn_pct"), CritPct: pct("managed_crit_pct")},
		IntervalS:     n("interval_s"),
		AllAddresses:  v.Get("addresses") != "first",
		TimeoutS:      n("timeout_s"),
		Retries:       n("retries"),
		Debounce:      n("debounce"),
		RemindWarnS:   n("remind_warn_s"),
		RemindCritS:   n("remind_crit_s"),
		Workers:       n("workers"),
		RetentionDays: n("retention_days"),
		DigestEnabled: v.Get("digest_enabled") == "1",
		DigestWeekday: n("digest_weekday"),
		DigestHour:    n("digest_hour"),
	}
	if cur.Locked("workers") {
		d.Workers = cur.Defaults.Workers
		bad = slices.DeleteFunc(bad, func(k string) bool { return k == "workers" })
	}
	if cur.Locked("retention_days") {
		d.RetentionDays = cur.Defaults.RetentionDays
		bad = slices.DeleteFunc(bad, func(k string) bool { return k == "retention_days" })
	}
	if len(bad) > 0 {
		chans, _ := s.Core.Channels.List(r.Context())
		s.settingsPage(w, r, http.StatusBadRequest, "settings-defaults", "defaults", "Settings",
			defaultsData{D: cur.Defaults, Channels: chans, Error: "Enter whole numbers in every field (" + strings.Join(bad, ", ") + ")."})
		return
	}
	for _, c := range v["digest_channel"] {
		if id, err := strconv.ParseInt(c, 10, 64); err == nil {
			d.DigestChannels = append(d.DigestChannels, id)
		}
	}
	if err := s.Settings.SaveDefaults(r.Context(), d); err != nil {
		if msg, ok := s.formError(w, r, err); ok {
			chans, _ := s.Core.Channels.List(r.Context())
			s.settingsPage(w, r, http.StatusBadRequest, "settings-defaults", "defaults", "Settings", defaultsData{D: d, Channels: chans, Error: msg})
		}
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "settings.defaults", "defaults", fmt.Sprintf("manual=%d/%d %d%%/%d%% managed=%d/%d %d%%/%d%% interval=%s workers=%d retention=%d digest=%v",
		d.Manual.WarnDays, d.Manual.CritDays, d.Manual.WarnPct, d.Manual.CritPct, d.Managed.WarnDays, d.Managed.CritDays, d.Managed.WarnPct, d.Managed.CritPct, durationLabel(d.IntervalS), d.Workers, d.RetentionDays, d.DigestEnabled))
	s.Sched.Reload()
	s.back(w, r, "/settings/defaults", "Defaults saved. Targets with their own values keep them.", "ok")
}

func (s *Server) digestSend(w http.ResponseWriter, r *http.Request) {
	if err := s.Sched.SendDigest(r.Context()); err != nil {
		s.back(w, r, "/settings/defaults", "Digest not sent: "+err.Error(), "crit")
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "digest.send", "digest", "sent on request")
	s.back(w, r, "/settings/defaults", "Digest queued for delivery.", "ok")
}

// Users.

type usersData struct {
	Users  []auth.User
	Edit   *auth.User
	Link   string
	Error  string
	Form   auth.User
	Google bool
	// OIDC is the generic OpenID Connect provider, under OIDCName.
	OIDC     bool
	OIDCName string
	Self     int64
	// Mail is true when an enabled SMTP channel can carry invite links;
	// without one, an admin sets the first password.
	Mail bool
}

// methodSetPassword is the invite form's choice for a password user whose
// first password the admin sets, offered when no SMTP channel is set up.
const methodSetPassword = "local-set"

// mailReady reports whether an enabled SMTP channel exists to e-mail
// invite and password links.
func (s *Server) mailReady(ctx context.Context) bool {
	chans, err := s.Core.Channels.Enabled(ctx)
	if err != nil {
		return false
	}
	for _, c := range chans {
		if c.Kind == notify.KindSMTP {
			return true
		}
	}
	return false
}

// newUserForm is the empty invite form: an e-mailed link when mail works,
// otherwise a password the admin sets.
func newUserForm(mail bool) auth.User {
	f := auth.User{Role: authz.Viewer, Method: auth.MethodLocal}
	if !mail {
		f.Method = methodSetPassword
	}
	return f
}

func (s *Server) settingsUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.Auth.ListUsers(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	mail := s.mailReady(r.Context())
	d := usersData{Users: us, Google: info(r).settings.GoogleEnabled(), OIDC: info(r).settings.OIDCEnabled(), OIDCName: info(r).settings.SignIn.OIDCLabel(), Self: user(r).ID, Form: newUserForm(mail), Mail: mail}
	if id, err := strconv.ParseInt(r.URL.Query().Get("edit"), 10, 64); err == nil {
		for i := range us {
			if us[i].ID == id {
				u := us[i]
				d.Edit = &u
			}
		}
	}
	s.settingsPage(w, r, http.StatusOK, "settings-users", "users", "Settings", d)
}

func (s *Server) userCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	role, rerr := authz.ParseRole(r.PostFormValue("role"))
	method := r.PostFormValue("method")
	mail := s.mailReady(ctx)
	f := auth.User{Email: strings.TrimSpace(r.PostFormValue("email")), Name: strings.TrimSpace(r.PostFormValue("name")), Role: role, Method: method}
	fail := func(msg string) {
		us, _ := s.Auth.ListUsers(ctx)
		s.settingsPage(w, r, http.StatusBadRequest, "settings-users", "users", "Settings", usersData{Users: us, Form: f, Error: msg, Google: info(r).settings.GoogleEnabled(), OIDC: info(r).settings.OIDCEnabled(), OIDCName: info(r).settings.SignIn.OIDCLabel(), Self: user(r).ID, Mail: mail})
	}
	if rerr != nil {
		fail("Choose a role")
		return
	}
	setPassword := method == methodSetPassword
	pw := r.PostFormValue("password")
	if setPassword {
		if mail {
			fail("An SMTP channel is set up, so new users get an invite link by e-mail and choose their own password.")
			return
		}
		method = auth.MethodLocal
		if pw != r.PostFormValue("password2") {
			fail("The passwords do not match.")
			return
		}
		if err := s.Auth.CheckPasswordPolicy(pw, f.Email); err != nil {
			fail(s.userError(r, err))
			return
		}
	}
	u, err := s.Auth.CreateUser(ctx, f.Email, f.Name, role, method)
	if err != nil {
		fail(s.userError(r, err))
		return
	}
	if setPassword {
		if err := s.Auth.SetPassword(ctx, u.ID, pw); err != nil {
			_ = s.Auth.DeleteUser(ctx, u.ID)
			fail(s.userError(r, err))
			return
		}
	}
	detail := fmt.Sprintf("role=%s method=%s", u.Role, u.Method)
	if setPassword {
		detail += " password=set-by-admin"
	}
	s.Core.Audit(ctx, user(r).Email, "user.create", "user "+u.Email, detail)
	if u.Method != auth.MethodLocal {
		s.back(w, r, "/settings/users", u.Email+" can now sign in with "+s.methodName(r, u.Method)+".", "ok")
		return
	}
	if setPassword {
		s.back(w, r, "/settings/users", u.Email+" can sign in with the password you set. Pass it on securely; they can change it under Account.", "ok")
		return
	}
	link, sent, err := s.inviteLink(r, u)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.showLink(w, r, u, link, sent)
}

// inviteLink creates a one-time password link (7 days) and mails it through
// the first SMTP channel when there is one.
func (s *Server) inviteLink(r *http.Request, u auth.User) (string, bool, error) {
	tok, err := s.Auth.CreateToken(r.Context(), auth.TokenInvite, u.ID, auth.InviteTTL)
	if err != nil {
		return "", false, err
	}
	link := s.baseURL(r) + "/invite?token=" + tok
	chans, err := s.Core.Channels.Enabled(r.Context())
	if err != nil {
		return link, false, nil
	}
	for _, c := range chans {
		if c.Kind != notify.KindSMTP {
			continue
		}
		smtp := c.SMTP
		smtp.Recipients = []string{u.Email}
		msg := notify.Message{
			Subject: "[info] Your tlswatch account",
			Body:    fmt.Sprintf("An administrator created a tlswatch account for %s.\n\nSet your password with this link; it is valid for 7 days and can be used once:\n\n%s\n", u.Email, link),
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		err := (&notify.SMTPSender{S: smtp}).Send(ctx, msg)
		cancel()
		if err == nil {
			return link, true, nil
		}
		s.Log.Warn("invite mail failed", "channel", c.Name, "err", err)
		break
	}
	return link, false, nil
}

func (s *Server) showLink(w http.ResponseWriter, r *http.Request, u auth.User, link string, sent bool) {
	us, _ := s.Auth.ListUsers(r.Context())
	mail := s.mailReady(r.Context())
	d := usersData{Users: us, Link: link, Google: info(r).settings.GoogleEnabled(), OIDC: info(r).settings.OIDCEnabled(), OIDCName: info(r).settings.SignIn.OIDCLabel(), Self: user(r).ID, Form: newUserForm(mail), Mail: mail}
	text := "Send this one-time link to " + u.Email + "; it is valid for 7 days."
	if sent {
		text = "A one-time link was e-mailed to " + u.Email + ". You can also pass it on yourself; it is valid for 7 days."
	}
	p := &Page{Title: "Settings", Nav: "settings", SettingsNav: "users", Data: d, Notices: []Notice{{Kind: "ok", Text: text, Link: link}}}
	s.render(w, r, "settings-users", p)
}

// userError is the message for a failed user change: the error's own
// message when it is meant for the user, otherwise a generic one, the
// error being logged.
func (s *Server) userError(r *http.Request, err error) string {
	switch {
	case errors.Is(err, auth.ErrExists):
		return "A user with this e-mail address already exists."
	case errors.Is(err, auth.ErrLastAdmin):
		return "At least one enabled admin must remain."
	}
	if msg, ok := usererr.Message(err); ok {
		return msg
	}
	s.Log.Error("request failed", "request_id", info(r).id, "method", r.Method, "path", r.URL.Path, "err", err)
	return "Something went wrong. The error has been logged."
}

// formError returns the message to show on a form for a failed save. An
// error not meant for the user is answered as a server error instead, and
// ok is false.
func (s *Server) formError(w http.ResponseWriter, r *http.Request, err error) (msg string, ok bool) {
	if msg, ok := usererr.Message(err); ok {
		return msg, true
	}
	s.serverError(w, r, err)
	return "", false
}

func (s *Server) userUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such user.")
		return
	}
	role, err := authz.ParseRole(r.PostFormValue("role"))
	if err != nil {
		s.back(w, r, "/settings/users", "Choose a role.", "crit")
		return
	}
	method := r.PostFormValue("method")
	enabled := r.PostFormValue("enabled") == "1"
	name := strings.TrimSpace(r.PostFormValue("name"))
	if err := s.Auth.UpdateUser(r.Context(), id, name, role, method, enabled); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, "No such user.")
			return
		}
		s.back(w, r, fmt.Sprintf("/settings/users?edit=%d", id), s.userError(r, err), "crit")
		return
	}
	u, _ := s.Auth.UserByID(r.Context(), id)
	s.Core.Audit(r.Context(), user(r).Email, "user.update", "user "+u.Email, fmt.Sprintf("role=%s method=%s enabled=%v", role, method, enabled))
	s.back(w, r, "/settings/users", "User "+u.Email+" saved.", "ok")
}

func (s *Server) userLink(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such user.")
		return
	}
	u, err := s.Auth.UserByID(r.Context(), id)
	if err != nil || u.Method != auth.MethodLocal {
		s.fail(w, r, http.StatusNotFound, "No such local user.")
		return
	}
	link, sent, err := s.inviteLink(r, u)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "user.link", "user "+u.Email, "new one-time password link")
	s.showLink(w, r, u, link, sent)
}

// userPassword lets an admin set a local user's password when no SMTP
// channel can mail a link. It ends the user's sessions and clears a lockout.
func (s *Server) userPassword(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such user.")
		return
	}
	u, err := s.Auth.UserByID(r.Context(), id)
	if err != nil || u.Method != auth.MethodLocal {
		s.fail(w, r, http.StatusNotFound, "No such local user.")
		return
	}
	back := fmt.Sprintf("/settings/users?edit=%d", id)
	if s.mailReady(r.Context()) {
		s.back(w, r, back, "An SMTP channel is set up: send a new password link instead, so the user chooses their own password.", "crit")
		return
	}
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("password2") {
		s.back(w, r, back, "The passwords do not match.", "crit")
		return
	}
	if err := s.Auth.SetPassword(r.Context(), id, pw); err != nil {
		s.back(w, r, back, s.userError(r, err), "crit")
		return
	}
	if err := s.Auth.DeleteUserSessions(r.Context(), id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "user.password", "user "+u.Email, "password set by admin; sessions ended")
	s.back(w, r, "/settings/users", "New password set for "+u.Email+"; their sessions were signed out. Pass it on securely.", "ok")
}

func (s *Server) userUnlock(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such user.")
		return
	}
	u, err := s.Auth.UserByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such user.")
		return
	}
	if err := s.Auth.Unlock(r.Context(), id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "user.unlock", "user "+u.Email, "")
	s.back(w, r, "/settings/users", u.Email+" is unlocked and can sign in again.", "ok")
}

func (s *Server) userDelete(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such user.")
		return
	}
	u, err := s.Auth.UserByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such user.")
		return
	}
	if id == user(r).ID {
		s.back(w, r, fmt.Sprintf("/settings/users?edit=%d", id), "You cannot delete your own account.", "crit")
		return
	}
	if err := s.Auth.DeleteUser(r.Context(), id); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			s.fail(w, r, http.StatusNotFound, "No such user.")
			return
		}
		s.back(w, r, fmt.Sprintf("/settings/users?edit=%d", id), s.userError(r, err), "crit")
		return
	}
	s.Core.Audit(r.Context(), user(r).Email, "user.delete", "user "+u.Email, "role="+string(u.Role))
	s.back(w, r, "/settings/users", "User "+u.Email+" deleted.", "ok")
}

// Audit log.

type auditData struct {
	Entries []core.AuditEntry
	Query   string
	Limit   int
}

func (s *Server) settingsAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	es, err := s.Core.AuditLog(r.Context(), q, 500)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.settingsPage(w, r, http.StatusOK, "settings-audit", "audit", "Settings", auditData{Entries: es, Query: q, Limit: 500})
}

func (s *Server) auditCSV(w http.ResponseWriter, r *http.Request) {
	es, err := s.Core.AuditLog(r.Context(), r.URL.Query().Get("q"), 0)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="tlswatch-audit-%s.csv"`, s.now().Format("2006-01-02")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "user", "action", "object", "details"})
	for _, e := range es {
		_ = cw.Write([]string{time.Unix(e.At, 0).UTC().Format(time.RFC3339), csvSafe(e.User), e.Action, csvSafe(e.Object), csvSafe(e.Details)})
	}
	cw.Flush()
}

type aboutData struct {
	Version   string
	Go        string
	DBPath    string
	Schema    int
	Listen    string
	Started   time.Time
	Checks    int64
	LastCheck time.Time
	Backlog   int
	Env       map[string]string
}

var started = time.Now()

func (s *Server) settingsAbout(w http.ResponseWriter, r *http.Request) {
	st := s.Sched.Status()
	s.settingsPage(w, r, http.StatusOK, "settings-about", "about", "Settings", aboutData{
		Version: s.Version, Go: runtime.Version(), DBPath: s.Core.DB.Path, Schema: db.SchemaVersion(), Listen: s.Listen,
		Started: started, Checks: st.Checks, LastCheck: st.LastCheck, Backlog: st.Backlog, Env: info(r).settings.Env,
	})
}

// Account.

type accountData struct {
	U     auth.User
	Error string
	// MethodName names how the user signs in.
	MethodName string
	// Two-factor sign-in: the recovery codes left, whether the role must
	// use it, and new recovery codes, shown this once.
	RecoveryLeft  int
	TOTPRequired  bool
	RecoveryCodes []string
	// Calendar feeds, the tags a new one can be limited to, and the URL of
	// one just created, shown this once.
	Calendars []core.Calendar
	Tags      []string
	NewFeed   string
	// API tokens, the roles and lifetimes a new one can have, and the
	// token just created, shown this once.
	Tokens     []auth.APIToken
	TokenRoles []authz.Role
	TokenTTLs  []tokenTTL
	NewToken   string
	TokenError string
}

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	d, err := s.accountData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "account", &Page{Title: "Account", Data: d})
}

func (s *Server) accountData(r *http.Request) (accountData, error) {
	d := accountData{U: user(r)}
	d.MethodName = s.methodName(r, d.U.Method)
	d.TOTPRequired = info(r).settings.SignIn.TOTPRequired(string(d.U.Role))
	var err error
	if d.U.HasTOTP() {
		if d.RecoveryLeft, err = s.Auth.RecoveryCodesLeft(r.Context(), d.U.ID); err != nil {
			return d, err
		}
	}
	if d.Calendars, err = s.Core.Calendars(r.Context(), d.U.ID); err != nil {
		return d, err
	}
	if d.Tokens, err = s.Auth.APITokens(r.Context(), d.U.ID); err != nil {
		return d, err
	}
	for _, role := range authz.Roles {
		if authz.AtMost(role, d.U.Role) {
			d.TokenRoles = append(d.TokenRoles, role)
		}
	}
	d.TokenTTLs = tokenTTLs(d.U.Role)
	ts, err := s.Core.Targets(r.Context())
	if err != nil {
		return d, err
	}
	for _, tc := range core.TagCounts(ts) {
		d.Tags = append(d.Tags, tc.Tag)
	}
	return d, nil
}

// calendarCreate makes a calendar feed and shows its URL once.
func (s *Server) calendarCreate(w http.ResponseWriter, r *http.Request) {
	u := user(r)
	c, token, err := s.Core.CreateCalendar(r.Context(), u.ID, r.PostFormValue("tag"))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	scope := "all targets"
	if c.Tag != "" {
		scope = "tag " + c.Tag
	}
	s.Core.Audit(r.Context(), u.Email, "calendar.create", fmt.Sprintf("calendar %d", c.ID), scope)
	d, err := s.accountData(r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	scheme := "http"
	if info(r).https {
		scheme = "https"
	}
	d.NewFeed = core.CalendarURL(info(r).settings, scheme+"://"+r.Host, token)
	s.render(w, r, "account", &Page{Title: "Account", Data: d})
}

// calendarDelete revokes one of the user's calendar feeds.
func (s *Server) calendarDelete(w http.ResponseWriter, r *http.Request) {
	u := user(r)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such calendar.")
		return
	}
	c, err := s.Core.DeleteCalendar(r.Context(), u.ID, id)
	if err != nil {
		s.failErr(w, r, err, "No such calendar.")
		return
	}
	scope := "all targets"
	if c.Tag != "" {
		scope = "tag " + c.Tag
	}
	s.Core.Audit(r.Context(), u.Email, "calendar.revoke", fmt.Sprintf("calendar %d", c.ID), scope)
	s.back(w, r, "/account", "Calendar feed revoked; its URL no longer works.", "ok")
}

// calendarFeed serves a calendar feed to whoever holds its token.
func (s *Server) calendarFeed(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutSuffix(r.PathValue("file"), ".ics")
	if !ok || token == "" {
		http.NotFound(w, r)
		return
	}
	c, err := s.Core.CalendarByToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		s.serverError(w, r, err)
		return
	}
	body, err := s.Core.CalendarICS(r.Context(), c)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.Header().Set("Cache-Control", "private, max-age=900")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_, _ = w.Write(body)
}

func (s *Server) accountSave(w http.ResponseWriter, r *http.Request) {
	u := user(r)
	theme := r.PostFormValue("theme")
	if err := s.Auth.SetTheme(r.Context(), u.ID, theme); err != nil {
		s.back(w, r, "/account", "Choose system, light or dark.", "crit")
		return
	}
	if name := strings.TrimSpace(r.PostFormValue("name")); name != u.Name {
		if err := s.Auth.SetName(r.Context(), u.ID, name); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	setCookie(w, info(r).https, themeCookie, theme, "/", 365*86400)
	s.back(w, r, "/account", "Account saved.", "ok")
}

// accountTheme sets the theme from the account menu and returns to the page
// it was chosen on.
func (s *Server) accountTheme(w http.ResponseWriter, r *http.Request) {
	theme := r.PostFormValue("theme")
	next := safeNext(r.PostFormValue("next"))
	// A demo visitor is no stored user: the cookie alone remembers it.
	var err error
	if s.Demo {
		if theme != "system" && theme != "light" && theme != "dark" {
			err = errors.New("unknown theme")
		}
	} else {
		err = s.Auth.SetTheme(r.Context(), user(r).ID, theme)
	}
	if err != nil {
		s.back(w, r, next, "Choose system, light or dark.", "crit")
		return
	}
	setCookie(w, info(r).https, themeCookie, theme, "/", 365*86400)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) accountPassword(w http.ResponseWriter, r *http.Request) {
	u := user(r)
	if u.Method != auth.MethodLocal {
		s.fail(w, r, http.StatusBadRequest, "This account signs in with "+s.methodName(r, u.Method)+".")
		return
	}
	fail := func(msg string) {
		d, err := s.accountData(r)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		d.Error = msg
		s.renderStatus(w, r, http.StatusBadRequest, "account", &Page{Title: "Account", Data: d})
	}
	// With TOTP, the right password answers ErrSecondFactor: this session
	// already passed the code.
	if _, err := s.Auth.Login(r.Context(), u.Email, r.PostFormValue("current"), info(r).ip); err != nil && !errors.Is(err, auth.ErrSecondFactor) {
		fail("The current password is incorrect.")
		return
	}
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("password2") {
		fail("The new passwords do not match.")
		return
	}
	if err := s.Auth.CheckPasswordPolicy(pw, u.Email); err != nil {
		fail(err.Error())
		return
	}
	if err := s.Auth.SetPassword(r.Context(), u.ID, pw); err != nil {
		s.serverError(w, r, err)
		return
	}
	// Other sessions end; this one continues with a new token.
	_ = s.Auth.DeleteUserSessions(r.Context(), u.ID)
	s.Core.Audit(r.Context(), u.Email, "user.password", "user "+u.Email, "password changed")
	raw, _, err := s.Auth.NewSession(r.Context(), u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.setSessionCookie(w, r, raw)
	s.back(w, r, "/account", "Password changed. Other sessions were signed out.", "ok")
}
