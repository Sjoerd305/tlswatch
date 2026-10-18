package web

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/sjoerd305/tlswatch/internal/auth"
	"github.com/sjoerd305/tlswatch/internal/authz"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// API tokens under Account: a user makes tokens for the public API with a
// role no higher than their own, sees each once, and revokes them.

// tokenTTL is a lifetime the form offers.
type tokenTTL struct {
	Days  int // 0: never expires
	Label string
}

// tokenTTLs are the lifetimes a user of role can choose: 30 days to a
// year, and for admins no expiry.
func tokenTTLs(role authz.Role) []tokenTTL {
	out := []tokenTTL{{30, "30 days"}, {90, "90 days"}, {180, "180 days"}, {365, "1 year"}}
	if role == authz.Admin {
		out = append(out, tokenTTL{0, "Never"})
	}
	return out
}

func tokenObject(t auth.APIToken) string { return fmt.Sprintf("token %d %s", t.ID, t.Name) }

// tokenCreate makes an API token and shows it once.
func (s *Server) tokenCreate(w http.ResponseWriter, r *http.Request) {
	u := user(r)
	days, err := strconv.Atoi(r.PostFormValue("expiry"))
	if err != nil || days < 0 {
		days = 90
	}
	t, raw, err := s.Auth.CreateAPIToken(r.Context(), u, r.PostFormValue("name"), authz.Role(r.PostFormValue("role")), time.Duration(days)*24*time.Hour)
	d, derr := s.accountData(r)
	if derr != nil {
		s.serverError(w, r, derr)
		return
	}
	if err != nil {
		msg, ok := usererr.Message(err)
		if !ok {
			s.serverError(w, r, err)
			return
		}
		d.TokenError = msg
		s.renderStatus(w, r, http.StatusBadRequest, "account", &Page{Title: "Account", Data: d})
		return
	}
	expiry := "never"
	if t.ExpiresAt > 0 {
		expiry = time.Unix(t.ExpiresAt, 0).UTC().Format("2006-01-02")
	}
	s.Core.Audit(r.Context(), u.Email, "token.create", tokenObject(t), fmt.Sprintf("role=%s expires=%s", t.Role, expiry))
	if d.Tokens, err = s.Auth.APITokens(r.Context(), u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	d.NewToken = raw
	s.render(w, r, "account", &Page{Title: "Account", Data: d})
}

// tokenDelete revokes one of the user's API tokens.
func (s *Server) tokenDelete(w http.ResponseWriter, r *http.Request) {
	u := user(r)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "No such token.")
		return
	}
	t, err := s.Auth.DeleteAPIToken(r.Context(), u.ID, id)
	if err != nil {
		if err == auth.ErrNotFound {
			s.fail(w, r, http.StatusNotFound, "No such token.")
			return
		}
		s.serverError(w, r, err)
		return
	}
	s.Core.Audit(r.Context(), u.Email, "token.revoke", tokenObject(t), "")
	s.back(w, r, "/account#tokens", "API token "+t.Name+" revoked; it no longer works.", "ok")
}
