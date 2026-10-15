package web

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sjoerd305/tlswatch/internal/backup"
	"github.com/sjoerd305/tlswatch/internal/usererr"
)

// maxBackup is the largest backup accepted for a restore.
const maxBackup = 1 << 30

// transferTime is how long a backup download or upload may take, beyond
// the server's normal request timeouts.
const transferTime = 30 * time.Minute

type backupData struct {
	Error        string // of the download form
	RestoreError string
	DBPath       string
	MinLength    int
}

func (s *Server) backupPage(w http.ResponseWriter, r *http.Request, status int, d backupData) {
	d.DBPath, d.MinLength = s.Core.DB.Path, backup.MinPassphrase
	s.settingsPage(w, r, status, "settings-backup", "backup", "Settings", d)
}

func (s *Server) settingsBackup(w http.ResponseWriter, r *http.Request) {
	s.backupPage(w, r, http.StatusOK, backupData{})
}

// backupDownload streams an encrypted backup. A failure after the first
// bytes leaves a file without its last chunk, which does not restore.
func (s *Server) backupDownload(w http.ResponseWriter, r *http.Request) {
	pass := r.PostFormValue("passphrase")
	if err := backup.CheckPassphrase(pass, r.PostFormValue("passphrase2")); err != nil {
		msg, _ := usererr.Message(err)
		s.backupPage(w, r, http.StatusBadRequest, backupData{Error: msg})
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(s.now().Add(transferTime))
	now := s.now()
	name := fmt.Sprintf("tlswatch-%s.backup", now.In(info(r).settings.Location()).Format("2006-01-02-1504"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	s.Core.Audit(r.Context(), user(r).Email, "backup.download", "backup", name)
	if err := backup.Write(r.Context(), w, s.Core.DB, s.Key, pass, s.Version, now); err != nil {
		s.Log.Error("backup download", "request_id", info(r).id, "err", err)
	}
}

// backupRestore restores an uploaded backup from Settings › Backup.
func (s *Server) backupRestore(w http.ResponseWriter, r *http.Request) {
	if err := s.restoreUpload(w, r, false); err != nil {
		if msg, ok := s.restoreError(w, r, err); ok {
			s.backupPage(w, r, http.StatusBadRequest, backupData{RestoreError: msg})
		}
		return
	}
	s.restored(w, r)
}

// setupRestore restores an uploaded backup on the setup screen, so a new
// installation takes over from an old one without a throwaway admin. Like
// the setup form, it is open only while no account exists.
func (s *Server) setupRestore(w http.ResponseWriter, r *http.Request) {
	if !s.needsSetup(r) {
		s.back(w, r, "/login", "tlswatch is already set up. Sign in to restore a backup under Settings › Backup.", "info")
		return
	}
	if err := s.restoreUpload(w, r, true); err != nil {
		if msg, ok := s.restoreError(w, r, err); ok {
			s.renderStatus(w, r, http.StatusBadRequest, "setup", &Page{Title: "Set up tlswatch", Data: setupData{RestoreError: msg}})
		}
		return
	}
	s.restored(w, r)
}

// restored ends the request after a restore: every session was ended, so
// the user signs in again with an account from the backup.
func (s *Server) restored(w http.ResponseWriter, r *http.Request) {
	s.clearCookie(w, sessionCookie, info(r))
	s.back(w, r, "/login", "Backup restored. Sign in with an account from the backup.", "ok")
}

// errSetupDone stops a restore from the setup screen once an account
// exists.
var errSetupDone = usererr.New("tlswatch was set up in the meantime. Sign in to restore a backup under Settings › Backup")

// restoreError turns a restore error into the message for the form, or
// answers the request itself.
func (s *Server) restoreError(w http.ResponseWriter, r *http.Request, err error) (string, bool) {
	if mbe := (*http.MaxBytesError)(nil); errors.As(err, &mbe) {
		return fmt.Sprintf("The file is too large (%d MB at most).", maxBackup>>20), true
	}
	if errors.Is(err, errCSRF) {
		s.fail(w, r, http.StatusForbidden, "The form has expired. Reload the page and try again.")
		return "", false
	}
	if msg, ok := usererr.Message(err); ok {
		return msg + ".", true
	}
	s.serverError(w, r, err)
	return "", false
}

var errCSRF = errors.New("csrf")

// restoreUpload reads the restore form as a stream, in its field order
// (csrf, passphrase, confirm, then the file), and restores the file.
func (s *Server) restoreUpload(w http.ResponseWriter, r *http.Request, setup bool) error {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(s.now().Add(transferTime))
	_ = rc.SetWriteDeadline(s.now().Add(transferTime))
	mr, err := r.MultipartReader()
	if err != nil {
		return usererr.New("The form could not be read")
	}
	fields := map[string]string{}
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return usererr.New("Choose a backup file")
		}
		if err != nil {
			return err
		}
		name := part.FormName()
		if name != "file" {
			b, err := io.ReadAll(io.LimitReader(part, 4<<10))
			if err != nil {
				return err
			}
			fields[name] = string(b)
			continue
		}
		if !csrfMatch(r, info(r), fields["csrf"]) {
			return errCSRF
		}
		if !setup && fields["confirm"] != "1" {
			return usererr.New("Confirm that the restore replaces everything in tlswatch")
		}
		if part.FileName() == "" {
			return usererr.New("Choose a backup file")
		}
		return s.restore(r, part, fields["passphrase"], setup)
	}
}

// restore checks the upload, then replaces the database while checks,
// housekeeping and alert delivery are paused, and drops what was kept in
// memory about the old one.
func (s *Server) restore(r *http.Request, file io.Reader, pass string, setup bool) error {
	if !s.restoring.TryLock() {
		return usererr.New("Another restore is running")
	}
	defer s.restoring.Unlock()
	res, err := backup.Open(r.Context(), file, s.Core.DB, s.Key, pass)
	if err != nil {
		return err
	}
	defer res.Close()

	// Once the upload is in, finish even if the browser goes away.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Minute)
	defer cancel()
	if err := s.Sched.Pause(ctx); err != nil {
		return err
	}
	release := s.Dispatch.Hold()
	var guard func(context.Context, *sql.Conn) error
	if setup {
		guard = func(ctx context.Context, c *sql.Conn) error {
			var n int
			if err := c.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return errSetupDone
			}
			return nil
		}
	}
	err = s.Core.DB.Restore(ctx, res.Path, guard)
	s.Settings.Invalidate()
	s.Core.ForgetBundles()
	s.Auth.Forget()
	release()
	s.Sched.Resume(ctx, err == nil)
	if err != nil {
		return err
	}

	who, detail := "setup", "on the setup screen"
	if u := info(r).session; u != nil && !setup {
		who, detail = u.User.Email, "under Settings › Backup"
	}
	if m := res.Manifest; m != nil {
		detail += fmt.Sprintf("; backup of %s by tlswatch %s", time.Unix(m.Created, 0).UTC().Format(time.RFC3339), m.Version)
	} else {
		detail += "; plain database copy"
	}
	s.Core.Audit(ctx, who, "backup.restore", "backup", detail)
	s.Log.Info("backup restored", "request_id", info(r).id, "by", who, "ip", info(r).ip, "detail", strings.TrimPrefix(detail, "; "))
	return nil
}
