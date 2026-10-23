package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sjoerd305/tlswatch/internal/core"
)

// Export and import: Settings › Export downloads the targets and domain
// watches as YAML, and Targets › Add many takes the same document back,
// showing what it would change before anything is saved. See the
// specification, "Export and import".

// uploadedText reads the file chosen on the Add many form, if any. ok is
// false with an empty message when no file was chosen.
func uploadedText(r *http.Request) (text string, ok bool, msg string) {
	if r.MultipartForm == nil || len(r.MultipartForm.File["file"]) == 0 {
		return "", false, ""
	}
	fh := r.MultipartForm.File["file"][0]
	if fh.Size == 0 {
		return "", false, ""
	}
	f, err := fh.Open()
	if err != nil {
		return "", false, "The file could not be read."
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil || !utf8.Valid(b) {
		return "", false, "The file is not a text file."
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n"), true, ""
}

// importData is the import preview.
type importData struct {
	YAML   string
	Plan   core.ImportPlan
	Digest string
	Remove bool
	Notice string // why the preview is shown again
}

// Of returns the changes of op, of domain watches or of targets.
func (d importData) Of(op string, domains bool) []core.ImportChange {
	var out []core.ImportChange
	for _, c := range d.Plan.Changes {
		if c.Op == op && c.Domain == domains {
			out = append(out, c)
		}
	}
	return out
}

// Nothing reports whether importing the file would change nothing, even
// with removal ticked.
func (d importData) Nothing() bool {
	for _, c := range d.Plan.Changes {
		if c.Op != core.ImportUnchanged {
			return false
		}
	}
	return true
}

// importPreview reads an export document from the Add many form and shows
// what importing it would do; a problem in the file goes back to the form.
func (s *Server) importPreview(w http.ResponseWriter, r *http.Request, f bulkAddForm, remove bool, notice string) {
	plan, err := s.Core.PlanImport(r.Context(), []byte(f.Lines))
	if ie := (*core.ImportError)(nil); errors.As(err, &ie) {
		f.LineErrs = ie.Problems
		s.renderStatus(w, r, http.StatusBadRequest, "targets-bulk-add", &Page{Title: "Add targets", Nav: "targets", Data: f})
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, "targets-import", &Page{Title: "Import", Nav: "targets", Data: importData{YAML: f.Lines, Plan: plan, Digest: plan.Digest(), Remove: remove, Notice: notice}})
}

// targetsImport carries out the import the preview showed, in one
// transaction. When anything changed since the preview, the new preview
// is shown instead.
func (s *Server) targetsImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f := bulkAddForm{targetForm: formFromTarget(core.Target{}), Lines: r.PostFormValue("yaml")}
	f.New = true
	if err := s.formData(ctx, &f.targetForm); err != nil {
		s.serverError(w, r, err)
		return
	}
	remove := r.PostFormValue("remove") == "1"
	plan, err := s.Core.PlanImport(ctx, []byte(f.Lines))
	if err != nil || plan.Digest() != r.PostFormValue("digest") {
		s.importPreview(w, r, f, remove, "Targets or domains changed since the preview. Check what the import does now.")
		return
	}
	u := user(r)
	res, err := s.Core.ApplyImport(ctx, plan, remove, u.Email)
	if err != nil {
		if _, ok := s.formError(w, r, err); ok {
			s.importPreview(w, r, f, remove, "The import failed and nothing was saved: "+err.Error())
		}
		return
	}
	for _, a := range res.Audit {
		s.Core.Audit(ctx, u.Email, a.Action, a.Object, a.Details)
	}
	s.Sched.Reload()
	for _, id := range res.Targets {
		s.Sched.CheckSoon(id)
	}
	for _, id := range res.Domains {
		s.pollDomainSoon(id)
	}
	if res.Added+res.Changed+res.Removed == 0 {
		s.back(w, r, "/targets", "Nothing to import: everything matches the file.", "info")
		return
	}
	s.back(w, r, "/targets", fmt.Sprintf("Imported: %d added, %d changed, %d removed.", res.Added, res.Changed, res.Removed), "ok")
}

// Settings › Export.

type exportData struct {
	Targets, Domains int
}

func (s *Server) settingsExport(w http.ResponseWriter, r *http.Request) {
	ts, err := s.Core.Targets(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	ds, err := s.Core.Domains(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.settingsPage(w, r, http.StatusOK, "settings-export", "export", "Settings", exportData{Targets: len(ts), Domains: len(ds)})
}

func (s *Server) settingsExportYAML(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	b, err := s.Core.Export(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	writeExport(w, b)
}
