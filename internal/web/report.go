package web

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/report"
	"k0s_monitor/internal/version"
)

// The report for support (plan section 10.6). It is prepared on request,
// kept in memory for a while so it can be looked through before it is
// downloaded, and downloaded exactly as previewed.

const (
	reportTTL     = 30 * time.Minute
	maxReports    = 6
	reportTimeout = 90 * time.Second
)

type preparedReport struct {
	id, user, cluster string
	at                time.Time
	r                 *report.Report
}

// buildReport gathers a report for a cluster.
func (s *Server) buildReport(ctx context.Context, e *engine.Engine, o report.Options) *report.Report {
	ctx, cancel := context.WithTimeout(ctx, reportTimeout)
	defer cancel()
	st := e.State()
	conn := e.Conn()
	if st.Status == engine.StatusUnreachable {
		conn = nil
	}
	in := report.Input{State: st, Conn: conn, Tool: version.Version, Host: s.o.Host, Now: s.now(), Options: o}
	set := s.o.Packs.Current()
	if sup, _ := set.Support(e.Name()); sup != nil {
		in.Support = sup.Contact()
		if sup.URL != "" {
			in.Support += ", " + sup.URL
		}
	}
	for _, p := range set.For(e.Name()) {
		in.Packs = append(in.Packs, strings.TrimSpace(p.Name+" "+p.Version))
	}
	return report.Build(ctx, in)
}

// keepReport stores a prepared report and returns its ID; the oldest go
// when there are too many.
func (s *Server) keepReport(user, cluster string, r *report.Report) string {
	s.reportsMu.Lock()
	defer s.reportsMu.Unlock()
	s.expireReports()
	if len(s.reports) >= maxReports {
		var oldest *preparedReport
		for _, p := range s.reports {
			if oldest == nil || p.at.Before(oldest.at) {
				oldest = p
			}
		}
		delete(s.reports, oldest.id)
	}
	id := randomToken()
	s.reports[id] = &preparedReport{id: id, user: user, cluster: cluster, at: s.now(), r: r}
	return id
}

func (s *Server) expireReports() {
	for id, p := range s.reports {
		if s.now().Sub(p.at) > reportTTL {
			delete(s.reports, id)
		}
	}
}

// preparedFor returns a prepared report of the request's cluster that the
// signed-in user prepared, or nil.
func (s *Server) preparedFor(r *http.Request, id string) *preparedReport {
	s.reportsMu.Lock()
	defer s.reportsMu.Unlock()
	s.expireReports()
	p := s.reports[id]
	if p == nil || p.cluster != r.PathValue("cluster") || p.user != sessionUser(r) {
		return nil
	}
	return p
}

func sessionUser(r *http.Request) string {
	if sess := sessionOf(r); sess != nil {
		return sess.User
	}
	return ""
}

func reportOptions(get func(string) string, form bool) report.Options {
	if form {
		return report.Options{MaskIPs: get("maskIPs") != "", Logs: get("logs") != "", Suggestions: get("suggestions") != ""}
	}
	o := report.DefaultOptions
	flag := func(name string, v *bool) {
		switch strings.ToLower(get(name)) {
		case "true", "1", "yes", "on":
			*v = true
		case "false", "0", "no", "off":
			*v = false
		}
	}
	flag("maskIPs", &o.MaskIPs)
	flag("logs", &o.Logs)
	flag("suggestions", &o.Suggestions)
	return o
}

type reportData struct {
	Cluster     string
	Support     string
	Unreachable bool
	Options     report.Options
	ID          string
	Report      *report.Report
	Size        string
	Expires     string
	Groups      []reportGroup
	Error       string
}

type reportGroup struct {
	Title string
	Files []report.File
}

func sizeText(n int) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%.0f KB", float64(n)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
}

// groupFiles sorts a report's files for the preview.
func groupFiles(fs []report.File) []reportGroup {
	gs := []reportGroup{{Title: "Summary"}, {Title: "Cluster"}, {Title: "Describe output"}, {Title: "Logs"}}
	for _, f := range fs {
		switch {
		case f.Path == "index.html" || f.Path == "README.txt":
			gs[0].Files = append(gs[0].Files, f)
		case strings.HasPrefix(f.Path, "describe/"):
			gs[2].Files = append(gs[2].Files, f)
		case strings.HasPrefix(f.Path, "logs/"):
			gs[3].Files = append(gs[3].Files, f)
		default:
			gs[1].Files = append(gs[1].Files, f)
		}
	}
	out := gs[:0]
	for _, g := range gs {
		if len(g.Files) > 0 {
			out = append(out, g)
		}
	}
	return out
}

func (s *Server) reportPage(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	st := e.State()
	d := reportData{Cluster: e.Name(), Unreachable: st.Status == engine.StatusUnreachable, Options: report.DefaultOptions}
	if sup, _ := s.o.Packs.Current().Support(e.Name()); sup != nil {
		d.Support = sup.Contact()
	}
	if id := r.URL.Query().Get("id"); id != "" {
		if p := s.preparedFor(r, id); p != nil {
			d.ID, d.Report, d.Options = id, p.r, p.r.Options
			d.Size = sizeText(p.r.Size())
			d.Expires = p.at.Add(reportTTL).Format("15:04")
			d.Groups = groupFiles(p.r.Files)
		} else {
			d.Error = "That report is gone: prepared reports are kept for 30 minutes. Prepare it again."
		}
	}
	nav := navOf(st)
	s.render(w, r, "report", &page{Title: "Report for support", Nav: "report", Cluster: &nav, Data: d})
}

func (s *Server) reportForm(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	o := reportOptions(r.PostFormValue, true)
	rep := s.buildReport(r.Context(), e, o)
	id := s.keepReport(sessionUser(r), e.Name(), rep)
	s.audit(r, "report.prepare", fmt.Sprintf("%s: %d files, IP addresses %s", e.Name(), len(rep.Files), map[bool]string{true: "masked", false: "shown"}[o.MaskIPs]))
	http.Redirect(w, r, fmt.Sprintf("/c/%s/report?id=%s", e.Name(), id), http.StatusSeeOther)
}

func (s *Server) writeReportZip(w http.ResponseWriter, rep *report.Report) {
	var buf bytes.Buffer
	if err := rep.Zip(&buf); err != nil {
		http.Error(w, "The report couldn't be written: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", rep.FileName()))
	h.Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) reportDownload(w http.ResponseWriter, r *http.Request) {
	p := s.preparedFor(r, r.PathValue("id"))
	if p == nil {
		s.notFound(w, r, "That report is gone: prepared reports are kept for 30 minutes. Prepare it again.")
		return
	}
	s.audit(r, "report.download", fmt.Sprintf("%s: %s", p.cluster, p.r.FileName()))
	s.writeReportZip(w, p.r)
}

// reportFile shows one file of a prepared report. The summary is a page of
// its own, without scripts, that the preview frames; the rest is text.
func (s *Server) reportFile(w http.ResponseWriter, r *http.Request) {
	p := s.preparedFor(r, r.PathValue("id"))
	if p == nil {
		http.Error(w, "That report is gone: prepared reports are kept for 30 minutes.", http.StatusNotFound)
		return
	}
	f := p.r.File(r.PathValue("path"))
	if f == nil {
		http.Error(w, "The report has no such file.", http.StatusNotFound)
		return
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	if strings.HasSuffix(f.Path, ".html") {
		// Its own styles only: no scripts, no requests, and only this
		// site may frame it.
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'")
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Content-Type", "text/html; charset=utf-8")
	} else {
		h.Set("Content-Type", "text/plain; charset=utf-8")
	}
	_, _ = w.Write(f.Data)
}

// apiReport returns a report as a zip file, or with ?preview=true what it
// would hold.
func (s *Server) apiReport(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	q := r.URL.Query()
	rep := s.buildReport(r.Context(), e, reportOptions(q.Get, false))
	if p := strings.ToLower(q.Get("preview")); p == "true" || p == "1" {
		writeJSON(w, http.StatusOK, rep)
		return
	}
	s.audit(r, "report.download", fmt.Sprintf("%s: %s (API)", e.Name(), rep.FileName()))
	s.writeReportZip(w, rep)
}
