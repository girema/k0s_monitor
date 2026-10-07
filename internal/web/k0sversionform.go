package web

import (
	"net/http"
	"net/url"
	"strings"

	"k0s_monitor/internal/config"
	"k0s_monitor/internal/engine"
)

// k0sVersionForm is a cluster's setting for the k0s version it should run,
// which the version check (C10) compares every node with.
type k0sVersionForm struct {
	// Editable is true for clusters added in the UI.
	Editable      bool
	Version, From string
	// Running is the version most controllers run: what is expected when
	// none is set.
	Running  string
	Notice   string
	NoticeOK bool
}

func k0sVersionFormOf(c config.Cluster, st *engine.State) k0sVersionForm {
	f := k0sVersionForm{Editable: c.FromUI, Version: c.K0sVersion, From: c.K0sVersionFrom}
	if f.Version != "" && f.From == "" {
		f.From = "the configuration file"
	}
	if st != nil && st.Snapshot != nil {
		snap := *st.Snapshot
		snap.ExpectedK0s = nil
		if v, _, ok := snap.ExpectedVersion(); ok {
			f.Running = v.Raw
		}
	}
	return f
}

// clusterK0sForm sets or clears the k0s version a cluster should run.
func (s *Server) clusterK0sForm(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	c := e.Cluster()
	f := k0sVersionFormOf(c, e.State())
	v := strings.TrimSpace(r.PostFormValue("version"))
	if !c.FromUI {
		f.Notice = "This cluster comes from the configuration file: set k0sVersion for it there and restart the service."
		s.renderClusterSettings(w, r, e, settingsForms{k0s: &f}, http.StatusBadRequest)
		return
	}
	if v != "" && !config.K0sVersionRE.MatchString(v) {
		f.Version, f.Notice = v, "A k0s version looks like v1.36.4+k0s.1."
		s.renderClusterSettings(w, r, e, settingsForms{k0s: &f}, http.StatusBadRequest)
		return
	}
	if v != "" && !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	from := "set in k0s-monitor"
	if v == "" {
		from = ""
	}
	if err := s.o.Store.SetClusterK0sVersion(c.Name, v, from); err != nil {
		f.Notice = "Could not save: " + err.Error()
		s.renderClusterSettings(w, r, e, settingsForms{k0s: &f}, http.StatusInternalServerError)
		return
	}
	c.K0sVersion, c.K0sVersionFrom = v, from
	if _, err := s.o.Fleet.Replace(c); err != nil {
		f.Notice = "Saved, but the cluster could not be restarted: " + err.Error()
		s.renderClusterSettings(w, r, e, settingsForms{k0s: &f}, http.StatusInternalServerError)
		return
	}
	detail := "the version most controllers run"
	if v != "" {
		detail = v
	}
	s.audit(r, "cluster.k0sversion", c.Name+": "+detail)
	http.Redirect(w, r, "/c/"+url.PathEscape(c.Name)+"/settings?saved=k0s#k0s", http.StatusSeeOther)
}
