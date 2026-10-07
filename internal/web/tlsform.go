package web

import (
	"net/http"
	"net/url"

	"k0s_monitor/internal/account"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/engine"
)

// tlsForm is the cluster setting for reading the certificates in TLS
// Secrets, which the app certificate check (X09) needs.
type tlsForm struct {
	// State is "ok", "not allowed", "off", or why they can't be read.
	State string
	// Certs counts the certificates read.
	Certs int
	// Editable is true for clusters added in the UI; On is the setting.
	Editable, On bool
	// Commands grant k0s-monitor's read-only account the permission;
	// Uploaded says the uploaded credentials are used instead.
	Commands string
	Uploaded bool
	Notice   string
	NoticeOK bool
}

func tlsFormOf(c config.Cluster, st *engine.State, accountKind string) tlsForm {
	f := tlsForm{Editable: c.FromUI, On: c.TLSSecretsOn(), Uploaded: accountKind == "uploaded"}
	if st.Info != nil {
		f.State = st.Info.TLSSecrets
	}
	if st.Snapshot != nil {
		f.Certs = len(st.Snapshot.TLSCerts)
	}
	if f.State == "not allowed" && !f.Uploaded {
		f.Commands = account.TLSSecretsCommands
	}
	return f
}

// clusterTLSForm turns reading a cluster's TLS Secrets on or off.
func (s *Server) clusterTLSForm(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	c := e.Cluster()
	on := r.PostFormValue("on") == "1"
	f := tlsFormOf(c, e.State(), "")
	if !c.FromUI {
		f.Notice = "This cluster comes from the configuration file: set readTLSSecrets for it there and restart the service."
		s.renderClusterSettings(w, r, e, settingsForms{tls: &f}, http.StatusBadRequest)
		return
	}
	if err := s.o.Store.SetClusterTLSSecrets(c.Name, on); err != nil {
		f.Notice = "Could not save: " + err.Error()
		s.renderClusterSettings(w, r, e, settingsForms{tls: &f}, http.StatusInternalServerError)
		return
	}
	c.ReadTLSSecrets = nil
	if !on {
		c.ReadTLSSecrets = &on
	}
	if _, err := s.o.Fleet.Replace(c); err != nil {
		f.Notice = "Saved, but the cluster could not be restarted: " + err.Error()
		s.renderClusterSettings(w, r, e, settingsForms{tls: &f}, http.StatusInternalServerError)
		return
	}
	detail := "off"
	if on {
		detail = "on"
	}
	s.audit(r, "cluster.tls-secrets", c.Name+": reading TLS Secrets "+detail)
	http.Redirect(w, r, "/c/"+url.PathEscape(c.Name)+"/settings?saved=tls#tls", http.StatusSeeOther)
}
