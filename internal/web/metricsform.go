package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/metrics"
)

// metricsForm is the "Metrics source" part of a cluster's settings: where
// its Prometheus or VictoriaMetrics is.
type metricsForm struct {
	Mode    string // auto, url, service or off
	URL     string
	Service string
	// Editable is false for clusters from the configuration file.
	Editable bool
	// Host is the API server's host, for the hint when the metrics run on
	// the controller itself.
	Host string
	// Notice is the result of a test or a save.
	Notice   string
	NoticeOK bool
	Test     *cluster.PrometheusStatus
}

func metricsFormOf(c config.Cluster, st *cluster.Info) metricsForm {
	f := metricsForm{Mode: "auto", Editable: c.FromUI}
	if p := c.Prometheus; p != nil {
		switch {
		case p.Disabled:
			f.Mode = "off"
		case p.URL != "":
			f.Mode, f.URL = "url", p.URL
		case p.Service != "":
			f.Mode, f.Service = "service", p.Service
		}
	}
	if st != nil {
		if u, err := url.Parse(st.Server); err == nil {
			f.Host = u.Hostname()
		}
	}
	return f
}

// prometheusOf turns the form into the setting; nil means automatic.
func (f metricsForm) prometheus() *config.Prometheus {
	switch f.Mode {
	case "url":
		return &config.Prometheus{URL: strings.TrimSpace(f.URL)}
	case "service":
		return &config.Prometheus{Service: strings.TrimSpace(f.Service)}
	case "off":
		return &config.Prometheus{Disabled: true}
	}
	return nil
}

// check says what is wrong with the form, in words.
func (f metricsForm) check(c config.Cluster) string {
	switch f.Mode {
	case "auto", "off":
		return ""
	case "url":
		u, err := url.Parse(strings.TrimSpace(f.URL))
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return "Enter the address as http://host:port or https://host:port, for example http://10.0.0.5:8428."
		}
		if u.User != nil {
			return "The address can't hold a user name or password: they would be stored unencrypted. For metrics that need a password, set the cluster up in the configuration file with passwordFile."
		}
		if strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/metrics") {
			return "That looks like an exporter's metrics page. Enter the address of the Prometheus or VictoriaMetrics that stores the metrics, without /metrics."
		}
	case "service":
		if _, _, _, ok := (&config.Prometheus{Service: f.Service}).ServiceParts(); !ok {
			return "Enter the Service as namespace/name:port, for example monitoring/prometheus-k8s:9090 or vm/vmselect-main:8481/select/0/prometheus."
		}
	default:
		return "Choose where the metrics come from."
	}
	c.Prometheus = f.prometheus()
	if err := c.Validate(); err != nil {
		return err.Error()
	}
	return ""
}

// clusterMetricsForm tests or saves a cluster's metrics source.
func (s *Server) clusterMetricsForm(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	c := e.Cluster()
	st := e.State()
	f := metricsFormOf(c, st.Info)
	f.Mode, f.URL, f.Service = r.PostFormValue("mode"), r.PostFormValue("url"), r.PostFormValue("service")
	action := r.PostFormValue("action")

	if msg := f.check(c); msg != "" {
		f.Notice = msg
		s.renderClusterSettings(w, r, e, settingsForms{metrics: &f}, http.StatusBadRequest)
		return
	}
	if action == "save" {
		if !c.FromUI {
			f.Notice = "This cluster comes from the configuration file: set prometheus there and restart the service."
			s.renderClusterSettings(w, r, e, settingsForms{metrics: &f}, http.StatusBadRequest)
			return
		}
		c.Prometheus = f.prometheus()
		if err := s.o.Store.SetClusterPrometheus(c.Name, c.Prometheus); err != nil {
			f.Notice = "Could not save: " + err.Error()
			s.renderClusterSettings(w, r, e, settingsForms{metrics: &f}, http.StatusInternalServerError)
			return
		}
		if _, err := s.o.Fleet.Replace(c); err != nil {
			f.Notice = "Saved, but the cluster could not be restarted: " + err.Error()
			s.renderClusterSettings(w, r, e, settingsForms{metrics: &f}, http.StatusInternalServerError)
			return
		}
		s.audit(r, "cluster.metrics", c.Name+": "+describeMetrics(c.Prometheus))
		http.Redirect(w, r, "/c/"+url.PathEscape(c.Name)+"/settings?saved=metrics#metrics", http.StatusSeeOther)
		return
	}

	// Test: look for the metrics the way the engine will, with the
	// cluster's own account.
	if f.Mode == "off" {
		f.Notice, f.NoticeOK = "Metrics are turned off: nothing to test.", true
		s.renderClusterSettings(w, r, e, settingsForms{metrics: &f}, http.StatusOK)
		return
	}
	conn := e.Conn()
	if conn == nil {
		f.Notice = "The cluster can't be reached right now, so this can't be tested."
		s.renderClusterSettings(w, r, e, settingsForms{metrics: &f}, http.StatusOK)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	var nodes []*corev1.Node
	if st.Snapshot != nil {
		nodes = st.Snapshot.Nodes
	}
	pst := metrics.Check(ctx, conn.Client, f.prometheus(), nodes)
	f.Test = &pst
	switch {
	case pst.State == "ok":
		f.Notice, f.NoticeOK = "It answers: "+pst.Target+". It has "+pst.Message+". Save to use it.", true
	case f.Mode == "url":
		f.Notice = "No answer. " + pst.Message
		// Look next door: the metrics store often runs on the same host
		// as the exporter that was entered.
		if near := metrics.Nearby(ctx, f.URL); len(near) > 0 {
			f.Notice += " On the same host, " + near[0] + " answers the query API: it is filled in below. Test it, then Save."
			f.URL = near[0]
		} else if pst.Hint != "" {
			f.Notice += " " + pst.Hint
		}
	default:
		f.Notice = "No answer. " + pst.Message
	}
	s.renderClusterSettings(w, r, e, settingsForms{metrics: &f}, http.StatusOK)
}

func describeMetrics(p *config.Prometheus) string {
	switch {
	case p == nil:
		return "found automatically"
	case p.Disabled:
		return "off"
	case p.URL != "":
		return p.URL
	}
	return "service " + p.Service
}
