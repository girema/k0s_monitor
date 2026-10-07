package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k0s_monitor/internal/account"
	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/conntest"
	"k0s_monitor/internal/importer"
	"k0s_monitor/internal/metrics"
	"k0s_monitor/internal/store"
)

// A draft is an upload that is not saved yet. It stays on the server, so
// credentials are sent once and never back to the browser.
type draft struct {
	id      string
	created time.Time
	result  *importer.Result
	report  *conntest.Report
}

const draftLifetime = 30 * time.Minute

func (s *Server) putDraft(r *importer.Result) *draft {
	s.draftsMu.Lock()
	defer s.draftsMu.Unlock()
	now := s.now()
	for id, d := range s.drafts {
		if now.Sub(d.created) > draftLifetime {
			delete(s.drafts, id)
		}
	}
	// Keep at most a few: one person adds one cluster at a time.
	for len(s.drafts) >= 10 {
		var oldest *draft
		for _, d := range s.drafts {
			if oldest == nil || d.created.Before(oldest.created) {
				oldest = d
			}
		}
		delete(s.drafts, oldest.id)
	}
	d := &draft{id: randomID(), created: now, result: r}
	s.drafts[d.id] = d
	return d
}

func (s *Server) getDraft(id string) *draft {
	s.draftsMu.Lock()
	defer s.draftsMu.Unlock()
	d := s.drafts[id]
	if d == nil || s.now().Sub(d.created) > draftLifetime {
		return nil
	}
	return d
}

func (s *Server) dropDraft(id string) {
	s.draftsMu.Lock()
	defer s.draftsMu.Unlock()
	delete(s.drafts, id)
}

func (s *Server) addClusterPage(w http.ResponseWriter, r *http.Request) {
	data := addClusterData{CanStore: s.o.CanStoreClusters, Full: len(s.o.Fleet.Engines()) >= config.MaxClusters,
		RemoveCommands: account.RemoveCommands}
	s.render(w, r, "addcluster", &page{Title: "Add cluster", Nav: "add", Data: data})
}

type addClusterData struct {
	CanStore       bool
	Full           bool
	RemoveCommands string
}

type importRequest struct {
	Files []importer.Input `json:"files"`
}

type importResponse struct {
	DraftID string           `json:"draftId,omitempty"`
	Result  *importer.Result `json:"result"`
	// Server is the suggested server address when the kubeconfig's one only
	// works on the controller.
	Server string `json:"server,omitempty"`
}

func (s *Server) apiImport(w http.ResponseWriter, r *http.Request) {
	var req importRequest
	if err := readJSON(r, &req, importer.MaxFiles*importer.MaxFileSize+64<<10); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := importer.Detect(req.Files, s.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	out := importResponse{Result: res}
	if res.HasKubeconfig() {
		out.DraftID = s.putDraft(res).id
		if ctx, err := res.Context(""); err == nil && ctx.Loopback && len(res.Servers) > 0 {
			out.Server = res.Servers[0]
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type testRequest struct {
	DraftID string `json:"draftId"`
	Context string `json:"context,omitempty"`
	Server  string `json:"server,omitempty"`
	Proxy   string `json:"proxy,omitempty"`
}

// clusterFromDraft builds the cluster settings to test or save.
func clusterFromDraft(d *draft, name, context, server, proxy string) (config.Cluster, error) {
	kc, err := d.result.Minify(context)
	if err != nil {
		return config.Cluster{}, err
	}
	c := config.Cluster{Name: name, KubeconfigData: kc, Server: strings.TrimSpace(server), Proxy: strings.TrimSpace(proxy), FromUI: true}
	if c.Name == "" {
		c.Name = "draft"
	}
	return c, c.Validate()
}

func (s *Server) apiTest(w http.ResponseWriter, r *http.Request) {
	var req testRequest
	if err := readJSON(r, &req, 16<<10); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	d := s.getDraft(req.DraftID)
	if d == nil {
		writeError(w, http.StatusNotFound, "the upload expired; add the files again")
		return
	}
	c, err := clusterFromDraft(d, "", req.Context, req.Server, req.Proxy)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	rep := s.testConnection(ctx, c, conntest.Options{ExpectedNodes: len(d.result.Workers)})
	d.report = rep
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) testConnection(ctx context.Context, c config.Cluster, o conntest.Options) *conntest.Report {
	if s.o.TestConnection != nil {
		return s.o.TestConnection(ctx, c, o)
	}
	return conntest.Run(ctx, c, o)
}

type addRequest struct {
	DraftID     string `json:"draftId"`
	Name        string `json:"name"`
	Context     string `json:"context,omitempty"`
	Server      string `json:"server,omitempty"`
	Proxy       string `json:"proxy,omitempty"`
	Criticality string `json:"criticality,omitempty"`
	// Account is "readonly" (create k0s-monitor's own read-only account) or
	// "uploaded" (keep the uploaded credentials).
	Account string `json:"account"`
	// TLSSecrets lets the read-only account read Secrets, for the expiry of
	// apps' certificates. Omitted means yes.
	TLSSecrets *bool `json:"tlsSecrets,omitempty"`
}

type addResponse struct {
	Name    string   `json:"name"`
	URL     string   `json:"url"`
	Changed []string `json:"changed,omitempty"`
}

func (s *Server) apiAddCluster(w http.ResponseWriter, r *http.Request) {
	if !s.o.CanStoreClusters {
		writeJSON(w, http.StatusConflict, apiError{Error: "clusters can't be added in the UI: there is no key to encrypt their credentials",
			Hint: "Run k0s-monitor init on the jump host, or list the cluster in the configuration file."})
		return
	}
	var req addRequest
	if err := readJSON(r, &req, 16<<10); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	d := s.getDraft(req.DraftID)
	if d == nil {
		writeError(w, http.StatusNotFound, "the upload expired; add the files again")
		return
	}
	if d.result.Errors() {
		writeError(w, http.StatusBadRequest, "the files have a problem that must be fixed first")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	c, err := clusterFromDraft(d, req.Name, req.Context, req.Server, req.Proxy)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	c.Criticality = req.Criticality
	// The k0s version the product ships, from its k0sctl.yaml.
	if v := strings.TrimSpace(d.result.K0sVersion); v != "" && config.K0sVersionRE.MatchString(v) {
		if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		c.K0sVersion, c.K0sVersionFrom = v, "k0sctl.yaml"
	}
	if err := c.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.o.Fleet.Get(c.Name) != nil {
		writeError(w, http.StatusConflict, fmt.Sprintf("a cluster named %q already exists", c.Name))
		return
	}
	if n := len(s.o.Fleet.Engines()); n >= config.MaxClusters {
		writeError(w, http.StatusConflict, fmt.Sprintf("already %d clusters: one instance is sized for up to %d", n, config.MaxClusters))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	resp := addResponse{Name: c.Name, URL: "/c/" + c.Name}
	switch req.Account {
	case "readonly":
		server := c.Server
		if server == "" {
			if kctx, err := d.result.Context(req.Context); err == nil {
				server = kctx.Server
			}
		}
		res, err := s.createAccount(ctx, c, account.Options{Server: server, CAData: d.result.CAData(req.Context), ClusterName: c.Name,
			TLSSecrets: req.TLSSecrets == nil || *req.TLSSecrets})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "the read-only account could not be created: " + err.Error(),
				Hint: "Check the connection test, or choose to keep the uploaded credentials (Full mode)."})
			return
		}
		ro := c
		ro.KubeconfigData, ro.Server = res.Kubeconfig, ""
		if err := s.verifyAccess(ctx, ro); err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "the new read-only account can't sign in: " + err.Error()})
			return
		}
		c = ro
		resp.Changed = res.Changed
	case "uploaded":
	default:
		writeError(w, http.StatusBadRequest, `account must be "readonly" or "uploaded"`)
		return
	}

	sc := store.StoredCluster{Cluster: c, Account: req.Account, K0sctl: d.result.K0sctl, K0sConfig: d.result.K0sConfig}
	if err := s.o.Store.SaveCluster(sc); err != nil {
		writeError(w, http.StatusInternalServerError, "saving the cluster: "+err.Error())
		return
	}
	if _, err := s.o.Fleet.Add(c); err != nil {
		_ = s.o.Store.DeleteCluster(c.Name)
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.dropDraft(d.id)
	detail := c.Name + " (account: " + req.Account + ")"
	if len(resp.Changed) > 0 {
		detail += "; " + strings.Join(resp.Changed, ", ")
	}
	s.audit(r, "cluster.add", detail)
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) createAccount(ctx context.Context, c config.Cluster, o account.Options) (*account.Result, error) {
	if s.o.CreateAccount != nil {
		return s.o.CreateAccount(ctx, c, o)
	}
	rc, err := cluster.RESTConfig(c)
	if err != nil {
		return nil, err
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, err
	}
	// Let the account read the cluster's Prometheus, if there is one.
	if t, _ := metrics.Find(ctx, cs, c.Prometheus); t != nil && t.URL == "" {
		o.PrometheusNamespace, o.PrometheusProxyName = t.Namespace, t.ProxyName()
	}
	return account.Create(ctx, cs, o)
}

// verifyAccess checks that credentials can read the cluster.
func (s *Server) verifyAccess(ctx context.Context, c config.Cluster) error {
	if s.o.VerifyAccess != nil {
		return s.o.VerifyAccess(ctx, c)
	}
	rc, err := cluster.RESTConfig(c)
	if err != nil {
		return err
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}
	// A new token may take a moment to become valid.
	var lastErr error
	for i := 0; i < 10; i++ {
		vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, lastErr = cs.CoreV1().Pods("").List(vctx, metav1.ListOptions{Limit: 1})
		cancel()
		if lastErr == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return lastErr
}

func (s *Server) apiDeleteCluster(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	if !e.Cluster().FromUI {
		writeError(w, http.StatusConflict, "this cluster is listed in the configuration file; remove it there and restart the service")
		return
	}
	name := e.Name()
	s.o.Fleet.Remove(name)
	if err := s.o.Store.DeleteCluster(name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "cluster.remove", name)
	s.hub.publish("state", name, map[string]string{"cluster": name, "type": "removed"})
	w.WriteHeader(http.StatusNoContent)
}

func randomID() string {
	// Draft IDs are capabilities for the upload: as unguessable as sessions.
	return strings.ReplaceAll(randomToken(), "-", "")
}
