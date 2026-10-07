package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"k0s_monitor/internal/account"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/conntest"
	"k0s_monitor/internal/importer"
)

const uploadedKubeconfig = `apiVersion: v1
kind: Config
clusters: [{name: local, cluster: {server: "https://localhost:6443"}}]
contexts: [{name: Default, context: {cluster: local, user: user}}]
current-context: Default
users: [{name: user, user: {token: admin-token}}]
`

const k0sctlYAML = `apiVersion: k0sctl.k0sproject.io/v1beta1
kind: Cluster
metadata: {name: retail-us}
spec:
  hosts:
  - {role: controller, ssh: {address: 10.20.0.11}}
  - {role: worker, ssh: {address: 10.20.0.21}}
  k0s: {version: 1.36.4+k0s.1}
`

func jsonBody(v any) *strings.Reader {
	b, _ := json.Marshal(v)
	return strings.NewReader(string(b))
}

func TestAddClusterFlow(t *testing.T) {
	var tested, created config.Cluster
	var createOpts account.Options
	env := newEnv(t, func(o *Options) {
		o.TestConnection = func(_ context.Context, c config.Cluster, co conntest.Options) *conntest.Report {
			tested = c
			return &conntest.Report{OK: true, CanCreateAccount: true, Steps: []conntest.Step{{Name: "Sign in", Status: conntest.Pass}}}
		}
		o.CreateAccount = func(_ context.Context, c config.Cluster, ao account.Options) (*account.Result, error) {
			created, createOpts = c, ao
			return &account.Result{Kubeconfig: []byte("apiVersion: v1\nkind: Config\nusers: [{name: k0s-monitor, user: {token: ro-token}}]\n"),
				Changed: []string{"created ServiceAccount kube-system/k0s-monitor"}}, nil
		}
		o.VerifyAccess = func(context.Context, config.Cluster) error { return nil }
	})
	env.login()
	hdr := map[string]string{"X-CSRF-Token": env.csrf, "Content-Type": "application/json"}

	resp := env.do("POST", "/api/v1/clusters/import", jsonBody(importRequest{Files: []importer.Input{
		{Name: "cluster.config", Content: uploadedKubeconfig}, {Name: "k0sctl.yaml", Content: k0sctlYAML}}}), hdr)
	var imp importResponse
	json.NewDecoder(resp.Body).Decode(&imp)
	resp.Body.Close()
	if imp.DraftID == "" || imp.Result.Name != "retail-us" || imp.Server != "https://10.20.0.11:6443" {
		t.Fatalf("import = %+v", imp)
	}
	if strings.Contains(readBody(t, env.do("GET", "/api/v1/clusters", nil, nil)), "admin-token") {
		t.Error("credentials never go back to the browser")
	}

	resp = env.do("POST", "/api/v1/clusters/test", jsonBody(testRequest{DraftID: imp.DraftID, Server: imp.Server}), hdr)
	if resp.StatusCode != 200 {
		t.Fatalf("test: %d %s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()
	if tested.Server != "https://10.20.0.11:6443" || !strings.Contains(string(tested.KubeconfigData), "admin-token") {
		t.Errorf("tested = %+v", tested)
	}

	resp = env.do("POST", "/api/v1/clusters", jsonBody(addRequest{DraftID: imp.DraftID, Name: "retail-us", Server: imp.Server, Account: "readonly"}), hdr)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add: %d %s", resp.StatusCode, readBody(t, resp))
	}
	var added addResponse
	json.NewDecoder(resp.Body).Decode(&added)
	resp.Body.Close()
	if added.URL != "/c/retail-us" || createOpts.Server != "https://10.20.0.11:6443" || created.Name != "retail-us" {
		t.Errorf("added = %+v, account options = %+v", added, createOpts)
	}
	e := env.fleet.Get("retail-us")
	if e == nil || !e.Cluster().FromUI || !strings.Contains(string(e.Cluster().KubeconfigData), "ro-token") || e.Cluster().Server != "" {
		t.Fatalf("the engine uses the read-only account: %+v", e)
	}
	stored, err := env.st.Clusters()
	if err != nil || len(stored) != 1 || stored[0].Account != "readonly" || strings.Contains(string(stored[0].Cluster.KubeconfigData), "admin-token") ||
		!strings.Contains(string(stored[0].K0sctl), "retail-us") {
		t.Fatalf("stored = %+v %v", stored, err)
	}
	log, _ := env.st.AuditLog(5)
	if log[0].Action != "cluster.add" || !strings.Contains(log[0].Detail, "created ServiceAccount") {
		t.Errorf("audit = %+v", log[0])
	}

	// Its settings page says how to remove the account from the cluster.
	mustContain(t, readBody(t, env.do("GET", "/c/retail-us/settings", nil, nil)), "read-only account stays in the cluster",
		"kubectl delete clusterrolebinding k0s-monitor:reader", "kubectl delete clusterrolebinding,clusterrole k0s-monitor:secrets")
	// Reading TLS Secrets is asked for unless turned off, and can be
	// turned off and on for the cluster.
	if !createOpts.TLSSecrets {
		t.Error("the account was made without reading TLS Secrets")
	}
	mustContain(t, readBody(t, env.do("GET", "/c/retail-us/settings?mode=full", nil, nil)), "what the certificate check (X09) and the Secrets pages read",
		"may read every Secret", "Stop reading Secrets")
	if code, loc := env.postForm("/c/retail-us/settings/tls", url.Values{"on": {"0"}}); code != http.StatusSeeOther || loc != "/c/retail-us/settings?saved=tls#tls" {
		t.Fatalf("turn off: %d %s", code, loc)
	}
	if c := env.fleet.Get("retail-us").Cluster(); c.TLSSecretsOn() {
		t.Error("still reading TLS Secrets")
	}
	if stored, _ := env.st.Clusters(); stored[0].Cluster.TLSSecretsOn() {
		t.Error("stored as reading TLS Secrets")
	}
	if log, _ := env.st.AuditLog(1); log[0].Action != "cluster.tls-secrets" || log[0].Detail != "retail-us: reading TLS Secrets off" {
		t.Errorf("audit = %+v", log[0])
	}
	mustContain(t, readBody(t, env.do("GET", "/c/retail-us/settings?saved=tls", nil, nil)), "Read Secrets again")
	env.postForm("/c/retail-us/settings/tls", url.Values{"on": {"1"}})
	if c := env.fleet.Get("retail-us").Cluster(); !c.TLSSecretsOn() {
		t.Error("not reading TLS Secrets again")
	}

	// The k0s version comes from k0sctl.yaml, and can be changed.
	if c := e.Cluster(); c.K0sVersion != "v1.36.4+k0s.1" || c.K0sVersionFrom != "k0sctl.yaml" || stored[0].Cluster.K0sVersion != "v1.36.4+k0s.1" {
		t.Errorf("k0s version: %q from %q, stored %q", c.K0sVersion, c.K0sVersionFrom, stored[0].Cluster.K0sVersion)
	}
	mustContain(t, readBody(t, env.do("GET", "/c/retail-us/settings?mode=full", nil, nil)), `Expected: <b class="mono">v1.36.4&#43;k0s.1</b> (k0sctl.yaml)`)
	if code, body := env.postForm("/c/retail-us/settings/k0s", url.Values{"version": {"1.37"}}); code != http.StatusBadRequest || !strings.Contains(body, "looks like v1.36.4&#43;k0s.1") {
		t.Errorf("a bad version: %d", code)
	}
	if code, loc := env.postForm("/c/retail-us/settings/k0s", url.Values{"version": {"1.37.0+k0s.0"}}); code != http.StatusSeeOther || loc != "/c/retail-us/settings?saved=k0s#k0s" {
		t.Fatalf("set version: %d %s", code, loc)
	}
	if c := env.fleet.Get("retail-us").Cluster(); c.K0sVersion != "v1.37.0+k0s.0" || c.K0sVersionFrom != "set in k0s-monitor" {
		t.Errorf("after setting: %q from %q", c.K0sVersion, c.K0sVersionFrom)
	}
	if stored, _ := env.st.Clusters(); stored[0].Cluster.K0sVersion != "v1.37.0+k0s.0" {
		t.Errorf("stored after setting: %q", stored[0].Cluster.K0sVersion)
	}
	if log, _ := env.st.AuditLog(1); log[0].Action != "cluster.k0sversion" || log[0].Detail != "retail-us: v1.37.0+k0s.0" {
		t.Errorf("audit = %+v", log[0])
	}
	mustContain(t, readBody(t, env.do("GET", "/c/retail-us/settings?saved=k0s", nil, nil)), "Saved. The version check uses it")
	env.postForm("/c/retail-us/settings/k0s", url.Values{"version": {""}})
	if c := env.fleet.Get("retail-us").Cluster(); c.K0sVersion != "" || c.K0sVersionFrom != "" {
		t.Errorf("cleared: %q from %q", c.K0sVersion, c.K0sVersionFrom)
	}
	// A cluster from the configuration file is set there.
	if code, body := env.postForm("/c/edge-prod/settings/k0s", url.Values{"version": {"v1.36.4+k0s.1"}}); code != http.StatusBadRequest || !strings.Contains(body, "set k0sVersion for it there") {
		t.Errorf("config cluster: %d", code)
	}

	// The draft is used up; the same name can't be added twice.
	resp = env.do("POST", "/api/v1/clusters", jsonBody(addRequest{DraftID: imp.DraftID, Name: "retail-us", Account: "uploaded"}), hdr)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("a used draft: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Removing it deletes what was stored.
	resp = env.do("DELETE", "/api/v1/clusters/retail-us", nil, hdr)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %d %s", resp.StatusCode, readBody(t, resp))
	}
	if env.fleet.Get("retail-us") != nil {
		t.Error("the engine is stopped")
	}
	if cs, _ := env.st.Clusters(); len(cs) != 0 {
		t.Error("the stored cluster is deleted")
	}
	// A cluster from the configuration file can't be removed in the UI.
	resp = env.do("DELETE", "/api/v1/clusters/edge-prod", nil, hdr)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("config cluster delete: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAddClusterUploadedCredentials(t *testing.T) {
	env := newEnv(t, func(o *Options) {
		o.CreateAccount = func(context.Context, config.Cluster, account.Options) (*account.Result, error) {
			t.Error("no account is created when the uploaded credentials are kept")
			return nil, nil
		}
	})
	env.login()
	hdr := map[string]string{"X-CSRF-Token": env.csrf}
	kc := strings.Replace(uploadedKubeconfig, "https://localhost:6443", "https://10.20.0.11:6443", 1)
	resp := env.do("POST", "/api/v1/clusters/import", jsonBody(importRequest{Files: []importer.Input{{Content: kc}}}), hdr)
	var imp importResponse
	json.NewDecoder(resp.Body).Decode(&imp)
	resp.Body.Close()
	if imp.Server != "" {
		t.Errorf("no replacement address for a reachable server: %q", imp.Server)
	}
	resp = env.do("POST", "/api/v1/clusters", jsonBody(addRequest{DraftID: imp.DraftID, Name: "Bad Name", Account: "uploaded"}), hdr)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid name: %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = env.do("POST", "/api/v1/clusters", jsonBody(addRequest{DraftID: imp.DraftID, Name: "lab", Account: "uploaded", Criticality: "low"}), hdr)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add: %d %s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()
	e := env.fleet.Get("lab")
	if e == nil || !strings.Contains(string(e.Cluster().KubeconfigData), "admin-token") || e.Cluster().Criticality != "low" {
		t.Errorf("engine = %+v", e)
	}
}

func TestSwitchToReadOnlyAccount(t *testing.T) {
	var opts account.Options
	var used config.Cluster
	env := newEnv(t, func(o *Options) {
		o.CreateAccount = func(_ context.Context, c config.Cluster, ao account.Options) (*account.Result, error) {
			used, opts = c, ao
			return &account.Result{Kubeconfig: []byte("apiVersion: v1\nkind: Config\nusers: [{name: k0s-monitor, user: {token: ro-token}}]\n"),
				Changed: []string{"created ServiceAccount kube-system/k0s-monitor"}}, nil
		}
		o.VerifyAccess = func(context.Context, config.Cluster) error { return nil }
	})
	env.login()
	hdr := map[string]string{"X-CSRF-Token": env.csrf}
	kc := strings.Replace(uploadedKubeconfig, "https://localhost:6443", "https://10.20.0.11:6443", 1)
	resp := env.do("POST", "/api/v1/clusters/import", jsonBody(importRequest{Files: []importer.Input{{Content: kc}}}), hdr)
	var imp importResponse
	json.NewDecoder(resp.Body).Decode(&imp)
	resp.Body.Close()
	resp = env.do("POST", "/api/v1/clusters", jsonBody(addRequest{DraftID: imp.DraftID, Name: "lab", Account: "uploaded"}), hdr)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add: %d %s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()

	// The page warns, and offers the switch.
	mustContain(t, readBody(t, env.do("GET", "/c/lab/settings?mode=full", nil, nil)),
		"the credentials uploaded with the cluster", "an admin kubeconfig can change anything", "Switch to the read-only account")

	code, loc := env.postForm("/c/lab/settings/account", url.Values{})
	if code != http.StatusSeeOther || loc != "/c/lab/settings?saved=account#account" {
		t.Fatalf("switch: %d %s", code, loc)
	}
	// The checkbox for TLS Secrets was left unticked.
	if !strings.Contains(string(used.KubeconfigData), "admin-token") || opts.Server != "https://10.20.0.11:6443" || opts.ClusterName != "lab" || opts.TLSSecrets {
		t.Errorf("created with %+v from %q", opts, used.KubeconfigData)
	}
	stored, _ := env.st.Clusters()
	if len(stored) != 1 || stored[0].Account != "readonly" || strings.Contains(string(stored[0].Cluster.KubeconfigData), "admin-token") ||
		!strings.Contains(string(stored[0].Cluster.KubeconfigData), "ro-token") {
		t.Errorf("stored = %+v", stored)
	}
	if e := env.fleet.Get("lab"); e == nil || strings.Contains(string(e.Cluster().KubeconfigData), "admin-token") {
		t.Error("the engine still uses the uploaded credentials")
	}
	if log, _ := env.st.AuditLog(1); log[0].Action != "cluster.account" || !strings.Contains(log[0].Detail, "created ServiceAccount") {
		t.Errorf("audit = %+v", log[0])
	}
	body := readBody(t, env.do("GET", "/c/lab/settings?saved=account", nil, nil))
	mustContain(t, body, "k0s-monitor now uses its own read-only account", "k0s-monitor's own read-only account")
	if strings.Contains(body, "Switch to the read-only account") {
		t.Error("nothing to switch any more")
	}
	// Twice is refused, and so is a cluster from the configuration file.
	if code, body := env.postForm("/c/lab/settings/account", url.Values{}); code != http.StatusBadRequest || !strings.Contains(body, "already uses") {
		t.Errorf("again: %d", code)
	}
	if code, _ := env.postForm("/c/edge-prod/settings/account", url.Values{}); code != http.StatusBadRequest {
		t.Errorf("config cluster: %d", code)
	}
}

func TestImportRefusesCommands(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	kc := strings.Replace(uploadedKubeconfig, "{token: admin-token}", "{exec: {apiVersion: client.authentication.k8s.io/v1, command: /bin/sh}}", 1)
	resp := env.do("POST", "/api/v1/clusters/import", jsonBody(importRequest{Files: []importer.Input{{Content: kc}}}), map[string]string{"X-CSRF-Token": env.csrf})
	var imp importResponse
	json.NewDecoder(resp.Body).Decode(&imp)
	resp.Body.Close()
	if imp.DraftID != "" || !strings.Contains(imp.Result.Files[0].Error, "never runs commands") {
		t.Errorf("import = %+v", imp.Result.Files)
	}
}

func TestAddClusterPage(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	body := readBody(t, env.do("GET", "/clusters/add?mode=basic", nil, nil))
	mustContain(t, body, "Add cluster", "Drop files here", "Create a read-only account", "recommended", "/static/addcluster.js", "data-no-refresh")
	body = readBody(t, env.do("GET", "/clusters/add?mode=full", nil, nil))
	mustContain(t, body, "Use the uploaded credentials as they are", "Proxy (optional)", "Criticality", "kubectl delete clusterrolebinding k0s-monitor:reader")
}
