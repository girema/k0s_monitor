package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"k0s_monitor/internal/config"
	"k0s_monitor/internal/store"
)

// fakeVM answers the Prometheus query API like a VictoriaMetrics does.
func fakeVM(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" && r.URL.Path != "/api/v1/query_range" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		result := `[]`
		if strings.Contains(r.URL.Query().Get("query"), "vector(1)") {
			result = `[{"metric":{},"value":[1790517600,"1"]}]`
		}
		// VictoriaMetrics adds fields Prometheus doesn't have.
		w.Write([]byte(`{"status":"success","isPartial":false,"data":{"resultType":"vector","result":` + result + `},"stats":{"seriesFetched":"1"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (env *testEnv) postForm(path string, form url.Values) (int, string) {
	env.t.Helper()
	form.Set("csrf", env.csrf)
	resp := env.do("POST", path, strings.NewReader(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin"})
	body := readBody(env.t, resp)
	if resp.StatusCode == http.StatusSeeOther {
		body = resp.Header.Get("Location")
	}
	return resp.StatusCode, body
}

func TestMetricsSourceForm(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	vm := fakeVM(t)

	// The page offers the form; edge-prod comes from the configuration.
	resp := env.do("GET", "/c/edge-prod/settings?mode=full", nil, nil)
	mustContain(t, readBody(t, resp), "Metrics source", "comes from the configuration file", "Found automatically")

	for _, c := range []struct {
		form url.Values
		want string
	}{
		{url.Values{"mode": {"url"}, "url": {"10.0.0.5:8428"}, "action": {"test"}}, "Enter the address as http://host:port"},
		{url.Values{"mode": {"url"}, "url": {"http://admin:secret@10.0.0.5:8428"}, "action": {"test"}}, "can&#39;t hold a user name or password"},
		{url.Values{"mode": {"url"}, "url": {"http://10.0.0.5:9100/metrics"}, "action": {"test"}}, "exporter&#39;s metrics page"},
		{url.Values{"mode": {"service"}, "service": {"prometheus:9090"}, "action": {"test"}}, "namespace/name:port"},
	} {
		if code, body := env.postForm("/c/edge-prod/settings/metrics", c.form); code != http.StatusBadRequest || !strings.Contains(body, c.want) {
			t.Errorf("%v: %d, want %q", c.form, code, c.want)
		}
	}

	// Testing an address reads it once and says what it holds.
	code, body := env.postForm("/c/edge-prod/settings/metrics", url.Values{"mode": {"url"}, "url": {vm.URL}, "action": {"test"}})
	if code != http.StatusOK || !strings.Contains(body, "It answers: "+vm.URL) || !strings.Contains(body, "node-exporter on 0 of") {
		t.Errorf("test: %d\n%s", code, body)
	}
	if code, body := env.postForm("/c/edge-prod/settings/metrics", url.Values{"mode": {"url"}, "url": {"http://127.0.0.1:1"}, "action": {"test"}}); code != http.StatusOK || !strings.Contains(body, "No answer.") {
		t.Errorf("test of a closed port: %d", code)
	}
	// An address that is node-exporter says so.
	exporter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html lang="en"><head><title>Node Exporter</title></head></html>`))
	}))
	defer exporter.Close()
	if code, body := env.postForm("/c/edge-prod/settings/metrics", url.Values{"mode": {"url"}, "url": {exporter.URL}, "action": {"test"}}); code != http.StatusOK || !strings.Contains(body, "is node-exporter") {
		t.Errorf("test of a node-exporter: %d", code)
	}
	// A cluster from the configuration file can't be changed here.
	if code, body := env.postForm("/c/edge-prod/settings/metrics", url.Values{"mode": {"url"}, "url": {vm.URL}, "action": {"save"}}); code != http.StatusBadRequest || !strings.Contains(body, "configuration file") {
		t.Errorf("save for a configured cluster: %d", code)
	}

	// A cluster added in the UI keeps the setting and restarts with it.
	ui := config.Cluster{Name: "lab", KubeconfigData: []byte("unused"), FromUI: true}
	if err := env.st.SaveCluster(store.StoredCluster{Cluster: ui, Account: "readonly"}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.fleet.Add(ui); err != nil {
		t.Fatal(err)
	}
	code, loc := env.postForm("/c/lab/settings/metrics", url.Values{"mode": {"url"}, "url": {vm.URL}, "action": {"save"}})
	if code != http.StatusSeeOther || loc != "/c/lab/settings?saved=metrics#metrics" {
		t.Fatalf("save: %d %s", code, loc)
	}
	stored, _ := env.st.Clusters()
	if len(stored) != 1 || stored[0].Cluster.Prometheus == nil || stored[0].Cluster.Prometheus.URL != vm.URL {
		t.Errorf("stored: %+v", stored)
	}
	e := env.fleet.Get("lab")
	if p := e.Cluster().Prometheus; p == nil || p.URL != vm.URL {
		t.Errorf("the engine runs with %+v", p)
	}
	deadline := time.Now().Add(10 * time.Second)
	for e.State().Info == nil || e.State().Info.Prometheus == nil || e.State().Info.Prometheus.State != "ok" {
		if time.Now().After(deadline) {
			t.Fatalf("the restarted engine doesn't read %s: %+v", vm.URL, e.State().Info)
		}
		time.Sleep(20 * time.Millisecond)
	}
	resp = env.do("GET", "/c/lab/settings?saved=metrics", nil, nil)
	mustContain(t, readBody(t, resp), "Saved. The cluster was restarted", `value="`+vm.URL+`"`)
	if log, _ := env.st.AuditLog(1); len(log) != 1 || log[0].Action != "cluster.metrics" || log[0].Detail != "lab: "+vm.URL {
		t.Errorf("audit = %+v", log)
	}

	// Back to automatic.
	if code, _ := env.postForm("/c/lab/settings/metrics", url.Values{"mode": {"auto"}, "action": {"save"}}); code != http.StatusSeeOther {
		t.Errorf("save auto: %d", code)
	}
	if stored, _ := env.st.Clusters(); stored[0].Cluster.Prometheus != nil {
		t.Errorf("automatic is stored as no setting: %+v", stored[0].Cluster.Prometheus)
	}
}
