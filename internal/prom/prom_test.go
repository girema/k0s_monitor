package prom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	restclient "k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

func TestQueryAndRange(t *testing.T) {
	var gotAuth, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotQuery = r.URL.Query().Get("query")
		switch r.URL.Path {
		case "/prom/api/v1/query":
			if gotQuery == "bad(" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"status":"error","errorType":"bad_data","error":"parse error"}`))
				return
			}
			w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
				{"metric":{"instance":"10.0.0.1:9100"},"value":[1790000000,"0.25"]},
				{"metric":{"instance":"10.0.0.2:9100"},"value":[1790000000,"NaN"]}]}}`))
		case "/prom/api/v1/query_range":
			w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[
				{"metric":{"persistentvolumeclaim":"data"},"values":[[1790000600,"20"],[1790000000,"10"]]}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c, err := NewURL(Target{URL: srv.URL + "/prom/"}, Auth{BearerToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	ss, err := c.Query(context.Background(), "up", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ss) != 1 || ss[0].Value != 0.25 || ss[0].Labels["instance"] != "10.0.0.1:9100" {
		t.Errorf("samples = %+v (NaN values are dropped)", ss)
	}
	if gotAuth != "Bearer tok" || gotQuery != "up" {
		t.Errorf("auth %q, query %q", gotAuth, gotQuery)
	}
	series, err := c.QueryRange(context.Background(), "x", time.Unix(1790000000, 0), time.Unix(1790000600, 0), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 1 || len(series[0].Points) != 2 || series[0].Points[0].V != 10 {
		t.Errorf("series = %+v (points sorted by time)", series)
	}
	_, err = c.Query(context.Background(), "bad(", time.Time{})
	if perr, ok := err.(*Error); !ok || perr.Type != "bad_data" {
		t.Errorf("error = %v", err)
	}
}

func TestDiscover(t *testing.T) {
	svc := func(ns, name string, labels map[string]string, ports ...corev1.ServicePort) *corev1.Service {
		return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels}, Spec: corev1.ServiceSpec{Ports: ports}}
	}
	web := corev1.ServicePort{Name: "web", Port: 9090}
	got := Discover([]*corev1.Service{
		svc("monitoring", "alertmanager-operated", nil, corev1.ServicePort{Name: "web", Port: 9093}),
		svc("monitoring", "prometheus-node-exporter", map[string]string{"app.kubernetes.io/name": "prometheus"}, corev1.ServicePort{Port: 9100}),
		svc("monitoring", "prometheus-server", nil, corev1.ServicePort{Name: "http", Port: 80}),
		svc("monitoring", "prometheus-operated", map[string]string{"operated-prometheus": "true"},
			corev1.ServicePort{Name: "reloader-web", Port: 8080}, web),
		svc("apps", "shop", nil, corev1.ServicePort{Port: 80}),
	})
	var names []string
	for _, t := range got {
		names = append(names, t.Namespace+"/"+t.Service+":"+t.Port)
	}
	if strings.Join(names, " ") != "monitoring/prometheus-operated:9090 monitoring/prometheus-server:80" {
		t.Errorf("candidates = %v", names)
	}
	if got[0].ProxyName() != "http:prometheus-operated:9090" {
		t.Errorf("proxy name = %s", got[0].ProxyName())
	}
}

func TestDiscoverVictoriaMetrics(t *testing.T) {
	svc := func(ns, name string, labels map[string]string, port int32) *corev1.Service {
		return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels},
			Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "http", Port: port}}}}
	}
	got := Discover([]*corev1.Service{
		svc("vm", "vmagent-main", nil, 8429),
		svc("vm", "vminsert-main", nil, 8480),
		svc("vm", "vmstorage-main", nil, 8482),
		svc("vm", "vmalert-main", nil, 8080),
		svc("vm", "victoria-metrics-operator", nil, 8080),
		svc("kube-system", "victoria-metrics-k8s-stack-kube-scheduler", nil, 10259),
		svc("vm", "vmselect-main", map[string]string{"app.kubernetes.io/name": "vmselect"}, 8481),
		svc("vm", "vmsingle-main", map[string]string{"app.kubernetes.io/name": "vmsingle"}, 8428),
		// Custom names are found by VictoriaMetrics' ports.
		svc("monitoring", "metrics-db", nil, 8428),
		svc("obs", "query", nil, 8481),
		svc("apps", "shop", nil, 8080),
	})
	if len(got) != 4 {
		t.Fatalf("candidates = %+v", got)
	}
	if got[2].Service != "metrics-db" || got[2].Path != "" || got[3].Service != "query" || got[3].Path != "select/0/prometheus" {
		t.Errorf("by port: %+v %+v", got[2], got[3])
	}
	if got[0].Service != "vmsingle-main" || got[0].Port != "8428" || got[0].Path != "" {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Service != "vmselect-main" || got[1].Path != "select/0/prometheus" || got[1].String() != "vm/vmselect-main:8481/select/0/prometheus (service proxy)" {
		t.Errorf("second = %+v (%s)", got[1], got[1])
	}
}

type rawBody []byte

func (b rawBody) DoRaw(context.Context) ([]byte, error) { return b, nil }
func (b rawBody) Stream(context.Context) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(string(b))), nil
}

// A vmselect answers under its path, through the service proxy.
func TestProxyWithPath(t *testing.T) {
	cs := fake.NewClientset()
	var path string
	cs.Fake.AddProxyReactor("services", func(a k8stesting.Action) (bool, restclient.ResponseWrapper, error) {
		path = a.(k8stesting.ProxyGetAction).GetPath()
		return true, rawBody(`{"status":"success","data":{"resultType":"vector","result":[]}}`), nil
	})
	c := NewProxy(cs, Target{Namespace: "vm", Service: "vmselect-main", Scheme: "http", Port: "8481", Path: "select/0/prometheus"})
	if _, err := c.Query(context.Background(), "vector(1)", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if path != "select/0/prometheus/api/v1/query" {
		t.Errorf("path = %q", path)
	}
}

func TestNotQueryAPI(t *testing.T) {
	for body, exporter := range map[string]bool{
		`<html lang="en"><head><title>Node Exporter</title></head><body><a href="/metrics">Metrics</a></body></html>`: true,
		"# HELP node_load1 1m load average.\n# TYPE node_load1 gauge\nnode_load1 0.5\n":                               true,
		`<!doctype html><html><body>Grafana</body></html>`:                                                            false,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		c, _ := NewURL(Target{URL: srv.URL}, Auth{})
		_, err := c.Query(context.Background(), "vector(1)", time.Time{})
		var na *NotQueryAPIError
		if !errors.As(err, &na) || na.Exporter != exporter {
			t.Errorf("%.30q: %v", body, err)
		}
		srv.Close()
	}
}
