package metrics

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	restclient "k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"k0s_monitor/internal/prom"
)

type wrapper struct {
	b   []byte
	err error
}

func (w wrapper) DoRaw(context.Context) ([]byte, error) { return w.b, w.err }
func (w wrapper) Stream(context.Context) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(string(w.b))), w.err
}

func TestSourceFindsForbiddenThenReads(t *testing.T) {
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "monitoring", Name: "prometheus-k8s"},
		Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "web", Port: 9090}}}}
	cs := fake.NewClientset(svc)
	allowed := false
	var proxied []string
	fp := &fakeProm{instant: map[string][]prom.Sample{}}
	cs.Fake.AddProxyReactor("services", func(a k8stesting.Action) (bool, restclient.ResponseWrapper, error) {
		pa := a.(k8stesting.ProxyGetAction)
		proxied = append(proxied, pa.GetNamespace()+"/"+pa.GetScheme()+":"+pa.GetName()+":"+pa.GetPort()+"/"+pa.GetPath())
		if !allowed {
			return true, wrapper{err: apierrors.NewForbidden(schema.GroupResource{Resource: "services/proxy"}, pa.GetName(), nil)}, nil
		}
		b, err := fp.get(context.Background(), pa.GetPath(), pa.GetParams())
		return true, wrapper{b: b, err: err}, nil
	})
	src := NewSource(cs, nil, func() time.Time { return now })
	nodes := []*corev1.Node{node("worker-1", "10.0.0.1")}

	src.Update(context.Background(), []*corev1.Service{svc}, nodes)
	m, st := src.Latest()
	if m != nil || st.State != "forbidden" || !strings.Contains(st.Hint, "--resource-name=http:prometheus-k8s:9090") ||
		!strings.Contains(st.Hint, "kubectl -n monitoring create rolebinding k0s-monitor:prometheus") {
		t.Fatalf("status = %+v", st)
	}
	if proxied[0] != "monitoring/http:prometheus-k8s:9090/api/v1/query" {
		t.Errorf("proxied = %v", proxied)
	}

	// After access is granted, the next look (5 min later) reads metrics.
	allowed = true
	src.now = func() time.Time { return now.Add(6 * time.Minute) }
	src.Update(context.Background(), []*corev1.Service{svc}, nodes)
	m, st = src.Latest()
	if m == nil || st.State != "ok" || st.Target != "monitoring/prometheus-k8s:9090 (service proxy)" || st.NodesTotal != 1 {
		t.Fatalf("status = %+v, metrics %v", st, m)
	}
	if st.Message != "node-exporter on 0 of 1 nodes, no volume usage (kubelet metrics missing)" {
		t.Errorf("message = %q", st.Message)
	}
}

func TestSourceNotFound(t *testing.T) {
	src := NewSource(fake.NewClientset(), nil, nil)
	src.Update(context.Background(), nil, nil)
	if _, st := src.Latest(); st.State != "not-found" || !strings.Contains(st.Hint, "Metrics source") || !strings.Contains(st.Hint, "vmsingle") {
		t.Errorf("status = %+v", st)
	}
}
