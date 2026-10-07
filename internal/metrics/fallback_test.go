package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"

	"k0s_monitor/internal/account"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/snapshot"
)

func readyNode(name string) *corev1.Node {
	n := node(name, "10.0.0.1")
	n.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}
	return n
}

// fakeAPI answers the metrics API and the kubelets' summaries.
type fakeAPI struct {
	mu        sync.Mutex
	forbidden bool
	used      float64 // the volume's used bytes
	calls     map[string]int
}

func (f *fakeAPI) get(_ context.Context, path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[path]++
	switch {
	case path == "/apis/metrics.k8s.io/v1beta1/nodes":
		return []byte(`{"items":[{"metadata":{"name":"worker-1"},"usage":{"cpu":"1500m","memory":"6Gi"}},
			{"metadata":{"name":"worker-2"},"usage":{"cpu":"250m","memory":"1Gi"}}]}`), nil
	case strings.HasSuffix(path, "/proxy/stats/summary"):
		if f.forbidden {
			return nil, apierrors.NewForbidden(schema.GroupResource{Resource: "nodes/proxy"}, "worker-1", errors.New("denied"))
		}
		s := map[string]any{
			"node": map[string]any{"fs": map[string]any{"capacityBytes": 100 << 30, "availableBytes": 12 << 30, "inodes": 1000, "inodesFree": 400}},
			"pods": []any{map[string]any{"volume": []any{
				map[string]any{"name": "data", "capacityBytes": 10 << 30, "usedBytes": f.used, "inodes": 100, "inodesUsed": 10,
					"pvcRef": map[string]any{"name": "data-db", "namespace": "shop"}},
				map[string]any{"name": "tmp", "capacityBytes": 1 << 30, "usedBytes": 1},
			}}},
		}
		return json.Marshal(s)
	}
	return nil, fmt.Errorf("unexpected path %s", path)
}

func TestFallbackReads(t *testing.T) {
	api := &fakeAPI{used: 5 << 30}
	clock := now
	fb := newFallback(fake.NewClientset(), func() time.Time { return clock })
	fb.get = api.get
	d := fb.read(context.Background(), []*corev1.Node{readyNode("worker-1"), node("worker-2", "10.0.0.2")}, true, true)

	if u := d.usage["worker-1"]; u.CPUCores != 1.5 || u.MemoryBytes != 6<<30 {
		t.Errorf("usage = %+v", d.usage)
	}
	if !d.kubelet || len(d.volumes) != 1 || len(d.nodeFS) != 1 {
		t.Fatalf("kubelet %v, volumes %v, nodefs %v", d.kubelet, d.volumes, d.nodeFS)
	}
	if api.calls["/api/v1/nodes/worker-2/proxy/stats/summary"] != 0 {
		t.Errorf("a node that is not ready is not asked")
	}
	v := d.volumes["shop/data-db"]
	if v.Used != 5<<30 || v.Capacity != 10<<30 || v.Inodes != 100 || len(v.History) != 1 || v.Growth != nil {
		t.Errorf("volume = %+v", v)
	}
	if fs := d.nodeFS["worker-1"]; fs.Mountpoint != snapshot.K0sDataDir || math.Abs(fs.UsedFraction()-0.88) > 1e-9 {
		t.Errorf("nodefs = %+v", fs)
	}

	// Samples every 5 minutes give a growth after an hour: 60 MiB in each.
	for i := 1; i <= 13; i++ {
		clock = now.Add(time.Duration(i) * sampleEvery)
		api.used += 60 << 20
		d = fb.read(context.Background(), []*corev1.Node{readyNode("worker-1")}, false, true)
	}
	v = d.volumes["shop/data-db"]
	if len(v.History) != 14 || v.Growth == nil || math.Abs(v.Growth.BytesPerHour-720<<20) > 1 || snapshot.Known(v.Growth.BaselineBytesPerHour) {
		t.Fatalf("after an hour: %d samples, growth %+v", len(v.History), v.Growth)
	}
	// A read between samples adds none.
	clock = clock.Add(time.Minute)
	if d = fb.read(context.Background(), []*corev1.Node{readyNode("worker-1")}, false, true); len(d.volumes["shop/data-db"].History) != 14 {
		t.Errorf("sampled too often")
	}
}

func TestFallbackWithoutKubeletAccess(t *testing.T) {
	api := &fakeAPI{forbidden: true}
	clock := now
	fb := newFallback(fake.NewClientset(), func() time.Time { return clock })
	fb.get = api.get
	nodes := []*corev1.Node{readyNode("worker-1")}
	d := fb.read(context.Background(), nodes, true, true)
	if d.kubelet || d.noKubelet != notAllowed || len(d.usage) != 2 {
		t.Fatalf("kubelet %v (%s), usage %v", d.kubelet, d.noKubelet, d.usage)
	}
	// Refused kubelets are asked again only after 5 minutes.
	clock = now.Add(time.Minute)
	fb.read(context.Background(), nodes, false, true)
	if n := api.calls["/api/v1/nodes/worker-1/proxy/stats/summary"]; n != 1 {
		t.Errorf("asked %d times within 5 minutes", n)
	}
	clock = now.Add(6 * time.Minute)
	fb.read(context.Background(), nodes, false, true)
	if n := api.calls["/api/v1/nodes/worker-1/proxy/stats/summary"]; n != 2 {
		t.Errorf("asked %d times after 5 minutes", n)
	}
}

func TestMergeKeepsPrometheusValues(t *testing.T) {
	w1 := snapshot.NewNodeMetrics("10.0.0.1:9100")
	w1.Up = true
	base := &snapshot.Metrics{At: now, Have: map[string]bool{"node-exporter": true, "kubelet-volumes": true},
		Nodes:   map[string]*snapshot.NodeMetrics{"worker-1": w1},
		Volumes: map[string]*snapshot.VolumeMetrics{"shop/data": {Used: 1, Capacity: 2}}}
	d := fallbackData{kubelet: true,
		usage:   map[string]snapshot.NodeUsage{"worker-2": {CPUCores: 1}},
		volumes: map[string]*snapshot.VolumeMetrics{"shop/other": {Used: 1, Capacity: 2}},
		nodeFS:  map[string]*snapshot.Filesystem{"worker-1": {Size: 10, Avail: 1}, "worker-2": {Mountpoint: snapshot.K0sDataDir, Size: 10, Avail: 5}}}
	m, used := merge(base, d, now)
	if m.Nodes["worker-1"] != w1 || m.Nodes["worker-2"] == nil || len(base.Nodes) != 1 {
		t.Errorf("nodes: merged %v, base %v", m.Nodes, base.Nodes)
	}
	if m.Volumes["shop/data"] == nil || m.Volumes["shop/other"] != nil {
		t.Errorf("Prometheus volumes win: %v", m.Volumes)
	}
	if strings.Join(used, "; ") != "node CPU and memory from the metrics API; node disk usage from the kubelets" || !m.Have["kubelet-nodefs"] || base.Have["kubelet-nodefs"] {
		t.Errorf("used %v, have %v", used, m.Have)
	}
	if m2, _ := merge(nil, fallbackData{}, now); m2 != nil {
		t.Errorf("nothing to merge gives no metrics")
	}
}

func TestSourceFallsBackWithoutPrometheus(t *testing.T) {
	api := &fakeAPI{used: 5 << 30}
	src := NewSource(fake.NewClientset(), nil, func() time.Time { return now })
	src.fb.get = api.get
	src.Update(context.Background(), nil, []*corev1.Node{readyNode("worker-1")})
	m, st := src.Latest()
	if st.State != "not-found" || m == nil || !m.Have["kubelet-volumes"] || m.Volumes["shop/data-db"] == nil || m.NodeUsage["worker-1"].CPUCores != 1.5 {
		t.Fatalf("status %+v, metrics %+v", st, m)
	}
	if len(st.Fallbacks) != 3 || st.FallbackHint != "" {
		t.Errorf("fallbacks %v, hint %q", st.Fallbacks, st.FallbackHint)
	}
	if fs, ok := m.Nodes["worker-1"].KubeletFilesystem(); !ok || fs.Size != 100<<30 {
		t.Errorf("nodefs = %+v", m.Nodes["worker-1"])
	}

	// Without the permission, the status says how to grant it.
	api.forbidden = true
	src = NewSource(fake.NewClientset(), nil, func() time.Time { return now })
	src.fb.get = api.get
	src.Update(context.Background(), nil, []*corev1.Node{readyNode("worker-1")})
	m, st = src.Latest()
	if st.FallbackHint != account.KubeletStatsCommands || m == nil || m.Have["kubelet-volumes"] || len(m.NodeUsage) != 2 {
		t.Errorf("hint %q, metrics %+v", st.FallbackHint, m)
	}
}

// A node-exporter at the entered address, and VictoriaMetrics next to it.
func TestNearby(t *testing.T) {
	exporter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><head><title>Node Exporter</title></head></html>`))
	}))
	defer exporter.Close()
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"1"]}]}}`))
	}))
	defer vm.Close()
	_, vmPort, _ := net.SplitHostPort(strings.TrimPrefix(vm.URL, "http://"))
	_, exPort, _ := net.SplitHostPort(strings.TrimPrefix(exporter.URL, "http://"))
	saved := nearbyPorts
	nearbyPorts = []string{":" + exPort, ":" + vmPort}
	defer func() { nearbyPorts = saved }()

	st := Check(context.Background(), fake.NewClientset(), &config.Prometheus{URL: exporter.URL}, nil)
	if st.State == "ok" || !strings.Contains(st.Message, "is node-exporter") || !strings.Contains(st.Hint, "8428") {
		t.Errorf("status = %+v", st)
	}
	// The entered address itself is not suggested again.
	if got := Nearby(context.Background(), exporter.URL); len(got) != 1 || got[0] != "http://127.0.0.1:"+vmPort {
		t.Errorf("nearby = %v", got)
	}
}
