package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k0s_monitor/internal/prom"
)

var now = time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)

// fakeProm answers queries by the first key the query contains.
type fakeProm struct {
	instant map[string][]prom.Sample
	ranges  map[string][]prom.Series
	// alerts is the alerts API's answer; noAlertsAPI makes it fail, as
	// VictoriaMetrics does without vmalert.
	alerts      []map[string]any
	noAlertsAPI bool
	err         error
	calls       atomic.Int64
}

func (f *fakeProm) get(_ context.Context, path string, params map[string]string) ([]byte, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	if path == "api/v1/alerts" {
		if f.noAlertsAPI {
			return nil, &prom.Error{Type: "bad_data", Message: "missing -vmalert.proxyURL flag"}
		}
		return json.Marshal(map[string]any{"status": "success", "data": map[string]any{"alerts": f.alerts}})
	}
	q := params["query"]
	type vec struct {
		Metric map[string]string `json:"metric"`
		Value  [2]any            `json:"value"`
	}
	type mat struct {
		Metric map[string]string `json:"metric"`
		Values [][2]any          `json:"values"`
	}
	if path == "api/v1/query_range" {
		var out []mat
		for k, ss := range f.ranges {
			if strings.Contains(q, k) {
				for _, s := range ss {
					m := mat{Metric: s.Labels}
					for _, p := range s.Points {
						m.Values = append(m.Values, [2]any{float64(p.T.Unix()), fmt.Sprint(p.V)})
					}
					out = append(out, m)
				}
				break
			}
		}
		return json.Marshal(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": out}})
	}
	out := []vec{}
	best := ""
	for k := range f.instant {
		if strings.Contains(q, k) && len(k) > len(best) {
			best = k
		}
	}
	for _, s := range f.instant[best] {
		out = append(out, vec{Metric: s.Labels, Value: [2]any{float64(now.Unix()), fmt.Sprint(s.Value)}})
	}
	return json.Marshal(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": out}})
}

func sample(v float64, kv ...string) prom.Sample {
	l := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		l[kv[i]] = kv[i+1]
	}
	return prom.Sample{Labels: l, Value: v}
}

func node(name, ip string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: ip}}}}
}

func TestRead(t *testing.T) {
	const gi = 1 << 30
	var points []prom.Point
	for i := 0; i <= 36; i++ { // 6 h every 10 min, growing 1 GiB per hour
		points = append(points, prom.Point{T: now.Add(-6 * time.Hour).Add(time.Duration(i) * 10 * time.Minute), V: 2*gi + float64(i)*gi/6})
	}
	f := &fakeProm{
		instant: map[string][]prom.Sample{
			"node_uname_info": {
				sample(1, "instance", "10.0.0.1:9100", "nodename", "worker-1"),   // by IP
				sample(1, "instance", "w2.example:9100", "nodename", "worker-2"), // by node-exporter's host name
				sample(1, "instance", "10.9.9.9:9100", "nodename", "gone"),       // no such node
			},
			"(up)": {sample(1, "instance", "10.0.0.1:9100"), sample(0, "instance", "w2.example:9100"),
				sample(0, "instance", "10.0.0.1:10250")}, // the kubelet's target on the same node
			"kubelet_volume_stats_used_bytes": {sample(9*gi, "namespace", "shop", "persistentvolumeclaim", "data")},
			"kubelet_volume_stats_capacity_bytes": {
				sample(10*gi, "namespace", "shop", "persistentvolumeclaim", "data"),
			},
			"node_filesystem_size_bytes": {
				sample(50*gi, "instance", "10.0.0.1:9100", "mountpoint", "/", "device", "/dev/sda1", "fstype", "ext4"),
				sample(200*gi, "instance", "10.0.0.1:9100", "mountpoint", "/var/lib/k0s", "device", "/dev/sdb1", "fstype", "xfs"),
			},
			"node_filesystem_avail_bytes": {
				sample(5*gi, "instance", "10.0.0.1:9100", "mountpoint", "/", "device", "/dev/sda1", "fstype", "ext4"),
				sample(100*gi, "instance", "10.0.0.1:9100", "mountpoint", "/var/lib/k0s", "device", "/dev/sdb1", "fstype", "xfs"),
			},
			`mode="steal"`:                       {sample(0.3, "instance", "10.0.0.1:9100")},
			"node_timex_offset_seconds":          {sample(-2.5, "instance", "w2.example:9100")},
			"node_boot_time_seconds":             {sample(float64(now.Add(-time.Hour).Unix()), "instance", "10.0.0.1:9100")},
			"container_memory_working_set_bytes": {sample(480<<20, "namespace", "shop", "pod", "api-1", "container", "api")},
			"max_over_time(container_memory_working_set_bytes": {
				sample(510<<20, "namespace", "shop", "pod", "api-1", "container", "api"),
			},
		},
		ranges: map[string][]prom.Series{
			"kubelet_volume_stats_used_bytes": {{Labels: map[string]string{"namespace": "shop", "persistentvolumeclaim": "data"}, Points: points}},
			"node_filesystem_avail_bytes": {{Labels: map[string]string{"instance": "10.0.0.1:9100", "mountpoint": "/"},
				Points: []prom.Point{{T: now.Add(-time.Hour), V: 0.85}, {T: now, V: 0.9}}}},
		},
	}
	r := NewReader(prom.NewFunc(prom.Target{URL: "http://prom"}, f.get), func() time.Time { return now })
	m, err := r.Read(context.Background(), []*corev1.Node{node("worker-1", "10.0.0.1"), node("worker-2", "10.0.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Unmapped) != 1 || m.Unmapped[0] != "10.9.9.9:9100" {
		t.Errorf("unmapped = %v", m.Unmapped)
	}
	w1, w2 := m.Nodes["worker-1"], m.Nodes["worker-2"]
	if w1 == nil || w2 == nil {
		t.Fatalf("nodes = %+v", m.Nodes)
	}
	if !w1.Up || w2.Up || w1.CPUSteal != 0.3 || w2.ClockOffset != -2.5 || !w1.BootTime.Equal(now.Add(-time.Hour)) {
		t.Errorf("worker-1 %+v, worker-2 %+v", w1, w2)
	}
	if len(w1.Filesystems) != 2 || w1.Filesystems[0].Mountpoint != "/" || math.Abs(w1.Filesystems[0].UsedFraction()-0.9) > 1e-9 {
		t.Errorf("filesystems = %+v", w1.Filesystems)
	}
	v := m.Volumes["shop/data"]
	if v == nil || v.Used != 9*gi || v.Capacity != 10*gi || v.Growth == nil {
		t.Fatalf("volume = %+v", v)
	}
	if math.Abs(v.Growth.BytesPerHour-gi) > 1 || v.Growth.R2 < 0.999 || v.Growth.Window != 6*time.Hour {
		t.Errorf("growth = %+v", v.Growth)
	}
	if len(v.History) != 37 || v.History[36].V != 8*gi {
		t.Errorf("volume history has %d points", len(v.History))
	}
	if h := w1.FSHistory["/"]; len(h) != 2 || h[1].V != 0.9 {
		t.Errorf("filesystem history = %+v", w1.FSHistory)
	}
	if ttf, ok := v.TimeToFull(); !ok || ttf != time.Hour {
		t.Errorf("time to full = %s %v", ttf, ok)
	}
	c := m.Containers["shop/api-1/api"]
	if c == nil || c.WorkingSet != 480<<20 || c.PeakWorkingSet7d != 510<<20 {
		t.Errorf("container = %+v", c)
	}
	if !m.Have["node-exporter"] || !m.Have["kubelet-volumes"] || !m.Have["cadvisor"] || !m.Have["timex"] {
		t.Errorf("have = %v", m.Have)
	}

	// History is cached: a second read a minute later runs no range query.
	calls := f.calls.Load()
	r.now = func() time.Time { return now.Add(time.Minute) }
	if _, err := r.Read(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if extra := f.calls.Load() - calls; extra != 31 {
		t.Errorf("a cached read made %d requests, want the 30 instant queries and the alerts", extra)
	}
}

func TestLinearFit(t *testing.T) {
	var ps []prom.Point
	for i := 0; i < 10; i++ {
		v := float64(i) * 100
		if i%2 == 0 {
			v += 30
		}
		ps = append(ps, prom.Point{T: now.Add(time.Duration(i) * time.Hour), V: v})
	}
	slope, r2 := linearFit(ps)
	if math.Abs(slope-100) > 5 || r2 < 0.99 || r2 > 1 {
		t.Errorf("slope %f, r2 %f", slope, r2)
	}
	flat := []prom.Point{{T: now, V: 5}, {T: now.Add(time.Hour), V: 5}}
	if s, r := linearFit(flat); s != 0 || r != 1 {
		t.Errorf("flat: %f %f", s, r)
	}
}

func TestReadAlerts(t *testing.T) {
	f := &fakeProm{instant: map[string][]prom.Sample{}, alerts: []map[string]any{
		{"labels": map[string]string{"alertname": "KubePodCrashLooping", "severity": "warning", "namespace": "shop", "pod": "web-1"},
			"annotations": map[string]string{"summary": "Pod is crash looping.", "runbook_url": "https://runbooks.example/crash"},
			"state":       "firing", "activeAt": "2026-09-27T13:40:00Z"},
		{"labels": map[string]string{"alertname": "NodeDown", "severity": "critical", "instance": "10.0.0.1:9100"},
			"annotations": map[string]string{"description": "The node is down."}, "state": "firing", "activeAt": "2026-09-27T13:50:00Z"},
		{"labels": map[string]string{"alertname": "DiskSlow", "severity": "info"}, "state": "pending"},
		{"labels": map[string]string{"alertname": "Watchdog", "severity": "none"}, "state": "firing"},
	}}
	r := NewReader(prom.NewFunc(prom.Target{URL: "http://prom:9090"}, f.get), func() time.Time { return now })
	m, err := r.Read(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !m.AlertsRead || m.AlertsFrom != "alerts API" || len(m.Alerts) != 2 {
		t.Fatalf("alerts: read %v from %q: %+v", m.AlertsRead, m.AlertsFrom, m.Alerts)
	}
	// Most severe first; pending and heartbeat alerts are left out.
	down, crash := m.Alerts[0], m.Alerts[1]
	if down.Name != "NodeDown" || down.Text() != "The node is down." || down.Labels["instance"] != "10.0.0.1:9100" || down.Labels["alertname"] != "" {
		t.Errorf("node down: %+v", down)
	}
	if crash.Summary != "Pod is crash looping." || crash.Runbook != "https://runbooks.example/crash" || !crash.Since.Equal(now.Add(-20*time.Minute)) {
		t.Errorf("crash: %+v", crash)
	}

	// VictoriaMetrics without vmalert: the ALERTS series instead.
	f = &fakeProm{noAlertsAPI: true, instant: map[string][]prom.Sample{
		"ALERTS{":          {sample(1, "__name__", "ALERTS", "alertname", "KubePodCrashLooping", "alertstate", "firing", "severity", "warning", "namespace", "shop", "pod", "web-1")},
		"ALERTS_FOR_STATE": {sample(float64(now.Add(-time.Hour).Unix()), "__name__", "ALERTS_FOR_STATE", "alertname", "KubePodCrashLooping", "severity", "warning", "namespace", "shop", "pod", "web-1")},
	}}
	r = NewReader(prom.NewFunc(prom.Target{URL: "http://vm:8428"}, f.get), func() time.Time { return now })
	if m, err = r.Read(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if !m.AlertsRead || m.AlertsFrom != "ALERTS series" || len(m.Alerts) != 1 {
		t.Fatalf("ALERTS: read %v from %q: %+v", m.AlertsRead, m.AlertsFrom, m.Alerts)
	}
	if a := m.Alerts[0]; a.Name != "KubePodCrashLooping" || a.Labels["pod"] != "web-1" || a.Labels["alertstate"] != "" || !a.Since.Equal(now.Add(-time.Hour)) {
		t.Errorf("from ALERTS: %+v", a)
	}
}

func TestReadServices(t *testing.T) {
	f := &fakeProm{instant: map[string][]prom.Sample{
		"node_uname_info": {sample(1, "instance", "10.0.0.1:9100", "nodename", "worker-1")},
		"node_systemd_unit_state": {
			sample(1, "instance", "10.0.0.1:9100", "name", "k0sworker.service", "state", "failed"),
			sample(1, "instance", "10.0.0.9:9100", "name", "k0scontroller.service", "state", "active"), // a controller, no node
		},
		"node_systemd_service_restart_total": {
			sample(4, "instance", "10.0.0.9:9100", "name", "k0scontroller.service"),
			sample(2, "instance", "10.0.0.7:9100", "name", "k0sworker.service"), // no state: gone
		},
	}}
	r := NewReader(prom.NewFunc(prom.Target{URL: "http://prom:9090"}, f.get), func() time.Time { return now })
	m, err := r.Read(context.Background(), []*corev1.Node{node("worker-1", "10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Services) != 2 || !m.Have["systemd"] {
		t.Fatalf("services: %+v", m.Services)
	}
	w, c := m.Services[0], m.Services[1]
	if w.Node != "worker-1" || w.Unit != "k0sworker.service" || w.State != "failed" || !math.IsNaN(w.Restarts15m) {
		t.Errorf("worker: %+v", w)
	}
	if c.Node != "" || c.Host() != "10.0.0.9" || c.State != "active" || c.Restarts15m != 4 {
		t.Errorf("controller: %+v", c)
	}
}

func TestReadKernelSignals(t *testing.T) {
	f := &fakeProm{instant: map[string][]prom.Sample{
		"node_uname_info":                    {sample(1, "instance", "10.0.0.1:9100", "nodename", "worker-1")},
		"node_vmstat_oom_kill":               {sample(3, "instance", "10.0.0.1:9100")},
		"node_network_carrier_changes_total": {sample(4, "instance", "10.0.0.1:9100", "device", "eth0")},
	}}
	r := NewReader(prom.NewFunc(prom.Target{URL: "http://prom:9090"}, f.get), func() time.Time { return now })
	m, err := r.Read(context.Background(), []*corev1.Node{node("worker-1", "10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	n := m.Nodes["worker-1"]
	if n == nil || n.OOMKills15m != 3 || n.LinkFlaps["eth0"] != 4 {
		t.Errorf("worker-1: %+v", n)
	}
}
