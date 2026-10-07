//go:build demo

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	k8stesting "k8s.io/client-go/testing"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/snapshot"
)

// Demo mode (built with -tags demo) serves fake clusters made from YAML
// fixtures, for screenshots and trying the UI without a cluster.

// demoEpoch is the "now" of the fixtures in internal/rules/testdata.
var demoEpoch = time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)

func demoConfig(pattern string) (*config.Config, error) {
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) == 0 {
		return nil, errors.New("--demo needs a glob of YAML fixture files")
	}
	cfg := config.Default()
	if err := config.ApplyServeDefaults(cfg); err != nil {
		return nil, err
	}
	cfg.Listen = "127.0.0.1:8443"
	for _, f := range files {
		if len(cfg.Clusters) == config.MaxClusters {
			break
		}
		name := strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))
		c := config.Cluster{Name: name, Kubeconfig: f}
		// A fixture's expected k0s version stands for the cluster's setting.
		if snap, err := snapshot.FromYAMLFile(name, f, demoEpoch); err == nil && snap.ExpectedK0s != nil {
			c.K0sVersion, c.K0sVersionFrom = snap.ExpectedK0s.Version, snap.ExpectedK0s.From
		}
		cfg.Clusters = append(cfg.Clusters, c)
	}
	if home, err := os.UserHomeDir(); err == nil {
		cfg.DataDir = filepath.Join(home, ".local", "state", "k0s-monitor-demo")
	}
	// Product packs next to the fixtures.
	cfg.PacksDir = filepath.Join(filepath.Dir(pattern), "packs")
	return cfg, cfg.Validate()
}

func demoConnector(pattern string) cluster.Connector {
	if pattern == "" {
		return nil
	}
	return func(c config.Cluster, _ time.Duration) (*cluster.Conn, error) {
		data, err := os.ReadFile(c.Kubeconfig)
		if err != nil {
			return nil, err
		}
		var objs []runtime.Object
		dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
		for {
			var raw runtime.RawExtension
			if err := dec.Decode(&raw); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, err
			}
			if len(bytes.TrimSpace(raw.Raw)) == 0 || bytes.Contains(raw.Raw, []byte("apiregistration.k8s.io")) ||
				bytes.Contains(raw.Raw, []byte("k0s-monitor.io/v1")) || bytes.Contains(raw.Raw, []byte("autopilot.k0sproject.io/")) ||
				bytes.Contains(raw.Raw, []byte(`"apiVersion":"helm.k0sproject.io/`)) || bytes.Contains(raw.Raw, []byte(`"apiVersion":"k0s.k0sproject.io/`)) {
				continue // fake clients can't serve APIServices or k0s's objects; metrics and k0s's objects come from demoMetrics and demoControlPlane
			}
			obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(raw.Raw, nil, nil)
			if err != nil {
				return nil, err
			}
			objs = append(objs, obj)
		}
		client := fake.NewClientset(objs...)
		// The demo account may do everything, TLS Secrets included.
		client.PrependReactor("create", "selfsubjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
			r := a.(k8stesting.CreateAction).GetObject().(*authzv1.SelfSubjectAccessReview).DeepCopy()
			r.Status.Allowed = true
			return true, r, nil
		})
		return cluster.NewForClient(c.Name, "https://"+c.Name+".demo:6443", client, &version.Info{GitVersion: "v1.36.4+k0s"}), nil
	}
}

// demoNow runs the clock from the fixtures' "now", so their timestamps
// keep making sense.
func demoNow(pattern string) func() time.Time {
	if pattern == "" {
		return nil
	}
	start := time.Now()
	return func() time.Time { return demoEpoch.Add(time.Since(start)) }
}

// demoMetrics serves the Metrics document of each fixture as if the
// cluster's Prometheus had answered it.
func demoMetrics(pattern string, now func() time.Time) func(*cluster.Conn) engine.MetricsSource {
	if pattern == "" {
		return nil
	}
	files, _ := filepath.Glob(pattern)
	byName := map[string]string{}
	for _, f := range files {
		byName[strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))] = f
	}
	return func(conn *cluster.Conn) engine.MetricsSource {
		return &staticMetrics{name: conn.Name, file: byName[conn.Name], now: now}
	}
}

type staticMetrics struct {
	name, file string
	now        func() time.Time

	mu     sync.Mutex
	loaded bool
	m      *snapshot.Metrics
	nodes  int
}

func (s *staticMetrics) Update(_ context.Context, _ []*corev1.Service, nodes []*corev1.Node) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes = len(nodes)
	if s.loaded {
		return
	}
	s.loaded = true
	if snap, err := snapshot.FromYAMLFile(s.name, s.file, demoEpoch); err == nil {
		s.m = snap.Metrics
	}
}

func (s *staticMetrics) Latest() (*snapshot.Metrics, cluster.PrometheusStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		return nil, cluster.PrometheusStatus{State: "not-found", Message: "This demo cluster has no Metrics document, as a cluster without Prometheus.", At: s.now()}
	}
	m := *s.m
	m.At = s.now()
	return &m, cluster.PrometheusStatus{State: "ok", Target: "demo/prometheus:9090", NodeExporter: len(m.Nodes), NodesTotal: s.nodes,
		KubeletVolumes: m.Have["kubelet-volumes"], CAdvisor: m.Have["cadvisor"], Timex: m.Have["timex"], At: m.At}
}

// demoControlPlane serves the ControlPlane document of each fixture as if
// its controllers had answered it.
func demoControlPlane(pattern string, now func() time.Time) func(*cluster.Conn) engine.ControlPlaneSource {
	if pattern == "" {
		return nil
	}
	files, _ := filepath.Glob(pattern)
	byName := map[string]string{}
	for _, f := range files {
		byName[strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))] = f
	}
	return func(conn *cluster.Conn) engine.ControlPlaneSource {
		return &staticControlPlane{name: conn.Name, file: byName[conn.Name], now: now}
	}
}

type staticControlPlane struct {
	name, file string
	now        func() time.Time

	mu     sync.Mutex
	loaded bool
	cp     *snapshot.ControlPlane
}

func (s *staticControlPlane) Update(context.Context, []*corev1.Node) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loaded {
		return
	}
	s.loaded = true
	if snap, err := snapshot.FromYAMLFile(s.name, s.file, demoEpoch); err == nil {
		s.cp = snap.ControlPlane
	}
}

func (s *staticControlPlane) Latest() *snapshot.ControlPlane {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cp == nil {
		return nil
	}
	cp := *s.cp
	cp.At = s.now()
	return &cp
}

// demoCrashLogs reads the crash logs from each cluster's fixture
// (kind: CrashLogs).
func demoCrashLogs(pattern string) func(*cluster.Conn) engine.CrashLogSource {
	if pattern == "" {
		return nil
	}
	files, _ := filepath.Glob(pattern)
	byName := map[string]string{}
	for _, f := range files {
		byName[strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))] = f
	}
	return func(conn *cluster.Conn) engine.CrashLogSource {
		return &staticCrashLogs{name: conn.Name, file: byName[conn.Name]}
	}
}

type staticCrashLogs struct {
	name, file string

	mu     sync.Mutex
	loaded bool
	logs   map[string]*snapshot.CrashLog
}

func (s *staticCrashLogs) Update(context.Context, []*corev1.Pod) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loaded {
		return false
	}
	s.loaded = true
	if snap, err := snapshot.FromYAMLFile(s.name, s.file, demoEpoch); err == nil {
		s.logs = snap.CrashLogs
	}
	return len(s.logs) > 0
}

func (s *staticCrashLogs) Latest() map[string]*snapshot.CrashLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logs
}
