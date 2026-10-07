package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/version"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// staticCP is a control plane view that never changes.
type staticCP struct{ cp *snapshot.ControlPlane }

func (s staticCP) Update(context.Context, []*corev1.Node) {}
func (s staticCP) Latest() *snapshot.ControlPlane {
	cp := *s.cp
	cp.At = now
	return &cp
}

// controllers is a cluster of two controllers: the kubeconfig names ctrl-a,
// which can go down; ctrl-b always answers.
type controllers struct {
	h       *harness
	aDown   atomic.Bool
	bDown   atomic.Bool
	authErr atomic.Bool
	mu      sync.Mutex
	// names are the certificate names each connection to ctrl-b checked.
	names []string
}

func (cs *controllers) connect(c config.Cluster, _ time.Duration) (*cluster.Conn, error) {
	server := "https://10.0.0.5:6443"
	if c.Server != "" {
		server = c.Server
	}
	up := func() bool { return true }
	switch server {
	case "https://10.0.0.5:6443":
		up = func() bool { return !cs.aDown.Load() }
	case "https://10.0.0.6:6443":
		up = func() bool { return !cs.bDown.Load() }
		cs.mu.Lock()
		cs.names = append(cs.names, c.ServerName)
		cs.mu.Unlock()
	default:
		up = func() bool { return false }
	}
	return cluster.NewForClientWithPing(c.Name, server, cs.h.client, func(context.Context) (*version.Info, error) {
		if server == "https://10.0.0.5:6443" && cs.authErr.Load() {
			return nil, apierrors.NewUnauthorized("token expired")
		}
		if !up() {
			return nil, errors.New("dial tcp " + server[8:] + ": connect: connection refused")
		}
		return &version.Info{GitVersion: "v1.36.4+k0s"}, nil
	}), nil
}

func startHA(t *testing.T, store *memStore) (*harness, *controllers) {
	t.Helper()
	cs := &controllers{}
	view := &snapshot.ControlPlane{Server: "10.0.0.5", Controllers: []*snapshot.Controller{
		{Name: "ctrl-a", Address: "10.0.0.5:6443", Reached: true},
		{Name: "ctrl-b", Address: "10.0.0.6:6443", Reached: true},
		{Name: "ctrl-c", Address: "10.0.0.7:6443", Error: "no route to host"},
	}}
	h := start(t, "../rules/testdata/crashloop.yaml", func(o *Options, h *harness) {
		cs.h = h
		if store != nil {
			h.store = store
			o.Store = store
		}
		o.Connect = cs.connect
		o.ControlPlane = func(*cluster.Conn) ControlPlaneSource { return staticCP{view} }
		o.ControlPlaneInterval = 20 * time.Millisecond
		o.FailbackInterval = 30 * time.Millisecond
	})
	return h, cs
}

func connectedTo(h *harness) string {
	if c := h.e.Conn(); c != nil {
		return c.Server
	}
	return ""
}

func TestFailover(t *testing.T) {
	h, cs := startHA(t, nil)
	h.waitFor("connected", func(s *State) bool { return s.Status == StatusOK })
	// The controllers that answered are remembered, and stored.
	deadline := time.Now().Add(5 * time.Second)
	for len(h.store.ctrlsCopy()) != 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := h.store.ctrlsCopy(); len(got) != 2 || got[1] != (KnownController{Name: "ctrl-b", Address: "10.0.0.6:6443"}) {
		t.Fatalf("stored controllers = %+v", got)
	}

	// ctrl-a stops: k0s-monitor goes on through ctrl-b, and says so.
	cs.aDown.Store(true)
	st := h.waitFor("failover", func(s *State) bool {
		return s.Info != nil && s.Info.Fallback != nil && byRule(s, "endpoint.fallback") != nil
	})
	if connectedTo(h) != "https://10.0.0.6:6443" || st.Status != StatusOK {
		t.Fatalf("connected to %q, status %s", connectedTo(h), st.Status)
	}
	fb := st.Info.Fallback
	if fb.Server != "https://10.0.0.5:6443" || fb.Controller != "ctrl-b" || !fb.ServerIsController || fb.Error == nil || fb.Error.Kind != cluster.KindRefused {
		t.Errorf("fallback = %+v", fb)
	}
	f := byRule(st, "endpoint.fallback")
	if f.Severity != findings.Low || f.Resource.Name != "10.0.0.5:6443" {
		t.Errorf("finding: %s %s", f.Severity, f.Resource)
	}
	if byRule(st, "cluster.unreachable") != nil {
		t.Error("reported unreachable while another controller answers")
	}
	// Findings keep coming from the cluster through ctrl-b.
	if byRule(st, "pod.crashloop") == nil {
		t.Error("the cluster's own findings are gone")
	}
	cs.mu.Lock()
	for _, n := range cs.names {
		if n != cluster.InClusterName {
			t.Errorf("ctrl-b was connected to checking %q, not %s", n, cluster.InClusterName)
		}
	}
	cs.mu.Unlock()

	// ctrl-a is back: k0s-monitor returns to it once it answers twice.
	cs.aDown.Store(false)
	st = h.waitFor("failback", func(s *State) bool { return s.Info != nil && s.Info.Fallback == nil && s.Status == StatusOK })
	if connectedTo(h) != "https://10.0.0.5:6443" {
		t.Errorf("connected to %q after failback", connectedTo(h))
	}
	h.waitFor("fallback resolved", func(s *State) bool { return byRule(s, "endpoint.fallback") == nil })
}

func TestFailoverAfterRestart(t *testing.T) {
	// A restart while ctrl-a is down: the stored controllers are enough.
	store := newStore()
	store.ctrls = []KnownController{{Name: "ctrl-a", Address: "10.0.0.5:6443"}, {Name: "ctrl-b", Address: "10.0.0.6:6443"}}
	h, cs := startHA(t, store)
	cs.aDown.Store(true)
	h.waitFor("started on ctrl-b", func(s *State) bool { return s.Info != nil && s.Info.Fallback != nil && s.Status == StatusOK })
	if connectedTo(h) != "https://10.0.0.6:6443" {
		t.Errorf("connected to %q", connectedTo(h))
	}
}

func TestAllControllersDown(t *testing.T) {
	store := newStore()
	store.ctrls = []KnownController{{Name: "ctrl-a", Address: "10.0.0.5:6443"}, {Name: "ctrl-b", Address: "10.0.0.6:6443"}}
	h, cs := startHA(t, store)
	cs.aDown.Store(true)
	cs.bDown.Store(true)
	st := h.waitFor("unreachable", func(s *State) bool { return s.Status == StatusUnreachable })
	f := byRule(st, "cluster.unreachable")
	if f == nil || !strings.Contains(fmt.Sprint(f.Evidence), "ctrl-b 10.0.0.6:6443: none answers") {
		t.Errorf("the other controllers aren't named: %+v", f)
	}
}

func TestNoFailoverOnCredentials(t *testing.T) {
	// Rejected credentials aren't fixed by another controller.
	store := newStore()
	store.ctrls = []KnownController{{Name: "ctrl-b", Address: "10.0.0.6:6443"}}
	h, cs := startHA(t, store)
	cs.authErr.Store(true)
	st := h.waitFor("unreachable", func(s *State) bool { return s.Status == StatusUnreachable })
	if st.Error == nil || st.Error.Kind != cluster.KindUnauthorized {
		t.Errorf("error = %+v", st.Error)
	}
	if connectedTo(h) != "" {
		t.Errorf("connected to %q", connectedTo(h))
	}
}

func (m *memStore) ctrlsCopy() []KnownController {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]KnownController{}, m.ctrls...)
}
