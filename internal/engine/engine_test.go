package engine

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes/fake"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/testutil"
)

var now = time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)

// memStore is an in-memory Store that records calls.
type memStore struct {
	mu       sync.Mutex
	user     map[string]UserState
	open     map[string]time.Time
	resolved []string
	recorded map[string]findings.Priority
	ctrls    []KnownController
}

func newStore() *memStore {
	return &memStore{user: map[string]UserState{}, open: map[string]time.Time{}, recorded: map[string]findings.Priority{}}
}

func (m *memStore) UserStates(string) (map[string]UserState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]UserState{}
	for k, v := range m.user {
		out[k] = v
	}
	return out, nil
}
func (m *memStore) ClearUserState(_, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.user, id)
	return nil
}
func (m *memStore) OpenFindings(string) (map[string]time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]time.Time{}
	for k, v := range m.open {
		out[k] = v
	}
	return out, nil
}
func (m *memStore) RecordOpen(f *findings.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recorded[f.ID] = f.Priority
	return nil
}
func (m *memStore) RecordResolved(_, id string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resolved = append(m.resolved, id)
	return nil
}
func (m *memStore) Controllers(string) ([]KnownController, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.ctrls), nil
}
func (m *memStore) SetControllers(_ string, cs []KnownController) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ctrls = slices.Clone(cs)
	return nil
}
func (m *memStore) set(id string, us UserState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.user[id] = us
}
func (m *memStore) userState(id string) (UserState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	us, ok := m.user[id]
	return us, ok
}
func (m *memStore) wasResolved(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.resolved {
		if r == id {
			return true
		}
	}
	return false
}

// events collects engine events.
type events struct {
	mu  sync.Mutex
	all []Event
}

func (ev *events) add(e Event) {
	ev.mu.Lock()
	defer ev.mu.Unlock()
	ev.all = append(ev.all, e)
}

func (ev *events) find(t EventType, rule string) *Event {
	ev.mu.Lock()
	defer ev.mu.Unlock()
	for i := range ev.all {
		e := ev.all[i]
		if e.Type == t && (rule == "" || (e.Finding != nil && e.Finding.RuleID == rule)) {
			return &e
		}
	}
	return nil
}

type harness struct {
	t      *testing.T
	e      *Engine
	client *fake.Clientset
	store  *memStore
	ev     *events
	down   atomic.Bool
	cancel context.CancelFunc
	done   chan struct{}
}

func start(t *testing.T, fixture string, tweak func(*Options, *harness)) *harness {
	t.Helper()
	h := &harness{t: t, store: newStore(), ev: &events{}, done: make(chan struct{})}
	h.client = fake.NewClientset(testutil.Objects(t, fixture)...)
	o := Options{
		Cluster:          config.Cluster{Name: "edge", Kubeconfig: "unused"},
		Store:            h.store,
		OnEvent:          h.ev.add,
		Now:              func() time.Time { return now },
		MinInterval:      20 * time.Millisecond,
		MaxInterval:      100 * time.Millisecond,
		PingInterval:     20 * time.Millisecond,
		UnreachableAfter: 50 * time.Millisecond,
		RetryMin:         20 * time.Millisecond,
		RetryMax:         40 * time.Millisecond,
		Connect: func(c config.Cluster, _ time.Duration) (*cluster.Conn, error) {
			return cluster.NewForClientWithPing(c.Name, "https://10.0.0.5:6443", h.client, func(context.Context) (*version.Info, error) {
				if h.down.Load() {
					return nil, errors.New("dial tcp 10.0.0.5:6443: connect: connection refused")
				}
				return &version.Info{GitVersion: "v1.36.4+k0s"}, nil
			}), nil
		},
	}
	if tweak != nil {
		tweak(&o, h)
	}
	h.e = New(o)
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() {
		defer close(h.done)
		h.e.Run(ctx)
	}()
	t.Cleanup(h.stop)
	return h
}

func (h *harness) stop() {
	h.cancel()
	<-h.done
}

// waitFor polls the state until cond holds.
func (h *harness) waitFor(what string, cond func(*State) bool) *State {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if s := h.e.State(); cond(s) {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
	s := h.e.State()
	var got []string
	for _, f := range s.Findings {
		got = append(got, f.RuleID+" "+f.Resource.String()+" "+string(f.State))
	}
	h.t.Fatalf("timed out waiting for %s; status %s, findings %v", what, s.Status, got)
	return nil
}

func byRule(s *State, rule string) *findings.Finding {
	for _, f := range s.Findings {
		if f.RuleID == rule {
			return f
		}
	}
	return nil
}

func TestLifecycle(t *testing.T) {
	h := start(t, "../rules/testdata/crashloop.yaml", nil)
	s := h.waitFor("the crash loop", func(s *State) bool { return byRule(s, "pod.crashloop") != nil })
	crash := byRule(s, "pod.crashloop")
	if crash.FirstSeen == nil || !crash.FirstSeen.Equal(now) || crash.State != findings.StateOpen {
		t.Errorf("lifecycle fields = first %v state %q", crash.FirstSeen, crash.State)
	}
	if s.Status != StatusOK || s.Health == nil || s.Health.Score >= 100 || s.Info.Pods != 3 {
		t.Errorf("state = %s health %+v info %+v", s.Status, s.Health, s.Info)
	}
	if s.Counts[findings.P1] != 1 || s.Symptoms != 2 {
		t.Errorf("counts %v symptoms %d", s.Counts, s.Symptoms)
	}
	if e := h.ev.find(FindingOpened, "pod.crashloop"); e == nil || !e.Initial {
		t.Errorf("opened event = %+v", e)
	}
	if h.ev.find(ClusterConnected, "") == nil {
		t.Error("no cluster.connected event")
	}

	// A person acknowledges it: the state shows it right away.
	h.store.set(crash.ID, UserState{State: findings.StateAcknowledged, Priority: crash.Priority})
	h.e.Refresh()
	h.waitFor("the acknowledgement", func(s *State) bool {
		f := byRule(s, "pod.crashloop")
		return f != nil && f.State == findings.StateAcknowledged
	})

	// The crashing pods go away: after two evaluations without it, the
	// crash loop is resolved and its acknowledgement cleared.
	pods, _ := h.client.CoreV1().Pods("shop").List(context.Background(), metav1.ListOptions{})
	for _, p := range pods.Items {
		_ = h.client.CoreV1().Pods("shop").Delete(context.Background(), p.Name, metav1.DeleteOptions{})
	}
	h.waitFor("the crash loop to resolve", func(s *State) bool { return byRule(s, "pod.crashloop") == nil })
	if e := h.ev.find(FindingResolved, "pod.crashloop"); e == nil || e.Finding.State != findings.StateResolved {
		t.Errorf("resolved event = %+v", e)
	}
	if !h.store.wasResolved(crash.ID) {
		t.Error("the store was not told about the resolution")
	}
	if _, ok := h.store.userState(crash.ID); ok {
		t.Error("the acknowledgement should be cleared when the problem is resolved")
	}
}

func TestUnreachableKeepsStaleFindings(t *testing.T) {
	h := start(t, "../rules/testdata/crashloop.yaml", nil)
	before := h.waitFor("findings", func(s *State) bool { return byRule(s, "pod.crashloop") != nil })

	h.down.Store(true)
	s := h.waitFor("unreachable", func(s *State) bool { return s.Status == StatusUnreachable })
	f01 := byRule(s, cluster.UnreachableRuleID)
	if f01 == nil || f01.Priority != findings.P1 || s.Error == nil || s.Error.Kind != cluster.KindRefused {
		t.Fatalf("F01 = %+v, error %+v", f01, s.Error)
	}
	crash := byRule(s, "pod.crashloop")
	if crash == nil || !crash.Stale {
		t.Errorf("the last findings stay visible, marked stale: %+v", crash)
	}
	if s.Health == nil || s.Health.Score != before.Health.Score || s.HealthAt == nil {
		t.Errorf("the last known health is kept: %+v", s.Health)
	}
	if h.e.Conn() != nil {
		t.Error("no connection is offered while the cluster is down")
	}
	if h.ev.find(ClusterDisconnected, "") == nil || h.ev.find(FindingOpened, cluster.UnreachableRuleID) == nil {
		t.Error("missing disconnected or F01 events")
	}

	h.down.Store(false)
	s = h.waitFor("recovery", func(s *State) bool {
		return s.Status == StatusOK && byRule(s, cluster.UnreachableRuleID) == nil
	})
	if c := byRule(s, "pod.crashloop"); c == nil || c.Stale {
		t.Errorf("findings are live again: %+v", c)
	}
	if h.ev.find(FindingResolved, cluster.UnreachableRuleID) == nil {
		t.Error("F01 should resolve as soon as the cluster answers")
	}
}

func TestNeverConnects(t *testing.T) {
	var attempts atomic.Int32
	h := start(t, "../rules/testdata/crashloop.yaml", func(o *Options, _ *harness) {
		o.RetryMin, o.RetryMax = time.Hour, time.Hour
		o.Connect = func(config.Cluster, time.Duration) (*cluster.Conn, error) {
			attempts.Add(1)
			return nil, &cluster.ConnError{Kind: cluster.KindConfig, Plain: "The kubeconfig can't be used."}
		}
	})
	s := h.waitFor("unreachable", func(s *State) bool { return s.Status == StatusUnreachable })
	if s.RetryAt == nil || byRule(s, cluster.UnreachableRuleID) == nil || s.Health != nil {
		t.Errorf("state = %+v", s)
	}
	h.e.RetryNow()
	deadline := time.Now().Add(5 * time.Second)
	for attempts.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if attempts.Load() < 2 {
		t.Error("RetryNow should skip the backoff")
	}
}

func TestRestartDoesNotReopen(t *testing.T) {
	earlier := now.Add(-3 * time.Hour)
	crashID := findings.Fingerprint("edge", "pod.crashloop", findings.ObjectRef{Kind: "Deployment", Namespace: "shop", Name: "payments-api"})
	h := start(t, "../rules/testdata/crashloop.yaml", func(_ *Options, h *harness) {
		h.store.open[crashID] = earlier
		h.store.open["gone-since-last-run"] = earlier
	})
	s := h.waitFor("findings", func(s *State) bool { return byRule(s, "pod.crashloop") != nil })
	if f := byRule(s, "pod.crashloop"); !f.FirstSeen.Equal(earlier) {
		t.Errorf("first seen should survive a restart: %v", f.FirstSeen)
	}
	if h.ev.find(FindingOpened, "pod.crashloop") != nil {
		t.Error("a finding known from the last run is not new")
	}
	if !h.store.wasResolved("gone-since-last-run") {
		t.Error("a finding open at the last run and gone now is resolved")
	}
}

func TestWorseClearsAcknowledgement(t *testing.T) {
	crashID := findings.Fingerprint("edge", "pod.crashloop", findings.ObjectRef{Kind: "Deployment", Namespace: "shop", Name: "payments-api"})
	until := now.Add(time.Hour)
	h := start(t, "../rules/testdata/crashloop.yaml", func(_ *Options, h *harness) {
		// Snoozed while it was only P3; it is P1 now.
		h.store.user[crashID] = UserState{State: findings.StateSnoozed, Until: &until, Priority: findings.P3}
	})
	s := h.waitFor("findings", func(s *State) bool { return byRule(s, "pod.crashloop") != nil })
	if f := byRule(s, "pod.crashloop"); f.State != findings.StateOpen {
		t.Errorf("a problem that got worse is open again, got %s", f.State)
	}
}

func TestOnlyReadsFromTheCluster(t *testing.T) {
	h := start(t, "../rules/testdata/crashloop.yaml", nil)
	h.waitFor("a few evaluations", func(s *State) bool { return s.Evals >= 3 })
	h.stop()
	for _, a := range h.client.Actions() {
		switch {
		case a.GetVerb() == "get", a.GetVerb() == "list", a.GetVerb() == "watch":
		case a.GetVerb() == "create" && a.GetResource().Resource == "selfsubjectaccessreviews":
			// A question about its own permissions: nothing is stored.
		default:
			t.Errorf("the engine must not change the cluster: %s %s", a.GetVerb(), a.GetResource().Resource)
		}
		if a.GetResource().Resource == "secrets" {
			t.Errorf("the engine read Secrets without the permission: %s", a.GetVerb())
		}
	}
}

func TestFleet(t *testing.T) {
	client := fake.NewClientset()
	base := Options{
		MinInterval: 20 * time.Millisecond, MaxInterval: 100 * time.Millisecond,
		Connect: func(c config.Cluster, _ time.Duration) (*cluster.Conn, error) {
			return cluster.NewForClient(c.Name, "https://x:6443", client, &version.Info{GitVersion: "v1.36.4+k0s"}), nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fl := NewFleet(ctx, base)
	defer fl.Stop()
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		if _, err := fl.Add(config.Cluster{Name: n, Kubeconfig: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fl.Add(config.Cluster{Name: "f", Kubeconfig: "x"}); err == nil {
		t.Error("a sixth cluster must be refused")
	}
	if !fl.Remove("c") || fl.Get("c") != nil || len(fl.Engines()) != 4 {
		t.Error("remove failed")
	}
	if _, err := fl.Add(config.Cluster{Name: "a", Kubeconfig: "x"}); err == nil {
		t.Error("duplicate names must be refused")
	}
	if _, err := fl.Add(config.Cluster{Name: "Bad Name", Kubeconfig: "x"}); err == nil {
		t.Error("invalid clusters must be refused")
	}
	e := fl.Get("a")
	deadline := time.Now().Add(5 * time.Second)
	for e.State().Status != StatusOK && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if e.State().Status != StatusOK {
		t.Errorf("status = %s", e.State().Status)
	}
}
