// Package engine monitors one cluster continuously (plan section 4,
// "Evaluation loop"): it keeps a connection and informers, re-evaluates the
// rules when objects change, tracks each finding's lifecycle and publishes
// the result. A slow or unreachable cluster never affects the others,
// because each cluster has its own engine.
package engine

import (
	"context"
	"maps"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/alerts"
	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/collector"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/controlplane"
	"k0s_monitor/internal/correlate"
	"k0s_monitor/internal/crashlog"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/metrics"
	"k0s_monitor/internal/pack"
	"k0s_monitor/internal/priority"
	"k0s_monitor/internal/rules"
	"k0s_monitor/internal/snapshot"
)

// Status is the connection state of a cluster.
type Status string

const (
	StatusConnecting  Status = "connecting"
	StatusOK          Status = "ok"
	StatusPartial     Status = "partial" // some kinds can't be read
	StatusUnreachable Status = "unreachable"
)

// State is what the engine knows about its cluster at one moment. A
// published State is never changed; the engine replaces it.
type State struct {
	Name     string             `json:"name"`
	Status   Status             `json:"status"`
	Info     *cluster.Info      `json:"info,omitempty"`
	Error    *cluster.ConnError `json:"error,omitempty"`
	Warnings []string           `json:"warnings,omitempty"`
	// LastSync is the time of the last evaluation with live data.
	LastSync *time.Time `json:"lastSync,omitempty"`
	// UnreachableSince is set while the cluster can't be reached.
	UnreachableSince *time.Time `json:"unreachableSince,omitempty"`
	// RetryAt is when the next connection attempt happens.
	RetryAt *time.Time `json:"retryAt,omitempty"`

	// Findings in display order: each root cause, then its symptoms.
	Findings []*findings.Finding `json:"findings"`
	Skipped  []rules.Skipped     `json:"skippedRules,omitempty"`
	// Health is nil until the first evaluation. While the cluster is
	// unreachable it is the last known score, computed at HealthAt.
	Health   *priority.Health          `json:"health,omitempty"`
	HealthAt *time.Time                `json:"healthAt,omitempty"`
	Counts   map[findings.Priority]int `json:"counts"`
	Symptoms int                       `json:"foldedSymptoms"`
	// Suggestions counts the good-practice findings, which Counts leaves
	// out.
	Suggestions int                `json:"suggestions"`
	Snapshot    *snapshot.Snapshot `json:"-"`
	Evals       int                `json:"evaluations"`
}

// Finding returns the finding with this ID, or nil.
func (s *State) Finding(id string) *findings.Finding {
	for _, f := range s.Findings {
		if f.ID == id {
			return f
		}
	}
	return nil
}

// EventType names what changed.
type EventType string

const (
	FindingOpened       EventType = "finding.opened"
	FindingUpdated      EventType = "finding.updated"
	FindingResolved     EventType = "finding.resolved"
	HealthChanged       EventType = "health.changed"
	ClusterConnected    EventType = "cluster.connected"
	ClusterDisconnected EventType = "cluster.disconnected"
	// StateChanged follows every newly published State.
	StateChanged EventType = "cluster.state"
)

// Event reports one change. Finding is a copy that may be kept.
type Event struct {
	Type    EventType         `json:"type"`
	Cluster string            `json:"cluster"`
	Finding *findings.Finding `json:"finding,omitempty"`
	// Previous is the priority before an update.
	Previous findings.Priority `json:"previousPriority,omitempty"`
	// Initial marks findings of the first evaluation after the engine
	// started, which were not known from earlier runs.
	Initial bool      `json:"initial,omitempty"`
	Time    time.Time `json:"time"`
}

// UserState is what a person set on a finding.
type UserState struct {
	State findings.State // acknowledged or snoozed
	Until *time.Time     // end of a snooze
	// Priority is the finding's priority when the state was set. If the
	// finding gets worse, the state is cleared so it notifies again.
	Priority findings.Priority
	// By is the user who set it.
	By string
}

// Store keeps what must survive a restart. All methods may be called from
// the engine goroutine; a nil Store keeps everything in memory.
type Store interface {
	UserStates(cluster string) (map[string]UserState, error)
	ClearUserState(cluster, id string) error
	// OpenFindings returns the first-seen time of findings that were open
	// when the tool last ran, so a restart does not report them as new.
	OpenFindings(cluster string) (map[string]time.Time, error)
	RecordOpen(f *findings.Finding) error
	RecordResolved(cluster, id string, at time.Time) error
	// Controllers returns the controllers last reached at their own
	// addresses, to fail over to after a restart; SetControllers keeps them.
	Controllers(cluster string) ([]KnownController, error)
	SetControllers(cluster string, cs []KnownController) error
}

// Options configure an engine. Zero timing values take the defaults.
type Options struct {
	Cluster    config.Cluster
	Thresholds config.Thresholds
	Timeouts   config.Scan
	Connect    cluster.Connector
	Store      Store
	OnEvent    func(Event)
	Now        func() time.Time

	// MinInterval and MaxInterval bound how often rules run: at most once
	// per MinInterval after a change, and at least once per MaxInterval.
	MinInterval, MaxInterval time.Duration
	// PingInterval is how often the API server is checked.
	PingInterval time.Duration
	// UnreachableAfter is how long pings must fail before the cluster is
	// reported unreachable.
	UnreachableAfter time.Duration
	// ProbeInterval is how often capabilities are probed again.
	ProbeInterval time.Duration
	// RetryMin and RetryMax bound the reconnect backoff.
	RetryMin, RetryMax time.Duration
	// MetricsInterval is how often metrics are read from Prometheus.
	MetricsInterval time.Duration
	// Metrics makes the metrics source for a connection. The default
	// finds the cluster's Prometheus.
	Metrics func(conn *cluster.Conn) MetricsSource
	// ControlPlaneInterval is how often each controller is asked.
	ControlPlaneInterval time.Duration
	// ControlPlane makes the control-plane source for a connection. The
	// default asks each controller directly.
	ControlPlane func(conn *cluster.Conn) ControlPlaneSource
	// CrashLogInterval is how often the logs of new crashes are read.
	CrashLogInterval time.Duration
	// CrashLogs makes the crash-log source for a connection. The default
	// reads the logs through the API server.
	CrashLogs func(conn *cluster.Conn) CrashLogSource
	// FailbackInterval is how often, while another controller is used, the
	// kubeconfig's server is tried again; after answering twice in a row
	// it is used again.
	FailbackInterval time.Duration
	// FailoverAfter is how many checks in a row must fail before another
	// controller is tried.
	FailoverAfter int
	// Packs are the product packs: their checks, texts and names. Nil for
	// none.
	Packs *pack.Registry
}

// ControlPlaneSource keeps a cluster's view of its controllers fresh.
type ControlPlaneSource interface {
	Update(ctx context.Context, nodes []*corev1.Node)
	// Latest returns the last view, or nil.
	Latest() *snapshot.ControlPlane
}

// CrashLogSource reads the logs of the last crashes of crashing containers.
type CrashLogSource interface {
	// Update reads the logs of new crashes, and returns true when it read
	// something.
	Update(ctx context.Context, pods []*corev1.Pod) bool
	// Latest returns what the logs read so far say.
	Latest() map[string]*snapshot.CrashLog
}

// MetricsSource keeps a cluster's metrics fresh.
type MetricsSource interface {
	// Update reads new metrics; services and nodes come from the cache.
	Update(ctx context.Context, services []*corev1.Service, nodes []*corev1.Node)
	// Latest returns the last metrics (nil if none) and the source's state.
	Latest() (*snapshot.Metrics, cluster.PrometheusStatus)
}

func (o *Options) defaults() {
	set := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	set(&o.MinInterval, 10*time.Second)
	set(&o.MaxInterval, 60*time.Second)
	set(&o.PingInterval, 10*time.Second)
	set(&o.UnreachableAfter, 30*time.Second)
	set(&o.ProbeInterval, 5*time.Minute)
	set(&o.RetryMin, 5*time.Second)
	set(&o.RetryMax, 2*time.Minute)
	set(&o.MetricsInterval, 60*time.Second)
	set(&o.ControlPlaneInterval, 30*time.Second)
	set(&o.FailbackInterval, time.Minute)
	set(&o.CrashLogInterval, 30*time.Second)
	if o.FailoverAfter == 0 {
		o.FailoverAfter = 2
	}
	if o.Connect == nil {
		o.Connect = cluster.Connect
	}
	if o.Metrics == nil {
		o.Metrics = func(conn *cluster.Conn) MetricsSource {
			src := metrics.NewSource(conn.Client, o.Cluster.Prometheus, o.Now)
			src.SetQueries(func() []string { return o.Packs.Current().Queries(o.Cluster.Name) })
			return src
		}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.ControlPlane == nil {
		o.ControlPlane = func(conn *cluster.Conn) ControlPlaneSource {
			return controlplane.NewSource(conn, o.Now)
		}
	}
	if o.CrashLogs == nil {
		o.CrashLogs = func(conn *cluster.Conn) CrashLogSource {
			return crashlog.NewSource(conn.Client, o.Now)
		}
	}
	if o.Timeouts.ConnectTimeout == 0 {
		o.Timeouts = config.DefaultScan()
	}
	if o.Thresholds.CrashLoopRestarts == 0 {
		o.Thresholds = config.DefaultThresholds()
	}
}

// tracked is the lifecycle of one finding across evaluations.
type tracked struct {
	last      *findings.Finding
	firstSeen time.Time
	missing   int
	priority  findings.Priority
	title     string
}

// Engine monitors one cluster. Create it with New and call Run.
type Engine struct {
	o     Options
	state atomic.Pointer[State]
	conn  atomic.Pointer[cluster.Conn]

	refresh chan struct{}
	retry   chan struct{}

	// known are the controllers to fail over to; fallback is set while
	// another controller than the kubeconfig's is used (Run goroutine).
	knownMu  sync.Mutex
	known    []KnownController
	fallback *fallbackState

	// Owned by the Run goroutine.
	mu        sync.Mutex // guards tracked and restored against Refresh
	tracked   map[string]*tracked
	restored  map[string]time.Time
	userState map[string]UserState
	evaluated bool
}

// New creates an engine. Nothing happens until Run.
func New(o Options) *Engine {
	o.defaults()
	e := &Engine{
		o:       o,
		refresh: make(chan struct{}, 1),
		retry:   make(chan struct{}, 1),
		tracked: map[string]*tracked{},
	}
	e.state.Store(&State{Name: o.Cluster.Name, Status: StatusConnecting, Counts: emptyCounts()})
	return e
}

// Name is the cluster's name.
func (e *Engine) Name() string { return e.o.Cluster.Name }

// Cluster is the cluster's configuration.
func (e *Engine) Cluster() config.Cluster { return e.o.Cluster }

// State returns the latest published state. Do not modify it.
func (e *Engine) State() *State { return e.state.Load() }

// Conn returns the live connection, or nil while there is none. Pages use it
// for describe, events and logs.
func (e *Engine) Conn() *cluster.Conn { return e.conn.Load() }

// Refresh re-applies acknowledgements and snoozes right away, for example
// after a person changed one.
func (e *Engine) Refresh() {
	select {
	case e.refresh <- struct{}{}:
	default:
	}
}

// RefreshAndWait is Refresh, then waits (up to timeout) until the new
// state is published, so a page loaded right after shows the change.
func (e *Engine) RefreshAndWait(timeout time.Duration) {
	before := e.State()
	e.Refresh()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if e.State() != before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// RetryNow skips the wait before the next connection attempt.
func (e *Engine) RetryNow() {
	select {
	case e.retry <- struct{}{}:
	default:
	}
}

// Run monitors the cluster until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	if e.o.Store != nil {
		if open, err := e.o.Store.OpenFindings(e.Name()); err == nil {
			e.restored = open
		}
		if cs, err := e.o.Store.Controllers(e.Name()); err == nil {
			e.knownMu.Lock()
			e.known = cs
			e.knownMu.Unlock()
		}
	}
	wait := e.o.RetryMin
	var next *dialed
	for ctx.Err() == nil {
		d := next
		next = nil
		if d == nil {
			var err error
			if d, err = e.dial(ctx); err != nil {
				server := ""
				if d != nil {
					server = d.conn.Server
				}
				e.unreachable(err, server, e.o.Now().Add(wait))
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				case <-e.retry:
				case <-e.refresh:
					e.reapply()
					continue
				}
				wait = min(wait*2, e.o.RetryMax)
				continue
			}
		}
		wait = e.o.RetryMin
		again, nd := e.session(ctx, d)
		if !again {
			return
		}
		next = nd
	}
}

// session watches the cluster over one connection. It returns true when a
// new session should start (the readable kinds changed, or another
// controller is to be used: then with its connection) and false when ctx
// ended.
func (e *Engine) session(ctx context.Context, d *dialed) (bool, *dialed) {
	conn, v := d.conn, d.v
	pctx, cancel := context.WithTimeout(ctx, e.o.Timeouts.SyncTimeout.D())
	info, allowed := cluster.Probe(pctx, conn, v)
	if !e.o.Cluster.TLSSecretsOn() {
		cluster.TLSSecretsOff(info, allowed)
	}
	cancel()

	sctx, stop := context.WithCancel(ctx)
	col := collector.New(conn.Client, allowed)
	dirty := make(chan struct{}, 1)
	col.OnChange(func() {
		select {
		case dirty <- struct{}{}:
		default:
		}
	})
	col.Start(sctx)
	defer func() {
		e.conn.Store(nil)
		stop()
		col.Shutdown()
	}()

	wctx, cancel := context.WithTimeout(sctx, e.o.Timeouts.SyncTimeout.D())
	_, _ = col.WaitForSync(wctx) // kinds still loading are reported by live
	cancel()
	if ctx.Err() != nil {
		return false, nil
	}

	src := e.o.Metrics(conn)
	go e.metricsLoop(sctx, col, src, dirty)
	cps := e.o.ControlPlane(conn)
	go e.controlPlaneLoop(sctx, col, cps, dirty)
	cls := e.o.CrashLogs(conn)
	go e.crashLogLoop(sctx, col, cls, dirty)

	e.conn.Store(conn)
	wasDown := e.State().Status != StatusOK && e.State().Status != StatusPartial
	e.live(col, src, cps, cls, info, allowed)
	if wasDown {
		e.emit(Event{Type: ClusterConnected, Cluster: e.Name(), Time: e.o.Now()})
	}

	last := time.Now()
	pending := false
	lastOK := time.Now()
	down := false
	var downKind cluster.ErrorKind
	fails := 0
	var minTimer <-chan time.Time
	maxTick := time.NewTicker(e.o.MaxInterval)
	pingTick := time.NewTicker(e.o.PingInterval)
	probeTick := time.NewTicker(e.o.ProbeInterval)
	defer maxTick.Stop()
	defer pingTick.Stop()
	defer probeTick.Stop()
	// While another controller is used, the kubeconfig's server is tried
	// again now and then.
	var failback <-chan time.Time
	backOK := 0
	if conn.Fallback != nil {
		t := time.NewTicker(e.o.FailbackInterval)
		defer t.Stop()
		failback = t.C
	}

	evaluate := func() {
		pending = false
		minTimer = nil
		last = time.Now()
		if !down {
			e.live(col, src, cps, cls, info, allowed)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return false, nil
		case <-dirty:
			pending = true
			if wait := e.o.MinInterval - time.Since(last); wait <= 0 {
				evaluate()
			} else if minTimer == nil {
				minTimer = time.After(wait)
			}
		case <-minTimer:
			minTimer = nil
			if pending {
				evaluate()
			}
		case <-maxTick.C:
			evaluate()
		case <-e.refresh:
			e.reapply()
		case <-e.retry:
			// Already connected; a check now is harmless.
			pingTick.Reset(time.Millisecond)
		case <-pingTick.C:
			pingTick.Reset(e.o.PingInterval)
			pctx, cancel := context.WithTimeout(ctx, e.o.Timeouts.ConnectTimeout.D())
			_, err := conn.Ping(pctx)
			cancel()
			if err == nil {
				fails = 0
			} else if fails++; fails >= e.o.FailoverAfter && (conn.Fallback != nil || len(e.alternates(conn.Server)) > 0) {
				// The kubeconfig's server, or another controller, may answer
				// where this one doesn't.
				if nd, derr := e.dial(ctx); derr == nil && nd.conn.Server != conn.Server {
					return true, nd
				}
			}
			switch {
			case err == nil:
				lastOK = time.Now()
				if down {
					down = false
					e.conn.Store(conn)
					evaluate()
					e.emit(Event{Type: ClusterConnected, Cluster: e.Name(), Time: e.o.Now()})
				}
			case time.Since(lastOK) >= e.o.UnreachableAfter || down:
				// Publish when the cluster goes down and when the reason
				// changes, not on every failed check.
				kind := cluster.Classify(err, conn.Server, e.o.Cluster.Proxy).Kind
				if !down || kind != downKind {
					down, downKind = true, kind
					e.conn.Store(nil)
					e.unreachable(err, conn.Server, e.o.Now().Add(e.o.PingInterval))
				}
			}
		case <-failback:
			nd := e.kubeconfigServer(ctx)
			if nd == nil {
				backOK = 0
				continue
			}
			if backOK++; backOK >= 2 {
				e.fallback = nil
				return true, nd
			}
		case <-probeTick.C:
			if down {
				continue
			}
			pctx, cancel := context.WithTimeout(ctx, e.o.Timeouts.SyncTimeout.D())
			newInfo, newAllowed := cluster.Probe(pctx, conn, v)
			if !e.o.Cluster.TLSSecretsOn() {
				cluster.TLSSecretsOff(newInfo, newAllowed)
			}
			cancel()
			if !maps.Equal(allowed, newAllowed) {
				return true, nil
			}
			info = newInfo
		}
	}
}

// metricsLoop reads metrics right away and then every MetricsInterval,
// and asks for an evaluation after each read.
func (e *Engine) metricsLoop(ctx context.Context, col *collector.Collector, src MetricsSource, dirty chan<- struct{}) {
	t := time.NewTicker(e.o.MetricsInterval)
	defer t.Stop()
	for {
		svcs, nodes := col.ServicesAndNodes()
		uctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		src.Update(uctx, svcs, nodes)
		cancel()
		select {
		case dirty <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// controlPlaneLoop asks the controllers right away and then every
// ControlPlaneInterval, and asks for an evaluation after each round.
func (e *Engine) controlPlaneLoop(ctx context.Context, col *collector.Collector, src ControlPlaneSource, dirty chan<- struct{}) {
	t := time.NewTicker(e.o.ControlPlaneInterval)
	defer t.Stop()
	for {
		_, nodes := col.ServicesAndNodes()
		uctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		src.Update(uctx, nodes)
		cancel()
		e.learn(src.Latest())
		select {
		case dirty <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// crashLogLoop reads the logs of new crashes right away and then every
// CrashLogInterval, and asks for an evaluation when it read one.
func (e *Engine) crashLogLoop(ctx context.Context, col *collector.Collector, src CrashLogSource, dirty chan<- struct{}) {
	t := time.NewTicker(e.o.CrashLogInterval)
	defer t.Stop()
	for {
		uctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		read := src.Update(uctx, col.Pods())
		cancel()
		if read {
			select {
			case dirty <- struct{}{}:
			default:
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// live evaluates the rules on the current cache and publishes the result.
func (e *Engine) live(col *collector.Collector, src MetricsSource, cps ControlPlaneSource, cls CrashLogSource, info *cluster.Info, allowed map[snapshot.Kind]bool) {
	now := e.o.Now()
	synced := col.Synced()
	snap := col.Snapshot(e.Name(), now, synced)
	packs := e.o.Packs.Current()
	snap.ExpectedK0s = packs.Expected(e.Name(), e.o.Cluster.K0sVersion, e.o.Cluster.K0sVersionFrom)
	m, pst := src.Latest()
	// Metrics older than three reads are stale: their rules are skipped
	// rather than judged on old values.
	if m != nil && now.Sub(m.At) <= 3*e.o.MetricsInterval {
		snap.Metrics = m
		snap.Available[snapshot.KindMetrics] = m.ForRules()
	}
	// Likewise for the controllers' answers.
	if cp := cps.Latest(); cp != nil && now.Sub(cp.At) <= 3*e.o.ControlPlaneInterval+20*time.Second {
		snap.ControlPlane = cp
		snap.Available[snapshot.KindControlPlane] = true
	}
	snap.CrashLogs = cls.Latest()
	if fb := info.Fallback; fb != nil {
		snap.Fallback = &snapshot.Fallback{Server: cluster.Address(fb.Server), Controller: fb.Controller,
			Address: cluster.Address(info.Server), ServerIsController: fb.ServerIsController, Since: fb.Since}
		if fb.Error != nil {
			snap.Fallback.Error = fb.Error.Plain
		}
	}
	fs, skipped := rules.EvaluateRules(append(rules.All(), packs.Rules(e.Name())...), snap, e.o.Thresholds)
	packs.Apply(e.Name(), fs, snap)
	priority.Apply(fs, snap, e.o.Cluster.Criticality)
	alerts.Link(fs, snap)

	var warnings []string
	var loading []string
	for _, k := range snapshot.AllKinds {
		if allowed[k] && !synced[k] {
			loading = append(loading, string(k))
		}
	}
	if len(loading) > 0 {
		warnings = append(warnings, "still loading: "+strings.Join(loading, ", "))
	}

	infoCopy := *info
	infoCopy.Nodes = len(snap.Nodes)
	infoCopy.Pods = len(snap.Pods)
	infoCopy.Prometheus = &pst
	status := StatusOK
	if len(info.Unreadable) > 0 || len(warnings) > 0 {
		status = StatusPartial
	}
	st := &State{
		Name:     e.Name(),
		Status:   status,
		Info:     &infoCopy,
		Warnings: warnings,
		LastSync: &now,
		Skipped:  skipped,
		Snapshot: snap,
	}
	e.publish(st, fs, true)
}

// unreachable publishes the cluster as unreachable: the last findings stay,
// marked stale, next to an F01 finding that explains the failure.
func (e *Engine) unreachable(err error, server string, retryAt time.Time) {
	ce := cluster.Classify(err, server, e.o.Cluster.Proxy)
	f := cluster.Unreachable(e.Name(), ce)
	if alts := e.alternates(server); len(alts) > 0 && failsOver(ce.Kind) {
		var tried []string
		for _, k := range alts {
			tried = append(tried, strings.TrimSpace(k.Name+" "+k.Address))
		}
		f.AddFact("Other controllers tried", strings.Join(tried, ", ")+": none answers")
	}
	priority.Apply([]*findings.Finding{f}, nil, e.o.Cluster.Criticality)

	prev := e.State()
	now := e.o.Now()
	since := now
	if prev.UnreachableSince != nil {
		since = *prev.UnreachableSince
	}
	st := &State{
		Name:             e.Name(),
		Status:           StatusUnreachable,
		Info:             prev.Info,
		Error:            ce,
		LastSync:         prev.LastSync,
		UnreachableSince: &since,
		RetryAt:          &retryAt,
		Skipped:          prev.Skipped,
		Health:           prev.Health,
		HealthAt:         prev.HealthAt,
		Snapshot:         prev.Snapshot,
	}
	if prev.Status != StatusUnreachable {
		e.emit(Event{Type: ClusterDisconnected, Cluster: e.Name(), Time: now})
	}
	e.publish(st, []*findings.Finding{f}, false)
}

// publish merges new findings into the lifecycle, folds them, applies what
// people set, and publishes st. When live is false only fs (the F01
// finding) is current; everything else is kept as stale.
func (e *Engine) publish(st *State, fs []*findings.Finding, live bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.o.Now()
	initial := !e.evaluated
	e.evaluated = true

	var opened []*findings.Finding
	seen := map[string]bool{}
	for _, f := range fs {
		seen[f.ID] = true
		t := e.tracked[f.ID]
		if t == nil {
			first := now
			restored := false
			if at, ok := e.restored[f.ID]; ok {
				first, restored = at, true
			}
			t = &tracked{firstSeen: first}
			e.tracked[f.ID] = t
			if !restored {
				opened = append(opened, f)
			}
		}
		t.missing = 0
		first := t.firstSeen
		f.FirstSeen = &first
		f.LastSeen = &now
		t.last = f
	}
	// Findings that were open when the tool last ran and are gone now are
	// resolved by this first evaluation.
	if live && e.restored != nil {
		for id := range e.restored {
			if !seen[id] && e.tracked[id] == nil && e.o.Store != nil {
				_ = e.o.Store.RecordResolved(e.Name(), id, now)
				_ = e.o.Store.ClearUserState(e.Name(), id)
			}
		}
		e.restored = nil
	}

	all := append([]*findings.Finding(nil), fs...)
	var resolved []*findings.Finding
	for id, t := range e.tracked {
		if seen[id] {
			continue
		}
		if !live {
			c := t.last.Clone()
			c.Stale = true
			all = append(all, c)
			continue
		}
		t.missing++
		// A condition must be absent twice before it counts as resolved,
		// so a finding does not flap. The unreachable finding resolves as
		// soon as the cluster answers.
		if t.missing >= 2 || t.last.RuleID == cluster.UnreachableRuleID {
			resolved = append(resolved, t.last)
			delete(e.tracked, id)
			continue
		}
		c := t.last.Clone()
		t.last = c
		all = append(all, c)
	}

	all = correlate.Fold(all)
	e.userState = e.loadUserStates()
	e.applyUserStates(all, now)

	// Events, after folding, which can raise a root's priority.
	var events []Event
	isOpened := map[string]bool{}
	for _, f := range opened {
		isOpened[f.ID] = true
	}
	for _, f := range all {
		t := e.tracked[f.ID]
		if t == nil || f.Stale {
			continue
		}
		switch {
		case isOpened[f.ID]:
			events = append(events, Event{Type: FindingOpened, Cluster: e.Name(), Finding: f.Clone(), Initial: initial, Time: now})
			if e.o.Store != nil {
				_ = e.o.Store.RecordOpen(f)
			}
		case t.priority != "" && (t.priority != f.Priority || t.title != f.Title):
			events = append(events, Event{Type: FindingUpdated, Cluster: e.Name(), Finding: f.Clone(), Previous: t.priority, Time: now})
			if e.o.Store != nil {
				_ = e.o.Store.RecordOpen(f)
			}
		}
		t.priority = f.Priority
		t.title = f.Title
	}
	for _, f := range resolved {
		c := f.Clone()
		c.State = findings.StateResolved
		events = append(events, Event{Type: FindingResolved, Cluster: e.Name(), Finding: c, Time: now})
		if e.o.Store != nil {
			_ = e.o.Store.RecordResolved(e.Name(), f.ID, now)
			_ = e.o.Store.ClearUserState(e.Name(), f.ID)
		}
	}

	st.Findings = all
	st.Counts, st.Symptoms, st.Suggestions = count(all)
	prev := e.State()
	if live {
		h := priority.HealthOf(all)
		st.Health = &h
		st.HealthAt = &now
		st.Evals = prev.Evals + 1
		if prev.Health == nil || prev.Health.Score != h.Score {
			events = append(events, Event{Type: HealthChanged, Cluster: e.Name(), Time: now})
		}
	} else {
		st.Evals = prev.Evals
	}
	e.state.Store(st)
	for _, ev := range events {
		e.emit(ev)
	}
	e.emit(Event{Type: StateChanged, Cluster: e.Name(), Time: now})
}

// reapply publishes the current findings again with fresh user states.
func (e *Engine) reapply() {
	e.mu.Lock()
	prev := e.State()
	cp := *prev
	cp.Findings = make([]*findings.Finding, len(prev.Findings))
	for i, f := range prev.Findings {
		cp.Findings[i] = f.Clone()
	}
	e.userState = e.loadUserStates()
	e.applyUserStates(cp.Findings, e.o.Now())
	e.state.Store(&cp)
	e.mu.Unlock()
	e.emit(Event{Type: StateChanged, Cluster: e.Name(), Time: e.o.Now()})
}

func (e *Engine) loadUserStates() map[string]UserState {
	if e.o.Store == nil {
		return nil
	}
	us, err := e.o.Store.UserStates(e.Name())
	if err != nil {
		return e.userState
	}
	return us
}

// applyUserStates sets State on each finding. A snooze that ended, or a
// finding that got worse since it was acknowledged or snoozed, returns to
// open.
func (e *Engine) applyUserStates(fs []*findings.Finding, now time.Time) {
	for _, f := range fs {
		f.State = findings.StateOpen
		f.SnoozedUntil = nil
		f.StateBy = ""
		us, ok := e.userState[f.ID]
		if !ok {
			continue
		}
		expired := us.State == findings.StateSnoozed && us.Until != nil && !now.Before(*us.Until)
		worse := us.Priority != "" && f.Priority.Rank() < us.Priority.Rank()
		if expired || worse {
			delete(e.userState, f.ID)
			if e.o.Store != nil {
				_ = e.o.Store.ClearUserState(e.Name(), f.ID)
			}
			continue
		}
		f.State = us.State
		f.SnoozedUntil = us.Until
		f.StateBy = us.By
	}
}

func (e *Engine) emit(ev Event) {
	if e.o.OnEvent != nil {
		e.o.OnEvent(ev)
	}
}

func emptyCounts() map[findings.Priority]int {
	return map[findings.Priority]int{findings.P1: 0, findings.P2: 0, findings.P3: 0, findings.P4: 0}
}

// count returns root causes by priority and the number of symptoms.
func count(fs []*findings.Finding) (roots map[findings.Priority]int, symptoms, suggestions int) {
	roots = emptyCounts()
	for _, f := range fs {
		switch {
		case f.IsSymptom():
			symptoms++
		case f.IsHygiene():
			suggestions++
		default:
			roots[f.Priority]++
		}
	}
	return roots, symptoms, suggestions
}
