// Package fleet runs one engine per cluster. Each cluster is scanned on its
// own, so a slow or unreachable cluster never delays or breaks the others.
package fleet

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

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

// Status of one cluster in a scan.
type Status string

const (
	StatusOK          Status = "ok"
	StatusPartial     Status = "partial"
	StatusUnreachable Status = "unreachable"
)

// ClusterResult is the outcome of scanning one cluster.
type ClusterResult struct {
	Name     string                    `json:"name"`
	Status   Status                    `json:"status"`
	Info     *cluster.Info             `json:"info,omitempty"`
	Error    *cluster.ConnError        `json:"error,omitempty"`
	Warnings []string                  `json:"warnings,omitempty"`
	Skipped  []rules.Skipped           `json:"skippedRules,omitempty"`
	Findings []*findings.Finding       `json:"findings"`
	Counts   map[findings.Priority]int `json:"counts"`
	Symptoms int                       `json:"foldedSymptoms"`
	// Suggestions counts the good-practice findings, which Counts leaves
	// out.
	Suggestions int    `json:"suggestions"`
	Duration    string `json:"duration"`
}

// Manager scans the configured clusters.
type Manager struct {
	Config  *config.Config
	Connect cluster.Connector
	Now     func() time.Time
	// Packs are the product packs to apply; nil for none.
	Packs *pack.Set
}

// NewManager returns a manager that connects with cluster.Connect.
func NewManager(cfg *config.Config) *Manager {
	return &Manager{Config: cfg, Connect: cluster.Connect, Now: time.Now}
}

// Scan scans the named clusters (all when names is empty) concurrently and
// returns the results in configuration order.
func (m *Manager) Scan(ctx context.Context, names []string) ([]*ClusterResult, error) {
	var targets []config.Cluster
	if len(names) == 0 {
		targets = m.Config.Clusters
	} else {
		for _, n := range names {
			c, ok := m.Config.Cluster(n)
			if !ok {
				return nil, fmt.Errorf("unknown cluster %q", n)
			}
			targets = append(targets, c)
		}
	}
	results := make([]*ClusterResult, len(targets))
	var wg sync.WaitGroup
	for i, c := range targets {
		wg.Add(1)
		go func(i int, c config.Cluster) {
			defer wg.Done()
			results[i] = m.scanOne(ctx, c)
		}(i, c)
	}
	wg.Wait()
	return results, nil
}

func (m *Manager) scanOne(ctx context.Context, c config.Cluster) *ClusterResult {
	start := m.Now()
	res := &ClusterResult{Name: c.Name, Status: StatusOK}
	defer func() { res.Duration = m.Now().Sub(start).Round(time.Millisecond).String() }()

	fail := func(err error, server string) *ClusterResult {
		ce := cluster.Classify(err, server, "")
		res.Status = StatusUnreachable
		res.Error = ce
		f := Unreachable(c.Name, ce)
		priority.Apply([]*findings.Finding{f}, nil, c.Criticality)
		res.Findings = []*findings.Finding{f}
		res.Counts = countRoots(res.Findings)
		return res
	}

	conn, err := m.Connect(c, m.Config.Scan.ConnectTimeout.D())
	if err != nil {
		return fail(err, "")
	}
	pingCtx, cancel := context.WithTimeout(ctx, m.Config.Scan.ConnectTimeout.D())
	v, err := conn.Ping(pingCtx)
	cancel()
	if err != nil {
		return fail(err, conn.Server)
	}

	probeCtx, cancel := context.WithTimeout(ctx, m.Config.Scan.SyncTimeout.D())
	info, allowed := cluster.Probe(probeCtx, conn, v)
	if !c.TLSSecretsOn() {
		cluster.TLSSecretsOff(info, allowed)
	}
	cancel()
	res.Info = info

	runCtx, stop := context.WithCancel(ctx)
	col := collector.New(conn.Client, allowed)
	col.Start(runCtx)
	syncCtx, cancel := context.WithTimeout(runCtx, m.Config.Scan.SyncTimeout.D())
	synced, err := col.WaitForSync(syncCtx)
	cancel()
	if err != nil {
		res.Status = StatusPartial
		res.Warnings = append(res.Warnings, err.Error())
	}
	snap := col.Snapshot(c.Name, m.Now(), synced)
	snap.ExpectedK0s = m.Packs.Expected(c.Name, c.K0sVersion, c.K0sVersionFrom)
	// Read the metrics once, for the disk, volume and VM rules.
	src := metrics.NewSource(conn.Client, c.Prometheus, m.Now)
	src.SetQueries(func() []string { return m.Packs.Queries(c.Name) })
	mctx, cancel := context.WithTimeout(runCtx, m.Config.Scan.SyncTimeout.D())
	src.Update(mctx, snap.Services, snap.Nodes)
	cancel()
	mt, pst := src.Latest()
	info.Prometheus = &pst
	if mt != nil {
		snap.Metrics = mt
		snap.Available[snapshot.KindMetrics] = mt.ForRules()
	}
	// Ask each controller once, for the control plane rules.
	cps := controlplane.NewSource(conn, m.Now)
	cctx, cancel := context.WithTimeout(runCtx, m.Config.Scan.SyncTimeout.D())
	cps.Update(cctx, snap.Nodes)
	cancel()
	if cp := cps.Latest(); cp != nil {
		snap.ControlPlane = cp
		snap.Available[snapshot.KindControlPlane] = true
	}
	// Read the logs of the last crashes, to explain them.
	cls := crashlog.NewSource(conn.Client, m.Now)
	lctx, cancel := context.WithTimeout(runCtx, m.Config.Scan.SyncTimeout.D())
	for i := 0; i < 3 && cls.Update(lctx, snap.Pods); i++ {
	}
	cancel()
	snap.CrashLogs = cls.Latest()
	stop()
	col.Shutdown()

	info.Nodes = len(snap.Nodes)
	info.Pods = len(snap.Pods)
	if len(info.Unreadable) > 0 && res.Status == StatusOK {
		res.Status = StatusPartial
	}

	fs, skipped := rules.EvaluateRules(append(rules.All(), m.Packs.Rules(c.Name)...), snap, m.Config.Thresholds)
	m.Packs.Apply(c.Name, fs, snap)
	priority.Apply(fs, snap, c.Criticality)
	alerts.Link(fs, snap)
	res.Findings = correlate.Fold(fs)
	res.Skipped = skipped
	res.Counts = countRoots(res.Findings)
	for _, f := range res.Findings {
		switch {
		case f.IsSymptom():
			res.Symptoms++
		case f.IsHygiene():
			res.Suggestions++
		}
	}
	return res
}

// EvaluateSnapshot runs rules, scoring and folding on a snapshot. It is the
// same pipeline Scan uses after collection.
func EvaluateSnapshot(s *snapshot.Snapshot, t config.Thresholds, criticality string) ([]*findings.Finding, []rules.Skipped) {
	fs, skipped := rules.Evaluate(s, t)
	priority.Apply(fs, s, criticality)
	alerts.Link(fs, s)
	return correlate.Fold(fs), skipped
}

func countRoots(fs []*findings.Finding) map[findings.Priority]int {
	out := map[findings.Priority]int{findings.P1: 0, findings.P2: 0, findings.P3: 0, findings.P4: 0}
	for _, f := range fs {
		if !f.IsSymptom() && !f.IsHygiene() {
			out[f.Priority]++
		}
	}
	return out
}

// Totals sums root-cause counts over several clusters.
func Totals(results []*ClusterResult) map[findings.Priority]int {
	out := map[findings.Priority]int{findings.P1: 0, findings.P2: 0, findings.P3: 0, findings.P4: 0}
	for _, r := range results {
		for p, n := range r.Counts {
			out[p] += n
		}
	}
	return out
}

// Worst returns the most urgent priority among root causes, or "" if none.
func Worst(results []*ClusterResult) findings.Priority {
	var ps []findings.Priority
	for p, n := range Totals(results) {
		if n > 0 {
			ps = append(ps, p)
		}
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].Rank() < ps[j].Rank() })
	if len(ps) == 0 {
		return ""
	}
	return ps[0]
}
