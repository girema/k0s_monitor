// Package metrics reads the values the M2 rules need from a cluster's
// Prometheus: volume usage and growth, node filesystems, CPU steal and
// iowait, disk latency, clock, reboots, memory and swap, and container
// memory and CPU throttling (plan section 6.1).
package metrics

import (
	"context"
	"errors"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/prom"
	"k0s_monitor/internal/snapshot"
)

// k0sUnits are k0s's own services. k0s runs containerd itself, inside the
// worker's service, so containerd has no unit of its own on a k0s host.
const k0sUnits = `k0s(worker|controller)\\.service`

func sortedServiceKeys(m map[string]*snapshot.ServiceState) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// virtualNICs are network interfaces that come and go with pods and
// tunnels: their links changing says nothing about the server's network.
const virtualNICs = `lo|veth.*|cali.*|cilium.*|lxc.*|flannel.*|cni.*|docker.*|kube-.*|vxlan.*|tunl.*|genev.*|wg.*|br-.*|virbr.*|tap.*|tun.*|nodelocaldns|dummy.*`

// Filesystems that are not disks.
const fsFilter = `fstype!~"tmpfs|ramfs|squashfs|overlay|nsfs|fuse\\..*|autofs|proc|sysfs|devtmpfs|cgroup2?|rpc_pipefs|iso9660|tracefs|securityfs|debugfs|bpf|configfs|pstore|mqueue|hugetlbfs|binfmt_misc"`

const containerFilter = `container!="",container!="POD"`

// Reader reads metrics through one Prometheus client. It caches the
// expensive history queries: volume growth for 5 minutes, and the 7-day
// baselines and peaks for an hour.
type Reader struct {
	c   *prom.Client
	now func() time.Time

	mu        sync.Mutex
	growthAt  time.Time
	growth    map[string]*snapshot.Growth
	volHist   map[string][]snapshot.Point
	fsAt      time.Time
	fsHist    []prom.Series
	weeklyAt  time.Time
	baseline  map[string]float64
	peaks     map[string]float64
	queryTime time.Duration
}

// NewReader returns a reader. now may be nil.
func NewReader(c *prom.Client, now func() time.Time) *Reader {
	if now == nil {
		now = time.Now
	}
	return &Reader{c: c, now: now}
}

// query is one instant query and what to do with its samples.
type query struct {
	q     string
	apply func([]prom.Sample)
}

// Read runs the queries. It fails only when Prometheus can't be queried at
// all; missing metrics just stay missing.
func (r *Reader) Read(ctx context.Context, nodes []*corev1.Node) (*snapshot.Metrics, error) {
	now := r.now()
	m := &snapshot.Metrics{
		Source:     r.c.Target.String(),
		At:         now,
		Volumes:    map[string]*snapshot.VolumeMetrics{},
		Nodes:      map[string]*snapshot.NodeMetrics{},
		Containers: map[string]*snapshot.ContainerMetrics{},
		Have:       map[string]bool{},
	}
	// First the node-exporter identities, so every other node metric can
	// be matched to a Node.
	unames, err := r.c.Query(ctx, `node_uname_info`, now)
	if err != nil {
		return nil, err
	}
	nm := newNodeMap(nodes, unames)
	m.Unmapped = nm.unmapped
	if len(unames) > 0 {
		m.Have["node-exporter"] = true
	}
	// A node with node-exporter data reports, whatever its scrape job is
	// called ("node", "node-exporter", ...); the up query below marks the
	// ones whose exporter can't be scraped right now.
	for _, u := range unames {
		if name, ok := nm.node(u.Labels); ok && m.Nodes[name] == nil {
			n := snapshot.NewNodeMetrics(u.Labels["instance"])
			n.Up = true
			m.Nodes[name] = n
		}
	}
	node := func(s prom.Sample) *snapshot.NodeMetrics {
		name, ok := nm.node(s.Labels)
		if !ok {
			return nil
		}
		n := m.Nodes[name]
		if n == nil {
			n = snapshot.NewNodeMetrics(s.Labels["instance"])
			m.Nodes[name] = n
		}
		return n
	}
	vol := func(s prom.Sample) *snapshot.VolumeMetrics {
		ns, pvc := s.Labels["namespace"], s.Labels["persistentvolumeclaim"]
		if ns == "" || pvc == "" {
			return nil
		}
		v := m.Volumes[ns+"/"+pvc]
		if v == nil {
			v = &snapshot.VolumeMetrics{Used: snapshot.Missing, Capacity: snapshot.Missing, InodesUsed: snapshot.Missing, Inodes: snapshot.Missing}
			m.Volumes[ns+"/"+pvc] = v
		}
		return v
	}
	ctr := func(s prom.Sample) *snapshot.ContainerMetrics {
		key := s.Labels["namespace"] + "/" + s.Labels["pod"] + "/" + s.Labels["container"]
		if s.Labels["pod"] == "" || s.Labels["container"] == "" {
			return nil
		}
		c := m.Containers[key]
		if c == nil {
			c = snapshot.NewContainerMetrics()
			m.Containers[key] = c
		}
		return c
	}
	services := map[string]*snapshot.ServiceState{} // instance/unit
	service := func(node string, l map[string]string) *snapshot.ServiceState {
		key := l["instance"] + "/" + l["name"]
		s := services[key]
		if s == nil {
			s = &snapshot.ServiceState{Node: node, Instance: l["instance"], Unit: l["name"], Restarts15m: snapshot.Missing}
			services[key] = s
		}
		return s
	}
	fs := map[string]map[string]*snapshot.Filesystem{} // node -> mountpoint
	fsOf := func(s prom.Sample) *snapshot.Filesystem {
		name, ok := nm.node(s.Labels)
		if !ok {
			return nil
		}
		mp := s.Labels["mountpoint"]
		if fs[name] == nil {
			fs[name] = map[string]*snapshot.Filesystem{}
		}
		f := fs[name][mp]
		if f == nil {
			f = &snapshot.Filesystem{Mountpoint: mp, Device: s.Labels["device"], FSType: s.Labels["fstype"],
				Size: snapshot.Missing, Avail: snapshot.Missing, Files: snapshot.Missing, FilesFree: snapshot.Missing}
			fs[name][mp] = f
		}
		return f
	}

	byVol := `max by (namespace, persistentvolumeclaim) `
	byCtr := `max by (namespace, pod, container) `
	qs := []query{
		{`max by (instance) (up)`, func(ss []prom.Sample) {
			// Only the node-exporter's own targets: other jobs, such as
			// the kubelet's, can have the node's address too.
			for _, s := range ss {
				if name, ok := nm.byInstance[s.Labels["instance"]]; ok && m.Nodes[name] != nil {
					m.Nodes[name].Up = s.Value == 1
				}
			}
		}},
		{byVol + `(kubelet_volume_stats_used_bytes)`, func(ss []prom.Sample) {
			for _, s := range ss {
				if v := vol(s); v != nil {
					v.Used = s.Value
				}
			}
		}},
		{byVol + `(kubelet_volume_stats_capacity_bytes)`, func(ss []prom.Sample) {
			if len(ss) > 0 {
				m.Have["kubelet-volumes"] = true
			}
			for _, s := range ss {
				if v := vol(s); v != nil {
					v.Capacity = s.Value
				}
			}
		}},
		{byVol + `(kubelet_volume_stats_inodes_used)`, func(ss []prom.Sample) {
			for _, s := range ss {
				if v := vol(s); v != nil {
					v.InodesUsed = s.Value
				}
			}
		}},
		{byVol + `(kubelet_volume_stats_inodes)`, func(ss []prom.Sample) {
			for _, s := range ss {
				if v := vol(s); v != nil {
					v.Inodes = s.Value
				}
			}
		}},
		{`max by (instance, node, mountpoint, device, fstype) (node_filesystem_size_bytes{` + fsFilter + `})`, func(ss []prom.Sample) {
			for _, s := range ss {
				if f := fsOf(s); f != nil {
					f.Size = s.Value
				}
			}
		}},
		{`max by (instance, node, mountpoint, device, fstype) (node_filesystem_avail_bytes{` + fsFilter + `})`, func(ss []prom.Sample) {
			for _, s := range ss {
				if f := fsOf(s); f != nil {
					f.Avail = s.Value
				}
			}
		}},
		{`max by (instance, node, mountpoint, device, fstype) (node_filesystem_files{` + fsFilter + `})`, func(ss []prom.Sample) {
			for _, s := range ss {
				if f := fsOf(s); f != nil {
					f.Files = s.Value
				}
			}
		}},
		{`max by (instance, node, mountpoint, device, fstype) (node_filesystem_files_free{` + fsFilter + `})`, func(ss []prom.Sample) {
			for _, s := range ss {
				if f := fsOf(s); f != nil {
					f.FilesFree = s.Value
				}
			}
		}},
		{`max by (instance, node, mountpoint, device, fstype) (node_filesystem_readonly{` + fsFilter + `})`, func(ss []prom.Sample) {
			for _, s := range ss {
				if f := fsOf(s); f != nil {
					f.ReadOnly = s.Value == 1
				}
			}
		}},
		{`count by (instance, node) (node_cpu_seconds_total{mode="idle"})`, func(ss []prom.Sample) {
			for _, s := range ss {
				if n := node(s); n != nil {
					n.CPUs = s.Value
				}
			}
		}},
		{`avg by (instance, node) (rate(node_cpu_seconds_total{mode="steal"}[5m]))`, func(ss []prom.Sample) {
			for _, s := range ss {
				if n := node(s); n != nil {
					n.CPUSteal = s.Value
				}
			}
		}},
		{`avg by (instance, node) (rate(node_cpu_seconds_total{mode="iowait"}[5m]))`, func(ss []prom.Sample) {
			for _, s := range ss {
				if n := node(s); n != nil {
					n.CPUIOWait = s.Value
				}
			}
		}},
		{`1 - avg by (instance, node) (rate(node_cpu_seconds_total{mode="idle"}[15m]))`, func(ss []prom.Sample) {
			for _, s := range ss {
				if n := node(s); n != nil {
					n.CPUBusy15m = s.Value
				}
			}
		}},
		{`max by (instance, node) (node_memory_MemTotal_bytes)`, func(ss []prom.Sample) {
			for _, s := range ss {
				if n := node(s); n != nil {
					n.MemTotal = s.Value
				}
			}
		}},
		{`max by (instance, node) (avg_over_time(node_memory_MemAvailable_bytes[15m]))`, func(ss []prom.Sample) {
			for _, s := range ss {
				if n := node(s); n != nil {
					n.MemAvailable15m = s.Value
				}
			}
		}},
		{`max by (instance, node) (node_memory_SwapTotal_bytes)`, func(ss []prom.Sample) {
			for _, s := range ss {
				if n := node(s); n != nil {
					n.SwapTotal = s.Value
				}
			}
		}},
		{`max by (instance, node) (node_memory_SwapFree_bytes)`, func(ss []prom.Sample) {
			for _, s := range ss {
				if n := node(s); n != nil {
					n.SwapFree = s.Value
				}
			}
		}},
		{`max by (instance, node, device) (rate(node_disk_read_time_seconds_total[5m]) / rate(node_disk_reads_completed_total[5m]) > 0)`, func(ss []prom.Sample) {
			for _, s := range ss {
				if n := node(s); n != nil {
					if !snapshot.Known(n.DiskReadLatency) || s.Value > n.DiskReadLatency {
						n.DiskReadLatency = s.Value
					}
					noteWorstDisk(n, s)
				}
			}
		}},
		{`max by (instance, node, device) (rate(node_disk_write_time_seconds_total[5m]) / rate(node_disk_writes_completed_total[5m]) > 0)`, func(ss []prom.Sample) {
			for _, s := range ss {
				if n := node(s); n != nil {
					if !snapshot.Known(n.DiskWriteLatency) || s.Value > n.DiskWriteLatency {
						n.DiskWriteLatency = s.Value
					}
					noteWorstDisk(n, s)
				}
			}
		}},
		{`max by (instance, node) (node_timex_offset_seconds)`, func(ss []prom.Sample) {
			if len(ss) > 0 {
				m.Have["timex"] = true
			}
			for _, s := range ss {
				if n := node(s); n != nil {
					n.ClockOffset = s.Value
				}
			}
		}},
		{`min by (instance, node) (node_timex_sync_status)`, func(ss []prom.Sample) {
			for _, s := range ss {
				if n := node(s); n != nil {
					n.ClockSynced = s.Value
				}
			}
		}},
		{`max by (instance, node, name, state) (node_systemd_unit_state{name=~"` + k0sUnits + `"}) == 1`, func(ss []prom.Sample) {
			for _, s := range ss {
				name, _ := nm.node(s.Labels)
				svc := service(name, s.Labels)
				svc.State = s.Labels["state"]
			}
		}},
		{`max by (instance, node, name) (increase(node_systemd_service_restart_total{name=~"` + k0sUnits + `"}[15m]))`, func(ss []prom.Sample) {
			for _, s := range ss {
				name, _ := nm.node(s.Labels)
				service(name, s.Labels).Restarts15m = s.Value
			}
		}},
		{`max by (instance, node) (increase(node_vmstat_oom_kill[15m]))`, func(ss []prom.Sample) {
			for _, s := range ss {
				if n := node(s); n != nil {
					n.OOMKills15m = s.Value
				}
			}
		}},
		{`max by (instance, node, device) (increase(node_network_carrier_changes_total{device!~"` + virtualNICs + `"}[15m]) > 0)`, func(ss []prom.Sample) {
			for _, s := range ss {
				if n := node(s); n != nil {
					if n.LinkFlaps == nil {
						n.LinkFlaps = map[string]float64{}
					}
					n.LinkFlaps[s.Labels["device"]] = s.Value
				}
			}
		}},
		{`max by (instance, node) (node_boot_time_seconds)`, func(ss []prom.Sample) {
			for _, s := range ss {
				if n := node(s); n != nil && s.Value > 0 {
					n.BootTime = time.Unix(int64(s.Value), 0).UTC()
				}
			}
		}},
		{byCtr + `(avg_over_time(container_memory_working_set_bytes{` + containerFilter + `}[10m]))`, func(ss []prom.Sample) {
			if len(ss) > 0 {
				m.Have["cadvisor"] = true
			}
			for _, s := range ss {
				if c := ctr(s); c != nil {
					c.WorkingSet = s.Value
				}
			}
		}},
		{`sum by (namespace, pod, container) (rate(container_cpu_cfs_throttled_periods_total{` + containerFilter + `}[15m])) / sum by (namespace, pod, container) (rate(container_cpu_cfs_periods_total{` + containerFilter + `}[15m]))`, func(ss []prom.Sample) {
			for _, s := range ss {
				if c := ctr(s); c != nil {
					c.Throttled = s.Value
				}
			}
		}},
	}
	if err := r.runAll(ctx, now, qs); err != nil {
		return nil, err
	}
	for _, key := range sortedServiceKeys(services) {
		// A restart count alone, without a state, is a unit that isn't on
		// this host any more.
		if s := services[key]; s.State != "" {
			m.Services = append(m.Services, *s)
			m.Have["systemd"] = true
		}
	}
	for name, byMount := range fs {
		n := m.Nodes[name]
		if n == nil {
			continue
		}
		mps := make([]string, 0, len(byMount))
		for mp := range byMount {
			mps = append(mps, mp)
		}
		sort.Strings(mps)
		for _, mp := range mps {
			if f := byMount[mp]; snapshot.Known(f.Size) && snapshot.Known(f.Avail) && f.Size > 0 {
				n.Filesystems = append(n.Filesystems, *f)
			}
		}
	}
	r.history(ctx, now, m, nm)
	r.alerts(ctx, now, m)
	return m, nil
}

// maxAlerts caps how many firing alerts are kept.
const maxAlerts = 500

// alerts reads the firing alerts: from the alerts API, which has their
// annotations, else from the ALERTS series. Neither working leaves
// AlertsRead false.
func (r *Reader) alerts(ctx context.Context, now time.Time, m *snapshot.Metrics) {
	actx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	as, err := r.c.Alerts(actx)
	m.AlertsFrom = "alerts API"
	if err != nil {
		if as, err = r.c.FiringAlerts(actx, now); err != nil {
			return
		}
		m.AlertsFrom = "ALERTS series"
	}
	m.AlertsRead = true
	for _, a := range as {
		name, sev := a.Labels["alertname"], a.Labels["severity"]
		if a.State != "firing" || name == "" || snapshot.IsHeartbeat(name, sev) {
			continue
		}
		labels := make(map[string]string, len(a.Labels))
		for k, v := range a.Labels {
			if k != "alertname" {
				labels[k] = v
			}
		}
		m.Alerts = append(m.Alerts, snapshot.Alert{Name: name, Severity: sev, Labels: labels,
			Summary: a.Annotations["summary"], Description: a.Annotations["description"], Runbook: a.Annotations["runbook_url"],
			Since: a.ActiveAt})
	}
	snapshot.SortAlerts(m.Alerts)
	if len(m.Alerts) > maxAlerts {
		m.Alerts = m.Alerts[:maxAlerts]
	}
}

// runAll runs the queries a few at a time. The first query error that
// isn't about a single query (for example a connection error) fails the
// read; a query Prometheus rejects is skipped.
func (r *Reader) runAll(ctx context.Context, now time.Time, qs []query) error {
	type result struct {
		i   int
		ss  []prom.Sample
		err error
	}
	results := make([]result, len(qs))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, q := range qs {
		wg.Add(1)
		go func(i int, q query) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			qctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			ss, err := r.c.Query(qctx, q.q, now)
			results[i] = result{i: i, ss: ss, err: err}
		}(i, q)
	}
	wg.Wait()
	for _, res := range results {
		if res.err != nil {
			var perr *prom.Error
			if errors.As(res.err, &perr) {
				continue
			}
			return res.err
		}
		qs[res.i].apply(res.ss)
	}
	return nil
}

// ReadQueries runs the product packs' queries. Each result is kept by its
// query; a query Prometheus refuses, or that takes too long, has its error
// kept instead.
func (r *Reader) ReadQueries(ctx context.Context, qs []string) (map[string][]snapshot.Sample, map[string]string) {
	now := r.now()
	results := map[string][]snapshot.Sample{}
	errs := map[string]string{}
	var mu sync.Mutex
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, q := range qs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			qctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			ss, err := r.c.Query(qctx, q, now)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs[q] = err.Error()
				return
			}
			out := make([]snapshot.Sample, 0, len(ss))
			for _, x := range ss {
				out = append(out, snapshot.Sample{Labels: x.Labels, Value: x.Value})
			}
			results[q] = out
		}()
	}
	wg.Wait()
	return results, errs
}

// noteWorstDisk remembers the device with the slowest operations.
func noteWorstDisk(n *snapshot.NodeMetrics, s prom.Sample) {
	worst := math.Max(orZero(n.DiskReadLatency), orZero(n.DiskWriteLatency))
	if s.Value >= worst {
		n.DiskDevice = s.Labels["device"]
	}
}

func orZero(v float64) float64 {
	if snapshot.Known(v) {
		return v
	}
	return 0
}

// history adds volume growth and the last 24 hours of volume and node
// filesystem usage, 7-day growth baselines and memory peaks, from cached
// range queries. Failures leave them out.
func (r *Reader) history(ctx context.Context, now time.Time, m *snapshot.Metrics, nm *nodeMap) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(m.Volumes) > 0 && now.Sub(r.growthAt) >= 5*time.Minute {
		hctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		series, err := r.c.QueryRange(hctx, `max by (namespace, persistentvolumeclaim) (kubelet_volume_stats_used_bytes)`,
			now.Add(-24*time.Hour), now, 10*time.Minute)
		cancel()
		if err == nil {
			r.growth = map[string]*snapshot.Growth{}
			r.volHist = map[string][]snapshot.Point{}
			for _, s := range series {
				key := s.Labels["namespace"] + "/" + s.Labels["persistentvolumeclaim"]
				if g := fitGrowth(s.Points, now); g != nil {
					r.growth[key] = g
				}
				r.volHist[key] = points(s.Points)
			}
			r.growthAt = now
		}
	}
	if m.Have["node-exporter"] && now.Sub(r.fsAt) >= 5*time.Minute {
		hctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		series, err := r.c.QueryRange(hctx, `max by (instance, node, mountpoint) (1 - node_filesystem_avail_bytes{`+fsFilter+`} / node_filesystem_size_bytes{`+fsFilter+`})`,
			now.Add(-24*time.Hour), now, 10*time.Minute)
		cancel()
		if err == nil {
			r.fsHist, r.fsAt = series, now
		}
	}
	for _, s := range r.fsHist {
		name, ok := nm.node(s.Labels)
		if n := m.Nodes[name]; ok && n != nil {
			if n.FSHistory == nil {
				n.FSHistory = map[string][]snapshot.Point{}
			}
			n.FSHistory[s.Labels["mountpoint"]] = points(s.Points)
		}
	}
	if now.Sub(r.weeklyAt) >= time.Hour {
		wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		base, err1 := r.c.Query(wctx, `max by (namespace, persistentvolumeclaim) (deriv(kubelet_volume_stats_used_bytes[7d]))`, now)
		peaks, err2 := r.c.Query(wctx, `max by (namespace, pod, container) (max_over_time(container_memory_working_set_bytes{`+containerFilter+`}[7d:30m]))`, now)
		cancel()
		if err1 == nil || err2 == nil {
			r.weeklyAt = now
		}
		if err1 == nil {
			r.baseline = map[string]float64{}
			for _, s := range base {
				r.baseline[s.Labels["namespace"]+"/"+s.Labels["persistentvolumeclaim"]] = s.Value * 3600
			}
		}
		if err2 == nil {
			r.peaks = map[string]float64{}
			for _, s := range peaks {
				r.peaks[s.Labels["namespace"]+"/"+s.Labels["pod"]+"/"+s.Labels["container"]] = s.Value
			}
		}
	}
	for key, v := range m.Volumes {
		v.History = r.volHist[key]
		if g := r.growth[key]; g != nil {
			gc := *g
			gc.BaselineBytesPerHour = snapshot.Missing
			if b, ok := r.baseline[key]; ok {
				gc.BaselineBytesPerHour = b
			}
			v.Growth = &gc
		}
	}
	for key, c := range m.Containers {
		if p, ok := r.peaks[key]; ok {
			c.PeakWorkingSet7d = p
		}
	}
}

// points converts Prometheus points. The result is shared between reads
// and must not be changed.
func points(ps []prom.Point) []snapshot.Point {
	out := make([]snapshot.Point, len(ps))
	for i, p := range ps {
		out[i] = snapshot.Point{T: p.T, V: p.V}
	}
	return out
}

// fitGrowth fits a line to the last 6 hours of samples, and to the last 24
// hours when the 6-hour fit is poor (R² < 0.6), as in plan section 9.
func fitGrowth(points []prom.Point, now time.Time) *snapshot.Growth {
	window := func(d time.Duration) []prom.Point {
		var out []prom.Point
		for _, p := range points {
			if now.Sub(p.T) <= d {
				out = append(out, p)
			}
		}
		return out
	}
	six := window(6 * time.Hour)
	if len(six) < 12 {
		return nil
	}
	slope, r2 := linearFit(six)
	g := &snapshot.Growth{BytesPerHour: slope, Window: 6 * time.Hour, R2: r2, Samples: len(six)}
	if r2 < 0.6 {
		day := window(24 * time.Hour)
		if s24, r24 := linearFit(day); len(day) >= 12 && r24 > r2 {
			g.BytesPerHour, g.Window, g.R2, g.Samples = s24, 24*time.Hour, r24, len(day)
		}
	}
	g.RecentBytesPerHour = snapshot.Missing
	if hour := window(70 * time.Minute); len(hour) >= 4 {
		g.RecentBytesPerHour, _ = linearFit(hour)
	}
	return g
}

// linearFit returns the least-squares slope per hour and R².
func linearFit(points []prom.Point) (slope, r2 float64) {
	n := float64(len(points))
	if n < 2 {
		return 0, 0
	}
	t0 := points[0].T
	var sx, sy, sxx, sxy, syy float64
	for _, p := range points {
		x := p.T.Sub(t0).Hours()
		sx += x
		sy += p.V
		sxx += x * x
		sxy += x * p.V
		syy += p.V * p.V
	}
	den := n*sxx - sx*sx
	if den == 0 {
		return 0, 0
	}
	slope = (n*sxy - sx*sy) / den
	vy := n*syy - sy*sy
	if vy <= 0 {
		return slope, 1 // a flat line fits perfectly
	}
	r := (n*sxy - sx*sy) / math.Sqrt(den*vy)
	return slope, r * r
}

// nodeMap matches node-exporter series to Nodes: by the instance's IP, by
// the node label some setups add, by the host name node-exporter reports,
// or by the instance name itself.
type nodeMap struct {
	byInstance map[string]string
	byName     map[string]bool
	unmapped   []string
}

func newNodeMap(nodes []*corev1.Node, unames []prom.Sample) *nodeMap {
	nm := &nodeMap{byInstance: map[string]string{}, byName: map[string]bool{}}
	byAddr := map[string]string{}
	for _, n := range nodes {
		nm.byName[n.Name] = true
		for _, a := range n.Status.Addresses {
			byAddr[a.Address] = n.Name
		}
	}
	for _, u := range unames {
		inst := u.Labels["instance"]
		host := hostOf(inst)
		switch {
		case nm.byName[u.Labels["node"]]:
			nm.byInstance[inst] = u.Labels["node"]
		case byAddr[host] != "":
			nm.byInstance[inst] = byAddr[host]
		case nm.byName[u.Labels["nodename"]]:
			nm.byInstance[inst] = u.Labels["nodename"]
		case nm.byName[host]:
			nm.byInstance[inst] = host
		case byAddr[u.Labels["nodename"]] != "":
			nm.byInstance[inst] = byAddr[u.Labels["nodename"]]
		default:
			nm.unmapped = append(nm.unmapped, inst)
		}
	}
	sort.Strings(nm.unmapped)
	return nm
}

func (nm *nodeMap) node(labels map[string]string) (string, bool) {
	if n := labels["node"]; nm.byName[n] {
		return n, true
	}
	if n, ok := nm.byInstance[labels["instance"]]; ok {
		return n, true
	}
	if h := hostOf(labels["instance"]); nm.byName[h] {
		return h, true
	}
	return "", false
}

func hostOf(instance string) string {
	if h, _, err := net.SplitHostPort(instance); err == nil {
		return strings.Trim(h, "[]")
	}
	return instance
}
