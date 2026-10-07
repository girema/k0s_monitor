package snapshot

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
)

// metricsDoc is a Metrics fixture: what Prometheus would have answered,
// written the way people read it. Sizes may be quantities such as "9.5Gi".
//
//	apiVersion: k0s-monitor.io/v1
//	kind: Metrics
//	volumes:
//	  shop/data: {used: 9.5Gi, capacity: 10Gi, growthPerHour: 100Mi}
//	nodes:
//	  worker-1: {cpuSteal: 0.3, filesystems: [{mountpoint: /, size: 50Gi, avail: 4Gi}]}
//	containers:
//	  shop/api-1/api: {workingSet: 480Mi}
//	alerts:
//	- {name: KubePodCrashLooping, severity: warning, labels: {namespace: shop, pod: api-1}, summary: ..., for: 20m}
//	services:
//	- {node: worker-3, unit: k0sworker.service, state: failed}
//
// The last 24 hours of a volume follow its growth (and its 7-day baseline
// before the growth window), unless history lists values evenly spread over
// the day. A filesystem's history is its used share; it is flat unless
// history is given.
type metricsDoc struct {
	Source     string                  `json:"source"`
	Have       []string                `json:"have"`
	Volumes    map[string]volumeDoc    `json:"volumes"`
	Nodes      map[string]nodeDoc      `json:"nodes"`
	Containers map[string]containerDoc `json:"containers"`
	// Queries are results of product packs' queries, by query.
	Queries map[string][]struct {
		Labels map[string]string `json:"labels"`
		Value  float64           `json:"value"`
	} `json:"queries"`
	// Alerts fire; without the key, alerts can't be read.
	Alerts *[]alertDoc `json:"alerts"`
	// Services are systemd services from node-exporter.
	Services []struct {
		Node, Instance, Unit, State string
		Restarts15m                 num `json:"restarts15m"`
	} `json:"services"`
}

type alertDoc struct {
	Name, Severity                string
	Labels                        map[string]string
	Summary, Description, Runbook string
	// For is how long it has been firing, such as "20m".
	For string `json:"for"`
}

type volumeDoc struct {
	Used, Capacity, InodesUsed, Inodes num
	GrowthPerHour                      num    `json:"growthPerHour"`
	GrowthWindow                       string `json:"growthWindow"`
	R2                                 num    `json:"r2"`
	RecentPerHour                      num    `json:"recentPerHour"`
	BaselinePerHour                    num    `json:"baselinePerHour"`
	History                            []num  `json:"history"`
}

type fsDoc struct {
	Mountpoint, Device, FSType string
	Size, Avail, Files         num
	FilesFree                  num `json:"filesFree"`
	ReadOnly                   bool
	History                    []num
}

type nodeDoc struct {
	Instance                          string
	Up                                *bool
	Filesystems                       []fsDoc
	CPUSteal                          num `json:"cpuSteal"`
	CPUIOWait                         num `json:"cpuIOWait"`
	CPUBusy15m                        num `json:"cpuBusy15m"`
	CPUs                              num `json:"cpus"`
	MemTotal                          num `json:"memTotal"`
	MemAvailable15m                   num `json:"memAvailable15m"`
	SwapTotal, SwapFree               num
	DiskReadLatency, DiskWriteLatency num
	DiskDevice                        string
	ClockOffset, ClockSynced          num
	BootTime                          *time.Time
	OOMKills15m                       num                `json:"oomKills15m"`
	LinkFlaps                         map[string]float64 `json:"linkFlaps"`
}

type containerDoc struct {
	WorkingSet num `json:"workingSet"`
	Peak7d     num `json:"peak7d"`
	Throttled  num `json:"throttled"`
}

// num is a number or a quantity string; unset is NaN.
type num struct {
	v   float64
	set bool
}

func (n *num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		n.v, n.set = f, true
		return nil
	}
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return fmt.Errorf("%s is neither a number nor a quantity", b)
	}
	n.v, n.set = q.AsApproximateFloat64(), true
	return nil
}

func (n num) val() float64 {
	if !n.set {
		return Missing
	}
	return n.v
}

// parseMetricsDoc turns a Metrics fixture into Metrics.
func parseMetricsDoc(js []byte, now time.Time) (*Metrics, error) {
	var d metricsDoc
	if err := json.Unmarshal(js, &d); err != nil {
		return nil, err
	}
	m := &Metrics{Source: d.Source, At: now, Volumes: map[string]*VolumeMetrics{}, Nodes: map[string]*NodeMetrics{},
		Containers: map[string]*ContainerMetrics{}, Have: map[string]bool{}}
	if m.Source == "" {
		m.Source = "fixture"
	}
	for _, h := range d.Have {
		m.Have[h] = true
	}
	for k, v := range d.Volumes {
		vm := &VolumeMetrics{Used: v.Used.val(), Capacity: v.Capacity.val(), InodesUsed: v.InodesUsed.val(), Inodes: v.Inodes.val()}
		if v.GrowthPerHour.set {
			w := 6 * time.Hour
			if v.GrowthWindow != "" {
				d, err := time.ParseDuration(v.GrowthWindow)
				if err != nil {
					return nil, fmt.Errorf("volume %s: %w", k, err)
				}
				w = d
			}
			r2 := 1.0
			if v.R2.set {
				r2 = v.R2.v
			}
			vm.Growth = &Growth{BytesPerHour: v.GrowthPerHour.v, Window: w, R2: r2, Samples: 36,
				RecentBytesPerHour: v.RecentPerHour.val(), BaselineBytesPerHour: v.BaselinePerHour.val()}
		}
		switch {
		case len(v.History) > 0:
			vm.History = spread(v.History, now)
		case Known(vm.Used):
			vm.History = volumeHistory(vm, now)
		}
		m.Volumes[k] = vm
	}
	for name, n := range d.Nodes {
		nm := NewNodeMetrics(n.Instance)
		nm.Up = n.Up == nil || *n.Up
		nm.FSHistory = map[string][]Point{}
		for _, f := range n.Filesystems {
			fs := Filesystem{Mountpoint: f.Mountpoint, Device: f.Device, FSType: f.FSType,
				Size: f.Size.val(), Avail: f.Avail.val(), Files: f.Files.val(), FilesFree: f.FilesFree.val(), ReadOnly: f.ReadOnly}
			nm.Filesystems = append(nm.Filesystems, fs)
			if len(f.History) > 0 {
				nm.FSHistory[f.Mountpoint] = spread(f.History, now)
			} else if u := fs.UsedFraction(); Known(u) {
				nm.FSHistory[f.Mountpoint] = spread([]num{{v: u, set: true}, {v: u, set: true}}, now)
			}
		}
		nm.CPUSteal, nm.CPUIOWait, nm.CPUBusy15m, nm.CPUs = n.CPUSteal.val(), n.CPUIOWait.val(), n.CPUBusy15m.val(), n.CPUs.val()
		nm.MemTotal, nm.MemAvailable15m = n.MemTotal.val(), n.MemAvailable15m.val()
		nm.SwapTotal, nm.SwapFree = n.SwapTotal.val(), n.SwapFree.val()
		nm.DiskReadLatency, nm.DiskWriteLatency, nm.DiskDevice = n.DiskReadLatency.val(), n.DiskWriteLatency.val(), n.DiskDevice
		nm.ClockOffset, nm.ClockSynced = n.ClockOffset.val(), n.ClockSynced.val()
		if n.BootTime != nil {
			nm.BootTime = n.BootTime.UTC()
		}
		nm.OOMKills15m, nm.LinkFlaps = n.OOMKills15m.val(), n.LinkFlaps
		m.Nodes[name] = nm
	}
	for k, c := range d.Containers {
		m.Containers[k] = &ContainerMetrics{WorkingSet: c.WorkingSet.val(), PeakWorkingSet7d: c.Peak7d.val(), Throttled: c.Throttled.val()}
	}
	if len(d.Queries) > 0 {
		m.Queries = map[string][]Sample{}
		for q, ss := range d.Queries {
			for _, x := range ss {
				m.Queries[q] = append(m.Queries[q], Sample{Labels: x.Labels, Value: x.Value})
			}
		}
	}
	for _, s := range d.Services {
		m.Services = append(m.Services, ServiceState{Node: s.Node, Instance: s.Instance, Unit: s.Unit, State: s.State, Restarts15m: s.Restarts15m.val()})
		m.Have["systemd"] = true
	}
	if d.Alerts != nil {
		m.AlertsRead, m.AlertsFrom = true, "alerts API"
		for _, a := range *d.Alerts {
			al := Alert{Name: a.Name, Severity: a.Severity, Labels: a.Labels, Summary: a.Summary, Description: a.Description, Runbook: a.Runbook}
			if al.Labels == nil {
				al.Labels = map[string]string{}
			}
			if a.For != "" {
				d, err := time.ParseDuration(a.For)
				if err != nil {
					return nil, fmt.Errorf("alert %s: %w", a.Name, err)
				}
				al.Since = now.Add(-d)
			}
			m.Alerts = append(m.Alerts, al)
		}
		SortAlerts(m.Alerts)
	}
	return m, nil
}

// spread places values evenly over the 24 hours before now.
func spread(vs []num, now time.Time) []Point {
	if len(vs) == 1 {
		return []Point{{T: now, V: vs[0].val()}}
	}
	step := 24 * time.Hour / time.Duration(len(vs)-1)
	out := make([]Point, len(vs))
	for i, v := range vs {
		out[i] = Point{T: now.Add(-24 * time.Hour).Add(time.Duration(i) * step), V: v.val()}
	}
	return out
}

// volumeHistory makes 24 hours of samples, every 10 minutes, that end at
// the volume's usage and follow its growth.
func volumeHistory(v *VolumeMetrics, now time.Time) []Point {
	rate, window, before := 0.0, 24*time.Hour, 0.0
	if g := v.Growth; g != nil {
		rate, window, before = g.BytesPerHour, g.Window, g.BytesPerHour
		if Known(g.BaselineBytesPerHour) {
			before = g.BaselineBytesPerHour
		}
	}
	var out []Point
	for i := 144; i >= 0; i-- {
		back := time.Duration(i) * 10 * time.Minute
		h := back.Hours()
		used := v.Used - rate*min(h, window.Hours())
		if back > window {
			used -= before * (h - window.Hours())
		}
		out = append(out, Point{T: now.Add(-back), V: max(used, 0)})
	}
	return out
}
