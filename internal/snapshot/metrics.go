package snapshot

import (
	"math"
	"strings"
	"time"
)

// KindMetrics stands for usable metrics from Prometheus. Rules that need
// them list it in Needs, and are skipped when it is missing.
const KindMetrics Kind = "metrics"

// Metrics are the values read from Prometheus for one evaluation. Values
// that are missing are NaN; use Known.
type Metrics struct {
	// Source names where the values come from.
	Source string
	// At is when they were read.
	At time.Time

	// Volumes by "namespace/claim".
	Volumes map[string]*VolumeMetrics
	// Nodes by node name. Only nodes with node-exporter data are present.
	Nodes map[string]*NodeMetrics
	// Containers by "namespace/pod/container".
	Containers map[string]*ContainerMetrics

	// Have says which kinds of data exist: "node-exporter",
	// "kubelet-volumes", "kubelet-nodefs", "cadvisor", "timex".
	Have map[string]bool
	// Unmapped lists node-exporter instances that match no Node.
	Unmapped []string

	// NodeUsage is CPU and memory per node from the metrics API, for
	// nodes that Prometheus has no node-exporter data for.
	NodeUsage map[string]NodeUsage
	// Fallbacks says what came from the metrics API or the kubelets
	// instead of Prometheus, in words.
	Fallbacks []string

	// Queries are the results of the product packs' queries, by query,
	// and QueryErrors why Prometheus refused one.
	Queries     map[string][]Sample
	QueryErrors map[string]string

	// Services are k0s's systemd services on the hosts node-exporter
	// covers, from its systemd collector (when it is on).
	Services []ServiceState

	// Alerts are the alerts that fire, most severe first, without the
	// heartbeat alerts. AlertsRead says they could be read; AlertsFrom
	// says how: "alerts API" or "ALERTS series".
	Alerts     []Alert
	AlertsRead bool
	AlertsFrom string
}

// Sample is one series of a query's result.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// ForRules reports whether the metrics hold data that rules use: from
// Prometheus, or volume and disk usage from the kubelets. CPU and memory
// from the metrics API alone are only shown.
func (m *Metrics) ForRules() bool {
	if m == nil {
		return false
	}
	for _, ok := range m.Have {
		if ok {
			return true
		}
	}
	return !strings.HasPrefix(m.Source, "kubelet") && len(m.Fallbacks) == 0
}

// ServiceState is a systemd service on a host, from node-exporter's
// systemd collector.
type ServiceState struct {
	// Node is the node the host is; empty for a host that isn't one, such
	// as a controller without a worker.
	Node     string
	Instance string
	// Unit is the service, such as "k0sworker.service".
	Unit string
	// State is active, activating, deactivating, inactive or failed.
	State string
	// Restarts15m is how often it restarted in the last 15 minutes; NaN
	// when node-exporter doesn't count restarts.
	Restarts15m float64
}

// Host is the host part of the instance.
func (s ServiceState) Host() string {
	if i := strings.LastIndex(s.Instance, ":"); i > 0 && !strings.HasSuffix(s.Instance, "]") {
		return strings.Trim(s.Instance[:i], "[]")
	}
	return s.Instance
}

// NodeUsage is a node's current use, from the metrics API.
type NodeUsage struct {
	CPUCores, MemoryBytes float64
	At                    time.Time
}

// Known reports whether a metric value is present.
func Known(v float64) bool { return !math.IsNaN(v) }

// Missing is the value of a metric that is not present.
var Missing = math.NaN()

// Point is one sample of a series.
type Point struct {
	T time.Time
	V float64
}

// VolumeMetrics is the usage of one persistent volume claim.
type VolumeMetrics struct {
	Used, Capacity     float64
	InodesUsed, Inodes float64
	// Growth is how fast Used grows, from Prometheus history. Nil when
	// there is not enough history.
	Growth *Growth
	// History is Used over the last 24 hours, oldest first.
	History []Point
}

// Growth is a fitted growth rate.
type Growth struct {
	// BytesPerHour is the slope of the best fit, over Window.
	BytesPerHour float64
	Window       time.Duration
	// R2 is how well a straight line fits (1 is perfect).
	R2      float64
	Samples int
	// RecentBytesPerHour is the slope over the last hour, to show when
	// the rate changed.
	RecentBytesPerHour float64
	// BaselineBytesPerHour is the 7-day slope, when known.
	BaselineBytesPerHour float64
}

// forecastHorizon is as far ahead as a volume forecast goes. A volume that
// fills up later than this isn't filling up in any sense that matters, and
// a time.Duration can't hold more than about 292 years: a volume growing by
// a few bytes an hour would wrap around to a negative time, "full now".
const forecastHorizon = 10 * 365 * 24 * time.Hour

// TimeToFull returns how long until the volume is full at this rate, or
// false when it is not growing, or so slowly that it won't be full within
// ten years.
func (v *VolumeMetrics) TimeToFull() (time.Duration, bool) {
	if v.Growth == nil || !Known(v.Growth.BytesPerHour) || v.Growth.BytesPerHour <= 0 || !Known(v.Capacity) || !Known(v.Used) {
		return 0, false
	}
	left := v.Capacity - v.Used
	if left <= 0 {
		return 0, true
	}
	hours := left / v.Growth.BytesPerHour
	if hours > forecastHorizon.Hours() {
		return 0, false
	}
	return time.Duration(hours * float64(time.Hour)), true
}

// Filesystem is one mounted filesystem on a node.
type Filesystem struct {
	Mountpoint, Device, FSType string
	Size, Avail                float64
	Files, FilesFree           float64
	ReadOnly                   bool
}

// UsedFraction returns the share of space used.
func (f Filesystem) UsedFraction() float64 {
	if f.Size <= 0 {
		return Missing
	}
	return (f.Size - f.Avail) / f.Size
}

// InodesUsedFraction returns the share of inodes used.
func (f Filesystem) InodesUsedFraction() float64 {
	if f.Files <= 0 {
		return Missing
	}
	return (f.Files - f.FilesFree) / f.Files
}

// NodeMetrics are node-exporter values for one node.
type NodeMetrics struct {
	Instance    string
	Up          bool
	Filesystems []Filesystem

	// CPU shares over 5 minutes (0..1), and busy over 15 minutes.
	CPUSteal, CPUIOWait, CPUBusy15m float64
	CPUs                            float64

	MemTotal, MemAvailable15m float64
	SwapTotal, SwapFree       float64

	// Worst average time per disk operation over 5 minutes, in seconds.
	DiskReadLatency, DiskWriteLatency float64
	DiskDevice                        string

	ClockOffset float64
	ClockSynced float64 // 1 synced, 0 not, NaN unknown
	BootTime    time.Time

	// FSHistory is the used share (0..1) of each filesystem over the last
	// 24 hours, by mountpoint, oldest first.
	FSHistory map[string][]Point

	// OOMKills15m is how many processes the kernel's out-of-memory killer
	// stopped in the last 15 minutes, containers held to their limit
	// included (node_vmstat_oom_kill).
	OOMKills15m float64
	// LinkFlaps are a network interface's link changes (down or up) in
	// the last 15 minutes, by interface; virtual interfaces are left out.
	LinkFlaps map[string]float64
}

// K0sDataDir is where k0s keeps the kubelet's and containerd's data.
const K0sDataDir = "/var/lib/k0s"

// KubeletFilesystem returns the filesystem that holds k0s's data dir: the
// mount with the longest mountpoint that is a prefix of it.
func (n *NodeMetrics) KubeletFilesystem() (Filesystem, bool) {
	var best Filesystem
	found := false
	for _, f := range n.Filesystems {
		mp := strings.TrimSuffix(f.Mountpoint, "/")
		if (mp == "" || K0sDataDir == mp || strings.HasPrefix(K0sDataDir, mp+"/")) && len(f.Mountpoint) >= len(best.Mountpoint) {
			best, found = f, true
		}
	}
	return best, found
}

// NewNodeMetrics returns node metrics with every value missing.
func NewNodeMetrics(instance string) *NodeMetrics {
	return &NodeMetrics{Instance: instance, CPUSteal: Missing, CPUIOWait: Missing, CPUBusy15m: Missing, CPUs: Missing,
		MemTotal: Missing, MemAvailable15m: Missing, SwapTotal: Missing, SwapFree: Missing,
		DiskReadLatency: Missing, DiskWriteLatency: Missing, ClockOffset: Missing, ClockSynced: Missing, OOMKills15m: Missing}
}

// ContainerMetrics are cAdvisor values for one container.
type ContainerMetrics struct {
	// WorkingSet is the memory working set, averaged over 10 minutes.
	WorkingSet float64
	// PeakWorkingSet7d is the highest working set over 7 days.
	PeakWorkingSet7d float64
	// Throttled is the share of CPU periods throttled over 15 minutes.
	Throttled float64
}

// NewContainerMetrics returns container metrics with every value missing.
func NewContainerMetrics() *ContainerMetrics {
	return &ContainerMetrics{WorkingSet: Missing, PeakWorkingSet7d: Missing, Throttled: Missing}
}
