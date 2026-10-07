package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"

	"k0s_monitor/internal/prom"
	"k0s_monitor/internal/snapshot"
)

// The fallbacks for clusters, or parts of them, that Prometheus doesn't
// cover (plan section 7): node CPU and memory from the metrics API, and
// volume and node disk usage from the kubelet's summary. The kubelet is
// read through the API server's node proxy, which needs get nodes/proxy;
// the read-only account doesn't have it unless it is granted separately.
// Growth comes from samples kept here, so forecasts start about an hour
// after k0s-monitor does.

// sampleEvery is how often usage is sampled for growth.
const sampleEvery = 5 * time.Minute

// keepSamples is how far back samples are kept.
const keepSamples = 24 * time.Hour

var errNoRawClient = errors.New("no REST client")

// fallback reads and samples what the metrics API and the kubelets give.
type fallback struct {
	// get reads an API server path; tests replace it.
	get func(ctx context.Context, path string) ([]byte, error)
	now func() time.Time

	mu sync.Mutex
	// denied is when the kubelets were last refused (no get nodes/proxy):
	// they are tried again after 5 minutes.
	denied    time.Time
	sampledAt time.Time
	volumes   map[string][]snapshot.Point // namespace/claim -> used bytes
	nodeFS    map[string][]snapshot.Point // node -> used share of nodefs
}

func newFallback(cs kubernetes.Interface, now func() time.Time) *fallback {
	f := &fallback{now: now, volumes: map[string][]snapshot.Point{}, nodeFS: map[string][]snapshot.Point{}}
	f.get = func(ctx context.Context, path string) ([]byte, error) {
		rc := cs.CoreV1().RESTClient()
		if rc == nil || reflect.ValueOf(rc).IsNil() {
			return nil, errNoRawClient
		}
		return rc.Get().AbsPath(path).DoRaw(ctx)
	}
	return f
}

// fallbackData is one read of the fallbacks.
type fallbackData struct {
	usage   map[string]snapshot.NodeUsage
	volumes map[string]*snapshot.VolumeMetrics
	nodeFS  map[string]*snapshot.Filesystem
	// kubelet says whether the kubelets could be read, and why not.
	kubelet   bool
	noKubelet string
}

// read fetches node usage (when usage is true) and kubelet summaries
// (when kubelet is true) for the ready nodes.
func (f *fallback) read(ctx context.Context, nodes []*corev1.Node, usage, kubelet bool) fallbackData {
	d := fallbackData{}
	if usage {
		d.usage = f.nodeUsage(ctx)
	}
	if !kubelet {
		return d
	}
	f.mu.Lock()
	wait := !f.denied.IsZero() && f.now().Sub(f.denied) < 5*time.Minute
	f.mu.Unlock()
	if wait {
		d.noKubelet = notAllowed
		return d
	}
	d.volumes, d.nodeFS = map[string]*snapshot.VolumeMetrics{}, map[string]*snapshot.Filesystem{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	read, forbidden := 0, 0
	for _, n := range nodes {
		if !snapshot.IsNodeReady(n) {
			continue
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			b, err := f.get(sctx, "/api/v1/nodes/"+name+"/proxy/stats/summary")
			if err != nil {
				if apierrors.IsForbidden(err) {
					mu.Lock()
					forbidden++
					mu.Unlock()
				}
				return
			}
			var s summary
			if json.Unmarshal(b, &s) != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			read++
			if fs := s.Node.FS; fs.CapacityBytes > 0 {
				d.nodeFS[name] = &snapshot.Filesystem{Mountpoint: snapshot.K0sDataDir, Device: "nodefs", Size: fs.CapacityBytes,
					Avail: fs.AvailableBytes, Files: fs.Inodes, FilesFree: fs.InodesFree}
			}
			for _, p := range s.Pods {
				for _, v := range p.Volumes {
					if v.PVCRef == nil || v.CapacityBytes <= 0 {
						continue
					}
					d.volumes[v.PVCRef.Namespace+"/"+v.PVCRef.Name] = &snapshot.VolumeMetrics{Used: v.UsedBytes, Capacity: v.CapacityBytes,
						InodesUsed: v.InodesUsed, Inodes: v.Inodes}
				}
			}
		}(n.Name)
	}
	wg.Wait()
	d.kubelet = read > 0
	switch {
	case read == 0 && forbidden > 0:
		d.noKubelet = notAllowed
		f.mu.Lock()
		f.denied = f.now()
		f.mu.Unlock()
	case read == 0:
		d.noKubelet = "no kubelet answered"
	}
	f.sample(d)
	return d
}

// notAllowed is why the kubelets can't be read without get nodes/proxy.
const notAllowed = "not allowed (get nodes/proxy)"

// sample keeps a point per volume and node every sampleEvery, and adds the
// history and growth to the read.
func (f *fallback) sample(d fallbackData) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	if now.Sub(f.sampledAt) >= sampleEvery {
		f.sampledAt = now
		keep := func(ps []snapshot.Point, v float64) []snapshot.Point {
			ps = append(ps, snapshot.Point{T: now, V: v})
			i := 0
			for i < len(ps) && now.Sub(ps[i].T) > keepSamples {
				i++
			}
			return append([]snapshot.Point(nil), ps[i:]...)
		}
		for k, v := range d.volumes {
			f.volumes[k] = keep(f.volumes[k], v.Used)
		}
		for k, fs := range d.nodeFS {
			f.nodeFS[k] = keep(f.nodeFS[k], fs.UsedFraction())
		}
		// Forget what is gone.
		for k := range f.volumes {
			if d.volumes[k] == nil {
				delete(f.volumes, k)
			}
		}
		for k := range f.nodeFS {
			if d.nodeFS[k] == nil {
				delete(f.nodeFS, k)
			}
		}
	}
	for k, v := range d.volumes {
		v.History = f.volumes[k]
		pts := make([]prom.Point, len(v.History))
		for i, p := range v.History {
			pts[i] = prom.Point{T: p.T, V: p.V}
		}
		if g := fitGrowth(pts, now); g != nil {
			g.BaselineBytesPerHour = snapshot.Missing
			v.Growth = g
		}
	}
}

// nodeUsage reads node CPU and memory from the metrics API.
func (f *fallback) nodeUsage(ctx context.Context) map[string]snapshot.NodeUsage {
	uctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	b, err := f.get(uctx, "/apis/metrics.k8s.io/v1beta1/nodes")
	if err != nil {
		return nil
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Timestamp time.Time         `json:"timestamp"`
			Usage     map[string]string `json:"usage"`
		} `json:"items"`
	}
	if json.Unmarshal(b, &list) != nil {
		return nil
	}
	out := map[string]snapshot.NodeUsage{}
	for _, it := range list.Items {
		u := snapshot.NodeUsage{CPUCores: snapshot.Missing, MemoryBytes: snapshot.Missing, At: it.Timestamp}
		if q, err := resource.ParseQuantity(it.Usage["cpu"]); err == nil {
			u.CPUCores = q.AsApproximateFloat64()
		}
		if q, err := resource.ParseQuantity(it.Usage["memory"]); err == nil {
			u.MemoryBytes = q.AsApproximateFloat64()
		}
		out[it.Metadata.Name] = u
	}
	return out
}

// summary is the part of the kubelet's /stats/summary that is used.
type summary struct {
	Node struct {
		FS fsStats `json:"fs"`
	} `json:"node"`
	Pods []struct {
		Volumes []struct {
			fsStats
			PVCRef *struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"pvcRef"`
		} `json:"volume"`
	} `json:"pods"`
}

type fsStats struct {
	AvailableBytes float64 `json:"availableBytes"`
	CapacityBytes  float64 `json:"capacityBytes"`
	UsedBytes      float64 `json:"usedBytes"`
	InodesFree     float64 `json:"inodesFree"`
	Inodes         float64 `json:"inodes"`
	InodesUsed     float64 `json:"inodesUsed"`
}

// merge adds the fallback data to what Prometheus gave (base may be nil)
// and says what it added. Prometheus values always win.
func merge(base *snapshot.Metrics, d fallbackData, now time.Time) (*snapshot.Metrics, []string) {
	m := base
	if m == nil {
		m = &snapshot.Metrics{Source: "kubelet and metrics API", At: now, Volumes: map[string]*snapshot.VolumeMetrics{},
			Nodes: map[string]*snapshot.NodeMetrics{}, Containers: map[string]*snapshot.ContainerMetrics{}, Have: map[string]bool{}}
	} else {
		c := *base
		c.Have = map[string]bool{}
		for k, v := range base.Have {
			c.Have[k] = v
		}
		c.Nodes = map[string]*snapshot.NodeMetrics{}
		for k, v := range base.Nodes {
			c.Nodes[k] = v
		}
		m = &c
	}
	var used []string
	if len(d.usage) > 0 {
		m.NodeUsage = d.usage
		used = append(used, "node CPU and memory from the metrics API")
	}
	if d.kubelet && !m.Have["kubelet-volumes"] && len(d.volumes) > 0 {
		m.Volumes = d.volumes
		m.Have["kubelet-volumes"] = true
		used = append(used, "volume usage from the kubelets")
	}
	var added []string
	for name, fs := range d.nodeFS {
		if m.Nodes[name] != nil {
			continue
		}
		nm := snapshot.NewNodeMetrics("")
		nm.Up = true
		nm.Filesystems = []snapshot.Filesystem{*fs}
		m.Nodes[name] = nm
		added = append(added, name)
	}
	if len(added) > 0 {
		sort.Strings(added)
		m.Have["kubelet-nodefs"] = true
		used = append(used, "node disk usage from the kubelets")
	}
	if base == nil && len(used) == 0 {
		return nil, nil
	}
	m.Fallbacks = used
	return m, used
}

// nodeFSHistory adds the sampled nodefs history to nodes from the kubelets.
func (f *fallback) nodeFSHistory(m *snapshot.Metrics) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for name, nm := range m.Nodes {
		if nm.Instance == "" && len(f.nodeFS[name]) > 0 {
			nm.FSHistory = map[string][]snapshot.Point{snapshot.K0sDataDir: f.nodeFS[name]}
		}
	}
}
