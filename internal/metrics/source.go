package metrics

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"k0s_monitor/internal/account"
	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/prom"
	"k0s_monitor/internal/snapshot"
)

// Source keeps one cluster's metrics fresh. It finds Prometheus (or uses
// the configured one), reads it, and says what went wrong when it can't.
type Source struct {
	cs  kubernetes.Interface
	cfg *config.Prometheus
	now func() time.Time

	mu           sync.Mutex
	reader       *Reader
	failures     int
	nextDiscover time.Time
	prom         *snapshot.Metrics // the last successful read of Prometheus
	latest       *snapshot.Metrics // with the fallbacks
	status       cluster.PrometheusStatus
	fb           *fallback
	queries      func() []string
}

// SetQueries sets where the product packs' queries come from; each read
// runs them too.
func (s *Source) SetQueries(f func() []string) {
	s.mu.Lock()
	s.queries = f
	s.mu.Unlock()
}

// promGrace is how long the last Prometheus read is used while Prometheus
// can't be read, before the fallbacks take over. The engine treats metrics
// as stale after three reads too.
const promGrace = 3 * time.Minute

// NewSource returns a source for one cluster. cfg may be nil.
func NewSource(cs kubernetes.Interface, cfg *config.Prometheus, now func() time.Time) *Source {
	if now == nil {
		now = time.Now
	}
	s := &Source{cs: cs, cfg: cfg, now: now, fb: newFallback(cs, now)}
	s.status = cluster.PrometheusStatus{State: "not-found", Message: "Prometheus has not been looked for yet."}
	if cfg != nil && cfg.Disabled {
		s.status = cluster.PrometheusStatus{State: "disabled", Message: "Metrics are turned off for this cluster in the configuration."}
	}
	return s
}

// Latest returns the last metrics read (nil if none) and the status.
func (s *Source) Latest() (*snapshot.Metrics, cluster.PrometheusStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latest, s.status
}

// Update finds Prometheus if needed and reads the metrics, and fills what
// Prometheus lacks from the fallbacks. services and nodes come from the
// cluster's current snapshot.
func (s *Source) Update(ctx context.Context, services []*corev1.Service, nodes []*corev1.Node) {
	if s.cfg != nil && s.cfg.Disabled {
		return
	}
	s.updatePrometheus(ctx, services, nodes)
	s.updateFallback(ctx, nodes)
}

// updateFallback reads what Prometheus doesn't give: node CPU and memory,
// and volume and node disk usage.
func (s *Source) updateFallback(ctx context.Context, nodes []*corev1.Node) {
	s.mu.Lock()
	base := s.prom
	if base != nil && s.status.State != "ok" && s.now().Sub(base.At) > promGrace {
		base = nil
	}
	s.mu.Unlock()
	usage, kubelet := base == nil, base == nil || !base.Have["kubelet-volumes"]
	for _, n := range nodes {
		if base != nil && base.Nodes[n.Name] == nil {
			usage, kubelet = true, true
		}
	}
	var d fallbackData
	if usage || kubelet {
		d = s.fb.read(ctx, nodes, usage, kubelet)
	}
	m, used := merge(base, d, s.now())
	if m != nil {
		s.fb.nodeFSHistory(m)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latest = m
	s.status.Fallbacks, s.status.FallbackHint = used, ""
	if kubelet && !d.kubelet && d.noKubelet == notAllowed {
		s.status.FallbackHint = account.KubeletStatsCommands
	}
}

func (s *Source) updatePrometheus(ctx context.Context, services []*corev1.Service, nodes []*corev1.Node) {
	s.mu.Lock()
	reader := s.reader
	if reader == nil && s.now().Before(s.nextDiscover) {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	if reader == nil {
		var st cluster.PrometheusStatus
		reader, st = s.find(ctx, services)
		s.mu.Lock()
		s.reader, s.failures = reader, 0
		if reader == nil {
			s.status = st
			s.status.At = s.now()
			s.nextDiscover = s.now().Add(5 * time.Minute)
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
	}

	m, err := reader.Read(ctx, nodes)
	if err == nil {
		s.mu.Lock()
		queries := s.queries
		s.mu.Unlock()
		if queries != nil {
			if qs := queries(); len(qs) > 0 {
				m.Queries, m.QueryErrors = reader.ReadQueries(ctx, qs)
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.failures++
		s.status = failure(reader.c.Target, err)
		s.status.At = s.now()
		if s.failures >= 3 && s.cfgTarget() == nil {
			// It may have moved: look again next time.
			s.reader = nil
		}
		return
	}
	s.failures = 0
	s.prom = m
	s.status = cluster.PrometheusStatus{
		State: "ok", Target: reader.c.Target.String(), At: s.now(),
		NodeExporter: len(m.Nodes), NodesTotal: len(nodes),
		KubeletVolumes: m.Have["kubelet-volumes"], CAdvisor: m.Have["cadvisor"], Timex: m.Have["timex"],
		Unmapped: m.Unmapped,
	}
	s.status.Message = coverage(s.status)
}

// cfgTarget returns the configured target, if any.
func (s *Source) cfgTarget() *prom.Target {
	if s.cfg == nil {
		return nil
	}
	if s.cfg.URL != "" {
		return &prom.Target{URL: s.cfg.URL}
	}
	if ns, name, port, ok := s.cfg.ServiceParts(); ok {
		return &prom.Target{Namespace: ns, Service: name, Port: port, Scheme: "http", Path: s.cfg.ServicePath()}
	}
	return nil
}

// find tries the configured Prometheus, or the discovered candidates, and
// returns a reader for the first that answers.
func (s *Source) find(ctx context.Context, services []*corev1.Service) (*Reader, cluster.PrometheusStatus) {
	var candidates []*prom.Client
	if t := s.cfgTarget(); t != nil {
		c, err := s.client(*t)
		if err != nil {
			return nil, cluster.PrometheusStatus{State: "error", Target: t.String(), Message: err.Error()}
		}
		candidates = append(candidates, c)
	} else {
		for _, t := range prom.Discover(services) {
			candidates = append(candidates, prom.NewProxy(s.cs, t))
			if t.Scheme == "http" {
				// Some installations serve HTTPS on the usual port.
				ht := t
				ht.Scheme = "https"
				candidates = append(candidates, prom.NewProxy(s.cs, ht))
			}
		}
	}
	if len(candidates) == 0 {
		return nil, cluster.PrometheusStatus{State: "not-found",
			Message: "No Prometheus or VictoriaMetrics was found in the cluster. Disk, volume and VM checks need one.",
			Hint: "k0s-monitor looks for Services such as prometheus-operated, prometheus-k8s, prometheus-server, vmsingle-… and vmselect-…, or labeled app.kubernetes.io/name=prometheus. " +
				"If yours runs elsewhere, for example on a controller host outside Kubernetes, enter its address under Metrics source on this page (prometheus.url in the configuration file)."}
	}
	var first *cluster.PrometheusStatus
	for _, c := range candidates {
		qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := c.Query(qctx, "vector(1)", time.Time{})
		cancel()
		if err == nil {
			return NewReader(c, s.now), cluster.PrometheusStatus{}
		}
		st := failure(c.Target, err)
		if first == nil || (st.State == "forbidden" && first.State != "forbidden") {
			first = &st
		}
	}
	return nil, *first
}

func (s *Source) client(t prom.Target) (*prom.Client, error) {
	if t.URL == "" {
		return prom.NewProxy(s.cs, t), nil
	}
	a := prom.Auth{Username: s.cfg.Username, CAFile: s.cfg.CAFile}
	read := func(path string) (string, error) {
		if path == "" {
			return "", nil
		}
		b, err := os.ReadFile(path)
		return strings.TrimSpace(string(b)), err
	}
	var err error
	if a.Password, err = read(s.cfg.PasswordFile); err != nil {
		return nil, err
	}
	if a.BearerToken, err = read(s.cfg.BearerTokenFile); err != nil {
		return nil, err
	}
	return prom.NewURL(t, a)
}

// failure explains why a Prometheus could not be read.
func failure(t prom.Target, err error) cluster.PrometheusStatus {
	st := cluster.PrometheusStatus{State: "error", Target: t.String()}
	var perr *prom.Error
	var na *prom.NotQueryAPIError
	switch {
	case errors.As(err, &na):
		st.Message = fmt.Sprintf("%s %s.", t, strings.TrimPrefix(na.What, "the address "))
		if na.Exporter {
			st.Hint = "Enter the address of the Prometheus or VictoriaMetrics that collects these metrics: VictoriaMetrics listens on port 8428 by default, Prometheus on 9090."
		}
	case apierrors.IsForbidden(err):
		st.State = "forbidden"
		st.Message = fmt.Sprintf("Metrics were found at %s, but k0s-monitor's account may not read them through the API server.", t)
		st.Hint = GrantCommands(t)
	case apierrors.IsNotFound(err) || apierrors.IsServiceUnavailable(err):
		st.Message = fmt.Sprintf("%s does not answer: %v", t, err)
	case errors.As(err, &perr):
		st.Message = t.String() + " rejected a query: " + perr.Message
	default:
		st.Message = fmt.Sprintf("%s can't be read: %v", t, err)
	}
	return st
}

// GrantCommands are the kubectl commands that let k0s-monitor's read-only
// account read one Prometheus Service through the API server.
func GrantCommands(t prom.Target) string {
	if t.URL != "" {
		return ""
	}
	return fmt.Sprintf("k0s kubectl -n %s create role %s --verb=get --resource=services/proxy --resource-name=%s\n"+
		"k0s kubectl -n %s create rolebinding %s --role=%s --serviceaccount=kube-system:k0s-monitor",
		t.Namespace, account.PrometheusRoleName, t.ProxyName(), t.Namespace, account.PrometheusRoleName, account.PrometheusRoleName)
}

// coverage summarizes which data exists, for the Data sources panel.
func coverage(st cluster.PrometheusStatus) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("node-exporter on %d of %d nodes", st.NodeExporter, st.NodesTotal))
	if st.KubeletVolumes {
		parts = append(parts, "volume usage")
	} else {
		parts = append(parts, "no volume usage (kubelet metrics missing)")
	}
	if st.CAdvisor {
		parts = append(parts, "container metrics")
	}
	if !st.Timex && st.NodeExporter > 0 {
		parts = append(parts, "no clock data")
	}
	return strings.Join(parts, ", ")
}

// Check finds the metrics as the engine will and reads them once. The status
// says where they are and which data they hold for these nodes.
func Check(ctx context.Context, cs kubernetes.Interface, cfg *config.Prometheus, nodes []*corev1.Node) cluster.PrometheusStatus {
	if cfg != nil && cfg.Disabled {
		return cluster.PrometheusStatus{State: "disabled", Message: "Metrics are turned off for this cluster."}
	}
	s := NewSource(cs, cfg, nil)
	var services []*corev1.Service
	if s.cfgTarget() == nil {
		list, err := cs.CoreV1().Services("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return cluster.PrometheusStatus{State: "error", Message: "Services can't be listed to look for Prometheus: " + err.Error()}
		}
		for i := range list.Items {
			services = append(services, &list.Items[i])
		}
	}
	s.updatePrometheus(ctx, services, nodes)
	_, st := s.Latest()
	return st
}

// nearbyPorts are where Nearby looks, best first.
var nearbyPorts = []string{":8428", ":9090", ":8481/select/0/prometheus"}

// Nearby tries the usual ports of Prometheus and VictoriaMetrics on the
// host of an address that didn't answer, and returns the addresses that
// do, best first: VictoriaMetrics single (8428), Prometheus (9090) and a
// VictoriaMetrics cluster's vmselect (8481).
func Nearby(ctx context.Context, address string) []string {
	u, err := url.Parse(address)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	host := u.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	var cands []string
	for _, c := range nearbyPorts {
		cand := "http://" + host + c
		if strings.TrimRight(cand, "/") != strings.TrimRight(address, "/") {
			cands = append(cands, cand)
		}
	}
	ok := make([]bool, len(cands))
	var wg sync.WaitGroup
	for i, cand := range cands {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := prom.NewURL(prom.Target{URL: cand}, prom.Auth{})
			if err != nil {
				return
			}
			qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			_, err = c.Query(qctx, "vector(1)", time.Time{})
			ok[i] = err == nil
		}()
	}
	wg.Wait()
	var out []string
	for i, cand := range cands {
		if ok[i] {
			out = append(out, cand)
		}
	}
	return out
}

// Find looks for a Prometheus that answers to the given client, as the
// connection test and account creation do before any engine runs.
func Find(ctx context.Context, cs kubernetes.Interface, cfg *config.Prometheus) (*prom.Target, cluster.PrometheusStatus) {
	if cfg != nil && cfg.Disabled {
		return nil, cluster.PrometheusStatus{State: "disabled", Message: "Metrics are turned off for this cluster."}
	}
	s := NewSource(cs, cfg, nil)
	var services []*corev1.Service
	if s.cfgTarget() == nil {
		list, err := cs.CoreV1().Services("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, cluster.PrometheusStatus{State: "error", Message: "Services can't be listed to look for Prometheus: " + err.Error()}
		}
		for i := range list.Items {
			services = append(services, &list.Items[i])
		}
	}
	r, st := s.find(ctx, services)
	if r == nil {
		return nil, st
	}
	t := r.c.Target
	return &t, cluster.PrometheusStatus{State: "ok", Target: t.String()}
}
