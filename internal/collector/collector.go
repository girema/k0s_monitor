// Package collector keeps an in-memory copy of one cluster using shared
// informers (list + watch), and builds snapshots from it. Watches reconnect
// on their own with backoff when the connection drops.
package collector

import (
	"context"
	"fmt"
	"sync"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"k0s_monitor/internal/snapshot"
)

// Collector watches the kinds it was allowed to read.
type Collector struct {
	factories []informers.SharedInformerFactory
	informers map[snapshot.Kind]cache.SharedIndexInformer
	listers   listers
	// apis polls aggregated API registrations, which have no typed
	// informer in client-go.
	apis     *apiServicePoller
	onChange []func()
}

type listers struct {
	pods           func() ([]*corev1.Pod, error)
	nodes          func() ([]*corev1.Node, error)
	services       func() ([]*corev1.Service, error)
	endpointSlices func() ([]*discoveryv1.EndpointSlice, error)
	ingresses      func() ([]*networkingv1.Ingress, error)
	pvcs           func() ([]*corev1.PersistentVolumeClaim, error)
	storageClasses func() ([]*storagev1.StorageClass, error)
	events         func() ([]*corev1.Event, error)
	namespaces     func() ([]*corev1.Namespace, error)
	deployments    func() ([]*appsv1.Deployment, error)
	replicaSets    func() ([]*appsv1.ReplicaSet, error)
	statefulSets   func() ([]*appsv1.StatefulSet, error)
	daemonSets     func() ([]*appsv1.DaemonSet, error)
	jobs           func() ([]*batchv1.Job, error)
	leases         func() ([]*coordinationv1.Lease, error)
	cronJobs       func() ([]*batchv1.CronJob, error)
	pvs            func() ([]*corev1.PersistentVolume, error)
	hpas           func() ([]*autoscalingv2.HorizontalPodAutoscaler, error)
	quotas         func() ([]*corev1.ResourceQuota, error)
	pdbs           func() ([]*policyv1.PodDisruptionBudget, error)
	tlsSecrets     func() ([]*corev1.Secret, error)
	validatingWHs  func() ([]*admissionv1.ValidatingWebhookConfiguration, error)
	mutatingWHs    func() ([]*admissionv1.MutatingWebhookConfiguration, error)
}

// stripManagedFields drops managedFields before objects enter the cache;
// rules never use them and they are a large part of every object.
func stripManagedFields(obj any) (any, error) {
	if n, ok := obj.(*corev1.Node); ok {
		snapshot.KeepCordonTime(n)
	}
	if a, err := meta.Accessor(obj); err == nil {
		a.SetManagedFields(nil)
	}
	return obj, nil
}

// New registers informers for the allowed kinds. Nothing runs until Start.
func New(cs kubernetes.Interface, allowed map[snapshot.Kind]bool) *Collector {
	main := informers.NewSharedInformerFactoryWithOptions(cs, 0, informers.WithTransform(stripManagedFields))
	events := informers.NewSharedInformerFactoryWithOptions(cs, 0,
		informers.WithTransform(stripManagedFields),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.FieldSelector = "type=Warning" }))
	leases := informers.NewSharedInformerFactoryWithOptions(cs, 0,
		informers.WithTransform(stripManagedFields),
		informers.WithNamespace(snapshot.NodeLeaseNamespace))

	c := &Collector{
		factories: []informers.SharedInformerFactory{main, events, leases},
		informers: map[snapshot.Kind]cache.SharedIndexInformer{},
	}
	if allowed[snapshot.KindTLSSecret] {
		// Only TLS Secrets are asked for, and only their certificate is
		// kept: the private key is dropped as each one arrives.
		secrets := informers.NewSharedInformerFactoryWithOptions(cs, 0,
			informers.WithTransform(func(obj any) (any, error) {
				if s, ok := obj.(*corev1.Secret); ok {
					return snapshot.OnlyTLSCert(s), nil
				}
				return obj, nil
			}),
			informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.FieldSelector = "type=" + string(corev1.SecretTypeTLS) }))
		c.factories = append(c.factories, secrets)
		i := secrets.Core().V1().Secrets()
		c.informers[snapshot.KindTLSSecret] = i.Informer()
		c.listers.tlsSecrets = func() ([]*corev1.Secret, error) { return i.Lister().List(labels.Everything()) }
	}
	all := labels.Everything()
	reg := func(k snapshot.Kind, inf cache.SharedIndexInformer) bool {
		if !allowed[k] {
			return false
		}
		c.informers[k] = inf
		return true
	}
	if i := main.Core().V1().Pods(); reg(snapshot.KindPod, i.Informer()) {
		c.listers.pods = func() ([]*corev1.Pod, error) { return i.Lister().List(all) }
	}
	if i := main.Core().V1().Nodes(); reg(snapshot.KindNode, i.Informer()) {
		c.listers.nodes = func() ([]*corev1.Node, error) { return i.Lister().List(all) }
	}
	if i := main.Core().V1().Services(); reg(snapshot.KindService, i.Informer()) {
		c.listers.services = func() ([]*corev1.Service, error) { return i.Lister().List(all) }
	}
	if i := main.Discovery().V1().EndpointSlices(); reg(snapshot.KindEndpointSlice, i.Informer()) {
		c.listers.endpointSlices = func() ([]*discoveryv1.EndpointSlice, error) { return i.Lister().List(all) }
	}
	if i := main.Networking().V1().Ingresses(); reg(snapshot.KindIngress, i.Informer()) {
		c.listers.ingresses = func() ([]*networkingv1.Ingress, error) { return i.Lister().List(all) }
	}
	if i := main.Core().V1().PersistentVolumeClaims(); reg(snapshot.KindPVC, i.Informer()) {
		c.listers.pvcs = func() ([]*corev1.PersistentVolumeClaim, error) { return i.Lister().List(all) }
	}
	if i := main.Storage().V1().StorageClasses(); reg(snapshot.KindStorageClass, i.Informer()) {
		c.listers.storageClasses = func() ([]*storagev1.StorageClass, error) { return i.Lister().List(all) }
	}
	if i := events.Core().V1().Events(); reg(snapshot.KindEvent, i.Informer()) {
		c.listers.events = func() ([]*corev1.Event, error) { return i.Lister().List(all) }
	}
	if i := main.Core().V1().Namespaces(); reg(snapshot.KindNamespace, i.Informer()) {
		c.listers.namespaces = func() ([]*corev1.Namespace, error) { return i.Lister().List(all) }
	}
	if i := main.Apps().V1().Deployments(); reg(snapshot.KindDeployment, i.Informer()) {
		c.listers.deployments = func() ([]*appsv1.Deployment, error) { return i.Lister().List(all) }
	}
	if i := main.Apps().V1().ReplicaSets(); reg(snapshot.KindReplicaSet, i.Informer()) {
		c.listers.replicaSets = func() ([]*appsv1.ReplicaSet, error) { return i.Lister().List(all) }
	}
	if i := main.Apps().V1().StatefulSets(); reg(snapshot.KindStatefulSet, i.Informer()) {
		c.listers.statefulSets = func() ([]*appsv1.StatefulSet, error) { return i.Lister().List(all) }
	}
	if i := main.Apps().V1().DaemonSets(); reg(snapshot.KindDaemonSet, i.Informer()) {
		c.listers.daemonSets = func() ([]*appsv1.DaemonSet, error) { return i.Lister().List(all) }
	}
	if i := main.Batch().V1().Jobs(); reg(snapshot.KindJob, i.Informer()) {
		c.listers.jobs = func() ([]*batchv1.Job, error) { return i.Lister().List(all) }
	}
	if i := leases.Coordination().V1().Leases(); reg(snapshot.KindLease, i.Informer()) {
		c.listers.leases = func() ([]*coordinationv1.Lease, error) { return i.Lister().List(all) }
	}
	if i := main.Batch().V1().CronJobs(); reg(snapshot.KindCronJob, i.Informer()) {
		c.listers.cronJobs = func() ([]*batchv1.CronJob, error) { return i.Lister().List(all) }
	}
	if i := main.Core().V1().PersistentVolumes(); reg(snapshot.KindPV, i.Informer()) {
		c.listers.pvs = func() ([]*corev1.PersistentVolume, error) { return i.Lister().List(all) }
	}
	if i := main.Autoscaling().V2().HorizontalPodAutoscalers(); reg(snapshot.KindHPA, i.Informer()) {
		c.listers.hpas = func() ([]*autoscalingv2.HorizontalPodAutoscaler, error) { return i.Lister().List(all) }
	}
	if i := main.Core().V1().ResourceQuotas(); reg(snapshot.KindQuota, i.Informer()) {
		c.listers.quotas = func() ([]*corev1.ResourceQuota, error) { return i.Lister().List(all) }
	}
	if i := main.Policy().V1().PodDisruptionBudgets(); reg(snapshot.KindPDB, i.Informer()) {
		c.listers.pdbs = func() ([]*policyv1.PodDisruptionBudget, error) { return i.Lister().List(all) }
	}
	if i := main.Admissionregistration().V1().ValidatingWebhookConfigurations(); reg(snapshot.KindValidatingWH, i.Informer()) {
		c.listers.validatingWHs = func() ([]*admissionv1.ValidatingWebhookConfiguration, error) { return i.Lister().List(all) }
	}
	if i := main.Admissionregistration().V1().MutatingWebhookConfigurations(); reg(snapshot.KindMutatingWH, i.Informer()) {
		c.listers.mutatingWHs = func() ([]*admissionv1.MutatingWebhookConfiguration, error) { return i.Lister().List(all) }
	}
	if allowed[snapshot.KindAPIService] {
		if rc := cs.Discovery().RESTClient(); rc != nil {
			c.apis = &apiServicePoller{rc: rc, interval: 30 * time.Second, changed: c.changed}
		}
	}
	return c
}

func (c *Collector) changed() {
	for _, fn := range c.onChange {
		fn()
	}
}

// apiServicePoller lists apiregistration.k8s.io/v1 APIServices regularly.
type apiServicePoller struct {
	rc       rest.Interface
	interval time.Duration
	changed  func()

	mu     sync.Mutex
	list   []snapshot.APIService
	synced bool
	done   chan struct{}
}

func (p *apiServicePoller) poll(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := p.rc.Get().AbsPath("/apis/apiregistration.k8s.io/v1/apiservices").Do(pctx).Raw()
	if err != nil {
		return
	}
	list, err := snapshot.ParseAPIServices(raw)
	if err != nil {
		return
	}
	p.mu.Lock()
	changed := !p.synced || !equalAPIServices(p.list, list)
	p.list, p.synced = list, true
	p.mu.Unlock()
	if changed && p.changed != nil {
		p.changed()
	}
}

func (p *apiServicePoller) run(ctx context.Context) {
	defer close(p.done)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		p.poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (p *apiServicePoller) get() ([]snapshot.APIService, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.list, p.synced
}

func equalAPIServices(a, b []snapshot.APIService) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Available != b[i].Available || a[i].Reason != b[i].Reason {
			return false
		}
	}
	return true
}

// OnChange calls fn after every add, update or delete of a watched object,
// including the initial list. fn must be quick and must not block.
func (c *Collector) OnChange(fn func()) {
	c.onChange = append(c.onChange, fn)
	h := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { fn() },
		UpdateFunc: func(any, any) { fn() },
		DeleteFunc: func(any) { fn() },
	}
	for _, inf := range c.informers {
		_, _ = inf.AddEventHandler(h)
	}
}

// Start runs the informers until ctx ends.
func (c *Collector) Start(ctx context.Context) {
	for _, f := range c.factories {
		f.Start(ctx.Done())
	}
	if c.apis != nil {
		c.apis.done = make(chan struct{})
		go c.apis.run(ctx)
	}
}

// Shutdown stops the informers and waits for them to exit. Cancel the
// context passed to Start first.
func (c *Collector) Shutdown() {
	for _, f := range c.factories {
		f.Shutdown()
	}
	if c.apis != nil && c.apis.done != nil {
		<-c.apis.done
	}
}

// hasSynced reports per kind whether its initial data is there.
func (c *Collector) hasSynced() map[snapshot.Kind]func() bool {
	out := map[snapshot.Kind]func() bool{}
	for k, inf := range c.informers {
		out[k] = inf.HasSynced
	}
	if c.apis != nil {
		out[snapshot.KindAPIService] = func() bool { _, ok := c.apis.get(); return ok }
	}
	return out
}

// WaitForSync waits until every informer has its initial list, or until ctx
// ends. It returns the kinds that synced; kinds that did not are reported in
// the error.
func (c *Collector) WaitForSync(ctx context.Context) (map[snapshot.Kind]bool, error) {
	synced := map[snapshot.Kind]bool{}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	checks := c.hasSynced()
	for {
		all := true
		for k, ok := range checks {
			if ok() {
				synced[k] = true
			} else {
				all = false
			}
		}
		if all {
			return synced, nil
		}
		select {
		case <-ctx.Done():
			var missing []string
			for k := range checks {
				if !synced[k] {
					missing = append(missing, string(k))
				}
			}
			return synced, fmt.Errorf("timed out waiting for %v", missing)
		case <-ticker.C:
		}
	}
}

// Synced returns the kinds whose initial data is there.
func (c *Collector) Synced() map[snapshot.Kind]bool {
	out := map[snapshot.Kind]bool{}
	for k, ok := range c.hasSynced() {
		if ok() {
			out[k] = true
		}
	}
	return out
}

// Snapshot copies the current cache into a snapshot. Only kinds in synced
// are marked available.
func (c *Collector) Snapshot(cluster string, now time.Time, synced map[snapshot.Kind]bool) *snapshot.Snapshot {
	s := &snapshot.Snapshot{Cluster: cluster, Now: now, Available: map[snapshot.Kind]bool{}}
	take := func(k snapshot.Kind, fn func() error) {
		if !synced[k] {
			return
		}
		if err := fn(); err == nil {
			s.Available[k] = true
		}
	}
	l := c.listers
	take(snapshot.KindPod, func() (err error) { s.Pods, err = l.pods(); return })
	take(snapshot.KindNode, func() (err error) { s.Nodes, err = l.nodes(); return })
	take(snapshot.KindService, func() (err error) { s.Services, err = l.services(); return })
	take(snapshot.KindEndpointSlice, func() (err error) { s.EndpointSlices, err = l.endpointSlices(); return })
	take(snapshot.KindIngress, func() (err error) { s.Ingresses, err = l.ingresses(); return })
	take(snapshot.KindPVC, func() (err error) { s.PVCs, err = l.pvcs(); return })
	take(snapshot.KindStorageClass, func() (err error) { s.StorageClasses, err = l.storageClasses(); return })
	take(snapshot.KindEvent, func() (err error) { s.Events, err = l.events(); return })
	take(snapshot.KindNamespace, func() (err error) { s.Namespaces, err = l.namespaces(); return })
	take(snapshot.KindDeployment, func() (err error) { s.Deployments, err = l.deployments(); return })
	take(snapshot.KindReplicaSet, func() (err error) { s.ReplicaSets, err = l.replicaSets(); return })
	take(snapshot.KindStatefulSet, func() (err error) { s.StatefulSets, err = l.statefulSets(); return })
	take(snapshot.KindDaemonSet, func() (err error) { s.DaemonSets, err = l.daemonSets(); return })
	take(snapshot.KindJob, func() (err error) { s.Jobs, err = l.jobs(); return })
	take(snapshot.KindLease, func() (err error) { s.Leases, err = l.leases(); return })
	take(snapshot.KindCronJob, func() (err error) { s.CronJobs, err = l.cronJobs(); return })
	take(snapshot.KindPV, func() (err error) { s.PVs, err = l.pvs(); return })
	take(snapshot.KindHPA, func() (err error) { s.HPAs, err = l.hpas(); return })
	take(snapshot.KindQuota, func() (err error) { s.Quotas, err = l.quotas(); return })
	take(snapshot.KindPDB, func() (err error) { s.PDBs, err = l.pdbs(); return })
	take(snapshot.KindTLSSecret, func() error {
		secrets, err := l.tlsSecrets()
		for _, sec := range secrets {
			if sec.Type == corev1.SecretTypeTLS { // the list asked only for these
				s.TLSCerts = append(s.TLSCerts, snapshot.TLSCertOf(sec))
			}
		}
		return err
	})
	take(snapshot.KindValidatingWH, func() (err error) { s.ValidatingWHs, err = l.validatingWHs(); return })
	take(snapshot.KindMutatingWH, func() (err error) { s.MutatingWHs, err = l.mutatingWHs(); return })
	take(snapshot.KindAPIService, func() error {
		list, ok := c.apis.get()
		if !ok {
			return fmt.Errorf("not polled yet")
		}
		s.APIServices = list
		return nil
	})
	return snapshot.New(s)
}

// Pods returns the cached Pods, for reading the logs of crashes; empty when
// pods are not collected.
func (c *Collector) Pods() []*corev1.Pod {
	if c.listers.pods == nil {
		return nil
	}
	pods, _ := c.listers.pods()
	return pods
}

// ServicesAndNodes returns the cached Services and Nodes, for finding
// Prometheus and mapping its data to nodes. Kinds that are not collected
// are empty.
func (c *Collector) ServicesAndNodes() ([]*corev1.Service, []*corev1.Node) {
	var svcs []*corev1.Service
	var nodes []*corev1.Node
	if c.listers.services != nil {
		svcs, _ = c.listers.services()
	}
	if c.listers.nodes != nil {
		nodes, _ = c.listers.nodes()
	}
	return svcs, nodes
}
