// Package snapshot holds an immutable view of one cluster, plus the lookup
// indexes that rules need. Rules only read snapshots; they never call the
// Kubernetes API, which keeps them fast, deterministic and easy to test.
package snapshot

import (
	"sort"
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Kind names a resource type the snapshot may contain.
type Kind string

const (
	KindPod           Kind = "pods"
	KindNode          Kind = "nodes"
	KindService       Kind = "services"
	KindEndpointSlice Kind = "endpointslices"
	KindIngress       Kind = "ingresses"
	KindPVC           Kind = "persistentvolumeclaims"
	KindStorageClass  Kind = "storageclasses"
	KindEvent         Kind = "events"
	KindNamespace     Kind = "namespaces"
	KindDeployment    Kind = "deployments"
	KindReplicaSet    Kind = "replicasets"
	KindStatefulSet   Kind = "statefulsets"
	KindDaemonSet     Kind = "daemonsets"
	KindJob           Kind = "jobs"
	KindLease         Kind = "leases"
	KindCronJob       Kind = "cronjobs"
	KindValidatingWH  Kind = "validatingwebhookconfigurations"
	KindMutatingWH    Kind = "mutatingwebhookconfigurations"
	KindAPIService    Kind = "apiservices"
	KindPV            Kind = "persistentvolumes"
	KindHPA           Kind = "horizontalpodautoscalers"
	KindQuota         Kind = "resourcequotas"
	KindPDB           Kind = "poddisruptionbudgets"
)

// AllKinds lists every kind the collector knows how to fetch.
var AllKinds = []Kind{
	KindPod, KindNode, KindService, KindEndpointSlice, KindIngress, KindPVC,
	KindStorageClass, KindEvent, KindNamespace, KindDeployment, KindReplicaSet,
	KindStatefulSet, KindDaemonSet, KindJob, KindLease, KindCronJob,
	KindValidatingWH, KindMutatingWH, KindAPIService, KindPV, KindHPA, KindQuota,
	KindPDB,
}

// APIService is the part of an aggregated API registration the rules use
// (apiregistration.k8s.io/v1, which client-go's typed clients don't cover).
type APIService struct {
	Name string
	// Service is "namespace/name" for an aggregated API, empty for APIs the
	// API server serves itself.
	Service   string
	Available bool
	Reason    string
	Message   string
	Since     time.Time
}

// NodeLeaseNamespace is where kubelets renew their heartbeat leases.
const NodeLeaseNamespace = "kube-node-lease"

// Snapshot is a point-in-time view of one cluster. Build it with New and do
// not modify it afterwards.
type Snapshot struct {
	Cluster string
	Now     time.Time

	Pods           []*corev1.Pod
	Nodes          []*corev1.Node
	Services       []*corev1.Service
	EndpointSlices []*discoveryv1.EndpointSlice
	Ingresses      []*networkingv1.Ingress
	PVCs           []*corev1.PersistentVolumeClaim
	StorageClasses []*storagev1.StorageClass
	Events         []*corev1.Event
	Namespaces     []*corev1.Namespace
	Deployments    []*appsv1.Deployment
	ReplicaSets    []*appsv1.ReplicaSet
	StatefulSets   []*appsv1.StatefulSet
	DaemonSets     []*appsv1.DaemonSet
	Jobs           []*batchv1.Job
	Leases         []*coordinationv1.Lease
	CronJobs       []*batchv1.CronJob
	ValidatingWHs  []*admissionv1.ValidatingWebhookConfiguration
	MutatingWHs    []*admissionv1.MutatingWebhookConfiguration
	APIServices    []APIService
	PVs            []*corev1.PersistentVolume
	HPAs           []*autoscalingv2.HorizontalPodAutoscaler
	Quotas         []*corev1.ResourceQuota
	PDBs           []*policyv1.PodDisruptionBudget
	// Metrics come from Prometheus; nil when there are none.
	Metrics *Metrics
	// ControlPlane comes from asking each controller; nil when that
	// wasn't possible.
	ControlPlane *ControlPlane
	// Fallback is set while k0s-monitor reads the cluster through another
	// controller because the kubeconfig's server doesn't answer.
	Fallback *Fallback
	// ExpectedK0s is the k0s version set for the cluster, if one is.
	ExpectedK0s *ExpectedK0s
	// CrashLogs say what the logs of crashing containers' last crashes
	// contain, by CrashLogKey; containers not read yet are absent.
	CrashLogs map[string]*CrashLog
	// TLSCerts are the certificates of the TLS Secrets, when the account
	// may read them (KindTLSSecret).
	TLSCerts []TLSCert

	// Available lists the kinds that were collected. Kinds that could not
	// be listed (for example because of missing permissions) are absent,
	// and rules that need them are skipped.
	Available map[Kind]bool

	idx index
}

type nsName struct{ ns, name string }

type index struct {
	podsByNode      map[string][]*corev1.Pod
	nodes           map[string]*corev1.Node
	replicaSets     map[nsName]*appsv1.ReplicaSet
	deployments     map[nsName]*appsv1.Deployment
	statefulSets    map[nsName]*appsv1.StatefulSet
	daemonSets      map[nsName]*appsv1.DaemonSet
	jobs            map[nsName]*batchv1.Job
	pvcs            map[nsName]*corev1.PersistentVolumeClaim
	storageClasses  map[string]*storagev1.StorageClass
	namespaces      map[string]*corev1.Namespace
	leases          map[string]*coordinationv1.Lease
	eventsByUID     map[types.UID][]*corev1.Event
	eventsByObject  map[string][]*corev1.Event
	slicesBySvc     map[nsName][]*discoveryv1.EndpointSlice
	ingressBackends map[nsName]bool
	podsByWorkload  map[Workload][]*corev1.Pod
	workloadOfPod   map[types.UID]Workload
	services        map[nsName]*corev1.Service
	cronJobs        map[nsName]*batchv1.CronJob
	jobsByCronJob   map[nsName][]*batchv1.Job
}

// New indexes the given objects. Nil slices are fine.
func New(s *Snapshot) *Snapshot {
	if s.Available == nil {
		s.Available = map[Kind]bool{}
	}
	if s.Now.IsZero() {
		s.Now = time.Now()
	}
	s.sortAll()
	s.buildIndex()
	return s
}

// Has reports whether the kind was collected.
func (s *Snapshot) Has(k Kind) bool { return s.Available[k] }

func (s *Snapshot) sortAll() {
	sortObjs(s.Pods, func(o *corev1.Pod) (string, string) { return o.Namespace, o.Name })
	sortObjs(s.Nodes, func(o *corev1.Node) (string, string) { return "", o.Name })
	sortObjs(s.Services, func(o *corev1.Service) (string, string) { return o.Namespace, o.Name })
	sortObjs(s.PVCs, func(o *corev1.PersistentVolumeClaim) (string, string) { return o.Namespace, o.Name })
	sortObjs(s.Deployments, func(o *appsv1.Deployment) (string, string) { return o.Namespace, o.Name })
	sortObjs(s.StatefulSets, func(o *appsv1.StatefulSet) (string, string) { return o.Namespace, o.Name })
	sortObjs(s.DaemonSets, func(o *appsv1.DaemonSet) (string, string) { return o.Namespace, o.Name })
	sortObjs(s.Jobs, func(o *batchv1.Job) (string, string) { return o.Namespace, o.Name })
	sortObjs(s.CronJobs, func(o *batchv1.CronJob) (string, string) { return o.Namespace, o.Name })
	sortObjs(s.PVs, func(o *corev1.PersistentVolume) (string, string) { return "", o.Name })
	sortObjs(s.HPAs, func(o *autoscalingv2.HorizontalPodAutoscaler) (string, string) { return o.Namespace, o.Name })
	sortObjs(s.Quotas, func(o *corev1.ResourceQuota) (string, string) { return o.Namespace, o.Name })
	sortObjs(s.PDBs, func(o *policyv1.PodDisruptionBudget) (string, string) { return o.Namespace, o.Name })
	sortObjs(s.Namespaces, func(o *corev1.Namespace) (string, string) { return "", o.Name })
	sortObjs(s.Ingresses, func(o *networkingv1.Ingress) (string, string) { return o.Namespace, o.Name })
	sortObjs(s.StorageClasses, func(o *storagev1.StorageClass) (string, string) { return "", o.Name })
	sortObjs(s.ValidatingWHs, func(o *admissionv1.ValidatingWebhookConfiguration) (string, string) { return "", o.Name })
	sortObjs(s.MutatingWHs, func(o *admissionv1.MutatingWebhookConfiguration) (string, string) { return "", o.Name })
}

func sortObjs[T any](objs []T, key func(T) (string, string)) {
	sort.SliceStable(objs, func(i, j int) bool {
		ni, ai := key(objs[i])
		nj, aj := key(objs[j])
		if ni != nj {
			return ni < nj
		}
		return ai < aj
	})
}

func (s *Snapshot) buildIndex() {
	x := index{
		podsByNode:      map[string][]*corev1.Pod{},
		nodes:           map[string]*corev1.Node{},
		replicaSets:     map[nsName]*appsv1.ReplicaSet{},
		deployments:     map[nsName]*appsv1.Deployment{},
		statefulSets:    map[nsName]*appsv1.StatefulSet{},
		daemonSets:      map[nsName]*appsv1.DaemonSet{},
		jobs:            map[nsName]*batchv1.Job{},
		pvcs:            map[nsName]*corev1.PersistentVolumeClaim{},
		storageClasses:  map[string]*storagev1.StorageClass{},
		namespaces:      map[string]*corev1.Namespace{},
		leases:          map[string]*coordinationv1.Lease{},
		eventsByUID:     map[types.UID][]*corev1.Event{},
		eventsByObject:  map[string][]*corev1.Event{},
		slicesBySvc:     map[nsName][]*discoveryv1.EndpointSlice{},
		ingressBackends: map[nsName]bool{},
		podsByWorkload:  map[Workload][]*corev1.Pod{},
		workloadOfPod:   map[types.UID]Workload{},
		services:        map[nsName]*corev1.Service{},
		cronJobs:        map[nsName]*batchv1.CronJob{},
		jobsByCronJob:   map[nsName][]*batchv1.Job{},
	}
	for _, n := range s.Nodes {
		x.nodes[n.Name] = n
	}
	for _, p := range s.Pods {
		if p.Spec.NodeName != "" {
			x.podsByNode[p.Spec.NodeName] = append(x.podsByNode[p.Spec.NodeName], p)
		}
	}
	for _, o := range s.ReplicaSets {
		x.replicaSets[nsName{o.Namespace, o.Name}] = o
	}
	for _, o := range s.Deployments {
		x.deployments[nsName{o.Namespace, o.Name}] = o
	}
	for _, o := range s.StatefulSets {
		x.statefulSets[nsName{o.Namespace, o.Name}] = o
	}
	for _, o := range s.DaemonSets {
		x.daemonSets[nsName{o.Namespace, o.Name}] = o
	}
	for _, o := range s.Jobs {
		x.jobs[nsName{o.Namespace, o.Name}] = o
		if ref := metav1.GetControllerOf(o); ref != nil && ref.Kind == "CronJob" {
			k := nsName{o.Namespace, ref.Name}
			x.jobsByCronJob[k] = append(x.jobsByCronJob[k], o)
		}
	}
	for _, o := range s.CronJobs {
		x.cronJobs[nsName{o.Namespace, o.Name}] = o
	}
	for _, o := range s.Services {
		x.services[nsName{o.Namespace, o.Name}] = o
	}
	for _, o := range s.PVCs {
		x.pvcs[nsName{o.Namespace, o.Name}] = o
	}
	for _, o := range s.StorageClasses {
		x.storageClasses[o.Name] = o
	}
	for _, o := range s.Namespaces {
		x.namespaces[o.Name] = o
	}
	for _, o := range s.Leases {
		if o.Namespace == NodeLeaseNamespace {
			x.leases[o.Name] = o
		}
	}
	for _, e := range s.Events {
		if e.InvolvedObject.UID != "" {
			x.eventsByUID[e.InvolvedObject.UID] = append(x.eventsByUID[e.InvolvedObject.UID], e)
		}
		key := e.InvolvedObject.Kind + "/" + e.InvolvedObject.Namespace + "/" + e.InvolvedObject.Name
		x.eventsByObject[key] = append(x.eventsByObject[key], e)
	}
	for _, es := range s.EndpointSlices {
		svc := es.Labels[discoveryv1.LabelServiceName]
		if svc != "" {
			k := nsName{es.Namespace, svc}
			x.slicesBySvc[k] = append(x.slicesBySvc[k], es)
		}
	}
	for _, ing := range s.Ingresses {
		for _, name := range ingressServiceNames(ing) {
			x.ingressBackends[nsName{ing.Namespace, name}] = true
		}
	}
	s.idx = x
	for _, p := range s.Pods {
		w := s.resolveWorkload(p)
		x.workloadOfPod[p.UID] = w
		x.podsByWorkload[w] = append(x.podsByWorkload[w], p)
	}
}

func ingressServiceNames(ing *networkingv1.Ingress) []string {
	var names []string
	add := func(b *networkingv1.IngressBackend) {
		if b != nil && b.Service != nil && b.Service.Name != "" {
			names = append(names, b.Service.Name)
		}
	}
	add(ing.Spec.DefaultBackend)
	for _, r := range ing.Spec.Rules {
		if r.HTTP == nil {
			continue
		}
		for i := range r.HTTP.Paths {
			add(&r.HTTP.Paths[i].Backend)
		}
	}
	return names
}

// Node returns the named node.
func (s *Snapshot) Node(name string) *corev1.Node { return s.idx.nodes[name] }

// PodsOnNode returns the pods bound to a node.
func (s *Snapshot) PodsOnNode(name string) []*corev1.Pod { return s.idx.podsByNode[name] }

// NodeLease returns the heartbeat lease of a node, if collected.
func (s *Snapshot) NodeLease(name string) *coordinationv1.Lease { return s.idx.leases[name] }

// PVC returns a claim.
func (s *Snapshot) PVC(ns, name string) *corev1.PersistentVolumeClaim {
	return s.idx.pvcs[nsName{ns, name}]
}

// StorageClass returns a storage class by name.
func (s *Snapshot) StorageClass(name string) *storagev1.StorageClass {
	return s.idx.storageClasses[name]
}

// Namespace returns a namespace.
func (s *Snapshot) Namespace(name string) *corev1.Namespace { return s.idx.namespaces[name] }

// Deployment returns a deployment.
func (s *Snapshot) Deployment(ns, name string) *appsv1.Deployment {
	return s.idx.deployments[nsName{ns, name}]
}

// EventsFor returns the warning events about an object, newest first.
func (s *Snapshot) EventsFor(uid types.UID, kind, ns, name string) []*corev1.Event {
	seen := map[types.UID]bool{}
	var out []*corev1.Event
	for _, e := range s.idx.eventsByUID[uid] {
		seen[e.UID] = true
		out = append(out, e)
	}
	for _, e := range s.idx.eventsByObject[kind+"/"+ns+"/"+name] {
		if !seen[e.UID] {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return EventTime(out[i]).After(EventTime(out[j])) })
	return out
}

// EventTime returns the most meaningful timestamp of an event.
func EventTime(e *corev1.Event) time.Time {
	switch {
	case !e.LastTimestamp.IsZero():
		return e.LastTimestamp.Time
	case e.Series != nil && !e.Series.LastObservedTime.IsZero():
		return e.Series.LastObservedTime.Time
	case !e.EventTime.IsZero():
		return e.EventTime.Time
	case !e.FirstTimestamp.IsZero():
		return e.FirstTimestamp.Time
	}
	return e.CreationTimestamp.Time
}

// EndpointSlicesFor returns the endpoint slices of a service.
func (s *Snapshot) EndpointSlicesFor(ns, svc string) []*discoveryv1.EndpointSlice {
	return s.idx.slicesBySvc[nsName{ns, svc}]
}

// IsIngressBackend reports whether an ingress routes to the service.
func (s *Snapshot) IsIngressBackend(ns, svc string) bool {
	return s.idx.ingressBackends[nsName{ns, svc}]
}

// Service returns a service.
func (s *Snapshot) Service(ns, name string) *corev1.Service { return s.idx.services[nsName{ns, name}] }

// StatefulSet returns a stateful set.
func (s *Snapshot) StatefulSet(ns, name string) *appsv1.StatefulSet {
	return s.idx.statefulSets[nsName{ns, name}]
}

// DaemonSet returns a daemon set.
func (s *Snapshot) DaemonSet(ns, name string) *appsv1.DaemonSet {
	return s.idx.daemonSets[nsName{ns, name}]
}

// CronJob returns a cron job.
func (s *Snapshot) CronJob(ns, name string) *batchv1.CronJob { return s.idx.cronJobs[nsName{ns, name}] }

// JobsOf returns the jobs a cron job created, oldest first.
func (s *Snapshot) JobsOf(cj *batchv1.CronJob) []*batchv1.Job {
	jobs := append([]*batchv1.Job{}, s.idx.jobsByCronJob[nsName{cj.Namespace, cj.Name}]...)
	sort.SliceStable(jobs, func(i, j int) bool {
		a, b := jobs[i].CreationTimestamp.Time, jobs[j].CreationTimestamp.Time
		if !a.Equal(b) {
			return a.Before(b)
		}
		return jobs[i].Name < jobs[j].Name
	})
	return jobs
}

// ReadyEndpoints counts the ready endpoints of a service.
func (s *Snapshot) ReadyEndpoints(ns, svc string) int {
	n := 0
	for _, es := range s.EndpointSlicesFor(ns, svc) {
		for _, ep := range es.Endpoints {
			if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
				n++
			}
		}
	}
	return n
}

// DefaultStorageClass returns the default storage class, or nil.
func (s *Snapshot) DefaultStorageClass() *storagev1.StorageClass {
	var found *storagev1.StorageClass
	for _, sc := range s.StorageClasses {
		if IsDefaultStorageClass(sc) {
			// Kubernetes picks the newest default when several exist.
			if found == nil || sc.CreationTimestamp.After(found.CreationTimestamp.Time) {
				found = sc
			}
		}
	}
	return found
}

// IsDefaultStorageClass reports whether the class is marked as default.
func IsDefaultStorageClass(sc *storagev1.StorageClass) bool {
	return sc.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" ||
		sc.Annotations["storageclass.beta.kubernetes.io/is-default-class"] == "true"
}

// PodsUsingClaim returns the pods that mount a claim.
func (s *Snapshot) PodsUsingClaim(ns, claim string) []*corev1.Pod {
	var out []*corev1.Pod
	for _, p := range s.Pods {
		if p.Namespace != ns {
			continue
		}
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == claim {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// ClaimsOfPod returns the claim names a pod mounts.
func ClaimsOfPod(p *corev1.Pod) []string {
	var out []string
	for _, v := range p.Spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			out = append(out, v.PersistentVolumeClaim.ClaimName)
		}
	}
	return out
}

// Job returns a Job by namespace and name, or nil.
func (s *Snapshot) Job(ns, name string) *batchv1.Job { return s.idx.jobs[nsName{ns, name}] }
