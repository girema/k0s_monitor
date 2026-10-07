package snapshot

import (
	"sort"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Workload is the top-level owner of a pod: a Deployment, StatefulSet,
// DaemonSet, CronJob, Job, ReplicaSet without a Deployment, or the pod
// itself when nothing owns it.
type Workload struct {
	Kind      string
	Namespace string
	Name      string
}

// PlainNoun is how Basic mode names the workload kind.
func (w Workload) PlainNoun() string {
	switch w.Kind {
	case "CronJob":
		return "scheduled job"
	case "Job":
		return "job"
	case "Pod":
		return "app part"
	}
	return "app"
}

// WorkloadOf returns the top-level owner of a pod.
func (s *Snapshot) WorkloadOf(p *corev1.Pod) Workload {
	if w, ok := s.idx.workloadOfPod[p.UID]; ok && p.UID != "" {
		return w
	}
	return s.resolveWorkload(p)
}

// PodsOf returns the pods that belong to a workload.
func (s *Snapshot) PodsOf(w Workload) []*corev1.Pod { return s.idx.podsByWorkload[w] }

func (s *Snapshot) resolveWorkload(p *corev1.Pod) Workload {
	ref := metav1.GetControllerOf(p)
	if ref == nil {
		return Workload{Kind: "Pod", Namespace: p.Namespace, Name: p.Name}
	}
	switch ref.Kind {
	case "ReplicaSet":
		if rs := s.idx.replicaSets[nsName{p.Namespace, ref.Name}]; rs != nil {
			if d := metav1.GetControllerOf(rs); d != nil && d.Kind == "Deployment" {
				return Workload{Kind: "Deployment", Namespace: p.Namespace, Name: d.Name}
			}
		} else if name, ok := deploymentNameFromReplicaSet(ref.Name, p); ok {
			// ReplicaSets were not collected: fall back to the naming
			// convention <deployment>-<pod-template-hash>.
			return Workload{Kind: "Deployment", Namespace: p.Namespace, Name: name}
		}
		return Workload{Kind: "ReplicaSet", Namespace: p.Namespace, Name: ref.Name}
	case "Job":
		if j := s.idx.jobs[nsName{p.Namespace, ref.Name}]; j != nil {
			if cj := metav1.GetControllerOf(j); cj != nil && cj.Kind == "CronJob" {
				return Workload{Kind: "CronJob", Namespace: p.Namespace, Name: cj.Name}
			}
		}
		return Workload{Kind: "Job", Namespace: p.Namespace, Name: ref.Name}
	default:
		return Workload{Kind: ref.Kind, Namespace: p.Namespace, Name: ref.Name}
	}
}

func deploymentNameFromReplicaSet(rsName string, p *corev1.Pod) (string, bool) {
	hash := p.Labels["pod-template-hash"]
	suffix := "-" + hash
	if hash == "" || len(rsName) <= len(suffix) || rsName[len(rsName)-len(suffix):] != suffix {
		return "", false
	}
	return rsName[:len(rsName)-len(suffix)], true
}

// DesiredReplicas returns how many pods the workload wants, and whether the
// number is known.
func (s *Snapshot) DesiredReplicas(w Workload) (int32, bool) {
	key := nsName{w.Namespace, w.Name}
	switch w.Kind {
	case "Deployment":
		if d := s.idx.deployments[key]; d != nil {
			return replicasOrOne(d.Spec.Replicas), true
		}
	case "StatefulSet":
		if o := s.idx.statefulSets[key]; o != nil {
			return replicasOrOne(o.Spec.Replicas), true
		}
	case "DaemonSet":
		if o := s.idx.daemonSets[key]; o != nil {
			return o.Status.DesiredNumberScheduled, true
		}
	case "ReplicaSet":
		if o := s.idx.replicaSets[key]; o != nil {
			return replicasOrOne(o.Spec.Replicas), true
		}
	case "Pod":
		return 1, true
	}
	return 0, false
}

func replicasOrOne(r *int32) int32 {
	if r == nil {
		return 1
	}
	return *r
}

// WorkloadMeta returns the metadata of a workload object, if collected.
func (s *Snapshot) WorkloadMeta(w Workload) *metav1.ObjectMeta {
	key := nsName{w.Namespace, w.Name}
	switch w.Kind {
	case "Deployment":
		if o := s.idx.deployments[key]; o != nil {
			return &o.ObjectMeta
		}
	case "StatefulSet":
		if o := s.idx.statefulSets[key]; o != nil {
			return &o.ObjectMeta
		}
	case "DaemonSet":
		if o := s.idx.daemonSets[key]; o != nil {
			return &o.ObjectMeta
		}
	case "ReplicaSet":
		if o := s.idx.replicaSets[key]; o != nil {
			return &o.ObjectMeta
		}
	case "Job":
		if o := s.idx.jobs[key]; o != nil {
			return &o.ObjectMeta
		}
	case "CronJob":
		if o := s.idx.cronJobs[key]; o != nil {
			return &o.ObjectMeta
		}
	}
	return nil
}

// SelectPods returns the pods in a namespace that match a label selector.
// An empty selector matches nothing, like a Service without selector.
func (s *Snapshot) SelectPods(ns string, selector map[string]string) []*corev1.Pod {
	if len(selector) == 0 {
		return nil
	}
	sel := labels.SelectorFromSet(selector)
	var out []*corev1.Pod
	for _, p := range s.Pods {
		if p.Namespace == ns && sel.Matches(labels.Set(p.Labels)) {
			out = append(out, p)
		}
	}
	return out
}

// SelectWorkloads returns the Deployments, StatefulSets and DaemonSets in
// the namespace whose pod template matches the selector, even when they
// have no pods, for example when scaled to 0.
func (s *Snapshot) SelectWorkloads(ns string, selector map[string]string) []Workload {
	if len(selector) == 0 {
		return nil
	}
	sel := labels.SelectorFromSet(selector)
	var out []Workload
	match := func(kind string, meta metav1.ObjectMeta, tmpl map[string]string) {
		if meta.Namespace == ns && sel.Matches(labels.Set(tmpl)) {
			out = append(out, Workload{Kind: kind, Namespace: ns, Name: meta.Name})
		}
	}
	for _, o := range s.Deployments {
		match("Deployment", o.ObjectMeta, o.Spec.Template.Labels)
	}
	for _, o := range s.StatefulSets {
		match("StatefulSet", o.ObjectMeta, o.Spec.Template.Labels)
	}
	for _, o := range s.DaemonSets {
		match("DaemonSet", o.ObjectMeta, o.Spec.Template.Labels)
	}
	return out
}

// IsPodTerminal reports whether a pod has finished for good.
func IsPodTerminal(p *corev1.Pod) bool {
	return p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
}

// IsPodReady reports whether the pod's Ready condition is true.
func IsPodReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// PodCondition returns a pod condition by type.
func PodCondition(p *corev1.Pod, t corev1.PodConditionType) *corev1.PodCondition {
	for i := range p.Status.Conditions {
		if p.Status.Conditions[i].Type == t {
			return &p.Status.Conditions[i]
		}
	}
	return nil
}

// NodeCondition returns a node condition by type.
func NodeCondition(n *corev1.Node, t corev1.NodeConditionType) *corev1.NodeCondition {
	for i := range n.Status.Conditions {
		if n.Status.Conditions[i].Type == t {
			return &n.Status.Conditions[i]
		}
	}
	return nil
}

// IsNodeReady reports whether a node's Ready condition is true.
func IsNodeReady(n *corev1.Node) bool {
	c := NodeCondition(n, corev1.NodeReady)
	return c != nil && c.Status == corev1.ConditionTrue
}

// RevisionAnnotation numbers a Deployment's ReplicaSets, one per revision.
const RevisionAnnotation = "deployment.kubernetes.io/revision"

// Revision is one revision of a Deployment: the ReplicaSet made for it.
type Revision struct {
	Number     int64
	ReplicaSet *appsv1.ReplicaSet
}

// Revisions returns a Deployment's revisions, newest first. The newest is
// the one the Deployment rolls out.
func (s *Snapshot) Revisions(ns, deployment string) []Revision {
	var out []Revision
	for _, rs := range s.ReplicaSets {
		if rs.Namespace != ns {
			continue
		}
		ref := metav1.GetControllerOf(rs)
		if ref == nil || ref.Kind != "Deployment" || ref.Name != deployment {
			continue
		}
		n, err := strconv.ParseInt(rs.Annotations[RevisionAnnotation], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, Revision{Number: n, ReplicaSet: rs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Number > out[j].Number })
	return out
}

// ReplicaSetOf returns the name of the ReplicaSet that owns a pod, or "".
func ReplicaSetOf(p *corev1.Pod) string {
	if ref := metav1.GetControllerOf(p); ref != nil && ref.Kind == "ReplicaSet" {
		return ref.Name
	}
	return ""
}
