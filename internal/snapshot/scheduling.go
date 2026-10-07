package snapshot

import (
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/component-helpers/scheduling/corev1/nodeaffinity"
	"k8s.io/klog/v2"
)

// conditionTaints are the taints Kubernetes puts on a node because of its
// conditions. They go away by themselves when the node recovers.
var conditionTaints = map[string]bool{
	corev1.TaintNodeNotReady:           true,
	corev1.TaintNodeUnreachable:        true,
	corev1.TaintNodeDiskPressure:       true,
	corev1.TaintNodeMemoryPressure:     true,
	corev1.TaintNodePIDPressure:        true,
	corev1.TaintNodeNetworkUnavailable: true,
}

// ConditionBlock tells which nodes keep a pending pod out only because of
// their condition, and which condition taints (present, or due because the
// node is not ready) stand for it.
type ConditionBlock struct {
	Nodes  []string
	Taints []string
}

// ConditionBlocked looks at the nodes the pod may run on (its node selector
// and required node affinity) and returns the ones that keep it out because
// of their condition: they are not Ready, or repel it only with condition
// taints. It returns nil when some candidate node is healthy: then the pod
// waits for something else, such as free CPU or memory. Nodes that are
// cordoned or tainted for other work are ignored, since their recovery
// would not help the pod.
func (s *Snapshot) ConditionBlocked(p *corev1.Pod) *ConditionBlock {
	aff := nodeaffinity.GetRequiredNodeAffinity(p)
	logger := klog.Background()
	var nodes []string
	taints := map[string]bool{}
	for _, n := range s.Nodes {
		if ok, err := aff.Match(n); err != nil || !ok {
			continue
		}
		if n.Spec.Unschedulable && !tolerated(logger, p, &corev1.Taint{Key: corev1.TaintNodeUnschedulable, Effect: corev1.TaintEffectNoSchedule}) {
			continue // cordoned; DaemonSet pods tolerate that
		}
		var cond []string
		other := false
		for i := range n.Spec.Taints {
			t := &n.Spec.Taints[i]
			if t.Effect == corev1.TaintEffectPreferNoSchedule || tolerated(logger, p, t) {
				continue
			}
			if conditionTaints[t.Key] {
				cond = append(cond, t.Key)
			} else {
				other = true
			}
		}
		if other {
			continue
		}
		if ready := NodeCondition(n, corev1.NodeReady); ready == nil || ready.Status != corev1.ConditionTrue {
			// Not ready, whether or not the taint is there yet. A node that
			// never reported has no capacity either, so the scheduler may
			// name that instead.
			key := corev1.TaintNodeUnreachable
			if ready != nil && ready.Status == corev1.ConditionFalse {
				key = corev1.TaintNodeNotReady
			}
			cond = append(cond, key)
		}
		if len(cond) == 0 {
			return nil
		}
		nodes = append(nodes, n.Name)
		for _, k := range cond {
			taints[k] = true
		}
	}
	if len(nodes) == 0 {
		return nil
	}
	b := &ConditionBlock{Nodes: nodes}
	for k := range taints {
		b.Taints = append(b.Taints, k)
	}
	sort.Strings(b.Nodes)
	sort.Strings(b.Taints)
	return b
}

func tolerated(logger klog.Logger, p *corev1.Pod, t *corev1.Taint) bool {
	for i := range p.Spec.Tolerations {
		if p.Spec.Tolerations[i].ToleratesTaint(logger, t, true) {
			return true
		}
	}
	return false
}

// DaemonSetShouldRun reports whether the daemon set places a pod on the
// node: its node selector and required affinity match, and the node has no
// taint it doesn't tolerate. Condition taints and cordoning are ignored,
// since daemon set pods tolerate them.
func DaemonSetShouldRun(ds *appsv1.DaemonSet, n *corev1.Node) bool {
	p := &corev1.Pod{Spec: ds.Spec.Template.Spec}
	if ok, err := nodeaffinity.GetRequiredNodeAffinity(p).Match(n); err != nil || !ok {
		return false
	}
	logger := klog.Background()
	for i := range n.Spec.Taints {
		t := &n.Spec.Taints[i]
		if t.Effect == corev1.TaintEffectPreferNoSchedule || conditionTaints[t.Key] || t.Key == corev1.TaintNodeUnschedulable {
			continue
		}
		if !tolerated(logger, p, t) {
			return false
		}
	}
	return true
}
