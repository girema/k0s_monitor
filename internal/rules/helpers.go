package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// containerHit is one container status that matched a rule.
type containerHit struct {
	pod    *corev1.Pod
	spec   *corev1.Container
	status corev1.ContainerStatus
}

// workloadGroup collects the hits of one workload, in a stable order.
type workloadGroup struct {
	w    snapshot.Workload
	hits []containerHit
}

// groupByWorkload walks every container of every non-terminal pod and groups
// the ones that match by top-level owner.
func groupByWorkload(s *snapshot.Snapshot, match func(p *corev1.Pod, cs corev1.ContainerStatus) bool) []*workloadGroup {
	groups := map[snapshot.Workload]*workloadGroup{}
	var order []snapshot.Workload
	for _, p := range s.Pods {
		if snapshot.IsPodTerminal(p) || p.DeletionTimestamp != nil {
			continue
		}
		statuses := append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...)
		for _, cs := range statuses {
			if !match(p, cs) {
				continue
			}
			w := s.WorkloadOf(p)
			g, ok := groups[w]
			if !ok {
				g = &workloadGroup{w: w}
				groups[w] = g
				order = append(order, w)
			}
			g.hits = append(g.hits, containerHit{pod: p, spec: containerSpec(p, cs.Name), status: cs})
		}
	}
	out := make([]*workloadGroup, 0, len(order))
	for _, w := range order {
		out = append(out, groups[w])
	}
	return out
}

func containerSpec(p *corev1.Pod, name string) *corev1.Container {
	for i := range p.Spec.Containers {
		if p.Spec.Containers[i].Name == name {
			return &p.Spec.Containers[i]
		}
	}
	for i := range p.Spec.InitContainers {
		if p.Spec.InitContainers[i].Name == name {
			return &p.Spec.InitContainers[i]
		}
	}
	return nil
}

// pods returns the distinct pods of the group.
func (g *workloadGroup) pods() []*corev1.Pod {
	seen := map[*corev1.Pod]bool{}
	var out []*corev1.Pod
	for _, h := range g.hits {
		if !seen[h.pod] {
			seen[h.pod] = true
			out = append(out, h.pod)
		}
	}
	return out
}

// worst returns the hit with the most restarts, the one to show as evidence.
func (g *workloadGroup) worst() containerHit {
	best := g.hits[0]
	for _, h := range g.hits[1:] {
		if h.status.RestartCount > best.status.RestartCount {
			best = h
		}
	}
	return best
}

// replicaImpact fills the impact of a problem that affects some pods of a
// workload, and returns "n of m pods" for titles.
func replicaImpact(s *snapshot.Snapshot, w snapshot.Workload, affected []*corev1.Pod, im *findings.Impact) string {
	desired, known := s.DesiredReplicas(w)
	n := len(affected)
	im.AffectedPods = n
	if !known || desired <= 0 {
		return plural(n, "pod", "pods")
	}
	ready := 0
	for _, p := range s.PodsOf(w) {
		if snapshot.IsPodReady(p) {
			ready++
		}
	}
	im.FractionDown = float64(n) / float64(desired)
	if im.FractionDown > 1 {
		im.FractionDown = 1
	}
	im.AllReplicasDown = ready == 0 && n > 0
	shown := n
	if int32(shown) > desired {
		shown = int(desired)
	}
	return fmt.Sprintf("%d of %d pods", shown, desired)
}

// exposed reports whether traffic from outside reaches the workload: a
// NodePort or LoadBalancer Service, or an Ingress, selects its pods.
func exposed(s *snapshot.Snapshot, w snapshot.Workload) bool {
	if !s.Has(snapshot.KindService) {
		return false
	}
	pods := s.PodsOf(w)
	if len(pods) == 0 {
		return false
	}
	for _, svc := range s.Services {
		if svc.Namespace != w.Namespace || len(svc.Spec.Selector) == 0 {
			continue
		}
		public := svc.Spec.Type == corev1.ServiceTypeNodePort ||
			svc.Spec.Type == corev1.ServiceTypeLoadBalancer ||
			s.IsIngressBackend(svc.Namespace, svc.Name)
		if !public {
			continue
		}
		for _, p := range s.SelectPods(svc.Namespace, svc.Spec.Selector) {
			if s.WorkloadOf(p) == w {
				return true
			}
		}
	}
	return false
}

func nodesOf(pods []*corev1.Pod) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range pods {
		if n := p.Spec.NodeName; n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func claimsOf(pods []*corev1.Pod) []findings.ObjectRef {
	seen := map[string]bool{}
	var out []findings.ObjectRef
	for _, p := range pods {
		for _, c := range snapshot.ClaimsOfPod(p) {
			if !seen[p.Namespace+"/"+c] {
				seen[p.Namespace+"/"+c] = true
				out = append(out, findings.ObjectRef{Kind: "PersistentVolumeClaim", Namespace: p.Namespace, Name: c})
			}
		}
	}
	return out
}

func podRefs(pods []*corev1.Pod, max int) []findings.ObjectRef {
	var out []findings.ObjectRef
	for i, p := range pods {
		if i == max {
			break
		}
		out = append(out, findings.ObjectRef{Kind: "Pod", Namespace: p.Namespace, Name: p.Name})
	}
	return out
}

func podNames(pods []*corev1.Pod, max int) string {
	var names []string
	for i, p := range pods {
		if i == max {
			names = append(names, "…")
			break
		}
		names = append(names, p.Name)
	}
	return strings.Join(names, ", ")
}
