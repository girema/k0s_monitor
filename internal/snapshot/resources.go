package snapshot

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// PodRequests returns the effective CPU and memory requests of a pod, the
// way the scheduler counts them: the larger of the sum of app containers
// and the largest init container, plus pod overhead.
func PodRequests(p *corev1.Pod) corev1.ResourceList {
	sum := corev1.ResourceList{}
	for _, c := range p.Spec.Containers {
		addList(sum, c.Resources.Requests)
	}
	for _, c := range p.Spec.InitContainers {
		if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			// Sidecars run alongside the app containers.
			addList(sum, c.Resources.Requests)
			continue
		}
		for name, q := range c.Resources.Requests {
			if cur, ok := sum[name]; !ok || q.Cmp(cur) > 0 {
				sum[name] = q.DeepCopy()
			}
		}
	}
	addList(sum, p.Spec.Overhead)
	return sum
}

func addList(dst, src corev1.ResourceList) {
	for name, q := range src {
		if cur, ok := dst[name]; ok {
			cur.Add(q)
			dst[name] = cur
		} else {
			dst[name] = q.DeepCopy()
		}
	}
}

// NodeFree is what is left on a node for new pods.
type NodeFree struct {
	Node   string
	CPU    resource.Quantity
	Memory resource.Quantity
}

// FreeOnSchedulableNodes returns, for every Ready and schedulable node, the
// allocatable CPU and memory minus the requests of the pods on it.
func (s *Snapshot) FreeOnSchedulableNodes() []NodeFree {
	var out []NodeFree
	for _, n := range s.Nodes {
		if n.Spec.Unschedulable || !IsNodeReady(n) {
			continue
		}
		cpu := n.Status.Allocatable.Cpu().DeepCopy()
		mem := n.Status.Allocatable.Memory().DeepCopy()
		for _, p := range s.PodsOnNode(n.Name) {
			if IsPodTerminal(p) {
				continue
			}
			r := PodRequests(p)
			cpu.Sub(*r.Cpu())
			mem.Sub(*r.Memory())
		}
		out = append(out, NodeFree{Node: n.Name, CPU: cpu, Memory: mem})
	}
	return out
}
