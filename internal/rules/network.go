package rules

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// ---------------------------------------------------------------------------
// X01 svc.no-endpoints

var serviceNoEndpointsRule = Rule{
	ID: "svc.no-endpoints", Code: "X01", Category: findings.Network,
	Needs: []snapshot.Kind{snapshot.KindService, snapshot.KindEndpointSlice, snapshot.KindPod},
	Eval:  evalServiceNoEndpoints,
}

func evalServiceNoEndpoints(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, svc := range c.S.Services {
		if svc.Spec.Type == corev1.ServiceTypeExternalName || len(svc.Spec.Selector) == 0 || svc.DeletionTimestamp != nil {
			continue
		}
		if c.S.Now.Sub(svc.CreationTimestamp.Time) < c.T.PendingAfter.D() {
			continue // new services get endpoints shortly
		}
		ready := 0
		for _, es := range c.S.EndpointSlicesFor(svc.Namespace, svc.Name) {
			for _, ep := range es.Endpoints {
				if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
					ready++
				}
			}
		}
		if ready > 0 {
			continue
		}
		var selected []*corev1.Pod
		for _, p := range c.S.SelectPods(svc.Namespace, svc.Spec.Selector) {
			if !snapshot.IsPodTerminal(p) {
				selected = append(selected, p)
			}
		}
		idle := c.S.SelectWorkloads(svc.Namespace, svc.Spec.Selector)
		if len(selected) == 0 && len(idle) == 0 {
			continue // svc.selector-mismatch explains it
		}
		public := svc.Spec.Type == corev1.ServiceTypeNodePort || svc.Spec.Type == corev1.ServiceTypeLoadBalancer
		viaIngress := c.S.Has(snapshot.KindIngress) && c.S.IsIngressBackend(svc.Namespace, svc.Name)
		sev := findings.Medium
		if public || viaIngress {
			sev = findings.High
		}
		f := c.newFinding(sev, findings.ObjectRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name})
		f.Impact.Exposed = public || viaIngress
		f.Impact.AffectedPods = len(selected)
		for _, p := range selected {
			w := workloadRef(c.S.WorkloadOf(p))
			if !containsRef(f.Links.Workloads, w) {
				f.Links.Workloads = append(f.Links.Workloads, w)
			}
		}
		f.Links.Nodes = nodesOf(selected)
		f.Affected = podRefs(selected, 10)
		sel := selectorString(svc.Spec.Selector)
		f.AddFact("Selector", sel)
		f.AddFact("Matching pods", fmt.Sprintf("%d, none ready", len(selected)))
		f.AddFact("Type", string(svc.Spec.Type))
		if viaIngress {
			f.AddFact("Used by an Ingress", "yes")
		}
		f.AddFact("Ports", servicePorts(svc))

		ns := svc.Namespace
		f.AddStep(findings.Step{Text: "Confirm there are no ready endpoints", Command: fmt.Sprintf("kubectl -n %s get endpointslices -l kubernetes.io/service-name=%s", ns, svc.Name)})
		exposure := "Requests to it fail."
		if viaIngress || public {
			exposure = "Requests to it from outside the cluster fail."
		}
		if len(selected) == 0 {
			// The app is there but has no pods, for example scaled to 0.
			w := idle[0]
			for _, iw := range idle {
				f.Links.Workloads = append(f.Links.Workloads, workloadRef(iw))
			}
			desired, _ := c.S.DesiredReplicas(w)
			state := "has no pods"
			if desired == 0 && w.Kind != "DaemonSet" {
				state = "is scaled to 0"
			}
			f.AddFact("Workload", fmt.Sprintf("%s (%s)", workloadRef(w).String(), state))
			f.Title = fmt.Sprintf("No endpoints: %s %s %s", strings.ToLower(w.Kind), w.Name, state)
			f.Summary = fmt.Sprintf("The Service selects the pods of %s %s, which %s, so it has nothing to send traffic to.", strings.ToLower(w.Kind), w.Name, state)
			f.Remedy.LikelyCause = "The app behind the Service is not running. If that is not on purpose, start it again."
			f.AddStep(findings.Step{Text: "See the app's desired and current replicas", Command: fmt.Sprintf("kubectl -n %s get %s -o wide", ns, kubectlTarget(w))})
			if desired == 0 && (w.Kind == "Deployment" || w.Kind == "StatefulSet") {
				f.AddStep(findings.Step{Text: "If the app should run, scale it up again", Command: fmt.Sprintf("kubectl -n %s scale %s --replicas=<n>", ns, kubectlTarget(w))})
			}
			f.Plain = findings.PlainText{
				Title:        fmt.Sprintf("The service %s has nothing behind it", svc.Name),
				WhatHappened: exposure + fmt.Sprintf(" The %s %s behind it isn't running.", w.PlainNoun(), w.Name),
				Why:          fmt.Sprintf("The %s %s has been stopped or has no parts running.", w.PlainNoun(), w.Name),
				WhatToDo:     "If this is not on purpose, send the report to your support team.",
			}
		} else {
			f.Title = fmt.Sprintf("No ready endpoints: %s match, none ready", plural(len(selected), "pod", "pods"))
			f.Summary = "The Service's pods exist but none is ready, so it has nothing to send traffic to."
			f.Remedy.LikelyCause = "The app behind the Service is not running or not ready. Its own problem is the root cause."
			f.AddStep(findings.Step{Text: "See the state of the pods behind it", Command: fmt.Sprintf("kubectl -n %s get pods -o wide -l %s", ns, sel)})
			f.Plain = findings.PlainText{
				Title:        fmt.Sprintf("The service %s has nothing behind it", svc.Name),
				WhatHappened: exposure + " None of the app parts behind it are ready.",
				Why:          "The app behind it isn't running properly. Its own problem explains why.",
				WhatToDo:     "Fix the app's problem first (see the related problem).",
			}
		}
		out = append(out, f)
	}
	return out
}

func servicePorts(svc *corev1.Service) string {
	var parts []string
	for _, p := range svc.Spec.Ports {
		s := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		if p.NodePort != 0 {
			s += fmt.Sprintf(" (node port %d)", p.NodePort)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// X04 dns.unhealthy

var dnsUnhealthyRule = Rule{
	ID: "dns.unhealthy", Code: "X04", Category: findings.Network,
	Needs: []snapshot.Kind{snapshot.KindPod, snapshot.KindDeployment},
	Eval:  evalDNSUnhealthy,
}

// dnsLabel is the label CoreDNS pods carry in k0s and upstream Kubernetes.
const dnsLabel = "k8s-app"

func evalDNSUnhealthy(c *Context) []*findings.Finding {
	dep := c.S.Deployment("kube-system", "coredns")
	var pods []*corev1.Pod
	for _, p := range c.S.Pods {
		if p.Namespace == "kube-system" && p.Labels[dnsLabel] == "kube-dns" && !snapshot.IsPodTerminal(p) && p.DeletionTimestamp == nil {
			pods = append(pods, p)
		}
	}
	if dep == nil && len(pods) == 0 {
		// DNS may be provided by something else; without CoreDNS objects we
		// cannot judge it.
		return nil
	}
	ready := 0
	var notReady []*corev1.Pod
	for _, p := range pods {
		if snapshot.IsPodReady(p) {
			ready++
		} else {
			notReady = append(notReady, p)
		}
	}
	desired := int32(len(pods))
	if dep != nil {
		desired = 1
		if dep.Spec.Replicas != nil {
			desired = *dep.Spec.Replicas
		}
	}
	if ready > 0 && len(notReady) == 0 && int32(ready) >= desired {
		return nil
	}
	ref := findings.ObjectRef{Kind: "Deployment", Namespace: "kube-system", Name: "coredns"}
	if dep == nil {
		ref = findings.ObjectRef{Kind: "Service", Namespace: "kube-system", Name: "kube-dns"}
	}
	sev := findings.Critical
	if ready > 0 {
		sev = findings.Medium
	}
	f := c.newFinding(sev, ref)
	f.System = true
	f.Impact.ClusterWide = ready == 0
	f.Impact.AffectedPods = len(notReady)
	f.Links.Workloads = []findings.ObjectRef{{Kind: "Deployment", Namespace: "kube-system", Name: "coredns"}}
	f.Links.Nodes = nodesOf(notReady)
	f.Affected = podRefs(notReady, 10)
	f.AddFact("Ready pods", fmt.Sprintf("%d of %d", ready, desired))
	var states []string
	for _, p := range notReady {
		states = append(states, p.Name+": "+podStateText(p))
	}
	f.AddFact("Pods", truncate(strings.Join(states, "; "), 400))

	switch {
	case desired == 0:
		f.Title = "CoreDNS is scaled to 0 replicas"
	case ready == 0:
		f.Title = fmt.Sprintf("No ready CoreDNS pods (0 of %d)", desired)
	default:
		f.Title = fmt.Sprintf("CoreDNS degraded: %d of %d pods ready", ready, desired)
	}
	f.Summary = "Cluster DNS (CoreDNS) is not fully available. Pods resolve Service names through it."
	f.Remedy.LikelyCause = "CoreDNS pods are not running or not ready. k0s normally manages CoreDNS itself."
	f.AddStep(findings.Step{Text: "See the CoreDNS deployment and pods", Command: "kubectl -n kube-system get deploy coredns\nkubectl -n kube-system get pods -l k8s-app=kube-dns -o wide"})
	f.AddStep(findings.Step{Text: "Read the CoreDNS logs and events", Command: "kubectl -n kube-system describe pods -l k8s-app=kube-dns\nkubectl -n kube-system logs -l k8s-app=kube-dns --tail=50"})
	if desired == 0 {
		f.AddStep(findings.Step{
			Text:    "Scale CoreDNS back up (k0s normally sets the replica count itself)",
			Command: "kubectl -n kube-system scale deploy coredns --replicas=2",
		})
	}
	what := "The service that lets apps find each other by name has no working copies."
	if ready > 0 {
		what = fmt.Sprintf("Only %d of %d copies of the service that lets apps find each other by name are working.", ready, desired)
	}
	f.Plain = findings.PlainText{
		Title:        "Name lookup (DNS) inside the cluster doesn't work",
		WhatHappened: what,
		Why:          "Apps that talk to other services by name fail while it is down.",
		WhatToDo:     "k0s normally keeps this service running on its own. If it stays down, send the report to your support team.",
	}
	if ready > 0 {
		f.Plain.Title = "Name lookup (DNS) inside the cluster is degraded"
		f.Plain.Why = "Name lookups still work, but with less capacity and no spare copy."
	}
	return []*findings.Finding{f}
}

func podStateText(p *corev1.Pod) string {
	for _, cs := range p.Status.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
			return cs.State.Waiting.Reason
		}
		if cs.State.Terminated != nil {
			return "Terminated: " + cs.State.Terminated.Reason
		}
	}
	if p.Spec.NodeName == "" {
		return "not scheduled"
	}
	return string(p.Status.Phase)
}
