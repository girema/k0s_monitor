package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// ---------------------------------------------------------------------------
// X02 svc.selector-mismatch

var selectorMismatchRule = Rule{
	ID: "svc.selector-mismatch", Code: "X02", Category: findings.Network,
	Needs: []snapshot.Kind{snapshot.KindService, snapshot.KindPod, snapshot.KindDeployment, snapshot.KindStatefulSet, snapshot.KindDaemonSet},
	Eval:  evalSelectorMismatch,
}

func evalSelectorMismatch(c *Context) []*findings.Finding {
	var out []*findings.Finding
	// Services for control plane pods that k0s doesn't have are H07's.
	k0sTargets := k0sControlPlaneTargets(c.S)
	for _, svc := range c.S.Services {
		if svc.Spec.Type == corev1.ServiceTypeExternalName || len(svc.Spec.Selector) == 0 || svc.DeletionTimestamp != nil {
			continue
		}
		if _, ok := k0sTargets[svc]; ok {
			continue
		}
		if c.S.Now.Sub(svc.CreationTimestamp.Time) < c.T.PendingAfter.D() {
			continue
		}
		if len(c.S.SelectPods(svc.Namespace, svc.Spec.Selector)) > 0 || len(c.S.SelectWorkloads(svc.Namespace, svc.Spec.Selector)) > 0 {
			continue
		}
		if c.S.Has(snapshot.KindEndpointSlice) && c.S.ReadyEndpoints(svc.Namespace, svc.Name) > 0 {
			continue // traffic flows, whatever the selector says
		}
		public := svc.Spec.Type == corev1.ServiceTypeNodePort || svc.Spec.Type == corev1.ServiceTypeLoadBalancer
		viaIngress := c.S.Has(snapshot.KindIngress) && c.S.IsIngressBackend(svc.Namespace, svc.Name)
		f := c.newFinding(findings.Medium, findings.ObjectRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name})
		f.Impact.Exposed = public || viaIngress
		sel := selectorString(svc.Spec.Selector)
		f.AddFact("Selector", sel)
		f.AddFact("Type", string(svc.Spec.Type))
		if viaIngress {
			f.AddFact("Used by an Ingress", "yes")
		}
		f.AddFact("Labels in use", labelsInUse(c.S, svc.Namespace, svc.Spec.Selector))
		if near := nearMiss(c.S, svc.Namespace, svc.Spec.Selector); near != "" {
			f.AddFact("Closest match", near)
		}

		ns := svc.Namespace
		f.Title = fmt.Sprintf("Selector %s matches no pods or workloads", sel)
		f.Summary = "The Service's selector matches nothing in the namespace, so it has nothing to send traffic to. This is often a typo in a label, or the app is not installed."
		f.Remedy.LikelyCause = "The selector does not match the labels of the app's pods, or the app is not deployed in this namespace."
		f.AddStep(findings.Step{Text: "Compare the selector with the pods' labels", Command: fmt.Sprintf("kubectl -n %s get pods --show-labels", ns)})
		f.AddStep(findings.Step{Text: "Fix the selector (or the pods' labels) so they match", Command: fmt.Sprintf("kubectl -n %s edit svc %s", ns, svc.Name)})
		exposure := "Requests to it fail."
		if f.Impact.Exposed {
			exposure = "Requests to it from outside the cluster fail."
		}
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The service %s isn't connected to any app", svc.Name),
			WhatHappened: exposure + " It has nothing to send them to.",
			Why:          "It looks for its app by a label that no app in the cluster has. Often the label is misspelled, or the app isn't installed.",
			WhatToDo:     "Send the report to your support team.",
		}
		out = append(out, f)
	}
	return out
}

// labelsInUse lists, for each selector key, the values pods in the
// namespace have: "app: payments-api, web".
func labelsInUse(s *snapshot.Snapshot, ns string, selector map[string]string) string {
	keys := make([]string, 0, len(selector))
	for k := range selector {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		seen := map[string]bool{}
		for _, p := range s.Pods {
			if p.Namespace == ns {
				if v, ok := p.Labels[k]; ok {
					seen[v] = true
				}
			}
		}
		vals := sortedKeys(seen)
		if len(vals) > 5 {
			vals = append(vals[:5], "…")
		}
		if len(vals) == 0 {
			vals = []string{"no pod has this label"}
		}
		parts = append(parts, k+": "+strings.Join(vals, ", "))
	}
	return strings.Join(parts, "; ")
}

// nearMiss finds a workload whose pods match all but one selector label,
// the usual typo: "deployment payments-api has app=payments-api".
func nearMiss(s *snapshot.Snapshot, ns string, selector map[string]string) string {
	if len(selector) == 0 {
		return ""
	}
	for _, p := range s.Pods {
		if p.Namespace != ns || snapshot.IsPodTerminal(p) {
			continue
		}
		var off []string
		for k, v := range selector {
			if p.Labels[k] != v {
				off = append(off, k)
			}
		}
		if len(off) != 1 {
			continue
		}
		w := s.WorkloadOf(p)
		k := off[0]
		if v, ok := p.Labels[k]; ok {
			return fmt.Sprintf("%s has %s=%s, not %s", workloadRef(w).String(), k, v, selector[k])
		}
		if len(selector) == 1 {
			continue // matching none of one label is no near miss
		}
		return fmt.Sprintf("%s has no label %s", workloadRef(w).String(), k)
	}
	return ""
}

// ---------------------------------------------------------------------------
// X03 ingress.backend-missing

var ingressBackendMissingRule = Rule{
	ID: "ingress.backend-missing", Code: "X03", Category: findings.Network,
	Needs: []snapshot.Kind{snapshot.KindIngress, snapshot.KindService},
	Eval:  evalIngressBackendMissing,
}

type ingressRoute struct {
	where   string // "shop.example.com/api"
	backend *networkingv1.IngressServiceBackend
}

func ingressRoutes(ing *networkingv1.Ingress) []ingressRoute {
	var out []ingressRoute
	if b := ing.Spec.DefaultBackend; b != nil && b.Service != nil {
		out = append(out, ingressRoute{where: "default backend", backend: b.Service})
	}
	for _, r := range ing.Spec.Rules {
		if r.HTTP == nil {
			continue
		}
		host := r.Host
		if host == "" {
			host = "*"
		}
		for _, p := range r.HTTP.Paths {
			if p.Backend.Service != nil {
				out = append(out, ingressRoute{where: host + orDefault(p.Path, "/"), backend: p.Backend.Service})
			}
		}
	}
	return out
}

// backendProblem returns why a backend can't work, or "".
func backendProblem(s *snapshot.Snapshot, ns string, b *networkingv1.IngressServiceBackend) string {
	svc := s.Service(ns, b.Name)
	if svc == nil {
		return fmt.Sprintf("Service %s does not exist", b.Name)
	}
	for _, p := range svc.Spec.Ports {
		if (b.Port.Name != "" && p.Name == b.Port.Name) || (b.Port.Name == "" && p.Port == b.Port.Number) {
			return ""
		}
	}
	port := b.Port.Name
	if port == "" {
		port = fmt.Sprintf("%d", b.Port.Number)
	}
	return fmt.Sprintf("Service %s has no port %s (it has %s)", b.Name, port, orDefault(servicePorts(svc), "no ports"))
}

func evalIngressBackendMissing(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, ing := range c.S.Ingresses {
		if ing.DeletionTimestamp != nil || c.S.Now.Sub(ing.CreationTimestamp.Time) < c.T.PendingAfter.D() {
			continue
		}
		var problems, where []string
		seen := map[string]bool{}
		missingSvc := ""
		for _, r := range ingressRoutes(ing) {
			p := backendProblem(c.S, ing.Namespace, r.backend)
			if p == "" {
				continue
			}
			where = append(where, r.where)
			if !seen[p] {
				seen[p] = true
				problems = append(problems, p)
			}
			if missingSvc == "" {
				missingSvc = r.backend.Name
			}
		}
		if len(problems) == 0 {
			continue
		}
		f := c.newFinding(findings.Medium, findings.ObjectRef{Kind: "Ingress", Namespace: ing.Namespace, Name: ing.Name})
		f.Impact.Exposed = true
		f.AddFact("Problems", strings.Join(problems, "; "))
		f.AddFact("Routes affected", truncate(strings.Join(where, ", "), 300))
		ns := ing.Namespace
		f.Title = problems[0]
		if len(problems) > 1 {
			f.Title += fmt.Sprintf(" (and %d more)", len(problems)-1)
		}
		f.Summary = fmt.Sprintf("Ingress %s routes %s to a backend that can't work: %s. Those requests fail with an error from the ingress controller.", ing.Name, strings.Join(where, ", "), strings.Join(problems, "; "))
		f.Remedy.LikelyCause = "The Service was not created, was deleted, or its name or port is misspelled in the Ingress."
		f.AddStep(findings.Step{Text: "Compare the Ingress backends with the Services", Command: fmt.Sprintf("kubectl -n %s describe ingress %s\nkubectl -n %s get svc", ns, ing.Name, ns)})
		f.AddStep(findings.Step{Text: "Create the Service, or fix the backend's name or port in the Ingress", Command: fmt.Sprintf("kubectl -n %s edit ingress %s", ns, ing.Name)})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("Web requests to %s go nowhere", where[0]),
			WhatHappened: fmt.Sprintf("The web entry point %s sends these requests to the service %s, which can't take them, so they fail.", ing.Name, missingSvc),
			Why:          "The service isn't installed, was removed, or its name or port is written differently.",
			WhatToDo:     "If this belongs to your product, send the report to your support team.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// X08 lb.pending

var lbPendingRule = Rule{
	ID: "lb.pending", Code: "X08", Category: findings.Network,
	Needs: []snapshot.Kind{snapshot.KindService},
	Eval:  evalLBPending,
}

func evalLBPending(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, svc := range c.S.Services {
		if svc.Spec.Type != corev1.ServiceTypeLoadBalancer || len(svc.Status.LoadBalancer.Ingress) > 0 || svc.DeletionTimestamp != nil {
			continue
		}
		created := svc.CreationTimestamp.Time
		if c.S.Now.Sub(created) < c.T.LBPendingAfter.D() {
			continue
		}
		f := c.newFinding(findings.Medium, findings.ObjectRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name})
		f.Since = &created
		var nodePorts []string
		for _, p := range svc.Spec.Ports {
			if p.NodePort != 0 {
				nodePorts = append(nodePorts, fmt.Sprintf("%d", p.NodePort))
			}
		}
		f.AddFact("Waiting for", ago(c.S.Now.Sub(created)))
		f.AddFact("Ports", servicePorts(svc))
		if svc.Spec.LoadBalancerClass != nil {
			f.AddFact("Load balancer class", *svc.Spec.LoadBalancerClass)
		}
		event := ""
		if c.S.Has(snapshot.KindEvent) {
			for _, e := range c.S.EventsFor(svc.UID, "Service", svc.Namespace, svc.Name) {
				event = e.Reason + ": " + e.Message
				break
			}
		}
		f.AddFact("Last event", truncate(event, 300))
		ns := svc.Namespace
		f.Title = fmt.Sprintf("LoadBalancer without an external address for %s", ago(c.S.Now.Sub(created)))
		f.Summary = "The Service asks for a load balancer, and nothing has given it an external address. k0s does not include a load balancer implementation; one such as MetalLB must be installed."
		f.Remedy.LikelyCause = "No load balancer controller (MetalLB, kube-vip or a cloud provider) is installed, or it has no free addresses left."
		f.AddStep(findings.Step{Text: "See the Service's events", Command: fmt.Sprintf("kubectl -n %s describe svc %s", ns, svc.Name)})
		f.AddStep(findings.Step{Text: "Check whether a load balancer controller runs", Command: "kubectl get pods -A | grep -i -E 'metallb|kube-vip|purelb|cilium|openelb'"})
		meanwhile := ""
		if len(nodePorts) > 0 {
			f.AddFact("Reachable meanwhile", "node port "+strings.Join(nodePorts, ", ")+" on any node")
			meanwhile = fmt.Sprintf(" Meanwhile it can be reached on port %s of any server.", strings.Join(nodePorts, ", "))
		}
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The service %s has no outside address", svc.Name),
			WhatHappened: fmt.Sprintf("It has been waiting %s for an address that can be reached from outside the cluster.%s", agoPlain(c.S.Now.Sub(created)), meanwhile),
			Why:          "Nothing in the cluster hands out outside addresses. k0s doesn't include this on its own; a load balancer such as MetalLB must be installed.",
			WhatToDo:     "Send the report to your support team; a load balancer must be installed or given more addresses.",
		}
		out = append(out, f)
	}
	return out
}
