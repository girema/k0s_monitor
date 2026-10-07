package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// serviceBackends returns the workloads behind a service and when its last
// ready pod stopped being ready. down is zero when it never had pods.
func serviceBackends(s *snapshot.Snapshot, svc *corev1.Service) (ws []findings.ObjectRef, down time.Time) {
	if svc == nil || len(svc.Spec.Selector) == 0 {
		return nil, time.Time{}
	}
	for _, p := range s.SelectPods(svc.Namespace, svc.Spec.Selector) {
		if snapshot.IsPodTerminal(p) {
			continue
		}
		if w := workloadRef(s.WorkloadOf(p)); !containsRef(ws, w) {
			ws = append(ws, w)
		}
		if cond := snapshot.PodCondition(p, corev1.PodReady); cond != nil && cond.LastTransitionTime.After(down) {
			down = cond.LastTransitionTime.Time
		}
	}
	for _, w := range s.SelectWorkloads(svc.Namespace, svc.Spec.Selector) {
		if r := workloadRef(w); !containsRef(ws, r) {
			ws = append(ws, r)
		}
	}
	return ws, down
}

// ---------------------------------------------------------------------------
// C05 webhook.blocking

var webhookBlockingRule = Rule{
	ID: "webhook.blocking", Code: "C05", Category: findings.ControlPlane,
	Needs: []snapshot.Kind{snapshot.KindValidatingWH, snapshot.KindMutatingWH, snapshot.KindService, snapshot.KindEndpointSlice, snapshot.KindPod},
	Eval:  evalWebhookBlocking,
}

// hook is the part of a validating or mutating webhook the rule uses.
type hook struct {
	name     string
	policy   *admissionv1.FailurePolicyType
	service  *admissionv1.ServiceReference
	rules    []admissionv1.RuleWithOperations
	nsSelect *metav1.LabelSelector
}

// coreResources are the resources whose blocking stops ordinary work:
// deploying, scaling and restarting apps.
var coreResources = map[string]bool{
	"*": true, "pods": true, "deployments": true, "replicasets": true, "statefulsets": true,
	"daemonsets": true, "jobs": true, "services": true, "configmaps": true, "secrets": true, "namespaces": true,
}

func evalWebhookBlocking(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, cfg := range c.S.ValidatingWHs {
		var hs []hook
		for _, w := range cfg.Webhooks {
			hs = append(hs, hook{w.Name, w.FailurePolicy, w.ClientConfig.Service, w.Rules, w.NamespaceSelector})
		}
		if f := webhookFinding(c, "ValidatingWebhookConfiguration", cfg.Name, hs); f != nil {
			out = append(out, f)
		}
	}
	for _, cfg := range c.S.MutatingWHs {
		var hs []hook
		for _, w := range cfg.Webhooks {
			hs = append(hs, hook{w.Name, w.FailurePolicy, w.ClientConfig.Service, w.Rules, w.NamespaceSelector})
		}
		if f := webhookFinding(c, "MutatingWebhookConfiguration", cfg.Name, hs); f != nil {
			out = append(out, f)
		}
	}
	return out
}

func webhookFinding(c *Context, kind, name string, hooks []hook) *findings.Finding {
	type blocked struct {
		h       hook
		svc     *corev1.Service
		problem string
	}
	var bs []blocked
	for _, h := range hooks {
		if h.policy != nil && *h.policy != admissionv1.Fail {
			continue
		}
		if h.service == nil {
			continue // an external URL: its health can't be seen from here
		}
		svc := c.S.Service(h.service.Namespace, h.service.Name)
		switch {
		case svc == nil:
			bs = append(bs, blocked{h, nil, fmt.Sprintf("Service %s/%s does not exist", h.service.Namespace, h.service.Name)})
		case svc.Spec.Type == corev1.ServiceTypeExternalName:
		case c.S.ReadyEndpoints(svc.Namespace, svc.Name) == 0:
			if c.S.Now.Sub(svc.CreationTimestamp.Time) < c.T.PendingAfter.D() {
				continue
			}
			if _, down := serviceBackends(c.S, svc); !down.IsZero() && c.S.Now.Sub(down) < c.T.PendingAfter.D() {
				continue // it was ready moments ago, for example during a restart
			}
			bs = append(bs, blocked{h, svc, fmt.Sprintf("Service %s/%s has no ready endpoints", svc.Namespace, svc.Name)})
		}
	}
	if len(bs) == 0 {
		return nil
	}
	f := c.newFinding(findings.Critical, findings.ObjectRef{Kind: kind, Name: name})
	f.System = true
	var names, problems, intercepts []string
	core := false
	for _, b := range bs {
		names = append(names, b.h.name)
		problems = append(problems, b.problem)
		ref := findings.ObjectRef{Kind: "Service", Namespace: b.h.service.Namespace, Name: b.h.service.Name}
		if !containsRef(f.Links.Services, ref) {
			f.Links.Services = append(f.Links.Services, ref)
		}
		ws, _ := serviceBackends(c.S, b.svc)
		for _, w := range ws {
			if !containsRef(f.Links.Workloads, w) {
				f.Links.Workloads = append(f.Links.Workloads, w)
			}
		}
		for _, r := range b.h.rules {
			var ops []string
			for _, o := range r.Operations {
				ops = append(ops, string(o))
			}
			for _, res := range r.Resources {
				if coreResources[strings.SplitN(res, "/", 2)[0]] {
					core = true
				}
			}
			intercepts = append(intercepts, strings.Join(ops, ", ")+" "+strings.Join(r.Resources, ", "))
		}
	}
	scope := "in all namespaces"
	if s := bs[0].h.nsSelect; s != nil && (len(s.MatchLabels) > 0 || len(s.MatchExpressions) > 0) {
		scope = "in namespaces matching " + metav1.FormatLabelSelector(s)
	}
	// Blocking ordinary resources everywhere stops all deployments.
	f.Impact.ClusterWide = core && scope == "in all namespaces"
	f.AddFact("Webhooks", strings.Join(names, ", "))
	f.AddFact("Problem", strings.Join(problems, "; "))
	f.AddFact("Intercepts", truncate(strings.Join(intercepts, "; "), 300)+" "+scope)
	f.AddFact("Failure policy", "Fail")

	resources := "matching objects"
	if len(bs[0].h.rules) > 0 && len(bs[0].h.rules[0].Resources) > 0 {
		resources = strings.Join(bs[0].h.rules[0].Resources, ", ")
	}
	svcName := bs[0].h.service.Namespace + "/" + bs[0].h.service.Name
	f.Title = fmt.Sprintf("Webhook %s blocks %s: %s", bs[0].h.name, resources, problems[0])
	f.Summary = fmt.Sprintf("Admission webhook %s must approve every create or update of %s %s, with failurePolicy Fail, and its backend is down (%s). Those requests are rejected, so deployments, restarts and updates of matching objects fail.",
		bs[0].h.name, resources, scope, problems[0])
	f.Remedy.LikelyCause = "The app that serves the webhook is not running, or was uninstalled while its webhook configuration stayed behind."
	lower := strings.ToLower(kind)
	f.AddStep(findings.Step{Text: "See the webhook configuration", Command: fmt.Sprintf("kubectl get %s %s -o yaml", lower, name)})
	f.AddStep(findings.Step{Text: "See the webhook's Service and its endpoints", Command: fmt.Sprintf("kubectl -n %s describe svc %s\nkubectl -n %s get endpointslices -l kubernetes.io/service-name=%s", bs[0].h.service.Namespace, bs[0].h.service.Name, bs[0].h.service.Namespace, bs[0].h.service.Name)})
	f.AddStep(findings.Step{
		Text:    "Fix the webhook's app (see the related problems). Only if that app was uninstalled on purpose, remove the leftover configuration",
		Plain:   "The app that answers the check must run again. If it was removed on purpose, its leftover check must be removed too.",
		Command: fmt.Sprintf("kubectl delete %s %s", lower, name),
	})
	f.Plain = findings.PlainText{
		Title:        fmt.Sprintf("Changes are blocked by a broken check (%s)", name),
		WhatHappened: fmt.Sprintf("Creating or changing %s needs the approval of the check %s, but the check doesn't answer, so these changes fail. Apps that need to restart or update may not come back.", resources, bs[0].h.name),
		Why:          fmt.Sprintf("The app that answers the check (service %s) isn't running or doesn't exist.", svcName),
		WhatToDo:     "Fix the check's app first (see the related problem). If it was uninstalled, its leftover check must be removed: send the report to your support team.",
	}
	return f
}

// ---------------------------------------------------------------------------
// C06 apiservice.unavailable

var apiServiceUnavailableRule = Rule{
	ID: "apiservice.unavailable", Code: "C06", Category: findings.ControlPlane,
	Needs: []snapshot.Kind{snapshot.KindAPIService, snapshot.KindService, snapshot.KindPod},
	Eval:  evalAPIServiceUnavailable,
}

func evalAPIServiceUnavailable(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, a := range c.S.APIServices {
		if a.Available || a.Service == "" || (!a.Since.IsZero() && c.S.Now.Sub(a.Since) < c.T.PendingAfter.D()) {
			continue
		}
		f := c.newFinding(findings.High, findings.ObjectRef{Kind: "APIService", Name: a.Name})
		f.System = true
		if !a.Since.IsZero() {
			since := a.Since
			f.Since = &since
		}
		ns, svcName, _ := strings.Cut(a.Service, "/")
		svc := c.S.Service(ns, svcName)
		f.Links.Services = []findings.ObjectRef{{Kind: "Service", Namespace: ns, Name: svcName}}
		f.Links.Workloads, _ = serviceBackends(c.S, svc)
		version, group, _ := strings.Cut(a.Name, ".")
		metrics := group == "metrics.k8s.io"
		f.AddFact("API", group+"/"+version)
		f.AddFact("Service", a.Service)
		f.AddFact("Reason", a.Reason)
		f.AddFact("Message", truncate(a.Message, 300))
		if !a.Since.IsZero() {
			f.AddFact("Unavailable for", ago(c.S.Now.Sub(a.Since)))
		}
		f.Title = fmt.Sprintf("Aggregated API %s unavailable: %s", a.Name, orDefault(a.Reason, "not available"))
		breaks := "Namespaces can't be fully deleted while it is down (they stay Terminating), and clients that discover all APIs report errors."
		if metrics {
			breaks = "k0s kubectl top and autoscaling (HPA) don't work, namespaces can't be fully deleted (they stay Terminating), and clients that discover all APIs report errors."
		}
		f.Summary = fmt.Sprintf("The API server can't reach the service %s that serves %s. %s", a.Service, group, breaks)
		f.Remedy.LikelyCause = fmt.Sprintf("The app behind %s is not running or not ready, or the API server can't reach it.", a.Service)
		f.AddStep(findings.Step{Text: "See the API registration's status", Command: fmt.Sprintf("kubectl get apiservice %s -o yaml", a.Name)})
		f.AddStep(findings.Step{Text: "See the service and its pods", Command: fmt.Sprintf("kubectl -n %s describe svc %s\nkubectl -n %s get endpointslices -l kubernetes.io/service-name=%s", ns, svcName, ns, svcName)})
		what := fmt.Sprintf("The extension that provides %s doesn't answer.", group)
		plainWhy := "Its app isn't running or can't be reached."
		if metrics {
			what = "The service that measures CPU and memory use (metrics-server) doesn't answer."
			plainWhy = "Its app isn't running or can't be reached. While it is down, usage numbers and automatic scaling don't work, and deleting namespaces gets stuck."
		}
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("Part of the cluster's API (%s) isn't available", group),
			WhatHappened: what,
			Why:          plainWhy,
			WhatToDo:     "It usually comes back once its app runs again (see the related problem). Otherwise send the report to your support team.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// C09 ns.stuck-terminating

var namespaceStuckRule = Rule{
	ID: "ns.stuck-terminating", Code: "C09", Category: findings.ControlPlane,
	Needs: []snapshot.Kind{snapshot.KindNamespace},
	Eval:  evalNamespaceStuck,
}

func evalNamespaceStuck(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, ns := range c.S.Namespaces {
		if ns.DeletionTimestamp == nil || c.S.Now.Sub(ns.DeletionTimestamp.Time) < c.T.NamespaceTerminatingAfter.D() {
			continue
		}
		since := ns.DeletionTimestamp.Time
		f := c.newFinding(findings.Medium, findings.ObjectRef{Kind: "Namespace", Name: ns.Name})
		f.Since = &since
		var reasons []string
		cause := ""
		conds := append([]corev1.NamespaceCondition{}, ns.Status.Conditions...)
		sort.SliceStable(conds, func(i, j int) bool { return conds[i].Type < conds[j].Type })
		for _, cond := range conds {
			if cond.Status != corev1.ConditionTrue {
				continue
			}
			reasons = append(reasons, fmt.Sprintf("%s: %s", cond.Type, truncate(cond.Message, 200)))
			switch cond.Type {
			case corev1.NamespaceDeletionDiscoveryFailure, corev1.NamespaceDeletionGVParsingFailure:
				cause = "discovery"
			case corev1.NamespaceFinalizersRemaining:
				if cause == "" {
					cause = "finalizers"
				}
			case corev1.NamespaceContentRemaining, corev1.NamespaceDeletionContentFailure:
				if cause == "" {
					cause = "content"
				}
			}
		}
		f.Links.Cause = cause
		f.AddFact("Terminating for", ago(c.S.Now.Sub(since)))
		f.AddFact("Conditions", truncate(strings.Join(reasons, "; "), 500))
		var finalizers []string
		for _, fz := range ns.Spec.Finalizers {
			finalizers = append(finalizers, string(fz))
		}
		f.AddFact("Finalizers", strings.Join(append(finalizers, ns.Finalizers...), ", "))

		f.Title = fmt.Sprintf("Terminating for %s", ago(c.S.Now.Sub(since)))
		f.AddStep(findings.Step{Text: "See why the deletion is stuck (status conditions)", Command: fmt.Sprintf("kubectl get namespace %s -o yaml", ns.Name)})
		switch cause {
		case "discovery":
			f.Title += ": an aggregated API is unavailable"
			f.Remedy.LikelyCause = "The namespace controller must list every API to delete the namespace's contents, and an aggregated API does not answer."
			f.AddStep(findings.Step{Text: "Find the unavailable API", Command: "kubectl get apiservices | grep -v True"})
		case "finalizers":
			f.Title += ": objects with finalizers remain"
			f.Remedy.LikelyCause = "Objects in the namespace have finalizers whose controller does not remove them, often because that controller was uninstalled first."
			f.AddStep(findings.Step{Text: "List what is left in the namespace", Command: fmt.Sprintf("kubectl api-resources --verbs=list --namespaced -o name | xargs -n 1 kubectl get --show-kind --ignore-not-found -n %s", ns.Name)})
		default:
			f.Title += ": content remains"
			f.Remedy.LikelyCause = "Some objects in the namespace can't be deleted yet."
			f.AddStep(findings.Step{Text: "List what is left in the namespace", Command: fmt.Sprintf("kubectl api-resources --verbs=list --namespaced -o name | xargs -n 1 kubectl get --show-kind --ignore-not-found -n %s", ns.Name)})
		}
		f.Summary = fmt.Sprintf("Namespace %s was deleted %s ago and is still Terminating. %s", ns.Name, ago(c.S.Now.Sub(since)), f.Remedy.LikelyCause)
		plainWhy := "Some of its contents can't be removed yet."
		if cause == "discovery" {
			plainWhy = "Part of the cluster's API doesn't answer, so its contents can't all be found and removed."
		}
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The namespace %s is stuck while being deleted", ns.Name),
			WhatHappened: fmt.Sprintf("It was deleted %s ago and is still being removed.", agoPlain(c.S.Now.Sub(since))),
			Why:          plainWhy,
			WhatToDo:     "Fix the related problem first if there is one. Otherwise send the report to your support team.",
		}
		out = append(out, f)
	}
	return out
}
