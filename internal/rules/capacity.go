package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// ---------------------------------------------------------------------------
// N07 node.overcommit

var nodeOvercommitRule = Rule{
	ID: "node.overcommit", Code: "N07", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindNode, snapshot.KindPod},
	Eval:  evalNodeOvercommit,
}

// podLimits sums a pod's container limits, like its requests.
func podLimits(p *corev1.Pod) corev1.ResourceList {
	out := corev1.ResourceList{}
	for _, c := range p.Spec.Containers {
		for k, v := range c.Resources.Limits {
			q := out[k]
			q.Add(v)
			out[k] = q
		}
	}
	return out
}

func evalNodeOvercommit(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, n := range c.S.Nodes {
		pods := activePodsOn(c, n.Name)
		if len(pods) == 0 {
			continue
		}
		req, lim := corev1.ResourceList{}, corev1.ResourceList{}
		for _, p := range pods {
			for k, v := range snapshot.PodRequests(p) {
				q := req[k]
				q.Add(v)
				req[k] = q
			}
			for k, v := range podLimits(p) {
				q := lim[k]
				q.Add(v)
				lim[k] = q
			}
		}
		type over struct {
			res        corev1.ResourceName
			kind       string
			share      float64
			used, have resource.Quantity
		}
		var overs []over
		for _, res := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
			alloc, ok := n.Status.Allocatable[res]
			if !ok || alloc.IsZero() {
				continue
			}
			if r := req[res]; r.AsApproximateFloat64()/alloc.AsApproximateFloat64() >= 0.9 {
				overs = append(overs, over{res, "requests", r.AsApproximateFloat64() / alloc.AsApproximateFloat64(), r, alloc})
			}
			if l := lim[res]; l.AsApproximateFloat64()/alloc.AsApproximateFloat64() > 1.5 {
				overs = append(overs, over{res, "limits", l.AsApproximateFloat64() / alloc.AsApproximateFloat64(), l, alloc})
			}
		}
		if len(overs) == 0 {
			continue
		}
		sev := findings.Low
		var parts, plainParts []string
		for _, o := range overs {
			if o.kind == "requests" {
				sev = findings.Medium
			}
			parts = append(parts, fmt.Sprintf("%s %s %s of allocatable", o.res, o.kind, pct(o.share)))
			f := "promised"
			if o.kind == "requests" {
				f = "reserved"
			}
			plainParts = append(plainParts, fmt.Sprintf("%s of its %s is %s", pct(o.share), plainResource(string(o.res)), f))
		}
		f := c.newFinding(sev, findings.ObjectRef{Kind: "Node", Name: n.Name})
		f.System = true
		f.Links.Nodes = []string{n.Name}
		for _, o := range overs {
			f.AddFact(fmt.Sprintf("%s %s", strings.ToUpper(string(o.res[:1]))+string(o.res[1:]), o.kind), fmt.Sprintf("%s of %s allocatable (%s)", o.used.String(), o.have.String(), pct(o.share)))
		}
		f.AddFact("Pods", fmt.Sprintf("%d", len(pods)))
		f.Title = strings.Join(parts, ", ")
		f.Summary = fmt.Sprintf("Node %s is committed beyond what it has: %s. Requests near 100%% leave no room to schedule; limits far above 100%% mean the pods can't all use what they may at once.", n.Name, strings.Join(parts, "; "))
		f.Remedy.LikelyCause = "The pods' requests and limits were not sized for this node, or too many pods run on it."
		f.AddStep(findings.Step{Text: "See what each pod requests and may use", Command: fmt.Sprintf("kubectl describe node %s | grep -A 30 'Non-terminated Pods'", n.Name)})
		f.AddStep(findings.Step{Text: "Right-size the workloads' requests and limits to what they use (k0s kubectl top), or add a node"})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The server %s has promised more than it has", n.Name),
			WhatHappened: strings.ToUpper(plainParts[0][:1]) + strings.Join(plainParts, "; ")[1:] + ".",
			Why:          "The apps on it are allowed to use more than the server can give at once. New apps may not fit, and busy apps may be slowed or stopped.",
			WhatToDo:     "Send the report to your support team; the apps' resource settings or the number of servers need to change.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// N09 node.pods-near-max

var nodePodsNearMaxRule = Rule{
	ID: "node.pods-near-max", Code: "N09", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindNode, snapshot.KindPod},
	Eval:  evalNodePodsNearMax,
}

func evalNodePodsNearMax(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, n := range c.S.Nodes {
		maxPods, ok := n.Status.Allocatable[corev1.ResourcePods]
		if !ok || maxPods.Value() == 0 {
			continue
		}
		pods := activePodsOn(c, n.Name)
		share := float64(len(pods)) / float64(maxPods.Value())
		if share < 0.9 {
			continue
		}
		f := c.newFinding(findings.Medium, findings.ObjectRef{Kind: "Node", Name: n.Name})
		f.System = true
		f.Links.Nodes = []string{n.Name}
		f.AddFact("Pods", fmt.Sprintf("%d of %d allowed (%s)", len(pods), maxPods.Value(), pct(share)))
		f.Title = fmt.Sprintf("%d of %d pods: the node is almost at its pod limit", len(pods), maxPods.Value())
		f.Summary = fmt.Sprintf("Node %s runs %d pods and allows %d. New pods won't be scheduled there once it is full.", n.Name, len(pods), maxPods.Value())
		f.Remedy.LikelyCause = "Many small pods run on this node, or old pods were not cleaned up."
		f.AddStep(findings.Step{Text: "List the pods on the node", Command: fmt.Sprintf("kubectl get pods -A -o wide --field-selector spec.nodeName=%s", n.Name)})
		f.AddStep(findings.Step{Text: "Raise maxPods in a k0s worker profile (a product update), or add a node"})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The server %s can run only a few more app parts", n.Name),
			WhatHappened: fmt.Sprintf("It runs %d app parts and allows %d.", len(pods), maxPods.Value()),
			Why:          "Each server has a limit on how many app parts it can run.",
			WhatToDo:     "Send the report to your support team; another server or a higher limit may be needed.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// W15 hpa.maxed and hpa.no-metrics

var hpaMaxedRule = Rule{
	ID: "hpa.maxed", Code: "W15", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindHPA},
	Eval:  evalHPAMaxed,
}

var hpaNoMetricsRule = Rule{
	ID: "hpa.no-metrics", Code: "W15", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindHPA},
	Eval:  evalHPANoMetrics,
}

func hpaCondition(h *autoscalingv2.HorizontalPodAutoscaler, t autoscalingv2.HorizontalPodAutoscalerConditionType) *autoscalingv2.HorizontalPodAutoscalerCondition {
	for i := range h.Status.Conditions {
		if h.Status.Conditions[i].Type == t {
			return &h.Status.Conditions[i]
		}
	}
	return nil
}

func hpaTarget(h *autoscalingv2.HorizontalPodAutoscaler) findings.ObjectRef {
	return findings.ObjectRef{Kind: h.Spec.ScaleTargetRef.Kind, Namespace: h.Namespace, Name: h.Spec.ScaleTargetRef.Name}
}

func evalHPAMaxed(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, h := range c.S.HPAs {
		if h.Status.CurrentReplicas < h.Spec.MaxReplicas {
			continue
		}
		cond := hpaCondition(h, autoscalingv2.ScalingLimited)
		if cond == nil || cond.Status != corev1.ConditionTrue || cond.Reason != "TooManyReplicas" {
			continue
		}
		since := cond.LastTransitionTime.Time
		if c.S.Now.Sub(since) < c.T.HPAMaxedAfter.D() {
			continue
		}
		f := c.newFinding(findings.Medium, findings.ObjectRef{Kind: "HorizontalPodAutoscaler", Namespace: h.Namespace, Name: h.Name})
		f.Since = &since
		target := hpaTarget(h)
		f.Links.Workloads = []findings.ObjectRef{target}
		f.AddFact("Target", target.String())
		f.AddFact("Replicas", fmt.Sprintf("%d, the maximum", h.Status.CurrentReplicas))
		f.AddFact("At the maximum for", ago(c.S.Now.Sub(since)))
		f.AddFact("Metrics", hpaMetricsText(h))
		f.Title = fmt.Sprintf("At its maximum of %d replicas for %s", h.Spec.MaxReplicas, ago(c.S.Now.Sub(since)))
		f.Summary = fmt.Sprintf("The autoscaler of %s wants more replicas but is at its maximum (%d). The app gets more load than it can handle at this size.", target.Name, h.Spec.MaxReplicas)
		f.Remedy.LikelyCause = "The load grew beyond what maxReplicas allows, or the app got slower and needs more replicas for the same load."
		f.AddStep(findings.Step{Text: "See the autoscaler's metrics and events", Command: fmt.Sprintf("kubectl -n %s describe hpa %s", h.Namespace, h.Name)})
		f.AddStep(findings.Step{Text: "If the nodes have room, raise maxReplicas", Command: fmt.Sprintf(`kubectl -n %s patch hpa %s -p '{"spec":{"maxReplicas":%d}}'`, h.Namespace, h.Name, h.Spec.MaxReplicas*3/2+1)})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The app %s is at its size limit", target.Name),
			WhatHappened: fmt.Sprintf("It has been running at its maximum of %d copies for %s, and would use more.", h.Spec.MaxReplicas, agoPlain(c.S.Now.Sub(since))),
			Why:          "It gets more work than it can handle with that many copies.",
			WhatToDo:     "Send the report to your support team; the maximum may need to be raised, if the servers have room.",
		}
		out = append(out, f)
	}
	return out
}

func hpaMetricsText(h *autoscalingv2.HorizontalPodAutoscaler) string {
	var parts []string
	for _, m := range h.Status.CurrentMetrics {
		if m.Resource != nil && m.Resource.Current.AverageUtilization != nil {
			parts = append(parts, fmt.Sprintf("%s %d%%", m.Resource.Name, *m.Resource.Current.AverageUtilization))
		}
	}
	for _, m := range h.Spec.Metrics {
		if m.Resource != nil && m.Resource.Target.AverageUtilization != nil {
			parts = append(parts, fmt.Sprintf("target %s %d%%", m.Resource.Name, *m.Resource.Target.AverageUtilization))
		}
	}
	return strings.Join(parts, ", ")
}

func evalHPANoMetrics(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, h := range c.S.HPAs {
		cond := hpaCondition(h, autoscalingv2.ScalingActive)
		if cond == nil || cond.Status != corev1.ConditionFalse || cond.Reason == "ScalingDisabled" {
			continue
		}
		since := cond.LastTransitionTime.Time
		if c.S.Now.Sub(since) < c.T.PendingAfter.D() {
			continue
		}
		f := c.newFinding(findings.Medium, findings.ObjectRef{Kind: "HorizontalPodAutoscaler", Namespace: h.Namespace, Name: h.Name})
		f.Since = &since
		target := hpaTarget(h)
		f.Links.Workloads = []findings.ObjectRef{target}
		f.Links.Cause = "metrics-api"
		if strings.Contains(cond.Reason, "External") || strings.Contains(cond.Reason, "Object") {
			f.Links.Cause = "custom-metrics"
		}
		f.AddFact("Target", target.String())
		f.AddFact("Reason", cond.Reason)
		f.AddFact("Message", truncate(cond.Message, 300))
		if m := missingRequest.FindStringSubmatch(cond.Message); m != nil {
			explainMissingRequest(c, f, h, target, m[1], m[2], m[3])
			out = append(out, f)
			continue
		}
		f.Title = fmt.Sprintf("Can't scale: %s", cond.Reason)
		f.Summary = fmt.Sprintf("The autoscaler of %s can't read the metrics it scales on, so it keeps the current number of replicas: %s", target.Name, truncate(cond.Message, 200))
		f.Remedy.LikelyCause = "The metrics API (metrics-server) is down or doesn't answer, or has no metrics for the pods yet."
		f.AddStep(findings.Step{Text: "See the autoscaler's events", Command: fmt.Sprintf("kubectl -n %s describe hpa %s", h.Namespace, h.Name)})
		f.AddStep(findings.Step{Text: "Check the metrics API", Command: "kubectl get apiservice v1beta1.metrics.k8s.io\nkubectl top pods -n " + h.Namespace})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("Automatic scaling of %s doesn't work", target.Name),
			WhatHappened: "It can't measure the app's load, so it can't add or remove copies.",
			Why:          "The service that measures CPU and memory use isn't answering.",
			WhatToDo:     "Fix the related metrics problem first if there is one. Otherwise send the report to your support team.",
		}
		out = append(out, f)
	}
	return out
}

// missingRequest is the autoscaler's complaint that a container has no
// request for the resource it scales on: "missing request for cpu in
// container session-cache of Pod login-5c7d9f6b48-k2x9m".
var missingRequest = regexp.MustCompile(`missing request for (\w+) in container "?([^"\s]+)"? of Pod "?([^"\s]+)"?`)

// explainMissingRequest says what to do when the autoscaler scales on
// usage as a share of the request, and a container of the pods has no
// request. The metrics themselves arrived: the autoscaler checks the
// requests only after it got them.
func explainMissingRequest(c *Context, f *findings.Finding, h *autoscalingv2.HorizontalPodAutoscaler, target findings.ObjectRef, res, container, pod string) {
	ns := h.Namespace
	w := snapshot.Workload{Kind: target.Kind, Namespace: target.Namespace, Name: target.Name}
	kt := kubectlTarget(w)
	name := res // in sentences: "CPU request", "memory request"
	if res == "cpu" {
		name = "CPU"
	}
	f.Links.Cause = "" // not the metrics API: nothing to fold under

	// The other containers, with their requests.
	var with []string
	main := ""
	if pods := c.S.PodsOf(w); len(pods) > 0 {
		for _, ct := range pods[0].Spec.Containers {
			if q, ok := ct.Resources.Requests[corev1.ResourceName(res)]; ok && ct.Name != container {
				with = append(with, ct.Name+" ("+q.String()+")")
				if main == "" {
					main = ct.Name
				}
			}
		}
	}
	f.AddFact("No "+name+" request", "container "+container)
	f.AddFact("With a "+name+" request", strings.Join(with, ", "))

	f.Title = fmt.Sprintf("Can't scale: container %s has no %s request", container, name)
	f.Summary = fmt.Sprintf("The autoscaler of %s scales on %s use as a share of the %s request. Container %s of its pods has no %s request, so the share can't be computed, and it keeps the current number of replicas.",
		target.Name, name, name, container, name)
	f.Remedy.LikelyCause = fmt.Sprintf("Scaling on %s utilization needs a %s request on every container of the pod, sidecars included: utilization is usage divided by the requests. Container %s has none. The metrics API works: the autoscaler got the metrics and checks the requests after that.",
		name, name, container)

	example := map[string]string{"cpu": "100m", "memory": "128Mi"}[res]
	if example == "" {
		example = "1"
	}
	f.AddStep(findings.Step{
		Text:    fmt.Sprintf("See the %s request of each container of %s", name, target.Name),
		Command: fmt.Sprintf(`kubectl -n %s get %s -o jsonpath='{range .spec.template.spec.containers[*]}{.name}{": "}{.resources.requests.%s}{"\n"}{end}'`, ns, kt, res),
	})
	f.AddStep(findings.Step{
		Text:    fmt.Sprintf("See how much %s %s uses, to choose its request: about its usual use", name, container),
		Command: fmt.Sprintf("kubectl -n %s top pod %s --containers", ns, pod),
	})
	set := findings.Step{
		Text:    fmt.Sprintf("Give container %s a %s request (replace %s with what you chose). Its pods restart one by one", container, name, example),
		Plain:   fmt.Sprintf("Whoever deploys %s should give its part %s a %s reservation (a %s request).", target.Name, container, plainResource(res), name),
		Command: fmt.Sprintf("kubectl -n %s set resources %s -c %s --requests=%s=%s", ns, kt, container, res, example),
	}
	if meta := c.S.WorkloadMeta(w); meta != nil && managedByTool(meta.Labels, meta.Annotations) {
		set.Text = fmt.Sprintf("Give container %s a %s request where %s is deployed from (for a Helm chart, in its values), and deploy it: a change made with kubectl is undone by the next deploy. To try it now (replace %s with what you chose)",
			container, name, target.Name, example)
	}
	f.AddStep(set)
	f.AddStep(findings.Step{
		Text:    "Once the new pods run, the autoscaler shows the current use again within a minute",
		Command: fmt.Sprintf("kubectl -n %s get hpa %s", ns, h.Name),
	})
	if main != "" {
		f.AddStep(findings.Step{
			Text: fmt.Sprintf("If %s is a sidecar you can't change, scale on %s's %s use only instead: in the autoscaler, replace the Resource metric with a ContainerResource metric", container, main, name),
			Command: fmt.Sprintf("kubectl -n %s edit hpa %s\n# in spec.metrics, instead of \"type: Resource\":\n# - type: ContainerResource\n#   containerResource:\n#     name: %s\n#     container: %s\n#     target: {type: Utilization, averageUtilization: %d}",
				ns, h.Name, res, main, targetUtilization(h, res)),
		})
	}

	f.Plain = findings.PlainText{
		Title:        fmt.Sprintf("Automatic scaling of %s doesn't work", target.Name),
		WhatHappened: fmt.Sprintf("It can't tell how busy %s is, so it can't add or remove copies.", target.Name),
		Why:          fmt.Sprintf("It measures how much of its reserved %s each part uses, and the part %s reserves none.", plainResource(res), container),
		WhatToDo:     fmt.Sprintf("Whoever deploys %s should give %s a %s reservation in its settings. Send the report to your support team.", target.Name, container, plainResource(res)),
	}
}

// targetUtilization is the autoscaler's target for a resource, or 70.
func targetUtilization(h *autoscalingv2.HorizontalPodAutoscaler, res string) int32 {
	for _, m := range h.Spec.Metrics {
		if m.Resource != nil && string(m.Resource.Name) == res && m.Resource.Target.AverageUtilization != nil {
			return *m.Resource.Target.AverageUtilization
		}
	}
	return 70
}

// ---------------------------------------------------------------------------
// W16 quota.exhausted

var quotaExhaustedRule = Rule{
	ID: "quota.exhausted", Code: "W16", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindQuota},
	Eval:  evalQuotaExhausted,
}

func evalQuotaExhausted(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, q := range c.S.Quotas {
		type use struct {
			res        corev1.ResourceName
			share      float64
			used, hard resource.Quantity
		}
		var uses []use
		for res, hard := range q.Status.Hard {
			used, ok := q.Status.Used[res]
			if !ok || hard.IsZero() {
				continue
			}
			if share := used.AsApproximateFloat64() / hard.AsApproximateFloat64(); share >= 0.9 {
				uses = append(uses, use{res, share, used, hard})
			}
		}
		if len(uses) == 0 {
			continue
		}
		sort.Slice(uses, func(i, j int) bool {
			if uses[i].share != uses[j].share {
				return uses[i].share > uses[j].share
			}
			return uses[i].res < uses[j].res
		})
		sev := findings.Medium
		if uses[0].share >= 1 {
			sev = findings.High
		}
		f := c.newFinding(sev, findings.ObjectRef{Kind: "ResourceQuota", Namespace: q.Namespace, Name: q.Name})
		var parts []string
		for _, u := range uses {
			parts = append(parts, fmt.Sprintf("%s %s of %s", u.res, u.used.String(), u.hard.String()))
			f.AddFact(string(u.res), fmt.Sprintf("%s of %s (%s)", u.used.String(), u.hard.String(), pct(u.share)))
		}
		refused := quotaRefusals(c, q.Namespace)
		if refused != "" {
			f.AddFact("Refused", refused)
		}
		f.Title = fmt.Sprintf("Quota %s: %s", ifStr(uses[0].share >= 1, "used up", "almost used up"), strings.Join(parts, ", "))
		f.Summary = fmt.Sprintf("ResourceQuota %s in namespace %s is at %s for %s. New pods, claims or objects that would exceed it are refused.", q.Name, q.Namespace, pct(uses[0].share), uses[0].res)
		f.Remedy.LikelyCause = "The namespace holds more than the quota was sized for, or leftovers (finished pods, old claims) still count against it."
		f.AddStep(findings.Step{Text: "See the quota and what uses it", Command: fmt.Sprintf("kubectl -n %s describe resourcequota %s", q.Namespace, q.Name)})
		f.AddStep(findings.Step{Text: "Delete leftovers, or raise the quota", Command: fmt.Sprintf("kubectl -n %s edit resourcequota %s", q.Namespace, q.Name)})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The space for apps in %s is %s", q.Namespace, ifStr(uses[0].share >= 1, "used up", "almost used up")),
			WhatHappened: fmt.Sprintf("The namespace %s has a limit, and %s of it is used.", q.Namespace, pct(uses[0].share)),
			Why:          "When the limit is reached, new app parts or storage can't be created there.",
			WhatToDo:     "Send the report to your support team; old leftovers can be removed or the limit raised.",
		}
		out = append(out, f)
	}
	return out
}

// quotaRefusals returns the latest "exceeded quota" event in a namespace.
func quotaRefusals(c *Context, ns string) string {
	if !c.S.Has(snapshot.KindEvent) {
		return ""
	}
	var latest *corev1.Event
	for _, e := range c.S.Events {
		if e.Namespace == ns && strings.Contains(e.Message, "exceeded quota") && (latest == nil || snapshot.EventTime(e).After(snapshot.EventTime(latest))) {
			latest = e
		}
	}
	if latest == nil {
		return ""
	}
	return fmt.Sprintf("%s %s: %s", latest.InvolvedObject.Kind, latest.InvolvedObject.Name, truncate(latest.Message, 200))
}

// ---------------------------------------------------------------------------
// W17 container.near-limit

var containerNearLimitRule = Rule{
	ID: "container.near-limit", Code: "W17", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindMetrics, snapshot.KindPod},
	Eval:  evalContainerNearLimit,
}

func evalContainerNearLimit(c *Context) []*findings.Finding {
	if c.S.Metrics == nil {
		return nil
	}
	type hit struct {
		pod       *corev1.Pod
		container string
		memShare  float64
		limit     resource.Quantity
		throttled float64
		cpuLimit  resource.Quantity
	}
	groups := map[snapshot.Workload][]hit{}
	var order []snapshot.Workload
	for _, p := range c.S.Pods {
		if snapshot.IsPodTerminal(p) || p.DeletionTimestamp != nil {
			continue
		}
		for _, ctr := range p.Spec.Containers {
			m := c.S.Metrics.Containers[p.Namespace+"/"+p.Name+"/"+ctr.Name]
			if m == nil {
				continue
			}
			h := hit{pod: p, container: ctr.Name, memShare: snapshot.Missing, throttled: snapshot.Missing}
			if lim, ok := ctr.Resources.Limits[corev1.ResourceMemory]; ok && !lim.IsZero() && snapshot.Known(m.WorkingSet) {
				h.memShare, h.limit = m.WorkingSet/lim.AsApproximateFloat64(), lim
			}
			if lim, ok := ctr.Resources.Limits[corev1.ResourceCPU]; ok && !lim.IsZero() {
				h.throttled, h.cpuLimit = m.Throttled, lim
			}
			_, memHit := level(h.memShare*100, c.T.ContainerMemoryPercent)
			_, cpuHit := level(h.throttled*100, c.T.CPUThrottledPercent)
			if !memHit && !cpuHit {
				continue
			}
			if !memHit {
				h.memShare = snapshot.Missing
			}
			if !cpuHit {
				h.throttled = snapshot.Missing
			}
			w := c.S.WorkloadOf(p)
			if _, ok := groups[w]; !ok {
				order = append(order, w)
			}
			groups[w] = append(groups[w], h)
		}
	}
	var out []*findings.Finding
	for _, w := range order {
		hits := groups[w]
		// The worst memory share first, then the most throttled.
		sort.SliceStable(hits, func(i, j int) bool { return orNaN0(hits[i].memShare) > orNaN0(hits[j].memShare) })
		h := hits[0]
		f := c.newFinding(findings.Medium, workloadRef(w))
		var pods []*corev1.Pod
		for _, x := range hits {
			pods = append(pods, x.pod)
		}
		f.Impact.AffectedPods = len(pods)
		f.Affected = podRefs(pods, 10)
		f.Links.Workloads = []findings.ObjectRef{workloadRef(w)}
		f.Links.Nodes = nodesOf(pods)
		f.AddFact("Container", h.container)
		var what []string
		if snapshot.Known(h.memShare) {
			what = append(what, fmt.Sprintf("memory at %s of its %s limit", pct(h.memShare), h.limit.String()))
			f.AddFact("Memory", fmt.Sprintf("%s of the %s limit (10 min average)", pct(h.memShare), h.limit.String()))
		}
		throttled := h
		for _, x := range hits {
			if orNaN0(x.throttled) > orNaN0(throttled.throttled) {
				throttled = x
			}
		}
		if snapshot.Known(throttled.throttled) {
			what = append(what, fmt.Sprintf("CPU throttled %s of the time (limit %s)", pct(throttled.throttled), throttled.cpuLimit.String()))
			f.AddFact("CPU throttled", fmt.Sprintf("%s of periods over 15 min, limit %s", pct(throttled.throttled), throttled.cpuLimit.String()))
		}
		f.AddFact("Pods", podNames(pods, 3))
		f.Title = strings.ToUpper(what[0][:1]) + strings.Join(what, ", ")[1:] + fmt.Sprintf(" (container %s)", h.container)
		f.Summary = fmt.Sprintf("Container %q of %s %s is close to its limits: %s.", h.container, strings.ToLower(w.Kind), w.Name, strings.Join(what, "; "))
		f.Remedy.LikelyCause = "The limits are lower than what the container needs under its current load."
		ns := h.pod.Namespace
		f.AddStep(findings.Step{Text: "Compare usage with the limits", Command: fmt.Sprintf("kubectl -n %s top pod %s --containers", ns, h.pod.Name)})
		if w.Kind != "Pod" {
			f.AddStep(findings.Step{Text: "Raise the limit that is too low", Command: fmt.Sprintf("kubectl -n %s set resources %s -c %s --limits=%s", ns, kubectlTarget(w), h.container, suggestLimits(h.limit, throttled.cpuLimit, snapshot.Known(h.memShare), snapshot.Known(throttled.throttled)))})
		}
		plain := "It is close to the memory it is allowed to use. If it goes over, it is stopped and restarted."
		if !snapshot.Known(h.memShare) {
			plain = "It is held back because it may use only a limited share of the processor, so it responds slowly."
		}
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The %s %s is close to its limits", w.PlainNoun(), w.Name),
			WhatHappened: plain,
			Why:          "Its limits are lower than what it needs for its current work.",
			WhatToDo:     "Raise its limits a little (step below), or send the report to your support team.",
		}
		out = append(out, f)
	}
	return out
}

func suggestLimits(mem, cpu resource.Quantity, memHit, cpuHit bool) string {
	var parts []string
	if memHit {
		parts = append(parts, "memory="+suggestMemory(mem))
	}
	if cpuHit {
		parts = append(parts, fmt.Sprintf("cpu=%dm", cpu.MilliValue()*3/2))
	}
	return strings.Join(parts, ",")
}

// ---------------------------------------------------------------------------
// S04 pv.released and pv.failed

var pvReleasedRule = Rule{
	ID: "pv.released", Code: "S04", Category: findings.Storage,
	Needs: []snapshot.Kind{snapshot.KindPV},
	Eval:  evalPVReleased,
}

func evalPVReleased(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, pv := range c.S.PVs {
		phase := pv.Status.Phase
		if phase != corev1.VolumeReleased && phase != corev1.VolumeFailed {
			continue
		}
		sev := findings.Low
		if phase == corev1.VolumeFailed {
			sev = findings.Medium
		}
		f := c.newFinding(sev, findings.ObjectRef{Kind: "PersistentVolume", Name: pv.Name})
		size := ""
		if q, ok := pv.Spec.Capacity[corev1.ResourceStorage]; ok {
			size = q.String()
		}
		claim := ""
		if ref := pv.Spec.ClaimRef; ref != nil {
			claim = ref.Namespace + "/" + ref.Name
		}
		f.AddFact("Phase", string(phase))
		f.AddFact("Size", size)
		f.AddFact("Was bound to", claim)
		f.AddFact("Reclaim policy", string(pv.Spec.PersistentVolumeReclaimPolicy))
		f.AddFact("StorageClass", pv.Spec.StorageClassName)
		f.AddFact("Message", truncate(pv.Status.Message, 300))
		if phase == corev1.VolumeFailed {
			f.Title = "Failed: " + truncate(orDefault(pv.Status.Message, "the volume could not be reclaimed"), 120)
			f.Summary = fmt.Sprintf("PersistentVolume %s (%s) failed to be reclaimed after its claim %s was deleted.", pv.Name, size, claim)
			f.Remedy.LikelyCause = "The storage driver could not delete or recycle the volume."
		} else {
			f.Title = fmt.Sprintf("Released: %s of data kept after claim %s was deleted", orDefault(size, "its data"), claim)
			f.Summary = fmt.Sprintf("PersistentVolume %s (%s) keeps the data of the deleted claim %s (reclaim policy %s). It uses storage and is never reused automatically.", pv.Name, size, claim, pv.Spec.PersistentVolumeReclaimPolicy)
			f.Remedy.LikelyCause = "Its claim was deleted, and the Retain policy keeps the data on purpose."
		}
		f.AddStep(findings.Step{Text: "See the volume", Command: "kubectl describe pv " + pv.Name})
		f.AddStep(findings.Step{
			Text:    "If the data is not needed any more, delete the volume (the data on the storage backend may need deleting too)",
			Plain:   "If the data is no longer needed, the leftover storage can be deleted.",
			Command: "kubectl delete pv " + pv.Name,
		})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("A leftover storage volume (%s) is kept", orDefault(size, "unknown size")),
			WhatHappened: fmt.Sprintf("The app that used it was removed, but its data (%s) was kept.", orDefault(size, "unknown size")),
			Why:          "The storage is set up to keep data until someone deletes it.",
			WhatToDo:     "If nobody needs the data, it can be deleted to free space. Ask your support team if you are unsure.",
		}
		if phase == corev1.VolumeFailed {
			f.Plain.Title = "A storage volume could not be cleaned up"
			f.Plain.WhatHappened = "The storage system failed to remove the volume of a deleted app."
			f.Plain.Why = "The storage system reported an error."
			f.Plain.WhatToDo = "Send the report to your support team."
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// S07 pvc.resize-stuck

var resizeStuckRule = Rule{
	ID: "pvc.resize-stuck", Code: "S07", Category: findings.Storage,
	Needs: []snapshot.Kind{snapshot.KindPVC},
	Eval:  evalResizeStuck,
}

func evalResizeStuck(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, pvc := range c.S.PVCs {
		var cond *corev1.PersistentVolumeClaimCondition
		for i := range pvc.Status.Conditions {
			t := pvc.Status.Conditions[i].Type
			if (t == corev1.PersistentVolumeClaimFileSystemResizePending || t == corev1.PersistentVolumeClaimResizing) && pvc.Status.Conditions[i].Status == corev1.ConditionTrue {
				cond = &pvc.Status.Conditions[i]
			}
		}
		if cond == nil || c.S.Now.Sub(cond.LastTransitionTime.Time) < 10*time.Minute {
			continue
		}
		since := cond.LastTransitionTime.Time
		ref := findings.ObjectRef{Kind: "PersistentVolumeClaim", Namespace: pvc.Namespace, Name: pvc.Name}
		f := c.newFinding(findings.Medium, ref)
		f.Since = &since
		f.Links.Claims = []findings.ObjectRef{ref}
		want, have := pvc.Spec.Resources.Requests[corev1.ResourceStorage], pvc.Status.Capacity[corev1.ResourceStorage]
		f.AddFact("Requested", want.String())
		f.AddFact("Current", have.String())
		f.AddFact("Condition", fmt.Sprintf("%s for %s", cond.Type, ago(c.S.Now.Sub(since))))
		f.AddFact("Message", truncate(cond.Message, 300))
		ns := pvc.Namespace
		if cond.Type == corev1.PersistentVolumeClaimFileSystemResizePending {
			f.Title = fmt.Sprintf("Resize to %s waits for the pod to restart (%s)", want.String(), ago(c.S.Now.Sub(since)))
			f.Summary = fmt.Sprintf("Claim %s was grown to %s, and its storage driver finishes the resize only when a pod mounts it again.", pvc.Name, want.String())
			f.Remedy.LikelyCause = "The storage driver needs an offline filesystem resize: the pod using the claim must restart."
			for _, p := range c.S.PodsUsingClaim(ns, pvc.Name) {
				f.AddStep(findings.Step{Text: "Restart the pod that uses the claim, when a short interruption is acceptable", Plain: "Restart the app part that uses the storage.", Command: fmt.Sprintf("kubectl -n %s delete pod %s", ns, p.Name)})
				break
			}
		} else {
			f.Title = fmt.Sprintf("Resize to %s stuck for %s", want.String(), ago(c.S.Now.Sub(since)))
			f.Summary = fmt.Sprintf("Claim %s has been resizing to %s for %s.", pvc.Name, want.String(), ago(c.S.Now.Sub(since)))
			f.Remedy.LikelyCause = "The storage driver's resizer is failing or not running."
		}
		f.AddStep(findings.Step{Text: "See the claim's events", Command: fmt.Sprintf("kubectl -n %s describe pvc %s", ns, pvc.Name)})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("Making the storage %s bigger isn't finished", pvc.Name),
			WhatHappened: fmt.Sprintf("It was made bigger (%s) %s ago, but the new size isn't in use yet.", want.String(), agoPlain(c.S.Now.Sub(since))),
			Why:          "The storage system finishes the change only when the app part using it restarts.",
			WhatToDo:     "Restart the app part at a quiet moment (step below), or send the report to your support team.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// C11 events.warning-spike

var warningSpikeRule = Rule{
	ID: "events.warning-spike", Code: "C11", Category: findings.ControlPlane,
	Needs: []snapshot.Kind{snapshot.KindEvent},
	Eval:  evalWarningSpike,
}

// A spike is at least spikeMin warnings in the last 10 minutes, and
// spikeFactor times the usual rate over the 50 minutes before.
const (
	spikeMin    = 30
	spikeFactor = 5
)

func evalWarningSpike(c *Context) []*findings.Finding {
	recent, before := 0, 0
	reasons := map[string]int{}
	for _, e := range c.S.Events {
		age := c.S.Now.Sub(snapshot.EventTime(e))
		switch {
		case age < 0:
		case age <= 10*time.Minute:
			recent++
			reasons[e.Reason]++
		case age <= time.Hour:
			before++
		}
	}
	usual := float64(before) / 5 // per 10 minutes
	if recent < spikeMin || float64(recent) < spikeFactor*maxFloat(usual, 1) {
		return nil
	}
	type rc struct {
		reason string
		n      int
	}
	var top []rc
	for r, n := range reasons {
		top = append(top, rc{r, n})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].n != top[j].n {
			return top[i].n > top[j].n
		}
		return top[i].reason < top[j].reason
	})
	var parts []string
	for i, t := range top {
		if i == 5 {
			break
		}
		parts = append(parts, fmt.Sprintf("%s %d", t.reason, t.n))
	}
	f := c.newFinding(findings.Medium, findings.ObjectRef{Kind: "Cluster", Name: c.S.Cluster})
	f.System = true
	f.AddFact("Last 10 min", fmt.Sprintf("%d warnings", recent))
	f.AddFact("Usual", fmt.Sprintf("%.0f per 10 min", usual))
	f.AddFact("Top reasons", strings.Join(parts, ", "))
	f.Title = fmt.Sprintf("Warning events jumped: %d in the last 10 min, usually %.0f", recent, usual)
	f.Summary = "Kubernetes reports many more warnings than usual. Something changed or started failing across the cluster; the top reasons point to it."
	f.Remedy.LikelyCause = "A rollout, a node or network problem, or an outside dependency that became unavailable."
	f.AddStep(findings.Step{Text: "See the latest warnings", Command: "kubectl get events -A --field-selector type=Warning --sort-by=.lastTimestamp | tail -n 40"})
	f.Plain = findings.PlainText{
		Title:        "Many more warnings than usual",
		WhatHappened: fmt.Sprintf("The cluster reported %d warnings in the last 10 minutes, far more than usual.", recent),
		Why:          "Something changed or started failing. The other problems on this page usually show what.",
		WhatToDo:     "Look at the other problems first. If there are none, send the report to your support team.",
	}
	return []*findings.Finding{f}
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
