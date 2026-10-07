package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// Hygiene rules (H01–H07) report good practices that are missing. Nothing
// is broken: they are suggestions, one per rule and namespace, listing the
// workloads. k0s's own components are left out, since only a k0s update
// changes them.

// hygieneHit is one workload (or pod, or disruption budget) that misses a
// good practice, and what exactly.
type hygieneHit struct {
	ref    findings.ObjectRef
	w      snapshot.Workload
	name   string // as listed: "deploy/api"
	detail string
}

// sample is a workload with one of its running pods, whose containers show
// what the workload runs, with the defaults a LimitRange adds.
type sample struct {
	w   snapshot.Workload
	pod *corev1.Pod
}

// samples returns the user's workloads of the given kinds, with one running
// pod each, in namespace and name order.
func samples(s *snapshot.Snapshot, kinds map[string]bool) []sample {
	seen := map[snapshot.Workload]bool{}
	var out []sample
	for _, p := range s.Pods {
		if snapshot.IsPodTerminal(p) || p.DeletionTimestamp != nil {
			continue
		}
		w := s.WorkloadOf(p)
		if !kinds[w.Kind] || seen[w] || isK0sManaged(w) {
			continue
		}
		seen[w] = true
		out = append(out, sample{w: w, pod: p})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].w.Namespace != out[j].w.Namespace {
			return out[i].w.Namespace < out[j].w.Namespace
		}
		return kubectlTarget(out[i].w) < kubectlTarget(out[j].w)
	})
	return out
}

var (
	// running are the workloads that run all the time.
	running = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true, "ReplicaSet": true}
	// owned adds scheduled jobs to them.
	owned = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true, "ReplicaSet": true, "CronJob": true}
)

// workloadHit is a hit for a sampled workload.
func workloadHit(sm sample, detail string) hygieneHit {
	return hygieneHit{ref: workloadRef(sm.w), w: sm.w, name: kubectlTarget(sm.w), detail: detail}
}

// byNamespace groups hits by namespace, in the order they came.
func byNamespace(hits []hygieneHit) ([]string, map[string][]hygieneHit) {
	var order []string
	m := map[string][]hygieneHit{}
	for _, h := range hits {
		if _, ok := m[h.ref.Namespace]; !ok {
			order = append(order, h.ref.Namespace)
		}
		m[h.ref.Namespace] = append(m[h.ref.Namespace], h)
	}
	return order, m
}

// verb picks the verb that agrees with n: verb(1, "runs", "run").
func verb(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// hygieneListed is how many hits a finding names.
const hygieneListed = 10

// hygieneFinding starts the finding for one namespace: the hits as
// evidence (label names them) and affected objects.
func hygieneFinding(c *Context, sev findings.Severity, ns, label string, hits []hygieneHit) *findings.Finding {
	f := c.newFinding(sev, findings.ObjectRef{Kind: "Namespace", Name: ns})
	var lines []string
	seen := map[findings.ObjectRef]bool{}
	for i, h := range hits {
		if i < hygieneListed {
			line := h.name
			if h.detail != "" {
				line += " (" + h.detail + ")"
			}
			lines = append(lines, line)
		}
		if len(f.Affected) < 20 {
			f.Affected = append(f.Affected, h.ref)
		}
		if h.w.Name != "" && !seen[workloadRef(h.w)] {
			seen[workloadRef(h.w)] = true
			f.Links.Workloads = append(f.Links.Workloads, workloadRef(h.w))
		}
	}
	if len(hits) > hygieneListed {
		lines = append(lines, fmt.Sprintf("and %d more", len(hits)-hygieneListed))
	}
	f.AddFact(label, strings.Join(lines, "; "))
	return f
}

// ---------------------------------------------------------------------------
// H01 hygiene.no-limits

var noLimitsRule = Rule{
	ID: "hygiene.no-limits", Code: "H01", Category: findings.Hygiene,
	Needs: []snapshot.Kind{snapshot.KindPod},
	Eval:  evalNoLimits,
}

func evalNoLimits(c *Context) []*findings.Finding {
	var hits []hygieneHit
	for _, sm := range samples(c.S, owned) {
		var parts []string
		for _, ct := range sm.pod.Spec.Containers {
			var miss []string
			if _, ok := ct.Resources.Limits[corev1.ResourceMemory]; !ok {
				miss = append(miss, "no memory limit")
			}
			if len(ct.Resources.Requests) == 0 {
				miss = append(miss, "no requests")
			}
			if len(miss) > 0 {
				parts = append(parts, ct.Name+": "+strings.Join(miss, ", "))
			}
		}
		if len(parts) > 0 {
			hits = append(hits, workloadHit(sm, strings.Join(parts, "; ")))
		}
	}
	order, m := byNamespace(hits)
	var out []*findings.Finding
	for _, ns := range order {
		hs := m[ns]
		f := hygieneFinding(c, findings.Low, ns, "Workloads", hs)
		f.Title = fmt.Sprintf("%s in %s %s containers without a memory limit or requests", plural(len(hs), "workload", "workloads"), ns, verb(len(hs), "runs", "run"))
		f.Summary = "Without a memory limit, a container can take all the memory of its node; when the node runs out, the kernel kills processes of other apps too, and Kubernetes evicts pods. " +
			"Without requests, the scheduler places it blindly, and it is the first to be evicted."
		f.AddStep(findings.Step{
			Text: "Set resources.requests (cpu and memory) and resources.limits.memory for each container where the app is installed (its chart or manifests). " +
				"Its peak memory use, with some room, is a good limit. A LimitRange can give defaults to a whole namespace",
			Plain:   "Ask the team that installs these apps to set memory limits for them.",
			Command: fmt.Sprintf("kubectl -n %s get pods -o custom-columns='POD:.metadata.name,CONTAINERS:.spec.containers[*].name,REQUESTS:.spec.containers[*].resources.requests,MEMORY LIMITS:.spec.containers[*].resources.limits.memory'\nkubectl -n %s get limitrange", ns, ns),
		})
		f.Plain = findings.PlainText{
			Title:        "Some apps in " + ns + " have no memory limit",
			WhatHappened: fmt.Sprintf("%s may use as much memory as %s.", plural(len(hs), "app", "apps"), verb(len(hs), "it wants", "they want")),
			Why:          "If one of them uses too much, other apps on the same server can be stopped. Nothing is broken now.",
			WhatToDo:     "Ask the team that installs these apps to set memory limits.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// H02 hygiene.no-probes

var noProbesRule = Rule{
	ID: "hygiene.no-probes", Code: "H02", Category: findings.Hygiene,
	Needs: []snapshot.Kind{snapshot.KindPod},
	Eval:  evalNoProbes,
}

func evalNoProbes(c *Context) []*findings.Finding {
	var hits []hygieneHit
	for _, sm := range samples(c.S, running) {
		var names []string
		for _, ct := range sm.pod.Spec.Containers {
			if ct.ReadinessProbe == nil && ct.LivenessProbe == nil && ct.StartupProbe == nil {
				names = append(names, ct.Name)
			}
		}
		if len(names) == 0 {
			continue
		}
		detail := strings.Join(names, ", ")
		if svc := serviceSelecting(c.S, sm.pod); svc != "" {
			detail += ", behind Service " + svc
		}
		hits = append(hits, workloadHit(sm, detail))
	}
	order, m := byNamespace(hits)
	var out []*findings.Finding
	for _, ns := range order {
		hs := m[ns]
		f := hygieneFinding(c, findings.Low, ns, "Workloads", hs)
		f.Title = fmt.Sprintf("%s in %s %s containers without health checks (probes)", plural(len(hs), "workload", "workloads"), ns, verb(len(hs), "has", "have"))
		f.Summary = "Kubernetes can't tell whether these containers work, only whether they run: without a readiness probe, a Service sends traffic to a pod as soon as it starts, " +
			"and without a liveness probe, a container that hangs is never restarted."
		first := hs[0]
		f.AddStep(findings.Step{
			Text: "Add a readinessProbe to each container that serves traffic, for example an HTTP GET on the app's health endpoint, and a livenessProbe for apps that can hang. " +
				"Keep the liveness probe lenient: a strict one restarts a slow app in a loop",
			Plain:   "Ask the team that installs these apps to add health checks to them.",
			Command: fmt.Sprintf("kubectl -n %s get %s -o jsonpath='{range .spec.template.spec.containers[*]}{.name}{\"\\treadiness: \"}{.readinessProbe}{\"\\tliveness: \"}{.livenessProbe}{\"\\n\"}{end}'", ns, first.name),
		})
		f.Plain = findings.PlainText{
			Title:        "Some apps in " + ns + " aren't checked for health",
			WhatHappened: fmt.Sprintf("Kubernetes can't tell whether %s really %s, only whether %s.", plural(len(hs), "app", "apps"), verb(len(hs), "works", "work"), verb(len(hs), "it runs", "they run")),
			Why:          "If one hangs, nothing restarts it, and users may reach it before it is ready. Nothing is broken now.",
			WhatToDo:     "Ask the team that installs these apps to add health checks.",
		}
		out = append(out, f)
	}
	return out
}

// serviceSelecting names a Service that sends traffic to the pod, or "".
func serviceSelecting(s *snapshot.Snapshot, p *corev1.Pod) string {
	for _, svc := range s.Services {
		if svc.Namespace != p.Namespace || len(svc.Spec.Selector) == 0 {
			continue
		}
		if labels.SelectorFromSet(svc.Spec.Selector).Matches(labels.Set(p.Labels)) {
			return svc.Name
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// H03 hygiene.latest-tag

var latestTagRule = Rule{
	ID: "hygiene.latest-tag", Code: "H03", Category: findings.Hygiene,
	Needs: []snapshot.Kind{snapshot.KindPod},
	Eval:  evalLatestTag,
}

// floatingImage reports whether an image names no fixed version: no tag or
// "latest", and no digest.
func floatingImage(image string) bool {
	if strings.Contains(image, "@") {
		return false // pinned by digest
	}
	slash, colon := strings.LastIndex(image, "/"), strings.LastIndex(image, ":")
	if colon <= slash {
		return true // no tag: latest
	}
	return image[colon+1:] == "latest"
}

func evalLatestTag(c *Context) []*findings.Finding {
	var hits []hygieneHit
	for _, sm := range samples(c.S, owned) {
		var parts []string
		for _, ct := range append(append([]corev1.Container{}, sm.pod.Spec.InitContainers...), sm.pod.Spec.Containers...) {
			if floatingImage(ct.Image) {
				parts = append(parts, ct.Name+": "+ct.Image)
			}
		}
		if len(parts) > 0 {
			hits = append(hits, workloadHit(sm, strings.Join(parts, "; ")))
		}
	}
	order, m := byNamespace(hits)
	var out []*findings.Finding
	for _, ns := range order {
		hs := m[ns]
		f := hygieneFinding(c, findings.Low, ns, "Workloads", hs)
		f.Title = fmt.Sprintf("%s in %s %s images without a fixed version (latest)", plural(len(hs), "workload", "workloads"), ns, verb(len(hs), "uses", "use"))
		f.Summary = "An image tagged latest, or without a tag, can change under the same name: a restart or a new node may pull another version than the one tested, " +
			"different pods can run different versions, and a rollback can't bring the old one back."
		f.AddStep(findings.Step{
			Text:    "Pin each image to a version tag or a digest (registry/app:1.4.2 or registry/app@sha256:…). The image IDs below show the digest each pod runs now",
			Plain:   "Ask the team that installs these apps to use exact version numbers.",
			Command: fmt.Sprintf("kubectl -n %s get pods -o jsonpath='{range .items[*]}{.metadata.name}{\"\\n\"}{range .status.containerStatuses[*]}{\"  \"}{.image}{\" \"}{.imageID}{\"\\n\"}{end}{end}'", ns),
		})
		f.Plain = findings.PlainText{
			Title:        "Some apps in " + ns + " don't use a fixed version",
			WhatHappened: fmt.Sprintf("%s may get another version whenever %s.", plural(len(hs), "app", "apps"), verb(len(hs), "it restarts", "they restart")),
			Why:          "The version that runs can change without anyone updating it, and going back is hard. Nothing is broken now.",
			WhatToDo:     "Ask the team that installs these apps to use exact version numbers.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// H04 hygiene.pdb-blocks-drain

var pdbBlocksDrainRule = Rule{
	ID: "hygiene.pdb-blocks-drain", Code: "H04", Category: findings.Hygiene,
	Needs: []snapshot.Kind{snapshot.KindPDB, snapshot.KindPod},
	Eval:  evalPDBBlocksDrain,
}

func evalPDBBlocksDrain(c *Context) []*findings.Finding {
	var hits []hygieneHit
	for _, pdb := range c.S.PDBs {
		st := pdb.Status
		// Every pod runs, yet none may be stopped: the budget's settings
		// block, not an outage.
		if st.ExpectedPods == 0 || st.DisruptionsAllowed > 0 || st.CurrentHealthy < st.ExpectedPods ||
			(pdb.Generation > 0 && st.ObservedGeneration < pdb.Generation) {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			continue
		}
		var w snapshot.Workload
		for _, p := range c.S.Pods {
			if p.Namespace == pdb.Namespace && sel.Matches(labels.Set(p.Labels)) && !snapshot.IsPodTerminal(p) {
				w = c.S.WorkloadOf(p)
				break
			}
		}
		if isK0sManaged(w) {
			continue
		}
		rule := ""
		switch {
		case pdb.Spec.MinAvailable != nil:
			rule = "minAvailable " + pdb.Spec.MinAvailable.String()
		case pdb.Spec.MaxUnavailable != nil:
			rule = "maxUnavailable " + pdb.Spec.MaxUnavailable.String()
		}
		detail := fmt.Sprintf("%s with %s", rule, plural(int(st.ExpectedPods), "pod", "pods"))
		if w.Name != "" {
			detail += ", " + kubectlTarget(w)
		}
		hits = append(hits, hygieneHit{ref: findings.ObjectRef{Kind: "PodDisruptionBudget", Namespace: pdb.Namespace, Name: pdb.Name},
			w: w, name: "pdb/" + pdb.Name, detail: strings.TrimPrefix(detail, " ")})
	}
	order, m := byNamespace(hits)
	var out []*findings.Finding
	for _, ns := range order {
		hs := m[ns]
		f := hygieneFinding(c, findings.Low, ns, "Disruption budgets", hs)
		f.Title = fmt.Sprintf("%s in %s %s no pod to be stopped", plural(len(hs), "disruption budget", "disruption budgets"), ns, verb(len(hs), "allows", "allow"))
		f.Summary = "These PodDisruptionBudgets allow no disruption even while all their pods run, typically one replica with minAvailable 1. " +
			"Draining a node, which k0s updates through Autopilot and node maintenance do, waits for these pods until it gives up, so updates and maintenance stall."
		f.AddStep(findings.Step{
			Text:    "Run at least 2 replicas of the workload, or allow one pod to be stopped (maxUnavailable: 1) in its PodDisruptionBudget, where the app is installed",
			Plain:   "Ask the team that installs these apps to run 2 copies of them, or to allow one copy to be stopped.",
			Command: fmt.Sprintf("kubectl -n %s get pdb", ns),
		})
		f.Plain = findings.PlainText{
			Title:        "Some apps in " + ns + " block server maintenance",
			WhatHappened: fmt.Sprintf("The settings of %s don't allow any of %s copies to be stopped, even for a moment.", plural(len(hs), "app", "apps"), verb(len(hs), "its", "their")),
			Why:          "Cluster updates and server maintenance must move apps from server to server. For these apps they wait until they give up. Nothing is broken now.",
			WhatToDo:     "Ask the team that installs these apps to run 2 copies of them, or to allow one copy to be stopped.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// H05 hygiene.privileged

var privilegedRule = Rule{
	ID: "hygiene.privileged", Code: "H05", Category: findings.Hygiene,
	Needs: []snapshot.Kind{snapshot.KindPod},
	Eval:  evalPrivileged,
}

func evalPrivileged(c *Context) []*findings.Finding {
	var hits []hygieneHit
	for _, sm := range samples(c.S, owned) {
		var names []string
		for _, ct := range append(append([]corev1.Container{}, sm.pod.Spec.InitContainers...), sm.pod.Spec.Containers...) {
			if ct.SecurityContext != nil && ct.SecurityContext.Privileged != nil && *ct.SecurityContext.Privileged {
				names = append(names, ct.Name)
			}
		}
		if len(names) > 0 {
			hits = append(hits, workloadHit(sm, strings.Join(names, ", ")))
		}
	}
	order, m := byNamespace(hits)
	var out []*findings.Finding
	for _, ns := range order {
		hs := m[ns]
		f := hygieneFinding(c, findings.Low, ns, "Workloads", hs)
		f.Title = fmt.Sprintf("%s in %s %s privileged containers", plural(len(hs), "workload", "workloads"), ns, verb(len(hs), "runs", "run"))
		f.Summary = "A privileged container has full access to its node: its devices, kernel settings and every other container on it. A bug or a break-in there reaches the whole node. " +
			"Storage and network drivers need it; ordinary apps don't."
		f.AddStep(findings.Step{
			Text:    "Unless it is a storage or network driver, remove securityContext.privileged and add only the capabilities the app needs (securityContext.capabilities.add)",
			Plain:   "If these apps aren't drivers for storage or networking, ask the team that installs them to remove the privileged setting.",
			Command: fmt.Sprintf("kubectl -n %s get %s -o jsonpath='{range .spec.template.spec.containers[*]}{.name}{\"\\t\"}{.securityContext}{\"\\n\"}{end}'", ns, hs[0].name),
		})
		f.Plain = findings.PlainText{
			Title:        "Some apps in " + ns + " have full access to their servers",
			WhatHappened: fmt.Sprintf("%s with full access to the server %s on.", verb(len(hs), "1 app runs", fmt.Sprintf("%d apps run", len(hs))), verb(len(hs), "it runs", "they run")),
			Why:          "Drivers for storage and networking need this; other apps don't, and it makes a security problem in them much worse. Nothing is broken now.",
			WhatToDo:     "If these apps aren't drivers, ask the team that installs them to remove the privileged setting.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// H06 hygiene.finished-pods

var finishedPodsRule = Rule{
	ID: "hygiene.finished-pods", Code: "H06", Category: findings.Hygiene,
	Needs: []snapshot.Kind{snapshot.KindPod, snapshot.KindJob},
	Eval:  evalFinishedPods,
}

// finishedAt is when a finished pod's last container stopped, else when
// the pod started or was created; zero when unknown.
func finishedAt(p *corev1.Pod) time.Time {
	var t time.Time
	for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
		if term := cs.State.Terminated; term != nil && term.FinishedAt.After(t) {
			t = term.FinishedAt.Time
		}
	}
	switch {
	case !t.IsZero():
		return t
	case p.Status.StartTime != nil:
		return p.Status.StartTime.Time
	}
	return p.CreationTimestamp.Time
}

func evalFinishedPods(c *Context) []*findings.Finding {
	after := c.T.FinishedPodsAfter.D()
	var hits []hygieneHit
	for _, p := range c.S.Pods {
		if !snapshot.IsPodTerminal(p) || p.DeletionTimestamp != nil {
			continue
		}
		// A Job's pods go with the Job, by its history limit or TTL.
		if ref := metav1.GetControllerOf(p); ref != nil && ref.Kind == "Job" && c.S.Job(p.Namespace, ref.Name) != nil {
			continue
		}
		t := finishedAt(p)
		if t.IsZero() {
			continue // no idea how old
		}
		age := c.S.Now.Sub(t)
		if age <= after {
			continue
		}
		reason := p.Status.Reason
		if reason == "" {
			reason = string(p.Status.Phase)
		}
		hits = append(hits, hygieneHit{ref: findings.ObjectRef{Kind: "Pod", Namespace: p.Namespace, Name: p.Name},
			w: c.S.WorkloadOf(p), name: p.Name, detail: reason + ", " + ago(age) + " ago"})
	}
	order, m := byNamespace(hits)
	var out []*findings.Finding
	for _, ns := range order {
		hs := m[ns]
		f := hygieneFinding(c, findings.Info, ns, "Pods", hs)
		f.Title = fmt.Sprintf("%s in %s finished more than %s ago", plural(len(hs), "pod", "pods"), ns, ago(after))
		f.Summary = "Pods that completed, failed or were evicted stay until someone deletes them: Kubernetes' own clean-up starts only at 12,500 of them. " +
			"They run nothing, but clutter lists and keep old events."
		var names []string
		for _, h := range hs {
			names = append(names, h.name)
		}
		cmd := fmt.Sprintf("kubectl -n %s delete pod %s", ns, strings.Join(names, " "))
		if len(names) > 30 {
			cmd = fmt.Sprintf("kubectl -n %s delete pod --field-selector=status.phase==Failed\nkubectl -n %s delete pod --field-selector=status.phase==Succeeded", ns, ns)
		}
		f.AddStep(findings.Step{
			Text:    "Delete them. Nothing runs in them, and their workloads don't need them",
			Plain:   "Remove them with this command.",
			Command: cmd,
		})
		f.Plain = findings.PlainText{
			Title:        "Old leftovers of apps in " + ns,
			WhatHappened: fmt.Sprintf("%s stopped long ago and %s never removed.", plural(len(hs), "app part", "app parts"), verb(len(hs), "was", "were")),
			Why:          "They don't run; they only fill the lists. Nothing is broken.",
			WhatToDo:     "Remove them with the command in the steps.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// H07 hygiene.k0s-control-plane-targets

var k0sControlPlaneTargetsRule = Rule{
	ID: "hygiene.k0s-control-plane-targets", Code: "H07", Category: findings.Hygiene,
	Needs: []snapshot.Kind{snapshot.KindService, snapshot.KindPod, snapshot.KindNode},
	Eval:  evalK0sControlPlaneTargets,
}

// controlPlaneParts are the control plane parts that kubeadm runs as pods
// in kube-system, which monitoring charts (kube-prometheus-stack,
// victoria-metrics-k8s-stack) make Services for, by the pods' label, and
// the chart values that turn them off. k0s runs them inside k0s on the
// controllers: no pod has these labels.
var controlPlaneParts = map[string]string{
	"kube-controller-manager": "kubeControllerManager",
	"kube-scheduler":          "kubeScheduler",
	"etcd":                    "kubeEtcd",
}

// controlPlaneTarget returns the part a Service selects as a kubeadm
// control plane pod ("component: kube-scheduler"), or "".
func controlPlaneTarget(svc *corev1.Service) string {
	if len(svc.Spec.Selector) != 1 {
		return ""
	}
	for k, v := range svc.Spec.Selector {
		if _, ok := controlPlaneParts[v]; ok && (k == "component" || k == "k8s-app" || k == "app.kubernetes.io/name") {
			return v
		}
	}
	return ""
}

// k0sControlPlaneTargets lists the Services, on k0s, that select control
// plane pods that k0s doesn't have: nothing ever matches them.
func k0sControlPlaneTargets(s *snapshot.Snapshot) map[*corev1.Service]string {
	out := map[*corev1.Service]string{}
	if !s.IsK0s() {
		return out
	}
	for _, svc := range s.Services {
		part := controlPlaneTarget(svc)
		if part == "" || svc.DeletionTimestamp != nil || len(s.SelectPods(svc.Namespace, svc.Spec.Selector)) > 0 {
			continue
		}
		out[svc] = part
	}
	return out
}

// helmRelease names the Helm release that made an object and its
// namespace (empty when unknown), if any.
func helmRelease(meta metav1.ObjectMeta) (name, namespace string) {
	if r := meta.Annotations["meta.helm.sh/release-name"]; r != "" {
		return r, meta.Annotations["meta.helm.sh/release-namespace"]
	}
	if meta.Labels["app.kubernetes.io/managed-by"] == "Helm" {
		return meta.Labels["app.kubernetes.io/instance"], ""
	}
	return "", ""
}

func evalK0sControlPlaneTargets(c *Context) []*findings.Finding {
	targets := k0sControlPlaneTargets(c.S)
	var hits []hygieneHit
	parts := map[string][]string{}     // namespace: the parts, sorted
	releases := map[string][2]string{} // namespace: the Helm release and its namespace
	for _, svc := range c.S.Services {
		part, ok := targets[svc]
		if !ok {
			continue
		}
		hits = append(hits, hygieneHit{ref: findings.ObjectRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name},
			name: "svc/" + svc.Name, detail: selectorString(svc.Spec.Selector)})
		parts[svc.Namespace] = append(parts[svc.Namespace], part)
		if r, rns := helmRelease(svc.ObjectMeta); r != "" && releases[svc.Namespace][1] == "" {
			releases[svc.Namespace] = [2]string{r, rns}
		}
	}
	order, m := byNamespace(hits)
	var out []*findings.Finding
	for _, ns := range order {
		hs := m[ns]
		f := hygieneFinding(c, findings.Info, ns, "Services", hs)
		ps := parts[ns]
		sort.Strings(ps)
		release, releaseNS := releases[ns][0], releases[ns][1]
		if release != "" {
			f.AddFact("Made by", "Helm release "+release)
		}
		f.Title = fmt.Sprintf("Monitoring looks for %s pods, which k0s doesn't have (%s in %s)", strings.Join(ps, ", "), plural(len(hs), "Service", "Services"), ns)
		f.Summary = "A monitoring chart (such as kube-prometheus-stack or victoria-metrics-k8s-stack) made these Services to collect metrics from " + strings.Join(ps, ", ") +
			", which clusters built with kubeadm run as pods. k0s runs them inside k0s on the controllers, so the Services never have pods: " +
			"their scrape targets stay empty, and the chart's alerts for them (such as KubeControllerManagerDown) may fire. Nothing in the cluster is broken."
		f.Remedy.LikelyCause = "The chart's default values are made for kubeadm clusters, where these parts run as pods in kube-system with labels such as component=kube-controller-manager."

		var values []string
		for _, p := range ps {
			values = append(values, controlPlaneParts[p]+": {enabled: false}")
		}
		who := "the chart that made them"
		if release != "" {
			who = "the Helm release " + release
		}
		cmd := fmt.Sprintf("# in the values of %s:\n%s", who, strings.Join(values, "\n"))
		if release != "" {
			where := "-n " + releaseNS + " "
			if releaseNS == "" {
				where = "-n <its namespace> "
			}
			cmd += fmt.Sprintf("\n# then upgrade it with your chart, for example:\nhelm %sget values %s > values.yaml   # add the lines above\nhelm %supgrade %s <chart> -f values.yaml", where, release, where, release)
		}
		f.AddStep(findings.Step{
			Text:    "Turn these parts off in the chart's values, and upgrade it: the Services, their scrape targets and alerts go away",
			Plain:   "Whoever manages the monitoring should turn these parts off in its settings.",
			Command: cmd,
		})
		f.AddStep(findings.Step{
			Text:    "To monitor them on k0s instead: k0s can collect their metrics itself when its controllers run with --enable-metrics-scraper, and offers them through a Pushgateway in the k0s-system namespace for your monitoring to scrape. See whether it is on",
			Command: "kubectl -n k0s-system get svc",
		})
		f.Plain = findings.PlainText{
			Title:        "Monitoring settings don't fit k0s",
			WhatHappened: "The monitoring tool looks for parts of the cluster's control center that k0s runs in a different way, so it finds nothing there, and may warn that they are down.",
			Why:          "Its default settings are made for other kinds of Kubernetes. Nothing is broken.",
			WhatToDo:     "Whoever manages the monitoring should turn these parts off in its settings (see the steps).",
		}
		out = append(out, f)
	}
	return out
}
