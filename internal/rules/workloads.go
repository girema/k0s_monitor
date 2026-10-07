package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// ---------------------------------------------------------------------------
// W01 pod.crashloop

var crashLoopRule = Rule{
	ID: "pod.crashloop", Code: "W01", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindPod},
	Eval:  evalCrashLoop,
}

func isCrashLooping(c *Context, cs corev1.ContainerStatus) bool {
	last := cs.LastTerminationState.Terminated
	if last != nil && last.Reason == "OOMKilled" {
		return false // reported by pod.oomkilled
	}
	if cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff" {
		return true
	}
	return cs.RestartCount >= c.T.CrashLoopRestarts && last != nil &&
		c.S.Now.Sub(last.FinishedAt.Time) <= c.T.CrashLoopWindow.D()
}

func evalCrashLoop(c *Context) []*findings.Finding {
	var out []*findings.Finding
	groups := groupByWorkload(c.S, func(p *corev1.Pod, cs corev1.ContainerStatus) bool {
		if _, runErr := isRunError(cs); runErr {
			return false // reported by pod.run-error
		}
		return isCrashLooping(c, cs) && probeKillEvent(c, p, cs) == nil // or by pod.probe-kills
	})
	for _, g := range groups {
		pods := g.pods()
		h := g.worst()
		f := c.newFinding(findings.High, workloadRef(g.w))
		count := replicaImpact(c.S, g.w, pods, &f.Impact)
		if f.Impact.AllReplicasDown {
			f.Severity = findings.Critical
		}
		f.Impact.Exposed = exposed(c.S, g.w)

		var code int32
		reason, msg := "", ""
		lastAgo := ""
		if t := h.status.LastTerminationState.Terminated; t != nil {
			code, reason, msg = t.ExitCode, t.Reason, t.Message
			if !t.FinishedAt.IsZero() {
				lastAgo = ago(c.S.Now.Sub(t.FinishedAt.Time)) + " ago"
			}
		}
		exit := fmt.Sprintf("%d", code)
		if reason != "" {
			exit += " (" + reason + ")"
		}
		f.Title = fmt.Sprintf("CrashLoopBackOff: container %q exits with code %d (%s)", h.status.Name, code, count)
		f.Summary = fmt.Sprintf("Container %q keeps stopping and being restarted: %d restarts so far. The last time, %s.",
			h.status.Name, h.status.RestartCount, exitCodeMeaning(code, reason))
		f.AddFact("Container", h.status.Name)
		f.AddFact("Exit code", exit)
		f.AddFact("Code means", exitText(code, reason))
		f.AddFact("Restarts", fmt.Sprintf("%d", h.status.RestartCount))
		f.AddFact("Last exit", lastAgo)
		f.AddFact("Last message", truncate(msg, 300))
		f.AddFact("Pods", podNames(pods, 3))
		f.Affected = append([]findings.ObjectRef{}, podRefs(pods, 10)...)
		f.Links.Workloads = []findings.ObjectRef{workloadRef(g.w)}
		f.Links.Nodes = nodesOf(pods)

		ns, pod := h.pod.Namespace, h.pod.Name
		f.Remedy.LikelyCause = "The app itself fails at start-up. Its log from the last crash usually names the reason."
		f.AddStep(findings.Step{
			Text:    "Read the log of the last crash",
			Plain:   "Look at the app's log from the last crash to see the error.",
			Command: fmt.Sprintf("kubectl -n %s logs %s -c %s --previous", ns, pod, h.status.Name),
		})
		f.AddStep(findings.Step{
			Text:    "Check the pod's last state and events",
			Command: fmt.Sprintf("kubectl -n %s describe pod %s", ns, pod),
		})
		if isK0sManaged(g.w) {
			f.AddStep(findings.Step{
				Text:    "k0s manages this component and undoes manual changes. Restarting the pod often helps",
				Plain:   "k0s manages this part of the cluster itself. Restarting it often helps.",
				Command: fmt.Sprintf("kubectl -n %s delete pod %s", ns, pod),
			})
			f.AddStep(findings.Step{
				Text:    "If it keeps failing, look for errors about it in the k0s controller's log",
				Command: fmt.Sprintf("sudo journalctl -u k0scontroller --since '30 min ago' --no-pager | grep -i %s | tail -n 50", g.w.Name),
				Host:    "a controller",
			})
		} else if (g.w.Kind == "Deployment" && recentRollout(c.S, g.w, pods) == nil) || g.w.Kind == "StatefulSet" || g.w.Kind == "DaemonSet" {
			// A recent update of a Deployment gets its own steps.
			f.AddStep(findings.Step{
				Text:    "If it started after an update, compare the revisions and undo the last one",
				Plain:   "If this started right after an update, undoing the update usually fixes it.",
				Command: fmt.Sprintf("kubectl -n %s rollout history %s\nkubectl -n %s rollout undo %s", ns, kubectlTarget(g.w), ns, kubectlTarget(g.w)),
			})
		}

		noun := g.w.PlainNoun()
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The %s %s keeps crashing", noun, g.w.Name),
			WhatHappened: fmt.Sprintf("It stops shortly after starting, and Kubernetes keeps starting it again. This has happened %d times.", h.status.RestartCount),
			Why:          fmt.Sprintf("The last time, %s.", exitCodeMeaning(code, reason)),
			WhatToDo:     "Look at its log to see the error (first step). If it started right after an update, undoing the update usually helps. Otherwise send the report to your support team.",
		}
		if isK0sManaged(g.w) {
			f.Plain.Title = fmt.Sprintf("The cluster component %s keeps crashing", g.w.Name)
			f.Plain.WhatToDo = "k0s manages this component itself. Restarting it often helps (steps below); if it keeps crashing, send the report to your support team."
		}
		explainCrash(c, f, crashLogOf(c.S, g, h), g.w)
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// W02 pod.oomkilled

var oomKilledRule = Rule{
	ID: "pod.oomkilled", Code: "W02", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindPod},
	Eval:  evalOOMKilled,
}

func evalOOMKilled(c *Context) []*findings.Finding {
	var out []*findings.Finding
	groups := groupByWorkload(c.S, func(_ *corev1.Pod, cs corev1.ContainerStatus) bool {
		if t := cs.State.Terminated; t != nil && t.Reason == "OOMKilled" {
			return true
		}
		t := cs.LastTerminationState.Terminated
		return t != nil && t.Reason == "OOMKilled" && c.S.Now.Sub(t.FinishedAt.Time) <= c.T.OOMWindow.D()
	})
	for _, g := range groups {
		pods := g.pods()
		h := g.worst()
		f := c.newFinding(findings.High, workloadRef(g.w))
		count := replicaImpact(c.S, g.w, pods, &f.Impact)
		if f.Impact.AllReplicasDown {
			f.Severity = findings.Critical
		}
		f.Impact.Exposed = exposed(c.S, g.w)

		var limit, request *resource.Quantity
		if h.spec != nil {
			if q, ok := h.spec.Resources.Limits[corev1.ResourceMemory]; ok {
				limit = &q
			}
			if q, ok := h.spec.Resources.Requests[corev1.ResourceMemory]; ok {
				request = &q
			}
		}
		limitText := "none"
		if limit != nil {
			limitText = limit.String()
		}
		f.Title = fmt.Sprintf("OOMKilled: container %q ran out of memory (limit %s, %s)", h.status.Name, limitText, count)
		f.AddFact("Container", h.status.Name)
		f.AddFact("Memory limit", limitText)
		if request != nil {
			f.AddFact("Memory request", request.String())
		}
		peak := snapshot.Missing
		if m := c.S.Metrics; m != nil {
			if cm := m.Containers[h.pod.Namespace+"/"+h.pod.Name+"/"+h.status.Name]; cm != nil {
				peak = cm.PeakWorkingSet7d
			}
		}
		if snapshot.Known(peak) {
			f.AddFact("Peak memory (7 days)", bytesIEC(peak))
		}
		f.AddFact("Restarts", fmt.Sprintf("%d", h.status.RestartCount))
		if t := h.status.LastTerminationState.Terminated; t != nil && !t.FinishedAt.IsZero() {
			f.AddFact("Last OOM kill", ago(c.S.Now.Sub(t.FinishedAt.Time))+" ago")
		}
		f.AddFact("Pods", podNames(pods, 3))
		f.Affected = podRefs(pods, 10)
		f.Links.Workloads = []findings.ObjectRef{workloadRef(g.w)}
		f.Links.Nodes = nodesOf(pods)

		ns := h.pod.Namespace
		f.AddStep(findings.Step{
			Text:    "Confirm the OOM kill in the pod's last state",
			Command: fmt.Sprintf("kubectl -n %s describe pod %s", ns, h.pod.Name),
		})
		noun := g.w.PlainNoun()
		if limit != nil {
			suggested := suggestMemory(*limit)
			if snapshot.Known(peak) && peak > limit.AsApproximateFloat64() {
				// 1.5 times the highest use seen, when that is above the limit.
				suggested = suggestMemory(*resource.NewQuantity(int64(peak), resource.BinarySI))
			}
			f.Summary = fmt.Sprintf("Container %q uses more memory than its limit of %s, so the kernel stops it and Kubernetes restarts it (%d restarts).",
				h.status.Name, limit.String(), h.status.RestartCount)
			f.Remedy.LikelyCause = "The memory limit is too low for the work the app does, or the app leaks memory."
			if g.w.Kind != "Pod" {
				f.AddStep(findings.Step{
					Text:    fmt.Sprintf("Raise the memory limit by about half, to %s, and watch whether it stays stable", suggested),
					Plain:   fmt.Sprintf("Raise its memory limit a little, for example to %s.", suggested),
					Command: fmt.Sprintf("kubectl -n %s set resources %s -c %s --limits=memory=%s", ns, kubectlTarget(g.w), h.status.Name, suggested),
				})
			}
			f.AddStep(findings.Step{
				Text:    "If memory keeps growing after the change, look for a leak: compare usage over time",
				Command: fmt.Sprintf("kubectl -n %s top pod %s --containers", ns, h.pod.Name),
			})
			f.Plain = findings.PlainText{
				Title:        fmt.Sprintf("The %s %s keeps running out of memory", noun, g.w.Name),
				WhatHappened: fmt.Sprintf("It needs more memory than it is allowed to use (%s), so it is stopped and started again. This has happened %d times.", limit.String(), h.status.RestartCount),
				Why:          "Either its memory limit is too low for its work, or it uses more and more memory over time.",
				WhatToDo:     fmt.Sprintf("Raise its memory limit a little, for example to %s, and check that it stays stable. If it keeps growing, send the report to your support team.", suggested),
			}
		} else {
			f.Summary = fmt.Sprintf("Container %q has no memory limit and was killed because its node ran out of memory (%d restarts).",
				h.status.Name, h.status.RestartCount)
			f.Remedy.LikelyCause = "The node ran out of memory. Containers without a memory limit are the first to be killed."
			f.AddStep(findings.Step{
				Text:    "Check the memory use of the node and its pods",
				Command: "kubectl top nodes\nkubectl top pods -A --sort-by=memory",
			})
			f.Plain = findings.PlainText{
				Title:        fmt.Sprintf("The %s %s was stopped because its server ran out of memory", noun, g.w.Name),
				WhatHappened: fmt.Sprintf("Its server ran out of memory, and this app was stopped to free some. This has happened %d times.", h.status.RestartCount),
				Why:          "The apps on that server together use more memory than it has, and this app has no memory limit.",
				WhatToDo:     "Give the app a memory limit, or move some apps to another server. Send the report to your support team if you are unsure.",
			}
		}
		out = append(out, f)
	}
	return out
}

// suggestMemory returns about 1.5 times the limit, rounded up to 64Mi.
func suggestMemory(limit resource.Quantity) string {
	const step = 64 << 20
	v := limit.Value() * 3 / 2
	v = (v + step - 1) / step * step
	return fmt.Sprintf("%dMi", v>>20)
}

// ---------------------------------------------------------------------------
// W03 pod.image-pull

var imagePullRule = Rule{
	ID: "pod.image-pull", Code: "W03", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindPod},
	Eval:  evalImagePull,
}

var imagePullReasons = map[string]bool{
	"ErrImagePull": true, "ImagePullBackOff": true, "InvalidImageName": true, "ErrImageNeverPull": true,
}

func evalImagePull(c *Context) []*findings.Finding {
	var out []*findings.Finding
	groups := groupByWorkload(c.S, func(_ *corev1.Pod, cs corev1.ContainerStatus) bool {
		return cs.State.Waiting != nil && imagePullReasons[cs.State.Waiting.Reason]
	})
	for _, g := range groups {
		pods := g.pods()
		h := g.hits[0]
		f := c.newFinding(findings.High, workloadRef(g.w))
		count := replicaImpact(c.S, g.w, pods, &f.Impact)
		if f.Impact.AllReplicasDown {
			f.Severity = findings.Critical
		}
		f.Impact.Exposed = exposed(c.S, g.w)

		image := h.status.Image
		if h.spec != nil {
			image = h.spec.Image
		}
		msg := h.status.State.Waiting.Message
		if ev := latestEventMessage(c, h.pod, "Failed"); ev != "" && (msg == "" || strings.HasPrefix(msg, "Back-off pulling image")) {
			msg = ev
		}
		pe := classifyPullError(h.status.State.Waiting.Reason, msg)
		registry := registryOf(image)

		f.Title = fmt.Sprintf("%s: image %s cannot be pulled, %s (%s)", h.status.State.Waiting.Reason, image, pe.short, count)
		f.Summary = fmt.Sprintf("Kubernetes cannot download the image %s for container %q: %s.", image, h.status.Name, pe.short)
		f.AddFact("Image", image)
		f.AddFact("Registry", registry)
		f.AddFact("Container", h.status.Name)
		f.AddFact("Error", truncate(msg, 400))
		f.AddFact("Pods", podNames(pods, 3))
		f.Affected = podRefs(pods, 10)
		f.Links.Workloads = []findings.ObjectRef{workloadRef(g.w)}
		f.Links.Nodes = nodesOf(pods)

		ns := h.pod.Namespace
		f.Remedy.LikelyCause = pe.cause
		f.AddStep(findings.Step{
			Text:    "See the full pull error in the pod's events",
			Command: fmt.Sprintf("kubectl -n %s describe pod %s", ns, h.pod.Name),
		})
		for _, st := range pe.steps(ns, image, registry, g.w) {
			f.AddStep(st)
		}
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The %s %s can't download its software", g.w.PlainNoun(), g.w.Name),
			WhatHappened: fmt.Sprintf("Kubernetes tries to download the image %s, but it fails, so the app can't start.", image),
			Why:          pe.plainWhy,
			WhatToDo:     pe.plainDo,
		}
		out = append(out, f)
	}
	return out
}

func latestEventMessage(c *Context, p *corev1.Pod, reason string) string {
	if !c.S.Has(snapshot.KindEvent) {
		return ""
	}
	for _, e := range c.S.EventsFor(p.UID, "Pod", p.Namespace, p.Name) {
		if e.Reason == reason {
			return e.Message
		}
	}
	return ""
}

type pullError struct {
	short, cause, plainWhy, plainDo string
	steps                           func(ns, image, registry string, w snapshot.Workload) []findings.Step
}

func noSteps(string, string, string, snapshot.Workload) []findings.Step { return nil }

func classifyPullError(reason, msg string) pullError {
	m := strings.ToLower(msg)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(m, s) {
				return true
			}
		}
		return false
	}
	checkTag := func(ns, image, registry string, w snapshot.Workload) []findings.Step {
		return []findings.Step{{
			Text:  fmt.Sprintf("Check that %s exists in %s, and fix the image name or tag in the workload", image, registry),
			Plain: "Check the image name and version (tag).",
		}}
	}
	switch {
	case reason == "InvalidImageName" || has("invalid reference format"):
		return pullError{
			short: "the image name is invalid", cause: "The image name is not a valid reference.",
			plainWhy: "The image name is written incorrectly.", plainDo: "Correct the image name. If the app comes with your product, send the report to your support team.",
			steps: checkTag,
		}
	case reason == "ErrImageNeverPull":
		return pullError{
			short: "the image is not on the node and pulling is disabled", cause: "imagePullPolicy is Never and the image was not pre-loaded on the node.",
			plainWhy: "The software was supposed to be pre-loaded on the server, but it isn't there.", plainDo: "Load the image onto the servers, or send the report to your support team.",
			steps: noSteps,
		}
	case has("repository does not exist or may require authorization"):
		return pullError{
			short: "the repository does not exist or needs credentials", cause: "The image repository does not exist, or it is private and no credentials were given.",
			plainWhy: "The registry either doesn't have this image or wants a login.", plainDo: "Check the image name. If it is private, the app needs registry credentials. Send the report to your support team if you are unsure.",
			steps: func(ns, image, registry string, w snapshot.Workload) []findings.Step {
				return append(checkTag(ns, image, registry, w), pullSecretStep(ns, registry))
			},
		}
	case has("not found", "manifest unknown", "name unknown", "no such image"):
		return pullError{
			short: "the image or tag does not exist", cause: "The image name or tag is wrong, or the tag was deleted from the registry.",
			plainWhy: "The registry doesn't have this version of the software.", plainDo: "Check the image name and version (tag). If the app comes with your product, send the report to your support team.",
			steps: checkTag,
		}
	case has("unauthorized", "authentication required", "401", "403", "denied", "insufficient_scope", "forbidden"):
		return pullError{
			short: "the registry refused access", cause: "The registry needs credentials that the pod does not have, or they are wrong.",
			plainWhy: "The registry wants a login that the app doesn't have.", plainDo: "Give the app registry credentials (an image pull secret), or send the report to your support team.",
			steps: func(ns, image, registry string, w snapshot.Workload) []findings.Step {
				return []findings.Step{pullSecretStep(ns, registry)}
			},
		}
	case has("toomanyrequests", "rate limit", "429"):
		return pullError{
			short: "the registry's rate limit was reached", cause: "The registry limits anonymous pulls (Docker Hub does), and the limit was reached.",
			plainWhy: "The registry temporarily refuses downloads because too many were made.", plainDo: "Wait a while and it may recover. For a lasting fix, use registry credentials or a registry mirror.",
			steps: func(ns, image, registry string, w snapshot.Workload) []findings.Step {
				return []findings.Step{pullSecretStep(ns, registry)}
			},
		}
	case has("x509", "certificate"):
		return pullError{
			short: "the registry's certificate is not trusted", cause: "The nodes do not trust the registry's TLS certificate (a private CA or an intercepting proxy).",
			plainWhy: "The servers don't trust the registry's security certificate.", plainDo: "The registry's certificate authority must be added to the servers' container runtime. Send the report to your support team.",
			steps: func(ns, image, registry string, w snapshot.Workload) []findings.Step {
				return []findings.Step{{Text: "On a node, test the connection to the registry", Command: fmt.Sprintf("curl -v https://%s/v2/", registry), Host: "any node"}}
			},
		}
	case has("no such host", "server misbehaving", "lookup "):
		return pullError{
			short: "the registry's name cannot be resolved", cause: "The nodes cannot resolve the registry's host name (DNS).",
			plainWhy: "The servers can't find the registry by its name.", plainDo: "Check the servers' DNS settings, or send the report to your support team.",
			steps: func(ns, image, registry string, w snapshot.Workload) []findings.Step {
				return []findings.Step{{Text: "On a node, check name resolution for the registry", Command: fmt.Sprintf("nslookup %s", registry), Host: "any node"}}
			},
		}
	case has("i/o timeout", "connection refused", "dial tcp", "deadline exceeded", "tls handshake timeout", "network is unreachable", "connection reset"):
		return pullError{
			short: "the registry cannot be reached", cause: "The nodes cannot open a connection to the registry: firewall, proxy or network problem.",
			plainWhy: "The servers can't connect to the registry over the network.", plainDo: "Check the network, firewall or proxy between the servers and the registry, or send the report to your support team.",
			steps: func(ns, image, registry string, w snapshot.Workload) []findings.Step {
				return []findings.Step{{Text: "On a node, test the connection to the registry", Command: fmt.Sprintf("curl -v https://%s/v2/", registry), Host: "any node"}}
			},
		}
	}
	return pullError{
		short: "the pull failed", cause: "The image pull failed. The error message has the details.",
		plainWhy: "Downloading the software failed.", plainDo: "Send the report to your support team.",
		steps: noSteps,
	}
}

func pullSecretStep(ns, registry string) findings.Step {
	return findings.Step{
		Text:    "Create registry credentials and reference them in the pod spec under imagePullSecrets",
		Command: fmt.Sprintf("kubectl -n %s create secret docker-registry regcred --docker-server=%s --docker-username=<user> --docker-password=<password>", ns, registry),
	}
}

// registryOf returns the registry host of an image reference.
func registryOf(image string) string {
	first, _, found := strings.Cut(image, "/")
	if !found {
		return "docker.io"
	}
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return first
	}
	return "docker.io"
}

// ---------------------------------------------------------------------------
// W06 pod.unschedulable

var unschedulableRule = Rule{
	ID: "pod.unschedulable", Code: "W06", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindPod, snapshot.KindNode},
	Eval:  evalUnschedulable,
}

func evalUnschedulable(c *Context) []*findings.Finding {
	type hit struct {
		pod  *corev1.Pod
		cond *corev1.PodCondition
	}
	groups := map[snapshot.Workload][]hit{}
	var order []snapshot.Workload
	for _, p := range c.S.Pods {
		if p.Status.Phase != corev1.PodPending || p.Spec.NodeName != "" || p.DeletionTimestamp != nil {
			continue
		}
		cond := snapshot.PodCondition(p, corev1.PodScheduled)
		if cond == nil || cond.Status != corev1.ConditionFalse || cond.Reason != corev1.PodReasonUnschedulable {
			continue
		}
		start := cond.LastTransitionTime.Time
		if start.IsZero() {
			start = p.CreationTimestamp.Time
		}
		if c.S.Now.Sub(start) < c.T.PendingAfter.D() {
			continue
		}
		w := c.S.WorkloadOf(p)
		if _, ok := groups[w]; !ok {
			order = append(order, w)
		}
		groups[w] = append(groups[w], hit{pod: p, cond: cond})
	}

	var out []*findings.Finding
	for _, w := range order {
		hits := groups[w]
		var pods []*corev1.Pod
		for _, h := range hits {
			pods = append(pods, h.pod)
		}
		first := hits[0]
		sev := findings.High
		if w.Kind == "Pod" {
			sev = findings.Medium
		}
		f := c.newFinding(sev, workloadRef(w))
		count := replicaImpact(c.S, w, pods, &f.Impact)
		f.Impact.Exposed = exposed(c.S, w)

		since := first.cond.LastTransitionTime.Time
		if since.IsZero() {
			since = first.pod.CreationTimestamp.Time
		}
		f.Since = &since
		reasons := parseSchedulerMessage(first.cond.Message)
		main := mainSchedulingReason(reasons)
		block := conditionBlock(c.S, pods)
		if block != nil {
			main = nodeConditionReason(block)
		}
		req := snapshot.PodRequests(first.pod)
		free := c.S.FreeOnSchedulableNodes()

		f.Title = fmt.Sprintf("Unschedulable for %s: %s (%s)", ago(c.S.Now.Sub(since)), main.short, count)
		f.Summary = fmt.Sprintf("The scheduler finds no node for the pod: %s", truncate(first.cond.Message, 300))
		f.AddFact("Scheduler", truncate(first.cond.Message, 400))
		f.AddFact("Requests", fmt.Sprintf("cpu %s, memory %s", req.Cpu().String(), req.Memory().String()))
		if best := mostFree(free); best != nil {
			f.AddFact("Most free node", fmt.Sprintf("%s: cpu %s, memory %s", best.Node, best.CPU.String(), best.Memory.String()))
		} else {
			f.AddFact("Most free node", "no Ready, schedulable node")
		}
		f.AddFact("Pending for", ago(c.S.Now.Sub(since)))
		f.AddFact("Pods", podNames(pods, 3))
		f.Affected = podRefs(pods, 10)
		f.Links.Workloads = []findings.ObjectRef{workloadRef(w)}
		f.Links.Claims = claimsOf(pods)
		if block != nil {
			f.AddFact("Waiting for", fmt.Sprintf("%s (%s)", strings.Join(block.Nodes, ", "), strings.Join(block.Taints, ", ")))
			f.Links.BlockedBy = block.Nodes
		}

		ns := first.pod.Namespace
		f.Remedy.LikelyCause = main.cause
		f.AddStep(findings.Step{
			Text:    "See the scheduler's reasons for every node",
			Command: fmt.Sprintf("kubectl -n %s describe pod %s", ns, first.pod.Name),
		})
		for _, st := range main.steps(ns, w) {
			f.AddStep(st)
		}
		plainWhy := main.plainWhy
		if main.kind == "resources" {
			if best := mostFree(free); best != nil {
				plainWhy = fmt.Sprintf("No server has enough free room. It asks for %s CPU and %s memory; the server with the most room has %s CPU and %s memory free.",
					req.Cpu().String(), req.Memory().String(), best.CPU.String(), best.Memory.String())
			}
		}
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The %s %s can't start", w.PlainNoun(), w.Name),
			WhatHappened: fmt.Sprintf("It has been waiting for a server to run on for %s.", agoPlain(c.S.Now.Sub(since))),
			Why:          plainWhy,
			WhatToDo:     main.plainDo,
		}
		out = append(out, f)
	}
	return out
}

// conditionBlock returns the nodes whose condition alone keeps the pods
// pending, or nil if any pod waits for something else.
func conditionBlock(s *snapshot.Snapshot, pods []*corev1.Pod) *snapshot.ConditionBlock {
	nodes := map[string]bool{}
	taints := map[string]bool{}
	for _, p := range pods {
		b := s.ConditionBlocked(p)
		if b == nil {
			return nil
		}
		for _, n := range b.Nodes {
			nodes[n] = true
		}
		for _, t := range b.Taints {
			taints[t] = true
		}
	}
	out := &snapshot.ConditionBlock{Nodes: sortedKeys(nodes), Taints: sortedKeys(taints)}
	if len(out.Nodes) == 0 {
		return nil
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// nodeConditionReason explains pods that wait for sick nodes to recover.
func nodeConditionReason(b *snapshot.ConditionBlock) schedExplanation {
	what := "have a problem"
	plain := "The servers that could run it have a problem of their own."
	if len(b.Taints) == 1 {
		switch b.Taints[0] {
		case corev1.TaintNodeDiskPressure:
			what, plain = "are low on disk space", "The servers that could run it are low on disk space."
		case corev1.TaintNodeMemoryPressure:
			what, plain = "are low on memory", "The servers that could run it are low on memory."
		case corev1.TaintNodePIDPressure:
			what, plain = "run too many processes", "The servers that could run it run too many processes."
		case corev1.TaintNodeNotReady, corev1.TaintNodeUnreachable:
			what, plain = "are not ready", "The servers that could run it are not working."
		}
	}
	nodeWord := "node " + b.Nodes[0]
	if len(b.Nodes) > 1 {
		nodeWord = fmt.Sprintf("%d nodes", len(b.Nodes))
	}
	return schedExplanation{
		kind:  "node-condition",
		short: fmt.Sprintf("waiting for %s to recover", nodeWord),
		cause: fmt.Sprintf("The only nodes that could run the pod %s (%s), so Kubernetes keeps new pods away from them. The pod starts by itself once they recover.",
			what, strings.Join(b.Taints, ", ")),
		plainWhy: plain,
		plainDo:  "Fix the server problem first (see the related server problem). The app starts by itself afterwards.",
		steps: func(ns string, w snapshot.Workload) []findings.Step {
			return []findings.Step{{Text: "See the conditions of the nodes", Command: "kubectl describe node " + strings.Join(b.Nodes, " ") + " | grep -A 10 Conditions"}}
		},
	}
}

func mostFree(free []snapshot.NodeFree) *snapshot.NodeFree {
	var best *snapshot.NodeFree
	for i := range free {
		if best == nil || free[i].Memory.Cmp(best.Memory) > 0 {
			best = &free[i]
		}
	}
	return best
}

type schedReason struct {
	count int
	text  string
}

// parseSchedulerMessage splits "0/5 nodes are available: 3 Insufficient
// memory, 2 node(s) had untolerated taint {a: b}. preemption: ..." into its
// parts. The reasons end with the first sentence; what follows (preemption,
// or the "no new claims to deallocate" note of newer versions) is not a
// reason.
func parseSchedulerMessage(msg string) []schedReason {
	_, rest, ok := strings.Cut(msg, "available: ")
	if !ok {
		return nil
	}
	if i := strings.Index(rest, ". "); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(strings.TrimSpace(rest), ".")
	var out []schedReason
	for _, part := range strings.Split(rest, ", ") {
		part = strings.TrimSpace(part)
		n := 0
		fields := strings.SplitN(part, " ", 2)
		if len(fields) == 2 {
			if _, err := fmt.Sscanf(fields[0], "%d", &n); err == nil {
				part = fields[1]
			}
		}
		out = append(out, schedReason{count: n, text: part})
	}
	return out
}

type schedExplanation struct {
	kind, short, cause, plainWhy, plainDo string
	steps                                 func(ns string, w snapshot.Workload) []findings.Step
}

func mainSchedulingReason(rs []schedReason) schedExplanation {
	best := schedReason{}
	for _, r := range rs {
		if r.count > best.count || best.text == "" {
			best = r
		}
	}
	t := strings.ToLower(best.text)
	nodes := func(ns string, w snapshot.Workload) []findings.Step {
		return []findings.Step{{Text: "Compare with the nodes", Command: "kubectl get nodes -o wide"}}
	}
	switch {
	case strings.Contains(t, "insufficient"):
		res := strings.TrimSpace(strings.TrimPrefix(t, "insufficient"))
		return schedExplanation{
			kind: "resources", short: "not enough free " + res + " on any node",
			cause:    "The pod requests more " + res + " than any node has left.",
			plainWhy: "No server has enough free room for it.",
			plainDo:  "Lower what the app asks for, free up room by stopping other apps, or add a server. Send the report to your support team if you are unsure.",
			steps: func(ns string, w snapshot.Workload) []findings.Step {
				s := []findings.Step{{Text: "See what is already requested on each node", Command: "kubectl describe nodes | grep -A 8 'Allocated resources'"}}
				if w.Kind != "Pod" {
					s = append(s, findings.Step{Text: "Or lower the requests of the workload if they are larger than it needs", Command: fmt.Sprintf("kubectl -n %s set resources %s --requests=cpu=<cpu>,memory=<memory>", ns, kubectlTarget(w))})
				}
				return s
			},
		}
	case strings.Contains(t, "unbound") && strings.Contains(t, "persistentvolumeclaim"):
		return schedExplanation{
			kind: "storage", short: "its storage volume is not ready",
			cause:    "A PersistentVolumeClaim the pod uses is not bound.",
			plainWhy: "The storage it needs hasn't been created yet.",
			plainDo:  "Fix the storage problem first (see the related storage problem).",
			steps: func(ns string, w snapshot.Workload) []findings.Step {
				return []findings.Step{{Text: "Check the claims in the namespace", Command: fmt.Sprintf("kubectl -n %s get pvc", ns)}}
			},
		}
	case strings.Contains(t, "volume node affinity"):
		return schedExplanation{
			kind: "storage", short: "its volume is tied to a node it cannot use",
			cause:    "The pod's volume can only be used on specific nodes, and none of them can run the pod.",
			plainWhy: "Its data lives on a server that can't run it right now.",
			plainDo:  "Bring the server that holds its data back, or send the report to your support team.",
			steps:    nodes,
		}
	case strings.Contains(t, "taint"):
		return schedExplanation{
			kind: "taints", short: "all nodes have taints it does not tolerate",
			cause:    "The nodes are reserved (tainted) for other work, and the pod has no matching toleration.",
			plainWhy: "The servers are reserved for other work.",
			plainDo:  "Send the report to your support team; the app's placement rules or the servers' reservations need to change.",
			steps: func(ns string, w snapshot.Workload) []findings.Step {
				return []findings.Step{{Text: "List the taints on the nodes", Command: "kubectl get nodes -o custom-columns=NAME:.metadata.name,TAINTS:.spec.taints"}}
			},
		}
	case strings.Contains(t, "affinity") || strings.Contains(t, "selector"):
		return schedExplanation{
			kind: "placement", short: "its placement rules match no node",
			cause:    "The pod's node selector or affinity rules match no available node.",
			plainWhy: "Its placement rules don't match any server.",
			plainDo:  "Send the report to your support team; the app's placement rules or the servers' labels need to change.",
			steps: func(ns string, w snapshot.Workload) []findings.Step {
				return []findings.Step{{Text: "Compare the pod's node selector with the node labels", Command: "kubectl get nodes --show-labels"}}
			},
		}
	case strings.Contains(t, "too many pods"):
		return schedExplanation{
			kind: "pods", short: "the nodes are full (too many pods)",
			cause:    "The nodes have reached their maximum number of pods.",
			plainWhy: "The servers already run as many app parts as they can.",
			plainDo:  "Add a server or remove unused apps.",
			steps:    nodes,
		}
	case strings.Contains(t, "unschedulable"):
		return schedExplanation{
			kind: "cordoned", short: "the nodes are cordoned",
			cause:    "The nodes are marked unschedulable (cordoned), for example after maintenance.",
			plainWhy: "The servers were paused for maintenance and don't accept new apps.",
			plainDo:  "If the maintenance is over, make the servers available again (uncordon).",
			steps: func(ns string, w snapshot.Workload) []findings.Step {
				return []findings.Step{{Text: "Uncordon the nodes when maintenance is done", Command: "kubectl get nodes\nkubectl uncordon <node>"}}
			},
		}
	case strings.Contains(t, "free ports"):
		return schedExplanation{
			kind: "ports", short: "the host port it needs is taken on every node",
			cause:    "The pod uses a hostPort that is already in use on every node.",
			plainWhy: "The network port it needs is already used on every server.",
			plainDo:  "Send the report to your support team.",
			steps:    nodes,
		}
	}
	short := "no node fits"
	if best.text != "" {
		short = best.text
	}
	return schedExplanation{
		kind: "other", short: short,
		cause:    "The scheduler found no suitable node. The message lists the reason for each node.",
		plainWhy: "No server can run it right now.",
		plainDo:  "Send the report to your support team.",
		steps:    nodes,
	}
}

// ---------------------------------------------------------------------------
// W12 deploy.unavailable

var deploymentUnavailableRule = Rule{
	ID: "deploy.unavailable", Code: "W12", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindDeployment, snapshot.KindPod},
	Eval:  evalDeploymentUnavailable,
}

func evalDeploymentUnavailable(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, d := range c.S.Deployments {
		desired := int32(1)
		if d.Spec.Replicas != nil {
			desired = *d.Spec.Replicas
		}
		available := d.Status.AvailableReplicas
		if desired == 0 || available >= desired || d.DeletionTimestamp != nil {
			continue
		}
		since := d.CreationTimestamp.Time
		deadline := false
		condMsg := ""
		for _, cond := range d.Status.Conditions {
			switch cond.Type {
			case "Available":
				if cond.Status == corev1.ConditionFalse && !cond.LastTransitionTime.IsZero() {
					since = cond.LastTransitionTime.Time
				}
			case "Progressing":
				if cond.Reason == "ProgressDeadlineExceeded" {
					deadline = true
					condMsg = cond.Message
				}
				if cond.Status == corev1.ConditionTrue && !cond.LastUpdateTime.IsZero() && cond.LastUpdateTime.After(since) {
					// The rollout made progress recently; measure from there.
					since = cond.LastUpdateTime.Time
				}
			}
		}
		if !deadline && c.S.Now.Sub(since) < c.T.DeploymentUnavailableAfter.D() {
			continue
		}
		w := snapshot.Workload{Kind: "Deployment", Namespace: d.Namespace, Name: d.Name}
		sev := findings.Medium
		switch {
		case available == 0:
			sev = findings.Critical
		case available*2 <= desired:
			sev = findings.High
		}
		f := c.newFinding(sev, workloadRef(w))
		f.Impact.AllReplicasDown = available == 0
		f.Impact.FractionDown = float64(desired-available) / float64(desired)
		f.Impact.Exposed = exposed(c.S, w)
		pods := c.S.PodsOf(w)
		var notReady []*corev1.Pod
		for _, p := range pods {
			if !snapshot.IsPodReady(p) && !snapshot.IsPodTerminal(p) {
				notReady = append(notReady, p)
			}
		}
		f.Impact.AffectedPods = len(notReady)
		f.Since = &since

		f.Title = fmt.Sprintf("%d of %d replicas available", available, desired)
		if deadline {
			f.Title += ", rollout stuck (ProgressDeadlineExceeded)"
		}
		if available == 0 {
			f.Summary = fmt.Sprintf("The deployment wants %d replicas but none is available, for %s.", desired, ago(c.S.Now.Sub(since)))
		} else {
			f.Summary = fmt.Sprintf("The deployment wants %d replicas but only %d are available, for %s.", desired, available, ago(c.S.Now.Sub(since)))
		}
		f.AddFact("Replicas", fmt.Sprintf("desired %d, updated %d, ready %d, available %d", desired, d.Status.UpdatedReplicas, d.Status.ReadyReplicas, available))
		f.AddFact("Revision", d.Annotations["deployment.kubernetes.io/revision"])
		f.AddFact("Rollout", truncate(condMsg, 300))
		if d.Spec.Paused {
			f.AddFact("Paused", "yes")
		}
		f.AddFact("Not ready pods", podNames(notReady, 3))
		f.Affected = podRefs(notReady, 10)
		f.Links.Workloads = []findings.ObjectRef{workloadRef(w)}
		f.Links.Nodes = nodesOf(notReady)

		ns := d.Namespace
		f.Remedy.LikelyCause = "Its pods are not becoming ready. The pods' own problems usually explain why."
		f.AddStep(findings.Step{Text: "See the rollout state", Command: fmt.Sprintf("kubectl -n %s rollout status deploy/%s --timeout=10s", ns, d.Name)})
		f.AddStep(findings.Step{Text: "See its pods and where they run", Command: fmt.Sprintf("kubectl -n %s get pods -o wide -l %s", ns, selectorString(d.Spec.Selector.MatchLabels))})
		if !isK0sManaged(w) {
			f.AddStep(findings.Step{
				Text:    "If a new revision broke it, undo the rollout",
				Plain:   "If this started after an update, undoing the update usually fixes it.",
				Command: fmt.Sprintf("kubectl -n %s rollout undo deploy/%s", ns, d.Name),
			})
		}
		title := fmt.Sprintf("The app %s is down", d.Name)
		if available > 0 {
			title = fmt.Sprintf("The app %s runs with fewer copies than it should (%d of %d)", d.Name, available, desired)
		}
		f.Plain = findings.PlainText{
			Title:        title,
			WhatHappened: fmt.Sprintf("%d of its %d copies are working, for %s.", available, desired, agoPlain(c.S.Now.Sub(since))),
			Why:          "Its app parts are not getting ready. Related problems usually explain why.",
			WhatToDo:     "Look at the related problems of its app parts first. If this started after an update, undoing the update usually helps.",
		}
		out = append(out, f)
	}
	return out
}

func selectorString(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
