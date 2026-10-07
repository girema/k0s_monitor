package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// podEvents returns the pod's warning events with one of the reasons,
// newest first.
func podEvents(c *Context, p *corev1.Pod, reasons ...string) []*corev1.Event {
	if !c.S.Has(snapshot.KindEvent) {
		return nil
	}
	var out []*corev1.Event
	for _, e := range c.S.EventsFor(p.UID, "Pod", p.Namespace, p.Name) {
		for _, r := range reasons {
			if e.Reason == r {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// severityForPods is High, or Critical when no replica of the workload works.
func severityForPods(f *findings.Finding, base findings.Severity) findings.Severity {
	if f.Impact.AllReplicasDown {
		return findings.Critical
	}
	return base
}

// ---------------------------------------------------------------------------
// W04 pod.config-error

var configErrorRule = Rule{
	ID: "pod.config-error", Code: "W04", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindPod},
	Eval:  evalConfigError,
}

var (
	missingObject = regexp.MustCompile(`(configmap|secret) "([^"]+)" not found`)
	missingKey    = regexp.MustCompile(`couldn't find key (\S+) in (ConfigMap|Secret) ([^/\s]+)/(\S+)`)
)

// configProblem is what a CreateContainerConfigError message is about.
type configProblem struct {
	kind    string // ConfigMap, Secret, or "" when not about one
	name    string
	key     string
	nonRoot bool
}

func parseConfigError(msg string) configProblem {
	if m := missingKey.FindStringSubmatch(msg); m != nil {
		return configProblem{kind: m[2], name: m[4], key: m[1]}
	}
	if m := missingObject.FindStringSubmatch(msg); m != nil {
		kind := "ConfigMap"
		if m[1] == "secret" {
			kind = "Secret"
		}
		return configProblem{kind: kind, name: m[2]}
	}
	if strings.Contains(msg, "runAsNonRoot") {
		return configProblem{nonRoot: true}
	}
	return configProblem{}
}

func evalConfigError(c *Context) []*findings.Finding {
	var out []*findings.Finding
	groups := groupByWorkload(c.S, func(_ *corev1.Pod, cs corev1.ContainerStatus) bool {
		return cs.State.Waiting != nil && cs.State.Waiting.Reason == "CreateContainerConfigError"
	})
	for _, g := range groups {
		pods := g.pods()
		h := g.hits[0]
		f := c.newFinding(findings.High, workloadRef(g.w))
		count := replicaImpact(c.S, g.w, pods, &f.Impact)
		f.Severity = severityForPods(f, findings.High)
		f.Impact.Exposed = exposed(c.S, g.w)

		msg := h.status.State.Waiting.Message
		if ev := podEvents(c, h.pod, "Failed"); len(ev) > 0 && msg == "" {
			msg = ev[0].Message
		}
		cp := parseConfigError(msg)
		ns := h.pod.Namespace
		f.AddFact("Container", h.status.Name)
		f.AddFact("Error", truncate(msg, 400))
		f.AddFact("Pods", podNames(pods, 3))
		f.Affected = podRefs(pods, 10)
		f.Links.Workloads = []findings.ObjectRef{workloadRef(g.w)}
		f.Links.Nodes = nodesOf(pods)
		f.AddStep(findings.Step{Text: "See the error in the pod's events", Command: fmt.Sprintf("kubectl -n %s describe pod %s", ns, h.pod.Name)})

		noun := g.w.PlainNoun()
		plainObj := "settings"
		if cp.kind == "Secret" {
			plainObj = "secret settings (passwords or keys)"
		}
		lower := strings.ToLower(cp.kind)
		switch {
		case cp.key != "":
			f.Title = fmt.Sprintf("CreateContainerConfigError: key %q is missing in %s %s (%s)", cp.key, cp.kind, cp.name, count)
			f.Summary = fmt.Sprintf("Container %q reads key %q from %s %s, and the key does not exist, so the container can't be created.", h.status.Name, cp.key, cp.kind, cp.name)
			f.Remedy.LikelyCause = fmt.Sprintf("The %s exists but lacks the key %q: the key is misspelled, or the %s is incomplete.", cp.kind, cp.key, cp.kind)
			f.AddStep(findings.Step{Text: fmt.Sprintf("List the keys the %s has (values are not shown)", cp.kind), Command: fmt.Sprintf("kubectl -n %s describe %s %s", ns, lower, cp.name)})
			f.AddStep(findings.Step{Text: fmt.Sprintf("Add the key to the %s, or fix the key name in the workload", cp.kind)})
			f.Plain = findings.PlainText{
				Title:        fmt.Sprintf("The %s %s can't start: an entry in its %s is missing", noun, g.w.Name, plainObj),
				WhatHappened: fmt.Sprintf("It reads the entry %q from %s, but that entry doesn't exist, so it can't start.", cp.key, cp.name),
				Why:          "The settings were installed incompletely, or the entry's name is misspelled.",
				WhatToDo:     "If the app comes with your product, the installation may be incomplete: send the report to your support team.",
			}
		case cp.kind != "":
			f.Title = fmt.Sprintf("CreateContainerConfigError: %s %s not found (%s)", cp.kind, cp.name, count)
			f.Summary = fmt.Sprintf("Container %q uses %s %s, which does not exist in namespace %s, so the container can't be created.", h.status.Name, cp.kind, cp.name, ns)
			f.Remedy.LikelyCause = fmt.Sprintf("The %s was not created, was deleted, or its name is misspelled in the workload.", cp.kind)
			f.AddStep(findings.Step{Text: fmt.Sprintf("Check which %ss exist in the namespace", cp.kind), Command: fmt.Sprintf("kubectl -n %s get %s", ns, lower)})
			f.AddStep(findings.Step{Text: fmt.Sprintf("Create the %s (or fix its name in the workload); the pod starts by itself afterwards", cp.kind)})
			f.Plain = findings.PlainText{
				Title:        fmt.Sprintf("The %s %s can't start: its %s are missing", noun, g.w.Name, plainObj),
				WhatHappened: fmt.Sprintf("It needs %s called %s, which doesn't exist, so it can't start.", plainObj, cp.name),
				Why:          "They were not installed, were deleted, or the name is misspelled.",
				WhatToDo:     "If the app comes with your product, the installation may be incomplete: send the report to your support team.",
			}
		case cp.nonRoot:
			f.Title = fmt.Sprintf("CreateContainerConfigError: runAsNonRoot, but the image runs as root (%s)", count)
			f.Summary = fmt.Sprintf("Container %q must not run as root (runAsNonRoot), but its image runs as root and sets no user.", h.status.Name)
			f.Remedy.LikelyCause = "The security context requires a non-root user, and the image's default user is root."
			f.AddStep(findings.Step{Text: "Set runAsUser to a non-zero user ID in the container's securityContext, or use an image that runs as a non-root user"})
			f.Plain = findings.PlainText{
				Title:        fmt.Sprintf("The %s %s can't start: its security settings don't fit its software", noun, g.w.Name),
				WhatHappened: "Its security settings forbid running as the administrator (root), but the software is built to run as root.",
				Why:          "The app's settings and its software don't match.",
				WhatToDo:     "Send the report to your support team.",
			}
		default:
			f.Title = fmt.Sprintf("CreateContainerConfigError: %s (%s)", truncate(msg, 120), count)
			f.Summary = fmt.Sprintf("The container %q can't be created because of its configuration: %s", h.status.Name, truncate(msg, 300))
			f.Remedy.LikelyCause = "The container's configuration refers to something that is missing or invalid."
			f.Plain = findings.PlainText{
				Title:        fmt.Sprintf("The %s %s can't start because of its settings", noun, g.w.Name),
				WhatHappened: "Kubernetes can't create it because something in its settings is missing or wrong.",
				Why:          "The error message in the details says what is missing.",
				WhatToDo:     "Send the report to your support team.",
			}
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// W05 pod.run-error

var runErrorRule = Rule{
	ID: "pod.run-error", Code: "W05", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindPod, snapshot.KindNode},
	Eval:  evalRunError,
}

// isRunError reports containers that fail before the app runs: the runtime
// can't create or start them.
func isRunError(cs corev1.ContainerStatus) (string, bool) {
	if w := cs.State.Waiting; w != nil && (w.Reason == "CreateContainerError" || w.Reason == "RunContainerError") {
		return w.Message, true
	}
	for _, t := range []*corev1.ContainerStateTerminated{cs.State.Terminated, cs.LastTerminationState.Terminated} {
		if t != nil && (t.Reason == "StartError" || t.Reason == "ContainerCannotRun") {
			return t.Message, true
		}
	}
	return "", false
}

func evalRunError(c *Context) []*findings.Finding {
	var out []*findings.Finding
	groups := groupByWorkload(c.S, func(_ *corev1.Pod, cs corev1.ContainerStatus) bool {
		_, ok := isRunError(cs)
		return ok
	})
	for _, g := range groups {
		pods := g.pods()
		h := g.hits[0]
		f := c.newFinding(findings.High, workloadRef(g.w))
		count := replicaImpact(c.S, g.w, pods, &f.Impact)
		f.Severity = severityForPods(f, findings.High)
		f.Impact.Exposed = exposed(c.S, g.w)

		msg, _ := isRunError(h.status)
		if msg == "" {
			if ev := podEvents(c, h.pod, "Failed"); len(ev) > 0 {
				msg = ev[0].Message
			}
		}
		image := h.status.Image
		if h.spec != nil {
			image = h.spec.Image
		}
		arch := ""
		if n := c.S.Node(h.pod.Spec.NodeName); n != nil {
			arch = n.Status.NodeInfo.Architecture
		}
		ns := h.pod.Namespace
		f.AddFact("Container", h.status.Name)
		f.AddFact("Image", image)
		f.AddFact("Error", truncate(msg, 400))
		if arch != "" {
			f.AddFact("Node", fmt.Sprintf("%s (%s)", h.pod.Spec.NodeName, arch))
		}
		f.AddFact("Restarts", fmt.Sprintf("%d", h.status.RestartCount))
		f.AddFact("Pods", podNames(pods, 3))
		f.Affected = podRefs(pods, 10)
		f.Links.Workloads = []findings.ObjectRef{workloadRef(g.w)}
		f.Links.Nodes = nodesOf(pods)
		f.AddStep(findings.Step{Text: "See the error in the pod's events", Command: fmt.Sprintf("kubectl -n %s describe pod %s", ns, h.pod.Name)})

		noun := g.w.PlainNoun()
		m := strings.ToLower(msg)
		switch {
		case strings.Contains(m, "exec format error"):
			f.Title = fmt.Sprintf("exec format error: image %s is not built for %s (%s)", image, orUnknown(arch), count)
			f.Summary = fmt.Sprintf("The program in image %s can't run on node %s: it was built for a different CPU architecture than the node's (%s).", image, h.pod.Spec.NodeName, orUnknown(arch))
			f.Remedy.LikelyCause = "The image was built for another CPU architecture (for example amd64 only, on an arm64 node)."
			f.AddStep(findings.Step{Text: "Check which platforms the image is built for", Command: fmt.Sprintf("docker manifest inspect %s | grep -A 3 platform", image), Host: "any machine with docker"})
			f.AddStep(findings.Step{Text: "Use a multi-architecture image, or keep the workload on nodes of the image's architecture with a nodeSelector on kubernetes.io/arch", Plain: "Use a version of the software built for this server's processor."})
			f.Plain = findings.PlainText{
				Title:        fmt.Sprintf("The %s %s can't run on its server's type of processor", noun, g.w.Name),
				WhatHappened: fmt.Sprintf("Its software was built for a different type of processor than the server %s has (%s).", h.pod.Spec.NodeName, orUnknown(arch)),
				Why:          "The software image doesn't include a version for this processor type.",
				WhatToDo:     "A version of the software for this processor type is needed. Send the report to your support team.",
			}
		case strings.Contains(m, "executable file not found") || strings.Contains(m, "no such file or directory"):
			f.Title = fmt.Sprintf("%s: the start command is not in the image (%s)", runReason(h.status), count)
			f.Summary = fmt.Sprintf("The command of container %q does not exist in image %s.", h.status.Name, image)
			f.Remedy.LikelyCause = "The command or entrypoint names a program that is not in the image, or the image is not the expected one."
			f.AddStep(findings.Step{Text: "Compare the container's command with the image's contents", Command: fmt.Sprintf("kubectl -n %s get pod %s -o jsonpath='{.spec.containers[*].command}'", ns, h.pod.Name)})
			f.Plain = findings.PlainText{
				Title:        fmt.Sprintf("The %s %s can't start: its start command is missing", noun, g.w.Name),
				WhatHappened: "The program it is told to start doesn't exist in its software image.",
				Why:          "The app's settings and its software version don't match.",
				WhatToDo:     "Send the report to your support team.",
			}
		case strings.Contains(m, "permission denied"):
			f.Title = fmt.Sprintf("%s: permission denied starting the container (%s)", runReason(h.status), count)
			f.Summary = fmt.Sprintf("Container %q can't be started: permission denied. %s", h.status.Name, truncate(msg, 200))
			f.Remedy.LikelyCause = "The start command is not executable, or the security settings forbid what it needs."
			f.Plain = findings.PlainText{
				Title:        fmt.Sprintf("The %s %s can't start: permission denied", noun, g.w.Name),
				WhatHappened: "Starting its program is refused.",
				Why:          "The program isn't allowed to run with the app's security settings, or it isn't marked as a program.",
				WhatToDo:     "Send the report to your support team.",
			}
		default:
			f.Title = fmt.Sprintf("%s: the container can't be started (%s)", runReason(h.status), count)
			f.Summary = fmt.Sprintf("The container runtime can't create or start container %q: %s", h.status.Name, truncate(msg, 300))
			f.Remedy.LikelyCause = "The container runtime (containerd) refused the container. The error message has the details."
			f.AddStep(findings.Step{
				Text:    "On the node: check the container runtime's log",
				Command: "sudo journalctl -u k0sworker --since '30 min ago' --no-pager | grep -i -E 'error|fail' | tail -n 50",
				Host:    orUnknown(h.pod.Spec.NodeName),
			})
			f.Plain = findings.PlainText{
				Title:        fmt.Sprintf("The %s %s can't be started", noun, g.w.Name),
				WhatHappened: "The server fails to start it before the app itself runs.",
				Why:          "The error message in the details says why.",
				WhatToDo:     "Send the report to your support team.",
			}
		}
		out = append(out, f)
	}
	return out
}

func runReason(cs corev1.ContainerStatus) string {
	if w := cs.State.Waiting; w != nil && (w.Reason == "CreateContainerError" || w.Reason == "RunContainerError") {
		return w.Reason
	}
	return "StartError"
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// ---------------------------------------------------------------------------
// W07 pod.stuck-creating

var stuckCreatingRule = Rule{
	ID: "pod.stuck-creating", Code: "W07", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindPod},
	Eval:  evalStuckCreating,
}

// creatingSince returns when a pod started waiting in ContainerCreating,
// or false if it isn't.
func creatingSince(p *corev1.Pod) (time.Time, bool) {
	if p.Status.Phase != corev1.PodPending || p.Spec.NodeName == "" || p.DeletionTimestamp != nil {
		return time.Time{}, false
	}
	creating := false
	for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
		if w := cs.State.Waiting; w != nil && w.Reason == "ContainerCreating" {
			creating = true
		}
		if w := cs.State.Waiting; w != nil && w.Reason != "ContainerCreating" && w.Reason != "PodInitializing" {
			return time.Time{}, false // another rule explains it
		}
	}
	if !creating && len(p.Status.ContainerStatuses) > 0 {
		return time.Time{}, false
	}
	since := p.CreationTimestamp.Time
	if cond := snapshot.PodCondition(p, corev1.PodScheduled); cond != nil && !cond.LastTransitionTime.IsZero() {
		since = cond.LastTransitionTime.Time
	}
	return since, true
}

// creatingCause classifies why a pod is stuck in ContainerCreating from
// its events.
type creatingCause struct {
	kind   string // network, storage, config, sandbox, unknown
	reason string
	msg    string
}

var sandboxNetwork = regexp.MustCompile(`(?i)(network|cni|plugin type|kube-router|calico|failed to set ?up)`)

func classifyCreating(c *Context, p *corev1.Pod) creatingCause {
	if len(p.Status.ContainerStatuses) == 0 && len(p.Status.InitContainerStatuses) == 0 {
		return creatingCause{kind: "not-started"}
	}
	e := (*corev1.Event)(nil)
	if evs := podEvents(c, p, "FailedCreatePodSandBox"); len(evs) > 0 {
		e = evs[0]
	} else {
		e = mountEvent(podEvents(c, p, "FailedMount", "FailedAttachVolume", "FailedMapVolume"))
	}
	if e == nil {
		return creatingCause{kind: "unknown"}
	}
	cc := creatingCause{reason: e.Reason, msg: e.Message}
	switch {
	case e.Reason == "FailedCreatePodSandBox" && sandboxNetwork.MatchString(e.Message):
		cc.kind = "network"
	case e.Reason == "FailedCreatePodSandBox":
		cc.kind = "sandbox"
	case missingObject.MatchString(e.Message) && !strings.Contains(e.Message, "persistentvolumeclaim"):
		cc.kind = "config"
	default:
		cc.kind = "storage"
	}
	return cc
}

func evalStuckCreating(c *Context) []*findings.Finding {
	type hit struct {
		pod   *corev1.Pod
		since time.Time
	}
	groups := map[snapshot.Workload][]hit{}
	var order []snapshot.Workload
	for _, p := range c.S.Pods {
		since, ok := creatingSince(p)
		if !ok || c.S.Now.Sub(since) < c.T.ContainerCreatingAfter.D() {
			continue
		}
		w := c.S.WorkloadOf(p)
		if _, ok := groups[w]; !ok {
			order = append(order, w)
		}
		groups[w] = append(groups[w], hit{p, since})
	}
	var out []*findings.Finding
	for _, w := range order {
		hits := groups[w]
		var pods []*corev1.Pod
		since := hits[0].since
		for _, h := range hits {
			pods = append(pods, h.pod)
			if h.since.Before(since) {
				since = h.since
			}
		}
		first := hits[0].pod
		cause := classifyCreating(c, first)
		sev := findings.High
		if cause.kind == "unknown" {
			sev = findings.Medium
		}
		f := c.newFinding(sev, workloadRef(w))
		count := replicaImpact(c.S, w, pods, &f.Impact)
		f.Impact.Exposed = exposed(c.S, w)
		f.Since = &since
		f.Affected = podRefs(pods, 10)
		f.Links.Workloads = []findings.ObjectRef{workloadRef(w)}
		f.Links.Nodes = nodesOf(pods)
		f.Links.Claims = claimsOf(pods)
		f.Links.Cause = cause.kind
		f.AddFact("Waiting for", ago(c.S.Now.Sub(since)))
		f.AddFact("Node", strings.Join(nodesOf(pods), ", "))
		if cause.reason != "" {
			f.AddFact("Last event", truncate(cause.reason+": "+cause.msg, 400))
		}
		f.AddFact("Pods", podNames(pods, 3))

		ns := first.Namespace
		f.AddStep(findings.Step{Text: "See the pod's events", Command: fmt.Sprintf("kubectl -n %s describe pod %s", ns, first.Name)})
		noun := w.PlainNoun()
		long := agoPlain(c.S.Now.Sub(since))
		f.Plain.Title = fmt.Sprintf("The %s %s is stuck while starting", noun, w.Name)
		f.Plain.WhatHappened = fmt.Sprintf("It got a server %s ago, but its programs haven't started yet.", long)
		switch cause.kind {
		case "network":
			f.Title = fmt.Sprintf("Stuck in ContainerCreating for %s: the pod network can't be set up (%s)", ago(c.S.Now.Sub(since)), count)
			f.Remedy.LikelyCause = "The network plugin (CNI) on the node can't give the pod a network. The node's CNI pod is usually not running."
			f.AddStep(findings.Step{Text: "Check the network plugin's pods on the node", Command: fmt.Sprintf("kubectl -n kube-system get pods -o wide --field-selector spec.nodeName=%s", first.Spec.NodeName)})
			f.Plain.Why = "The server can't connect it to the cluster network. The server's network component usually isn't working."
			f.Plain.WhatToDo = "Look at the related network problem first. If there is none, send the report to your support team."
		case "storage":
			reason := cause.reason
			if strings.Contains(cause.msg, "Multi-Attach") {
				reason += " (Multi-Attach)"
			}
			f.Title = fmt.Sprintf("Stuck in ContainerCreating for %s: %s (%s)", ago(c.S.Now.Sub(since)), reason, count)
			f.Remedy.LikelyCause = "A volume can't be attached or mounted on the node."
			f.AddStep(findings.Step{Text: "Check the volumes the pod uses", Command: fmt.Sprintf("kubectl -n %s get pvc", ns)})
			f.Plain.Why = "Its storage can't be connected to the server."
			f.Plain.WhatToDo = "Look at the related storage problem first. If there is none, send the report to your support team."
		case "config":
			f.Title = fmt.Sprintf("Stuck in ContainerCreating for %s: a mounted ConfigMap or Secret is missing (%s)", ago(c.S.Now.Sub(since)), count)
			f.Remedy.LikelyCause = "The pod mounts a ConfigMap or Secret that does not exist."
			f.AddStep(findings.Step{Text: "Create the missing ConfigMap or Secret named in the event, or fix its name in the workload"})
			f.Plain.Why = "Settings it needs (a ConfigMap or Secret) don't exist."
			f.Plain.WhatToDo = "If the app comes with your product, the installation may be incomplete: send the report to your support team."
		case "sandbox":
			f.Title = fmt.Sprintf("Stuck in ContainerCreating for %s: FailedCreatePodSandBox (%s)", ago(c.S.Now.Sub(since)), count)
			f.Remedy.LikelyCause = "The container runtime can't create the pod's sandbox. The event message has the details."
			f.AddStep(findings.Step{
				Text:    "On the node: check the k0s worker's log",
				Command: "sudo journalctl -u k0sworker --since '30 min ago' --no-pager | grep -i sandbox | tail -n 50",
				Host:    first.Spec.NodeName,
			})
			f.Plain.Why = "The server can't prepare a place to run it."
			f.Plain.WhatToDo = "Send the report to your support team."
		case "not-started":
			f.Title = fmt.Sprintf("Not started for %s: the kubelet on %s has not picked it up (%s)", ago(c.S.Now.Sub(since)), first.Spec.NodeName, count)
			f.Remedy.LikelyCause = "The pod is assigned to the node, but the node's kubelet has not reported on it: the kubelet is stopped, overloaded or can't reach the API server."
			f.AddStep(findings.Step{
				Text:    "On the node: check the k0s worker service",
				Command: "sudo systemctl status k0sworker\nsudo journalctl -u k0sworker --since '30 min ago' --no-pager | tail -n 100",
				Host:    first.Spec.NodeName,
			})
			f.Plain.WhatHappened = fmt.Sprintf("It was given the server %s %s ago, but that server hasn't started it.", first.Spec.NodeName, long)
			f.Plain.Why = "The server's k0s service isn't handling new apps. It may be stopped or overloaded."
			f.Plain.WhatToDo = "Send the report to whoever manages your servers, or to your support team."
		default:
			f.Title = fmt.Sprintf("Stuck in ContainerCreating for %s (%s)", ago(c.S.Now.Sub(since)), count)
			f.Remedy.LikelyCause = "No warning explains it. The node may still be downloading a large image, or the container runtime is slow."
			f.AddStep(findings.Step{Text: "See all of the pod's events, including image pulls", Command: fmt.Sprintf("kubectl -n %s get events --field-selector involvedObject.name=%s", ns, first.Name)})
			f.Plain.Why = "Nothing reports an error. The server may still be downloading a large software image."
			f.Plain.WhatToDo = "Wait a few more minutes. If it stays stuck, send the report to your support team."
		}
		f.Summary = fmt.Sprintf("The pod was scheduled to %s %s ago and its containers have not been created. %s", first.Spec.NodeName, ago(c.S.Now.Sub(since)), f.Remedy.LikelyCause)
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// W08 pod.stuck-terminating

var stuckTerminatingRule = Rule{
	ID: "pod.stuck-terminating", Code: "W08", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindPod, snapshot.KindNode},
	Eval:  evalStuckTerminating,
}

func evalStuckTerminating(c *Context) []*findings.Finding {
	groups := map[snapshot.Workload][]*corev1.Pod{}
	var order []snapshot.Workload
	for _, p := range c.S.Pods {
		if p.DeletionTimestamp == nil || c.S.Now.Sub(p.DeletionTimestamp.Time) < c.T.TerminatingAfter.D() {
			continue
		}
		w := c.S.WorkloadOf(p)
		if _, ok := groups[w]; !ok {
			order = append(order, w)
		}
		groups[w] = append(groups[w], p)
	}
	var out []*findings.Finding
	for _, w := range order {
		pods := groups[w]
		first := pods[0]
		f := c.newFinding(findings.Medium, workloadRef(w))
		f.Impact.AffectedPods = len(pods)
		since := first.DeletionTimestamp.Time
		f.Since = &since
		f.Affected = podRefs(pods, 10)
		f.Links.Workloads = []findings.ObjectRef{workloadRef(w)}
		f.Links.Nodes = nodesOf(pods)

		node := first.Spec.NodeName
		n := c.S.Node(node)
		nodeGone := node != "" && (n == nil || !snapshot.IsNodeReady(n))
		finalizers := strings.Join(first.Finalizers, ", ")
		f.AddFact("Deleted", ago(c.S.Now.Sub(since))+" ago")
		f.AddFact("Node", orUnknown(node))
		switch {
		case node != "" && n == nil:
			f.AddFact("Node state", "the node no longer exists")
		case nodeGone:
			f.AddFact("Node state", "NotReady")
		}
		f.AddFact("Finalizers", finalizers)
		f.AddFact("Pods", podNames(pods, 3))

		ns := first.Namespace
		count := plural(len(pods), "pod", "pods")
		f.AddStep(findings.Step{Text: "See the pod's state, finalizers and node", Command: fmt.Sprintf("kubectl -n %s get pod %s -o wide\nkubectl -n %s get pod %s -o jsonpath='{.metadata.finalizers}'", ns, first.Name, ns, first.Name)})
		noun := w.PlainNoun()
		f.Plain.Title = fmt.Sprintf("The %s %s is stuck while stopping", noun, w.Name)
		f.Plain.WhatHappened = fmt.Sprintf("It was told to stop %s ago, but it hasn't finished stopping (%s).", agoPlain(c.S.Now.Sub(since)), plural(len(pods), "part", "parts"))
		switch {
		case nodeGone:
			f.Title = fmt.Sprintf("Terminating for %s: its node %s is not reachable (%s)", ago(c.S.Now.Sub(since)), node, count)
			f.Remedy.LikelyCause = "The node the pod ran on is down, so nothing can confirm that the containers stopped. Kubernetes waits forever in that case."
			f.AddStep(findings.Step{
				Text:    "Only if the node is really gone (powered off or removed): force-delete the pod so it can be started elsewhere",
				Plain:   "If the server is really gone, the stuck part can be removed by force.",
				Command: fmt.Sprintf("kubectl -n %s delete pod %s --grace-period=0 --force", ns, first.Name),
			})
			f.Plain.Why = fmt.Sprintf("The server it ran on (%s) doesn't respond, so nobody can confirm that it stopped.", node)
			f.Plain.WhatToDo = "Fix the server problem first. If the server is gone for good, send the report to your support team; the stuck part can be removed by force."
		case finalizers != "":
			f.Title = fmt.Sprintf("Terminating for %s: waiting for finalizer %s (%s)", ago(c.S.Now.Sub(since)), finalizers, count)
			f.Remedy.LikelyCause = "A finalizer keeps the pod until its controller removes it, and that controller is not doing so (it may be down or uninstalled)."
			f.AddStep(findings.Step{
				Text:    "Fix or restart the controller that owns the finalizer. As a last resort, remove the finalizer",
				Command: fmt.Sprintf("kubectl -n %s patch pod %s --type=merge -p '{\"metadata\":{\"finalizers\":null}}'", ns, first.Name),
			})
			f.Plain.Why = "Another component must approve the removal first and doesn't."
			f.Plain.WhatToDo = "Send the report to your support team."
		default:
			f.Title = fmt.Sprintf("Terminating for %s: the kubelet has not confirmed the stop (%s)", ago(c.S.Now.Sub(since)), count)
			f.Remedy.LikelyCause = "The kubelet on the node can't stop the containers or unmount their volumes."
			f.AddStep(findings.Step{
				Text:    "On the node: look for errors while stopping the pod",
				Command: fmt.Sprintf("sudo journalctl -u k0sworker --since '30 min ago' --no-pager | grep %s | tail -n 50", first.Name),
				Host:    orUnknown(node),
			})
			f.Plain.Why = fmt.Sprintf("The server %s hasn't managed to stop it. A volume may be stuck, or the server's container service has a problem.", orUnknown(node))
			f.Plain.WhatToDo = "Send the report to your support team."
		}
		f.Summary = fmt.Sprintf("%s were deleted %s ago and are still there. %s", strings.ToUpper(count[:1])+count[1:], ago(c.S.Now.Sub(since)), f.Remedy.LikelyCause)
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// W09 pod.not-ready

var notReadyRule = Rule{
	ID: "pod.not-ready", Code: "W09", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindPod},
	Eval:  evalNotReady,
}

// notReadySince returns since when a running pod has not been ready while
// its containers kept running, or false if it is ready, has another
// problem, or the time is unknown.
func notReadySince(p *corev1.Pod) (time.Time, bool) {
	if p.Status.Phase != corev1.PodRunning || p.DeletionTimestamp != nil {
		return time.Time{}, false
	}
	cond := snapshot.PodCondition(p, corev1.PodReady)
	if cond == nil || cond.Status == corev1.ConditionTrue || cond.LastTransitionTime.IsZero() {
		return time.Time{}, false
	}
	since := cond.LastTransitionTime.Time
	for _, cs := range p.Status.ContainerStatuses {
		if cs.State.Running == nil {
			return time.Time{}, false // waiting or terminated: other rules
		}
		// A container that restarted recently belongs to a crash loop or
		// probe restarts, not to a pod that runs but never gets ready.
		if t := cs.State.Running.StartedAt.Time; t.After(since) {
			since = t
		}
	}
	return since, true
}

func probeText(pr *corev1.Probe) string {
	if pr == nil {
		return "none"
	}
	var what string
	switch {
	case pr.HTTPGet != nil:
		what = fmt.Sprintf("HTTP GET %s on port %s", orDefault(pr.HTTPGet.Path, "/"), pr.HTTPGet.Port.String())
	case pr.TCPSocket != nil:
		what = "TCP port " + pr.TCPSocket.Port.String()
	case pr.GRPC != nil:
		what = fmt.Sprintf("gRPC port %d", pr.GRPC.Port)
	case pr.Exec != nil:
		what = "command " + truncate(strings.Join(pr.Exec.Command, " "), 80)
	default:
		what = "unknown"
	}
	return fmt.Sprintf("%s, initial delay %ds, every %ds, timeout %ds, %d failures",
		what, pr.InitialDelaySeconds, max(pr.PeriodSeconds, 10), max(pr.TimeoutSeconds, 1), max(pr.FailureThreshold, 3))
}

// probeMessage tidies a probe failure event: an exec probe without output
// gives "Readiness probe failed: " with nothing after the colon.
func probeMessage(msg string) string {
	return strings.TrimSuffix(strings.TrimSpace(msg), ":")
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func evalNotReady(c *Context) []*findings.Finding {
	type hit struct {
		pod   *corev1.Pod
		since time.Time
	}
	groups := map[snapshot.Workload][]hit{}
	var order []snapshot.Workload
	for _, p := range c.S.Pods {
		since, ok := notReadySince(p)
		if !ok || c.S.Now.Sub(since) < c.T.NotReadyAfter.D() {
			continue
		}
		w := c.S.WorkloadOf(p)
		if _, ok := groups[w]; !ok {
			order = append(order, w)
		}
		groups[w] = append(groups[w], hit{p, since})
	}
	var out []*findings.Finding
	for _, w := range order {
		hits := groups[w]
		var pods []*corev1.Pod
		since := hits[0].since
		for _, h := range hits {
			pods = append(pods, h.pod)
			if h.since.Before(since) {
				since = h.since
			}
		}
		first := hits[0].pod
		f := c.newFinding(findings.Medium, workloadRef(w))
		count := replicaImpact(c.S, w, pods, &f.Impact)
		if f.Impact.AllReplicasDown {
			f.Severity = findings.High
		}
		f.Impact.Exposed = exposed(c.S, w)
		f.Since = &since
		f.Affected = podRefs(pods, 10)
		f.Links.Workloads = []findings.ObjectRef{workloadRef(w)}
		f.Links.Nodes = nodesOf(pods)

		var notReady []string
		var probe *corev1.Probe
		for _, cs := range first.Status.ContainerStatuses {
			if !cs.Ready {
				notReady = append(notReady, cs.Name)
				if spec := containerSpec(first, cs.Name); spec != nil && probe == nil {
					probe = spec.ReadinessProbe
				}
			}
		}
		lastFailure := ""
		for _, e := range podEvents(c, first, "Unhealthy") {
			if strings.HasPrefix(e.Message, "Readiness probe") {
				lastFailure = probeMessage(e.Message)
				break
			}
		}
		f.AddFact("Not ready for", ago(c.S.Now.Sub(since)))
		f.AddFact("Containers not ready", strings.Join(notReady, ", "))
		f.AddFact("Readiness probe", probeText(probe))
		f.AddFact("Last probe failure", truncate(lastFailure, 300))
		f.AddFact("Pods", podNames(pods, 3))

		ns := first.Namespace
		f.AddStep(findings.Step{Text: "See the probe failures in the pod's events", Command: fmt.Sprintf("kubectl -n %s describe pod %s", ns, first.Name)})
		f.AddStep(findings.Step{Text: "Read the app's log for what it waits for", Command: fmt.Sprintf("kubectl -n %s logs %s --tail=100", ns, first.Name)})
		f.AddStep(findings.Step{Text: "If the probe is wrong (path, port or timing), fix it in the workload", Command: fmt.Sprintf("kubectl -n %s edit %s", ns, kubectlTarget(w))})

		why := "Its health check fails."
		n := c.S.Node(first.Spec.NodeName)
		switch {
		case len(notReady) == 0 && n != nil && !snapshot.IsNodeReady(n):
			f.Title = fmt.Sprintf("Not Ready for %s: its node %s is not ready (%s)", ago(c.S.Now.Sub(since)), n.Name, count)
			f.Remedy.LikelyCause = "The node stopped reporting, so Kubernetes marks its pods not ready and sends them no traffic."
			why = fmt.Sprintf("The server it runs on (%s) stopped responding.", n.Name)
		case len(notReady) == 0 && len(first.Spec.ReadinessGates) > 0:
			f.Title = fmt.Sprintf("Running but not Ready for %s: a readiness gate is not met (%s)", ago(c.S.Now.Sub(since)), count)
			f.Remedy.LikelyCause = "All containers are ready, but a readiness gate set by another controller (for example a load balancer) is not."
			why = "Another component hasn't confirmed that it is ready."
		case lastFailure != "":
			f.Title = fmt.Sprintf("Running but not Ready for %s: %s (%s)", ago(c.S.Now.Sub(since)), truncate(lastFailure, 120), count)
			f.Remedy.LikelyCause = "The readiness probe fails. The app is waiting for something (a database, another service), or the probe checks the wrong path, port or timing."
			why = "Its health check fails: it says it isn't ready to work."
		default:
			f.Title = fmt.Sprintf("Running but not Ready for %s (%s)", ago(c.S.Now.Sub(since)), count)
			f.Remedy.LikelyCause = "The readiness probe fails. The app is waiting for something (a database, another service), or the probe checks the wrong path, port or timing."
		}
		f.Summary = fmt.Sprintf("The pod runs but is not ready, so it gets no traffic. %s", f.Remedy.LikelyCause)
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The %s %s is running but not ready", w.PlainNoun(), w.Name),
			WhatHappened: fmt.Sprintf("It has been running for %s without reporting that it is ready, so it gets no requests.", agoPlain(c.S.Now.Sub(since))),
			Why:          why + " Often the app waits for a database or another service it needs.",
			WhatToDo:     "Check the related problems of the services it needs. If there are none, send the report to your support team.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// W10 pod.probe-kills

var probeKillsRule = Rule{
	ID: "pod.probe-kills", Code: "W10", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindPod, snapshot.KindEvent},
	Eval:  evalProbeKills,
}

// probeKillWindow is how recent a liveness failure and a restart must be.
const probeKillWindow = time.Hour

// probeKillEvent returns the latest recent liveness or startup failure of
// a container that was restarted recently, or nil.
func probeKillEvent(c *Context, p *corev1.Pod, cs corev1.ContainerStatus) *corev1.Event {
	last := cs.LastTerminationState.Terminated
	if cs.RestartCount == 0 || last == nil || last.Reason == "OOMKilled" || c.S.Now.Sub(last.FinishedAt.Time) > probeKillWindow {
		return nil
	}
	for _, e := range podEvents(c, p, "Unhealthy") {
		if c.S.Now.Sub(snapshot.EventTime(e)) > probeKillWindow {
			break
		}
		if !strings.HasPrefix(e.Message, "Liveness probe") && !strings.HasPrefix(e.Message, "Startup probe") {
			continue
		}
		// Events name the container in the field path, for example
		// spec.containers{api}.
		if fp := e.InvolvedObject.FieldPath; fp != "" && !strings.Contains(fp, "{"+cs.Name+"}") {
			continue
		}
		return e
	}
	return nil
}

func evalProbeKills(c *Context) []*findings.Finding {
	var out []*findings.Finding
	groups := groupByWorkload(c.S, func(p *corev1.Pod, cs corev1.ContainerStatus) bool {
		return probeKillEvent(c, p, cs) != nil
	})
	for _, g := range groups {
		pods := g.pods()
		h := g.worst()
		f := c.newFinding(findings.Medium, workloadRef(g.w))
		count := replicaImpact(c.S, g.w, pods, &f.Impact)
		looping := false
		for _, x := range g.hits {
			if w := x.status.State.Waiting; w != nil && w.Reason == "CrashLoopBackOff" {
				looping = true
			}
		}
		switch {
		case f.Impact.AllReplicasDown:
			f.Severity = findings.Critical
		case looping:
			f.Severity = findings.High
		}
		f.Impact.Exposed = exposed(c.S, g.w)
		f.Affected = podRefs(pods, 10)
		f.Links.Workloads = []findings.ObjectRef{workloadRef(g.w)}
		f.Links.Nodes = nodesOf(pods)

		ev := probeKillEvent(c, h.pod, h.status)
		msg := probeMessage(ev.Message)
		kind := "liveness"
		var probe *corev1.Probe
		var startup *corev1.Probe
		if h.spec != nil {
			probe, startup = h.spec.LivenessProbe, h.spec.StartupProbe
		}
		if strings.HasPrefix(ev.Message, "Startup probe") {
			kind, probe = "startup", startup
		}
		f.AddFact("Container", h.status.Name)
		f.AddFact("Restarts", fmt.Sprintf("%d", h.status.RestartCount))
		f.AddFact("Last failure", truncate(msg, 300))
		f.AddFact("Probe", probeText(probe))
		if startup == nil && kind == "liveness" {
			f.AddFact("Startup probe", "none")
		}
		f.AddFact("Pods", podNames(pods, 3))

		ns := h.pod.Namespace
		f.Title = fmt.Sprintf("Restarted by its %s probe: %s (%s)", kind, truncate(msg, 100), count)
		f.Summary = fmt.Sprintf("Container %q fails its %s probe, so the kubelet kills and restarts it (%d restarts).", h.status.Name, kind, h.status.RestartCount)
		f.Remedy.LikelyCause = "The app hangs or is overloaded, or it needs longer to start than the probe allows."
		f.AddStep(findings.Step{Text: "See the probe failures and restarts", Command: fmt.Sprintf("kubectl -n %s describe pod %s", ns, h.pod.Name)})
		f.AddStep(findings.Step{Text: "Read the log from before the last restart", Command: fmt.Sprintf("kubectl -n %s logs %s -c %s --previous --tail=100", ns, h.pod.Name, h.status.Name)})
		fix := "If the app starts slowly, add a startupProbe or raise initialDelaySeconds; if it is slow under load, raise timeoutSeconds or failureThreshold"
		f.AddStep(findings.Step{Text: fix, Command: fmt.Sprintf("kubectl -n %s edit %s", ns, kubectlTarget(g.w))})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("Kubernetes keeps restarting the %s %s because its health check fails", g.w.PlainNoun(), g.w.Name),
			WhatHappened: fmt.Sprintf("Its health check failed, so Kubernetes restarted it. This has happened %d times.", h.status.RestartCount),
			Why:          "The app stops answering its health check: it hangs, is overloaded, or needs longer to start than the check allows.",
			WhatToDo:     "If it happens right after starting, the check needs more time. Send the report to your support team.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// W11 pod.evicted

var evictedRule = Rule{
	ID: "pod.evicted", Code: "W11", Category: findings.Workloads,
	Needs: []snapshot.Kind{snapshot.KindPod},
	Eval:  evalEvicted,
}

var lowOnResource = regexp.MustCompile(`low on resource: ([a-z-]+)`)

func evalEvicted(c *Context) []*findings.Finding {
	groups := map[snapshot.Workload][]*corev1.Pod{}
	var order []snapshot.Workload
	for _, p := range c.S.Pods {
		if p.Status.Phase != corev1.PodFailed || p.Status.Reason != "Evicted" {
			continue
		}
		if t := finishedAt(p); !t.IsZero() && c.S.Now.Sub(t) > c.T.FinishedPodsAfter.D() {
			continue // an old leftover: hygiene.finished-pods
		}
		w := c.S.WorkloadOf(p)
		if _, ok := groups[w]; !ok {
			order = append(order, w)
		}
		groups[w] = append(groups[w], p)
	}
	var out []*findings.Finding
	for _, w := range order {
		pods := groups[w]
		sort.SliceStable(pods, func(i, j int) bool { return pods[i].CreationTimestamp.After(pods[j].CreationTimestamp.Time) })
		newest := pods[0]
		f := c.newFinding(findings.Low, workloadRef(w))
		f.Impact.AffectedPods = len(pods)
		f.Affected = podRefs(pods, 10)
		f.Links.Workloads = []findings.ObjectRef{workloadRef(w)}
		f.Links.Nodes = nodesOf(pods)
		msg := newest.Status.Message
		resource := ""
		if m := lowOnResource.FindStringSubmatch(msg); m != nil {
			resource = m[1]
		}
		ownLimit := strings.Contains(msg, "exceeds")
		if !ownLimit {
			f.Links.Cause = "node-pressure"
		}
		f.AddFact("Evicted pods", fmt.Sprintf("%d", len(pods)))
		f.AddFact("Nodes", strings.Join(f.Links.Nodes, ", "))
		f.AddFact("Last message", truncate(msg, 300))
		f.AddFact("Pods", podNames(pods, 3))

		ns := newest.Namespace
		count := plural(len(pods), "pod", "pods")
		noun := w.PlainNoun()
		switch {
		case resource != "":
			f.Title = fmt.Sprintf("Evicted: %s (the node was low on %s)", count, resource)
			f.Remedy.LikelyCause = fmt.Sprintf("The node ran low on %s and the kubelet stopped pods to protect itself.", resource)
			f.Plain.Why = fmt.Sprintf("The server ran low on %s and stopped some app parts to protect itself.", plainResource(resource))
		case ownLimit:
			f.Title = fmt.Sprintf("Evicted: %s (%s)", count, truncate(msg, 100))
			f.Remedy.LikelyCause = "The pod used more than it is allowed, for example more than its ephemeral-storage limit."
			f.Plain.Why = "It used more disk space than it is allowed to."
		default:
			f.Title = "Evicted: " + count
			if msg != "" {
				f.Title += " (" + truncate(msg, 100) + ")"
			}
			f.Remedy.LikelyCause = "The kubelet stopped the pods, usually because the node was under pressure."
			f.Plain.Why = "The server stopped them, usually because it ran low on disk space or memory."
		}
		f.Summary = fmt.Sprintf("%s of %s %s were evicted and remain as Failed pods. %s Kubernetes replaces them where it can.", strings.ToUpper(count[:1])+count[1:], strings.ToLower(w.Kind), w.Name, f.Remedy.LikelyCause)
		f.AddStep(findings.Step{Text: "List the evicted pods", Command: fmt.Sprintf("kubectl -n %s get pods --field-selector=status.phase=Failed", ns)})
		f.AddStep(findings.Step{
			Text:    "When the cause is fixed, delete the evicted pods; they are only records",
			Plain:   "The stopped copies are only records and can be cleaned up.",
			Command: fmt.Sprintf("kubectl -n %s delete pods --field-selector=status.phase=Failed", ns),
		})
		if w.Kind == "Pod" {
			f.Plain.Title = fmt.Sprintf("The app part %s was stopped by its server", w.Name)
			f.Plain.WhatHappened = fmt.Sprintf("The server %s stopped it. It isn't restarted, because nothing manages it.", strings.Join(f.Links.Nodes, ", "))
		} else {
			f.Plain.Title = fmt.Sprintf("Parts of the %s %s were stopped by their server", noun, w.Name)
			f.Plain.WhatHappened = fmt.Sprintf("%s stopped by the server %s. Kubernetes starts replacements where it can.", plural(len(pods), "part was", "parts were"), strings.Join(f.Links.Nodes, ", "))
		}
		f.Plain.WhatToDo = "Fix the server problem if there is one (see the related problem). The stopped copies are only records and can be cleaned up."
		out = append(out, f)
	}
	return out
}

func plainResource(r string) string {
	switch r {
	case "ephemeral-storage", "nodefs", "imagefs":
		return "disk space"
	case "memory":
		return "memory"
	case "pids":
		return "process slots"
	case "cpu":
		return "CPU"
	}
	return r
}
