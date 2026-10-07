package rules

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// ---------------------------------------------------------------------------
// N01 node.not-ready

var nodeNotReadyRule = Rule{
	ID: "node.not-ready", Code: "N01", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindNode, snapshot.KindPod},
	Eval:  evalNodeNotReady,
}

func evalNodeNotReady(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, n := range c.S.Nodes {
		ready := snapshot.NodeCondition(n, corev1.NodeReady)
		if ready != nil && ready.Status == corev1.ConditionTrue {
			continue
		}
		f := c.newFinding(findings.Critical, findings.ObjectRef{Kind: "Node", Name: n.Name})
		f.System = true
		since := n.CreationTimestamp.Time
		status, reason, message := "Unknown", "NoStatus", "The node has never reported a Ready condition."
		if ready != nil {
			status, reason, message = string(ready.Status), ready.Reason, ready.Message
			if !ready.LastTransitionTime.IsZero() {
				since = ready.LastTransitionTime.Time
			}
		}
		f.Since = &since
		var pods []*corev1.Pod
		for _, p := range c.S.PodsOnNode(n.Name) {
			if !snapshot.IsPodTerminal(p) {
				pods = append(pods, p)
			}
		}
		f.Impact.AffectedPods = len(pods)

		f.Title = fmt.Sprintf("NotReady for %s (Ready=%s, %s)", ago(c.S.Now.Sub(since)), status, reason)
		f.Summary = fmt.Sprintf("The node's Ready condition is %s: %s", status, message)
		f.AddFact("Ready", fmt.Sprintf("%s (%s)", status, reason))
		f.AddFact("Message", truncate(message, 300))
		if ready != nil && !ready.LastHeartbeatTime.IsZero() {
			f.AddFact("Last heartbeat", ago(c.S.Now.Sub(ready.LastHeartbeatTime.Time))+" ago")
		}
		if l := c.S.NodeLease(n.Name); l != nil && l.Spec.RenewTime != nil {
			f.AddFact("Lease renewed", ago(c.S.Now.Sub(l.Spec.RenewTime.Time))+" ago")
		}
		f.AddFact("Pods on node", fmt.Sprintf("%d", len(pods)))
		f.AddFact("Role", nodeRole(n))
		ip := nodeIP(n)
		f.AddFact("Address", ip)
		f.AddFact("Kubelet", n.Status.NodeInfo.KubeletVersion)
		if n.Spec.Unschedulable {
			f.AddFact("Cordoned", "yes")
		}
		f.Affected = podRefs(pods, 20)

		unit := "k0sworker"
		if nodeRole(n) == "controller+worker" {
			unit = "k0scontroller"
		}
		f.Remedy.LikelyCause = "The machine is off or unreachable, it ran out of disk or memory, or the k0s service on it stopped."
		if ip != "" {
			f.AddStep(findings.Step{
				Text:    "Check that the machine answers on the network",
				Plain:   "Check that the machine is switched on and connected to the network.",
				Command: "ping -c 3 " + ip,
				Host:    "jump host",
			})
		}
		f.AddStep(findings.Step{
			Text:    "On the node: check the k0s service and its recent log",
			Plain:   "If you can log in to it, check that k0s runs, and read its recent messages.",
			Command: fmt.Sprintf("sudo k0s status\nsudo systemctl status %s\nsudo journalctl -u %s --since '30 min ago' --no-pager | tail -n 100", unit, unit),
			Host:    n.Name,
		})
		f.AddStep(findings.Step{
			Text:    "On the node: check free disk space and memory",
			Plain:   "If you can log in to it, check that its disk is not full.",
			Command: "df -h / /var/lib/k0s\nfree -m",
			Host:    n.Name,
		})
		f.AddStep(findings.Step{
			Text:    "See the node's conditions and the pods on it",
			Command: fmt.Sprintf("kubectl describe node %s\nkubectl get pods -A -o wide --field-selector spec.nodeName=%s", n.Name, n.Name),
		})
		happened := fmt.Sprintf("It stopped reporting to the cluster %s ago. %s were running on it.", agoPlain(c.S.Now.Sub(since)), plural(len(pods), "app part", "app parts"))
		if reason == "NodeStatusNeverUpdated" || ready == nil {
			happened = fmt.Sprintf("It was added to the cluster %s ago but has never reported that it is working.", agoPlain(c.S.Now.Sub(since)))
		}
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The server %s stopped responding", n.Name),
			WhatHappened: happened,
			Why:          "Most often the machine is switched off, has lost its network connection, has run out of disk space or memory, or its k0s service stopped.",
			WhatToDo:     "Check that the machine is switched on and connected. If you can log in to it, check its disk space and the k0s service (steps below), or send the report to whoever manages your servers.",
		}
		out = append(out, f)
	}
	return out
}

func nodeRole(n *corev1.Node) string {
	if r := n.Labels["node.k0sproject.io/role"]; r == "control-plane" {
		return "controller+worker"
	}
	if _, ok := n.Labels["node-role.kubernetes.io/control-plane"]; ok {
		return "controller+worker"
	}
	return "worker"
}

func nodeIP(n *corev1.Node) string {
	for _, a := range n.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			return a.Address
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// N02 node.pressure

var nodePressureRule = Rule{
	ID: "node.pressure", Code: "N02", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindNode, snapshot.KindPod},
	Eval:  evalNodePressure,
}

var pressureWords = map[corev1.NodeConditionType]struct{ short, plain string }{
	corev1.NodeDiskPressure:   {"disk", "disk space"},
	corev1.NodeMemoryPressure: {"memory", "memory"},
	corev1.NodePIDPressure:    {"PIDs", "process slots"},
}

func evalNodePressure(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, n := range c.S.Nodes {
		var active []corev1.NodeCondition
		for _, t := range []corev1.NodeConditionType{corev1.NodeDiskPressure, corev1.NodeMemoryPressure, corev1.NodePIDPressure} {
			if cond := snapshot.NodeCondition(n, t); cond != nil && cond.Status == corev1.ConditionTrue {
				active = append(active, *cond)
			}
		}
		if len(active) == 0 {
			continue
		}
		f := c.newFinding(findings.High, findings.ObjectRef{Kind: "Node", Name: n.Name})
		f.System = true
		if len(active) == 1 && active[0].Type == corev1.NodeDiskPressure {
			f.Links.Cause = "disk" // node.fs-high explains it when metrics exist
		}
		if len(active) == 1 && active[0].Type == corev1.NodeMemoryPressure {
			f.Links.Cause = "memory"
		}
		var evicted []*corev1.Pod
		for _, p := range c.S.PodsOnNode(n.Name) {
			if p.Status.Phase == corev1.PodFailed && p.Status.Reason == "Evicted" {
				evicted = append(evicted, p)
			}
		}
		f.Impact.AffectedPods = len(evicted)
		var names, plainNames []string
		earliest := active[0].LastTransitionTime.Time
		for _, cond := range active {
			w := pressureWords[cond.Type]
			names = append(names, string(cond.Type))
			plainNames = append(plainNames, w.plain)
			f.AddFact(string(cond.Type), fmt.Sprintf("since %s ago: %s", ago(c.S.Now.Sub(cond.LastTransitionTime.Time)), truncate(cond.Message, 200)))
			if cond.LastTransitionTime.Time.Before(earliest) {
				earliest = cond.LastTransitionTime.Time
			}
		}
		if !earliest.IsZero() {
			f.Since = &earliest
		}
		f.AddFact("Evicted pods", fmt.Sprintf("%d", len(evicted)))
		f.Affected = podRefs(evicted, 20)
		f.Title = strings.Join(names, ", ")
		if len(evicted) > 0 {
			f.Title += fmt.Sprintf(" (%s evicted)", plural(len(evicted), "pod", "pods"))
		}
		f.Summary = fmt.Sprintf("The kubelet reports %s. New pods are not scheduled there and pods may be evicted.", strings.Join(names, " and "))

		f.Remedy.LikelyCause = "The node is running out of " + strings.Join(plainNames, " and ") + "."
		for _, cond := range active {
			switch cond.Type {
			case corev1.NodeDiskPressure:
				f.AddStep(findings.Step{
					Text:    "On the node: find what uses the disk",
					Plain:   "If you can log in to it, find out what fills its disk.",
					Command: "df -h / /var/lib/k0s\nsudo du -xhd1 /var/lib/k0s | sort -h\nsudo du -xhd1 /var/log | sort -h",
					Host:    n.Name,
				})
				f.AddStep(findings.Step{
					Text:    "On the node: remove container images that no pod uses (needs crictl)",
					Plain:   "Remove old app images that are no longer used.",
					Command: "sudo crictl --runtime-endpoint unix:///run/k0s/containerd.sock rmi --prune",
					Host:    n.Name,
				})
			case corev1.NodeMemoryPressure:
				f.AddStep(findings.Step{
					Text:    "Find the pods that use the most memory",
					Command: "kubectl top pods -A --sort-by=memory | head -n 15",
				})
			case corev1.NodePIDPressure:
				f.AddStep(findings.Step{
					Text:    "On the node: count processes and compare with the limit",
					Command: "ps -eLf | wc -l\ncat /proc/sys/kernel/pid_max",
					Host:    n.Name,
				})
			}
		}
		if len(evicted) > 0 {
			f.AddStep(findings.Step{
				Text:    "When the pressure is gone, clean up the evicted pods",
				Command: fmt.Sprintf("kubectl delete pods -A --field-selector spec.nodeName=%s,status.phase=Failed", n.Name),
			})
		}
		sort.Strings(plainNames)
		what := "Kubernetes won't start new app parts on it until this is fixed."
		if len(evicted) > 0 {
			what = fmt.Sprintf("To protect itself, it has stopped %s; they are restarted on other servers if possible.", plural(len(evicted), "app part", "app parts"))
		}
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The server %s is running low on %s", n.Name, strings.Join(plainNames, " and ")),
			WhatHappened: what,
			Why:          pressurePlainWhy(active),
			WhatToDo:     "Free up room on the server (steps below), or send the report to whoever manages your servers.",
		}
		out = append(out, f)
	}
	return out
}

func pressurePlainWhy(active []corev1.NodeCondition) string {
	var parts []string
	for _, c := range active {
		switch c.Type {
		case corev1.NodeDiskPressure:
			parts = append(parts, "old app images, logs or temporary files are filling its disk")
		case corev1.NodeMemoryPressure:
			parts = append(parts, "the apps on it use more memory than it has")
		case corev1.NodePIDPressure:
			parts = append(parts, "the apps on it run too many processes")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	s := strings.Join(parts, ", and ")
	return strings.ToUpper(s[:1]) + s[1:] + "."
}

// ---------------------------------------------------------------------------
// N03 node.network-unavailable

var nodeNetworkUnavailableRule = Rule{
	ID: "node.network-unavailable", Code: "N03", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindNode, snapshot.KindPod},
	Eval:  evalNodeNetworkUnavailable,
}

func evalNodeNetworkUnavailable(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, n := range c.S.Nodes {
		cond := snapshot.NodeCondition(n, corev1.NodeNetworkUnavailable)
		if cond == nil || cond.Status != corev1.ConditionTrue {
			continue
		}
		f := c.newFinding(findings.High, findings.ObjectRef{Kind: "Node", Name: n.Name})
		f.System = true
		f.Links.Nodes = []string{n.Name}
		since := cond.LastTransitionTime.Time
		if !since.IsZero() {
			f.Since = &since
		}
		pods := 0
		for _, p := range c.S.PodsOnNode(n.Name) {
			if !snapshot.IsPodTerminal(p) {
				pods++
			}
		}
		f.Impact.AffectedPods = pods
		f.AddFact("NetworkUnavailable", fmt.Sprintf("%s: %s", cond.Reason, truncate(cond.Message, 200)))
		f.AddFact("Since", ago(c.S.Now.Sub(since))+" ago")
		f.AddFact("Pods on node", fmt.Sprintf("%d", pods))
		f.Title = fmt.Sprintf("NetworkUnavailable for %s (%s)", ago(c.S.Now.Sub(since)), orDefault(cond.Reason, "no reason given"))
		f.Summary = "The node reports that its pod network is not configured. New pods are kept away from it and pods on it can't reach other pods."
		f.Remedy.LikelyCause = "The network plugin (CNI) on the node is not running or has not set up the node's routes."
		f.AddStep(findings.Step{Text: "Check the network plugin's pod on the node", Command: fmt.Sprintf("kubectl -n kube-system get pods -o wide --field-selector spec.nodeName=%s", n.Name)})
		f.AddStep(findings.Step{Text: "See the node's conditions", Command: fmt.Sprintf("kubectl describe node %s | grep -A 12 Conditions", n.Name)})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The server %s has no working app network", n.Name),
			WhatHappened: fmt.Sprintf("It reports that its network for apps isn't set up. %s run on it and can't reach other apps; no new ones are started there.", plural(pods, "app part", "app parts")),
			Why:          "The network component on that server isn't working.",
			WhatToDo:     "Look at the related network problem first, or send the report to your support team.",
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// N08 node.cordoned-long

var nodeCordonedLongRule = Rule{
	ID: "node.cordoned-long", Code: "N08", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindNode},
	Eval:  evalNodeCordonedLong,
}

func evalNodeCordonedLong(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, n := range c.S.Nodes {
		since, ok := snapshot.CordonedSince(n)
		if !ok || c.S.Now.Sub(since) < c.T.CordonedAfter.D() {
			continue // without a known cordon time it can't be judged
		}
		f := c.newFinding(findings.Low, findings.ObjectRef{Kind: "Node", Name: n.Name})
		f.System = true
		f.Since = &since
		pods := 0
		for _, p := range c.S.PodsOnNode(n.Name) {
			if !snapshot.IsPodTerminal(p) {
				pods++
			}
		}
		f.AddFact("Cordoned", ago(c.S.Now.Sub(since))+" ago")
		f.AddFact("Ready", fmt.Sprintf("%t", snapshot.IsNodeReady(n)))
		f.AddFact("Pods still on node", fmt.Sprintf("%d", pods))
		f.Title = fmt.Sprintf("Cordoned for %s", ago(c.S.Now.Sub(since)))
		f.Summary = fmt.Sprintf("Node %s has been unschedulable for %s. Its capacity is unused for new pods, and the cluster has less room to reschedule if another node fails.", n.Name, ago(c.S.Now.Sub(since)))
		f.Remedy.LikelyCause = "The node was cordoned for maintenance and not uncordoned afterwards."
		f.AddStep(findings.Step{Text: "If the maintenance is over, make the node schedulable again", Plain: "If the maintenance is over, resume the server.", Command: "kubectl uncordon " + n.Name})
		f.AddStep(findings.Step{Text: "If the node is being retired, drain it and remove it from the cluster", Command: fmt.Sprintf("kubectl drain %s --ignore-daemonsets --delete-emptydir-data\nkubectl delete node %s", n.Name, n.Name)})
		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("The server %s has been paused for %s", n.Name, agoPlain(c.S.Now.Sub(since))),
			WhatHappened: "It doesn't accept new apps. Apps already on it keep running.",
			Why:          "Someone paused it (cordoned it) for maintenance, and it was not resumed.",
			WhatToDo:     "If the maintenance is over, resume it (first step). If the server is being retired, remove it from the cluster.",
		}
		out = append(out, f)
	}
	return out
}
