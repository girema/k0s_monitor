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
// N10 node.npd-condition

var npdConditionRule = Rule{
	ID: "node.npd-condition", Code: "N10", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindNode},
	Eval:  evalNPDCondition,
}

// npdCondition explains a problem condition that node-problem-detector
// sets on a node.
type npdCondition struct {
	short, cause, plain string
	// label names the condition in Basic mode's node status.
	label string
	// check is what to run on the node; {unit} is the k0s service.
	check string
}

// npdConditions are node-problem-detector's problem conditions (its default
// kernel, systemd and health-checker monitors). True means the problem is
// there.
var npdConditions = map[string]npdCondition{
	"KernelDeadlock": {
		label: "System partly frozen",
		short: "a task hangs in the kernel",
		cause: "A process has been stuck in the kernel for minutes, usually waiting for a disk or a network filesystem that doesn't answer. Processes that touch the same resource hang too; often only a reboot frees them.",
		plain: "a part of its system is frozen",
		check: "sudo dmesg -T | grep -iE 'blocked for more than|hung_task|task .* blocked' | tail -n 20",
	},
	"ReadonlyFilesystem": {
		label: "A disk can't be written",
		short: "a filesystem was remounted read-only",
		cause: "The kernel found errors on a disk and made its filesystem read-only to protect the data: nothing can be written there, pods on it fail, and the kubelet may too.",
		plain: "one of its disks has errors and can no longer be written to",
		check: "sudo dmesg -T | grep -iE 'remount|read-only|I/O error|EXT4-fs error|XFS' | tail -n 20\nfindmnt -rno TARGET,OPTIONS | grep -E '(^| |,)ro(,|$)'",
	},
	"FrequentKubeletRestart": {
		label: "App runner keeps restarting",
		short: "the kubelet keeps restarting",
		cause: "The kubelet, which runs the pods on this node, keeps crashing and being restarted.",
		plain: "the part that runs the apps keeps restarting",
		check: "sudo journalctl -u {unit} --since '1 hour ago' --no-pager | grep -iE 'kubelet.*(error|fatal|panic)' | tail -n 30",
	},
	"FrequentContainerdRestart": {
		label: "App starter keeps restarting",
		short: "the container runtime keeps restarting",
		cause: "containerd, which starts the containers on this node, keeps crashing and being restarted; containers can't be started or stopped meanwhile.",
		plain: "the part that starts the apps keeps restarting",
		check: "sudo journalctl -u {unit} --since '1 hour ago' --no-pager | grep -iE 'containerd.*(error|fatal|panic)' | tail -n 30",
	},
	"FrequentDockerRestart": {
		label: "Docker keeps restarting",
		short: "Docker keeps restarting",
		cause: "The Docker service on this node keeps crashing and being restarted. k0s doesn't use it for pods, but it can take resources and ports from them.",
		plain: "a service on it keeps restarting",
		check: "sudo journalctl -u docker --since '1 hour ago' --no-pager | tail -n 30",
	},
	"FrequentUnregisterNetDevice": {
		label: "Network fault",
		short: "network devices hang when removed",
		cause: "A known kernel fault (unregister_netdevice waiting): pods take very long to stop and start. A kernel update fixes it.",
		plain: "its network system has a known fault that slows apps down",
		check: "sudo dmesg -T | grep -i unregister_netdevice | tail -n 10\nuname -r",
	},
	"CorruptDockerOverlay2": {
		label: "App image storage damaged",
		short: "the container storage (overlay2) is damaged",
		cause: "The overlay filesystem that holds container images and writable layers reports errors: containers may fail to start or see damaged files.",
		plain: "its storage for app images is damaged",
		check: "sudo dmesg -T | grep -i overlay | tail -n 20",
	},
	"KubeletUnhealthy": {
		label: "App runner not responding",
		short: "the kubelet's health check fails",
		cause: "node-problem-detector's health checker can't reach the kubelet's health endpoint: the kubelet hangs or stopped.",
		plain: "the part that runs the apps doesn't respond",
		check: "sudo systemctl status {unit}\nsudo journalctl -u {unit} -n 100 --no-pager",
	},
	"ContainerRuntimeUnhealthy": {
		label: "App starter not responding",
		short: "the container runtime's health check fails",
		cause: "node-problem-detector's health checker can't reach containerd: containers can't be started or stopped.",
		plain: "the part that starts the apps doesn't respond",
		check: "sudo systemctl status {unit}\nsudo journalctl -u {unit} -n 100 --no-pager | grep -i containerd",
	},
}

// NodeProblemCondition reports whether a node condition is a problem
// node-problem-detector reports while it is True, with its Basic-mode
// label.
func NodeProblemCondition(t string) (label string, ok bool) {
	k, ok := npdConditions[t]
	return k.label, ok
}

func evalNPDCondition(c *Context) []*findings.Finding {
	var out []*findings.Finding
	for _, n := range c.S.Nodes {
		var active []corev1.NodeCondition
		for _, cond := range n.Status.Conditions {
			if _, known := npdConditions[string(cond.Type)]; known && cond.Status == corev1.ConditionTrue {
				active = append(active, cond)
			}
		}
		if len(active) == 0 {
			continue
		}
		sort.SliceStable(active, func(i, j int) bool { return active[i].Type < active[j].Type })
		f := c.newFinding(findings.High, findings.ObjectRef{Kind: "Node", Name: n.Name})
		f.System = true
		f.Impact.AffectedPods = len(c.S.PodsOnNode(n.Name))
		f.Links.Nodes = []string{n.Name}
		unit := "k0sworker"
		if nodeRole(n) == "controller+worker" {
			unit = "k0scontroller"
		}

		var shorts, plains, causes []string
		earliest := active[0].LastTransitionTime.Time
		for _, cond := range active {
			k := npdConditions[string(cond.Type)]
			shorts = append(shorts, k.short)
			plains = append(plains, k.plain)
			causes = append(causes, k.cause)
			value := fmt.Sprintf("since %s ago", ago(c.S.Now.Sub(cond.LastTransitionTime.Time)))
			if cond.Reason != "" {
				value = cond.Reason + ", " + value
			}
			if cond.Message != "" {
				value += ": " + truncate(cond.Message, 200)
			}
			f.AddFact(string(cond.Type), value)
			if cond.LastTransitionTime.Time.Before(earliest) {
				earliest = cond.LastTransitionTime.Time
			}
			f.AddStep(findings.Step{
				Text:    fmt.Sprintf("On the node: see why %s (%s)", k.short, cond.Type),
				Command: strings.ReplaceAll(k.check, "{unit}", unit),
				Host:    n.Name,
			})
		}
		if !earliest.IsZero() {
			f.Since = &earliest
		}
		f.AddFact("Pods on the node", fmt.Sprintf("%d", f.Impact.AffectedPods))
		f.AddFact("Reported by", "node-problem-detector")

		names := make([]string, len(active))
		for i, cond := range active {
			names[i] = string(cond.Type)
		}
		f.Title = fmt.Sprintf("%s: %s", n.Name, strings.Join(names, ", "))
		f.Summary = fmt.Sprintf("node-problem-detector reports that on %s %s. The node may still count as Ready while its pods hang or fail.", n.Name, strings.Join(shorts, ", and "))
		f.Remedy.LikelyCause = strings.Join(causes, " ")
		f.AddStep(findings.Step{
			Text:    "Move the pods to other nodes, then fix or reboot the node, and let pods back on it",
			Plain:   "Move the apps to other servers, then restart this server, and let the apps back on it.",
			Command: fmt.Sprintf("kubectl drain %s --ignore-daemonsets --delete-emptydir-data\n# fix or reboot the node, then:\nkubectl uncordon %s", n.Name, n.Name),
		})
		f.Plain = findings.PlainText{
			Title:        "The server " + n.Name + " has a system fault",
			WhatHappened: "On this server, " + strings.Join(plains, ", and ") + ".",
			Why:          "Apps on it may hang, fail to save data, or restart, even though the server looks online.",
			WhatToDo:     "Whoever looks after the server should check it (steps below). Moving the apps to other servers and restarting it usually helps.",
		}
		out = append(out, f)
	}
	return out
}
