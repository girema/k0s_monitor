package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// ---------------------------------------------------------------------------
// V04 vm.kernel-errors
//
// What only a server's kernel sees: disk I/O and filesystem errors, tasks
// hung waiting for storage, kernel oopses, memory errors, processes killed
// for lack of memory outside the apps' limits, and network links that go
// down. Two sources, neither installed by k0s-monitor:
//
//   - node-problem-detector's kernel monitor, which reads the kernel log
//     and reports these as events on the node (OOMKilling, TaskHung,
//     KernelOops, Ext4Error, IOError, …);
//   - node-exporter, through Prometheus: node_vmstat_oom_kill and
//     node_network_carrier_changes_total.
//
// The plan's fallback node agent would read the kernel log itself; these
// two cover the same errors where they run.

var kernelErrorsRule = Rule{
	ID: "vm.kernel-errors", Code: "V04", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindNode},
	Eval:  evalKernelErrors,
}

// kernelWindow is how far back events count; node-exporter's counters
// cover 15 minutes.
const kernelWindow = time.Hour

// kernelKind is a kind of kernel error.
type kernelKind struct {
	// topic is disk, memory, network or kernel; it decides the advice.
	topic string
	sev   findings.Severity
	// what names it in a list ("disk I/O errors"), plain in Basic mode.
	what, plain string
}

// npdKernelReasons are node-problem-detector's kernel monitor's event
// reasons (its default kernel-monitor.json), and the usual custom ones.
var npdKernelReasons = map[string]kernelKind{
	"IOError":             {"disk", findings.High, "disk I/O errors", "disk errors"},
	"Ext4Error":           {"disk", findings.High, "EXT4 filesystem errors", "errors in its files' storage"},
	"Ext4Warning":         {"disk", findings.Low, "EXT4 filesystem warnings", "warnings about its files' storage"},
	"XFSError":            {"disk", findings.High, "XFS filesystem errors", "errors in its files' storage"},
	"TaskHung":            {"disk", findings.High, "tasks hung for minutes", "programs stuck waiting, usually for storage"},
	"KernelOops":          {"kernel", findings.High, "kernel oopses", "errors in the operating system itself"},
	"MemoryReadError":     {"memory", findings.High, "memory read errors (hardware)", "errors reading its memory chips"},
	"OOMKilling":          {"memory", findings.Medium, "processes killed for lack of memory", "programs stopped because its memory ran out"},
	"UnregisterNetDevice": {"network", findings.Medium, "a network device stuck while being removed", "a stuck network device"},
}

// virtualNIC tells the interfaces whose links changing is normal: they come
// and go with pods and tunnels.
func virtualNIC(dev string) bool {
	for _, p := range []string{"lo", "veth", "cali", "cilium", "lxc", "flannel", "cni", "docker", "kube-", "vxlan", "tunl", "genev", "wg", "br-", "virbr", "tap", "tun", "nodelocaldns", "dummy"} {
		if strings.HasPrefix(dev, p) {
			return true
		}
	}
	return false
}

// kernelHit is one kind of error on a node: how often, and an example.
type kernelHit struct {
	kind    kernelKind
	count   int
	example string
	from    string
}

func evalKernelErrors(c *Context) []*findings.Finding {
	hits := map[string]map[string]*kernelHit{} // node -> what -> hit
	add := func(node string, k kernelKind, n int, example, from string) {
		if hits[node] == nil {
			hits[node] = map[string]*kernelHit{}
		}
		h := hits[node][k.what]
		if h == nil {
			h = &kernelHit{kind: k, from: from}
			hits[node][k.what] = h
		}
		h.count += n
		if h.example == "" {
			h.example = example
		}
	}
	// node-problem-detector's events.
	for _, e := range c.S.Events {
		if e.InvolvedObject.Kind != "Node" || c.S.Node(e.InvolvedObject.Name) == nil {
			continue
		}
		k, known := npdKernelReasons[e.Reason]
		if !known || !strings.Contains(e.Source.Component, "kernel-monitor") && e.ReportingController != "kernel-monitor" {
			continue
		}
		if c.S.Now.Sub(snapshot.EventTime(e)) > kernelWindow {
			continue
		}
		// A container killed at its own memory limit is the app's problem
		// (pod.oomkilled), not the server's.
		if e.Reason == "OOMKilling" && strings.Contains(e.Message, "Memory cgroup") {
			continue
		}
		n := int(e.Count)
		if n < 1 {
			n = 1
		}
		add(e.InvolvedObject.Name, k, n, strings.TrimSpace(e.Message), "node-problem-detector")
	}
	// node-exporter's counters.
	if m := c.S.Metrics; m != nil {
		for _, nm := range metricNodes(c) {
			name := nm.node.Name
			if v := nm.m.OOMKills15m; snapshot.Known(v) && v >= 0.5 {
				// Containers stopped at their own limit count too; what is
				// left was killed because the server ran out.
				host := int(v+0.5) - containerOOMs(c, name, 15*time.Minute)
				if host > 0 && hits[name][npdKernelReasons["OOMKilling"].what] == nil {
					add(name, npdKernelReasons["OOMKilling"], host, "", "node-exporter")
				}
			}
			devs := make([]string, 0, len(nm.m.LinkFlaps))
			for dev := range nm.m.LinkFlaps {
				devs = append(devs, dev)
			}
			sort.Strings(devs)
			for _, dev := range devs {
				if n := nm.m.LinkFlaps[dev]; n >= 2 && !virtualNIC(dev) {
					add(name, kernelKind{"network", findings.Medium, "network link of " + dev + " going down and up", "its network connection dropping"},
						int(n+0.5), "", "node-exporter")
				}
			}
		}
	}

	nodes := make([]string, 0, len(hits))
	for n := range hits {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	var out []*findings.Finding
	for _, node := range nodes {
		list := make([]*kernelHit, 0, len(hits[node]))
		for _, h := range hits[node] {
			list = append(list, h)
		}
		// Worst first, then the most frequent.
		sort.Slice(list, func(i, j int) bool {
			if list[i].kind.sev != list[j].kind.sev {
				return list[i].kind.sev > list[j].kind.sev
			}
			if list[i].count != list[j].count {
				return list[i].count > list[j].count
			}
			return list[i].kind.what < list[j].kind.what
		})
		out = append(out, kernelFinding(c, node, list))
	}
	return out
}

// containerOOMs counts the containers on a node that were stopped at their
// own memory limit within the window.
func containerOOMs(c *Context, node string, window time.Duration) int {
	n := 0
	for _, p := range c.S.PodsOnNode(node) {
		for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
			for _, t := range []*corev1.ContainerStateTerminated{cs.State.Terminated, cs.LastTerminationState.Terminated} {
				if t != nil && t.Reason == "OOMKilled" && c.S.Now.Sub(t.FinishedAt.Time) <= window {
					n++
				}
			}
		}
	}
	return n
}

func kernelFinding(c *Context, node string, list []*kernelHit) *findings.Finding {
	worst := list[0]
	f := c.newFinding(worst.kind.sev, findings.ObjectRef{Kind: "Node", Name: node})
	f.System = true
	f.Links.Nodes = []string{node}
	f.Links.Cause = worst.kind.topic
	var parts, plain []string
	topics := map[string]bool{}
	for _, h := range list {
		parts = append(parts, fmt.Sprintf("%s (%d)", h.kind.what, h.count))
		if !contains(plain, h.kind.plain) {
			plain = append(plain, h.kind.plain)
		}
		topics[h.kind.topic] = true
		value := fmt.Sprintf("%d in the last %s, from %s", h.count, ifStr(h.from == "node-exporter", "15 minutes", "hour"), h.from)
		if h.example != "" {
			value += "; for example: " + h.example
		}
		f.AddFact(capitalize(h.kind.what), value)
	}
	f.Title = fmt.Sprintf("Kernel errors on %s: %s", node, strings.Join(parts, ", "))
	f.Summary = fmt.Sprintf("The kernel of node %s reports %s. These come before the apps fail: a disk or the storage under a VM failing, memory running out outside the apps' limits, or the network link dropping.", node, strings.Join(parts, ", "))

	journal := "sudo journalctl -k --since '1 hour ago' --no-pager"
	switch worst.kind.topic {
	case "disk":
		f.Remedy.LikelyCause = "The disk, or the storage under the virtual machine, fails or stalls: I/O errors, filesystem errors and hung tasks all come from the storage not answering in time."
		f.AddStep(findings.Step{Text: "On the node: read the kernel's messages about the disks", Plain: "If you can log in to it, read what the system says about its disks.",
			Command: journal + " | grep -iE 'I/O error|blk_update|EXT4-fs|XFS|blocked for more than|remounting' | tail -n 50", Host: node})
		f.AddStep(findings.Step{Text: "Check the disks' health (physical disks), or the datastore's latency and errors (VMs)",
			Plain:   "Ask whoever runs your servers to check this server's disk, or the storage behind it if it is a virtual machine.",
			Command: "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT\nsudo smartctl -H /dev/sda", Host: node})
		f.AddStep(findings.Step{Text: "If the errors go on, drain the node before its filesystem goes read-only, and move its volumes' data",
			Command: fmt.Sprintf("kubectl cordon %s\nkubectl drain %s --ignore-daemonsets --delete-emptydir-data", node, node)})
	case "memory":
		f.Remedy.LikelyCause = "The node ran out of memory: something outside the apps' memory limits (a system service, k0s itself, or apps without limits) used it up, or a memory chip fails."
		f.AddStep(findings.Step{Text: "On the node: see what the kernel killed, and what uses the memory", Plain: "If you can log in to it, read which programs were stopped for lack of memory.",
			Command: journal + " | grep -iE 'out of memory|killed process|memory read error|EDAC' | tail -n 30\nps aux --sort=-rss | head -n 15", Host: node})
		f.AddStep(findings.Step{Text: "Give the apps on it memory limits, or move some away (see the apps without limits under Hygiene)",
			Command: "kubectl top pods -A --sort-by=memory | head -n 15"})
	case "network":
		f.Remedy.LikelyCause = "The node's network link goes down and up: a cable, switch port, NIC or the virtual network of the VM host."
		f.AddStep(findings.Step{Text: "On the node: see the link's state and its errors", Plain: "Ask whoever runs your servers to check this server's network connection.",
			Command: "ip -s link\n" + journal + " | grep -iE 'link is (up|down)|NIC Link|carrier' | tail -n 30", Host: node})
	default:
		f.Remedy.LikelyCause = "A kernel bug or a driver problem: the kernel reported an error in itself."
		f.AddStep(findings.Step{Text: "On the node: read the kernel's report", Plain: "If you can log in to it, read what the system reported, and send it to your support team.",
			Command: journal + " | grep -iE -A20 'Oops|BUG:|Call Trace' | head -n 80", Host: node})
		f.AddStep(findings.Step{Text: "Update the kernel and its drivers to the distribution's latest; reboot the node during a maintenance window"})
	}
	f.Plain = findings.PlainText{
		Title:        fmt.Sprintf("The server %s reports %s", node, worst.kind.plain),
		WhatHappened: fmt.Sprintf("Its operating system reports %s.", strings.Join(plain, ", ")),
		Why:          kernelWhy(worst.kind.topic),
		WhatToDo:     "Send the report for support to whoever runs your servers: they should check this server (steps below) before its apps start to fail.",
	}
	if len(topics) > 1 {
		f.Plain.Why += " More than one kind of error at once often means the server itself is in trouble."
	}
	return f
}

func kernelWhy(topic string) string {
	switch topic {
	case "disk":
		return "Its disk, or the storage behind it, fails or answers far too slowly. Apps on it can freeze, and its files can become read-only."
	case "memory":
		return "Its memory ran out, or a memory chip fails, so the system had to stop programs."
	case "network":
		return "Its network connection keeps dropping, so apps on it lose their connections."
	}
	return "The operating system ran into an error in itself, which can make the server unstable."
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
