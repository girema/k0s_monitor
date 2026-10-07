package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// The k0s system add-ons that run on every node as DaemonSets in
// kube-system: the network plugin (kube-router by default, or Calico),
// konnectivity-agent, and kube-proxy.

// addonGap is a node where an add-on's pod is missing or not ready.
type addonGap struct {
	node  string
	pod   *corev1.Pod
	state string
	since time.Time
}

// addonGaps lists the nodes where the daemon set should run a ready pod
// and hasn't for c.T.NotReadyAfter.
func addonGaps(c *Context, ds *appsv1.DaemonSet) []addonGap {
	byNode := map[string]*corev1.Pod{}
	for _, p := range c.S.PodsOf(snapshot.Workload{Kind: "DaemonSet", Namespace: ds.Namespace, Name: ds.Name}) {
		if snapshot.IsPodTerminal(p) || p.Spec.NodeName == "" {
			continue
		}
		if cur := byNode[p.Spec.NodeName]; cur == nil || cur.DeletionTimestamp != nil {
			byNode[p.Spec.NodeName] = p
		}
	}
	var gaps []addonGap
	for _, n := range c.S.Nodes {
		if !snapshot.DaemonSetShouldRun(ds, n) {
			continue
		}
		p := byNode[n.Name]
		if p == nil {
			since := n.CreationTimestamp.Time
			if ds.CreationTimestamp.After(since) {
				since = ds.CreationTimestamp.Time
			}
			if c.S.Now.Sub(since) >= c.T.NotReadyAfter.D() {
				gaps = append(gaps, addonGap{node: n.Name, state: "no pod", since: since})
			}
			continue
		}
		if snapshot.IsPodReady(p) {
			continue
		}
		since := p.CreationTimestamp.Time
		if cond := snapshot.PodCondition(p, corev1.PodReady); cond != nil && cond.LastTransitionTime.After(since) {
			since = cond.LastTransitionTime.Time
		}
		if c.S.Now.Sub(since) >= c.T.NotReadyAfter.D() {
			gaps = append(gaps, addonGap{node: n.Name, pod: p, state: addonPodState(p), since: since})
		}
	}
	return gaps
}

func addonPodState(p *corev1.Pod) string {
	s := podStateText(p)
	if s == string(corev1.PodRunning) {
		return "running, not ready"
	}
	return s
}

// addonFinding fills what the three add-on rules share.
func addonFinding(c *Context, ds *appsv1.DaemonSet, sev findings.Severity, gaps []addonGap) *findings.Finding {
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].node < gaps[j].node })
	ref := findings.ObjectRef{Kind: "DaemonSet", Namespace: ds.Namespace, Name: ds.Name}
	f := c.newFinding(sev, ref)
	f.System = true
	f.Links.Workloads = []findings.ObjectRef{ref}
	expected := 0
	for _, n := range c.S.Nodes {
		if snapshot.DaemonSetShouldRun(ds, n) {
			expected++
		}
	}
	since := gaps[0].since
	var states, nodes []string
	var pods []*corev1.Pod
	affected := 0
	for _, g := range gaps {
		f.Links.Nodes = append(f.Links.Nodes, g.node)
		nodes = append(nodes, g.node)
		states = append(states, g.node+": "+g.state)
		if g.pod != nil {
			pods = append(pods, g.pod)
		}
		if g.since.Before(since) {
			since = g.since
		}
		for _, p := range c.S.PodsOnNode(g.node) {
			if !snapshot.IsPodTerminal(p) {
				affected++
			}
		}
	}
	f.Since = &since
	f.Impact.ClusterWide = len(gaps) == expected
	f.Impact.AffectedPods = affected
	f.Affected = podRefs(pods, 10)
	f.AddFact("Nodes", fmt.Sprintf("%d of %d: %s", len(gaps), expected, truncate(strings.Join(states, "; "), 300)))
	f.AddFact("Since", ago(c.S.Now.Sub(since))+" ago")
	f.AddFact("Pods on those nodes", fmt.Sprintf("%d", affected))
	return f
}

// whereText is "on worker-2" or "on 2 of 3 nodes".
func whereText(f *findings.Finding, plain bool) string {
	n := len(f.Links.Nodes)
	noun := "node"
	if plain {
		noun = "server"
	}
	if n == 1 {
		return fmt.Sprintf("on %s %s", noun, f.Links.Nodes[0])
	}
	if f.Impact.ClusterWide {
		return fmt.Sprintf("on all %d %ss", n, noun)
	}
	return fmt.Sprintf("on %d %ss", n, noun)
}

// addonSteps are the kubectl steps every add-on rule starts with.
func addonSteps(f *findings.Finding, ds *appsv1.DaemonSet, gaps []addonGap) {
	sel := selectorString(ds.Spec.Selector.MatchLabels)
	f.AddStep(findings.Step{Text: "See the pods and their nodes", Command: fmt.Sprintf("kubectl -n kube-system get pods -o wide -l %s", sel)})
	for _, g := range gaps {
		if g.pod != nil {
			f.AddStep(findings.Step{
				Text:    "Read the log and events of the pod on " + g.node,
				Command: fmt.Sprintf("kubectl -n kube-system logs %s --all-containers --tail=100\nkubectl -n kube-system describe pod %s", g.pod.Name, g.pod.Name),
			})
			return
		}
	}
	f.AddStep(findings.Step{Text: "See why the DaemonSet has no pod there", Command: fmt.Sprintf("kubectl -n kube-system describe ds %s", ds.Name)})
}

// ---------------------------------------------------------------------------
// X05 cni.unhealthy

var cniUnhealthyRule = Rule{
	ID: "cni.unhealthy", Code: "X05", Category: findings.Network,
	Needs: []snapshot.Kind{snapshot.KindDaemonSet, snapshot.KindPod, snapshot.KindNode},
	Eval:  evalCNIUnhealthy,
}

func evalCNIUnhealthy(c *Context) []*findings.Finding {
	var ds *appsv1.DaemonSet
	for _, name := range []string{"kube-router", "calico-node"} {
		if ds = c.S.DaemonSet("kube-system", name); ds != nil {
			break
		}
	}
	if ds == nil {
		return nil // a custom network plugin; pod.stuck-creating still reports its failures
	}
	gaps := addonGaps(c, ds)
	// Pods that can't get a network are proof too, even when the plugin's
	// own pod looks ready.
	have := map[string]bool{}
	for _, g := range gaps {
		have[g.node] = true
	}
	sandbox := ""
	for _, p := range c.S.Pods {
		since, ok := creatingSince(p)
		if !ok || c.S.Now.Sub(since) < c.T.PendingAfter.D() {
			continue
		}
		cc := classifyCreating(c, p)
		if cc.kind != "network" {
			continue
		}
		if sandbox == "" {
			sandbox = cc.msg
		}
		if !have[p.Spec.NodeName] {
			have[p.Spec.NodeName] = true
			gaps = append(gaps, addonGap{node: p.Spec.NodeName, state: "pods can't get a network", since: since})
		}
	}
	if len(gaps) == 0 {
		return nil
	}
	f := addonFinding(c, ds, findings.Critical, gaps)
	f.AddFact("Network error", truncate(sandbox, 300))
	where := whereText(f, false)
	f.Title = fmt.Sprintf("%s not working %s (%s)", ds.Name, where, gaps[0].state)
	f.Summary = fmt.Sprintf("The network plugin %s is not ready %s. Pods there can't reach other pods, and new pods there can't start.", ds.Name, where)
	f.Remedy.LikelyCause = fmt.Sprintf("The %s pod on the node is failing. Its log usually says why: a crash, a missing kernel module, or blocked traffic between nodes.", ds.Name)
	addonSteps(f, ds, gaps)
	f.AddStep(findings.Step{
		Text:    "Restart the network plugin's pod on the node; the DaemonSet creates a new one",
		Command: fmt.Sprintf("kubectl -n kube-system delete pod -l %s --field-selector spec.nodeName=%s", selectorString(ds.Spec.Selector.MatchLabels), f.Links.Nodes[0]),
	})
	f.Plain = findings.PlainText{
		Title:        "The network between apps doesn't work " + whereText(f, true),
		WhatHappened: fmt.Sprintf("The network component (%s) isn't working there, so apps on it can't reach other apps, and new apps can't start there.", ds.Name),
		Why:          "Its own part on that server has a problem. Its log usually says which.",
		WhatToDo:     "Look at the component's log (steps below), or send the report to your support team.",
	}
	return []*findings.Finding{f}
}

// ---------------------------------------------------------------------------
// X06 konnectivity.agent-down

var konnectivityDownRule = Rule{
	ID: "konnectivity.agent-down", Code: "X06", Category: findings.Network,
	Needs: []snapshot.Kind{snapshot.KindDaemonSet, snapshot.KindPod, snapshot.KindNode},
	Eval:  evalKonnectivityDown,
}

func evalKonnectivityDown(c *Context) []*findings.Finding {
	ds := c.S.DaemonSet("kube-system", "konnectivity-agent")
	if ds == nil {
		return nil // single-node k0s runs without konnectivity
	}
	gaps := addonGaps(c, ds)
	if len(gaps) == 0 {
		return nil
	}
	f := addonFinding(c, ds, findings.High, gaps)
	where := whereText(f, false)
	f.Title = fmt.Sprintf("konnectivity-agent down %s (%s): logs, exec and port-forward fail there", where, gaps[0].state)
	f.Summary = fmt.Sprintf("The konnectivity agent is not ready %s. The API server reaches kubelets through it, so logs, exec, port-forward and kubelet data fail for pods there. The pods themselves keep running.", where)
	f.Remedy.LikelyCause = "The agent can't connect to the controllers on port 8132, often because of a firewall, or its pod is failing."
	addonSteps(f, ds, gaps)
	f.AddStep(findings.Step{
		Text:    "On the node: check that the controllers' konnectivity port 8132 can be reached",
		Plain:   "Check that the server can reach the controllers on port 8132.",
		Command: "nc -vz <controller address> 8132",
		Host:    f.Links.Nodes[0],
	})
	f.Plain = findings.PlainText{
		Title:        "Logs and remote commands don't work " + whereText(f, true),
		WhatHappened: "The connection agent (konnectivity-agent) there isn't working, so the cluster can't reach the server for logs, commands and some health data. Apps there keep running.",
		Why:          "The agent can't connect to the controllers, most often because a firewall blocks port 8132.",
		WhatToDo:     "Check that the server can reach the controllers on port 8132, or send the report to your support team.",
	}
	return []*findings.Finding{f}
}

// ---------------------------------------------------------------------------
// X07 kube-proxy.unhealthy

var kubeProxyUnhealthyRule = Rule{
	ID: "kube-proxy.unhealthy", Code: "X07", Category: findings.Network,
	Needs: []snapshot.Kind{snapshot.KindDaemonSet, snapshot.KindPod, snapshot.KindNode},
	Eval:  evalKubeProxyUnhealthy,
}

func evalKubeProxyUnhealthy(c *Context) []*findings.Finding {
	ds := c.S.DaemonSet("kube-system", "kube-proxy")
	if ds == nil {
		return nil // kube-proxy may be replaced by the network plugin
	}
	gaps := addonGaps(c, ds)
	if len(gaps) == 0 {
		return nil
	}
	f := addonFinding(c, ds, findings.High, gaps)
	where := whereText(f, false)
	f.Title = fmt.Sprintf("kube-proxy not ready %s (%s)", where, gaps[0].state)
	f.Summary = fmt.Sprintf("kube-proxy is not ready %s. It programs the Service addresses on each node, so Service changes stop working there and new Services can't be reached.", where)
	f.Remedy.LikelyCause = "The kube-proxy pod is failing. Its log usually names the reason, for example missing iptables or IPVS support."
	addonSteps(f, ds, gaps)
	f.Plain = findings.PlainText{
		Title:        "Service addresses may not work " + whereText(f, true),
		WhatHappened: "The component that routes requests to services (kube-proxy) isn't working there, so apps on it may not reach other services.",
		Why:          "Its part on that server has a problem. Its log usually says which.",
		WhatToDo:     "Look at its log (steps below), or send the report to your support team.",
	}
	return []*findings.Finding{f}
}
