// Package alerts links the alerts that fire in a cluster's Prometheus to
// the problems k0s-monitor finds (plan sections 6.1 and 17, M5): an alert
// about a pod, an app, a volume claim, a node or a controller shows on the
// problems about the same object.
package alerts

import (
	"net"
	"strings"
	"unicode"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// workloadLabels are the labels kube-state-metrics and the usual alert
// rules use to name an app, with the kind each names.
var workloadLabels = []struct{ label, kind string }{
	{"deployment", "Deployment"},
	{"statefulset", "StatefulSet"},
	{"daemonset", "DaemonSet"},
	{"cronjob", "CronJob"},
	{"job_name", "Job"},
	{"replicaset", "ReplicaSet"},
	{"horizontalpodautoscaler", "HorizontalPodAutoscaler"},
}

// Objects returns what an alert is about, from its labels: a pod and its
// app, an app, a volume claim, a node, a controller, a Service or a
// namespace, in that order of preference. Only the most specific kind
// counts: a pod's alert that also names the node it runs on is about the
// pod. The first object is the one to show.
func Objects(a snapshot.Alert, s *snapshot.Snapshot) []findings.ObjectRef {
	l := a.Labels
	ns := first(l, "namespace", "exported_namespace")
	if FromHostExporter(l) {
		// The labels name the exporter, which describes its host.
		if ref, ok := exporterHost(s, l, ns); ok {
			return []findings.ObjectRef{ref}
		}
		return nil
	}
	if pod := first(l, "pod", "exported_pod", "pod_name"); ns != "" && pod != "" {
		out := []findings.ObjectRef{{Kind: "Pod", Namespace: ns, Name: pod}}
		if w, ok := podOwner(s, ns, pod); ok {
			out = append(out, w)
		}
		return out
	}
	if ns != "" {
		var out []findings.ObjectRef
		for _, w := range workloadLabels {
			if name := l[w.label]; name != "" {
				ref := findings.ObjectRef{Kind: w.kind, Namespace: ns, Name: name}
				out = append(out, ref)
				if w.kind == "ReplicaSet" {
					if d, ok := deploymentOf(s, ns, name); ok {
						out = append(out, d)
					}
				}
			}
		}
		if len(out) > 0 {
			return out
		}
		if pvc := l["persistentvolumeclaim"]; pvc != "" {
			return []findings.ObjectRef{{Kind: "PersistentVolumeClaim", Namespace: ns, Name: pvc}}
		}
	}
	if node := first(l, "node", "exported_node", "kubernetes_node"); node != "" && (s == nil || s.Node(node) != nil) {
		return []findings.ObjectRef{{Kind: "Node", Name: node}}
	}
	if inst := l["instance"]; inst != "" && ns == "" {
		if ref, ok := hostOf(s, inst); ok {
			return []findings.ObjectRef{ref}
		}
	}
	if svc := l["service"]; ns != "" && svc != "" {
		return []findings.ObjectRef{{Kind: "Service", Namespace: ns, Name: svc}}
	}
	if ns != "" {
		return []findings.ObjectRef{{Kind: "Namespace", Name: ns}}
	}
	return nil
}

// Link adds every firing alert to the problems about its objects, and
// returns the alerts that match none. Good-practice suggestions get no
// alerts: they aren't problems.
func Link(fs []*findings.Finding, s *snapshot.Snapshot) (unmatched []snapshot.Alert) {
	if s == nil || s.Metrics == nil {
		return nil
	}
	for _, a := range s.Metrics.Alerts {
		objs := Objects(a, s)
		topic := TopicOf(a)
		matched := false
		for _, f := range fs {
			if f.IsHygiene() || !about(f, objs) {
				continue
			}
			// A server's alert joins the problems about the same thing on
			// that server: a disk alert, its disk problems.
			if isServer(f.Resource) && topic != "" && findingTopic(f) != topic {
				continue
			}
			matched = true
			f.Alerts = append(f.Alerts, refOf(a, objs))
		}
		if !matched {
			unmatched = append(unmatched, a)
		}
	}
	return unmatched
}

func refOf(a snapshot.Alert, objs []findings.ObjectRef) findings.Alert {
	r := findings.Alert{ID: a.ID(), Name: a.Name, Severity: a.Severity, Summary: a.Text(), Runbook: a.Runbook}
	if !a.Since.IsZero() {
		t := a.Since
		r.Since = &t
	}
	if len(objs) > 0 {
		r.About = objs[0]
	}
	return r
}

// about reports whether a finding is about one of the objects: its own
// object, the ones it affects, or the apps and claims it is linked to.
// The nodes it is merely linked to don't count: a node's alert belongs
// to the node's own problem.
func about(f *findings.Finding, objs []findings.ObjectRef) bool {
	for _, o := range objs {
		if o == f.Resource {
			return true
		}
		for _, r := range f.Affected {
			if o == r {
				return true
			}
		}
		for _, r := range f.Links.Workloads {
			if o == r {
				return true
			}
		}
		for _, r := range f.Links.Claims {
			if o == r {
				return true
			}
		}
	}
	return false
}

// Topics of a server's alerts and problems.
const (
	TopicDisk    = "disk"
	TopicMemory  = "memory"
	TopicCPU     = "cpu"
	TopicClock   = "clock"
	TopicNetwork = "network"
	TopicDown    = "down"
)

// topicWords say what a server's alert is about, by the words of its name
// and labels; the first topic that matches wins.
var topicWords = []struct {
	topic string
	words []string
}{
	{TopicClock, []string{"clock", "time", "ntp", "timex", "synchronising", "synchronizing", "chrony"}},
	{TopicDisk, []string{"disk", "io", "filesystem", "fs", "inode", "inodes", "device", "mountpoint", "space", "storage", "volume", "readonly"}},
	{TopicMemory, []string{"memory", "mem", "oom", "swap", "oomkill"}},
	{TopicCPU, []string{"cpu", "steal", "load", "throttling", "throttled"}},
	{TopicNetwork, []string{"network", "nic", "carrier", "interface", "conntrack", "link", "bond", "receive", "transmit"}},
	{TopicDown, []string{"down", "unreachable", "notready", "ready", "kubelet", "systemd", "service", "k0s", "reboot", "boot"}},
}

// TopicOf says what a server's alert is about: disk, memory, CPU, clock,
// network or the server being down; "" when it can't tell.
func TopicOf(a snapshot.Alert) string {
	words := map[string]bool{}
	for _, w := range splitWords(a.Name) {
		words[w] = true
	}
	for _, k := range []string{"device", "mountpoint", "fstype"} {
		if a.Labels[k] != "" && !strings.HasPrefix(strings.ToLower(a.Labels["device"]), "eth") {
			words["disk"] = true
		}
	}
	for _, t := range topicWords {
		for _, w := range t.words {
			if words[w] {
				return t.topic
			}
		}
	}
	return ""
}

// splitWords splits CamelCase, snake_case and dashed names into lower-case
// words: "NodeDiskIOSaturation" is node, disk, io, saturation.
func splitWords(s string) []string {
	var out []string
	var cur []rune
	rs := []rune(s)
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for i, r := range rs {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
			continue
		case unicode.IsUpper(r) && len(cur) > 0:
			prevLower := unicode.IsLower(rs[i-1])
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if prevLower || nextLower {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return out
}

// ruleTopics are the topics of the problems about a server.
var ruleTopics = map[string]string{
	"node.fs-high": TopicDisk, "node.inodes": TopicDisk, "vm.iowait": TopicDisk, "vm.host-fs": TopicDisk,
	"vm.memory": TopicMemory, "node.overcommit": TopicMemory,
	"vm.cpu-steal": TopicCPU, "node.saturation": TopicCPU,
	"vm.clock-skew":            TopicClock,
	"node.network-unavailable": TopicNetwork,
	"node.not-ready":           TopicDown, "vm.service-down": TopicDown, "vm.reboot": TopicDown,
	"controllers.count": TopicDown, "apiserver.readyz": TopicDown,
}

func findingTopic(f *findings.Finding) string {
	if f.RuleID == "node.pressure" || f.RuleID == "vm.kernel-errors" {
		switch f.Links.Cause {
		case "disk":
			return TopicDisk
		case "memory":
			return TopicMemory
		case "network":
			return TopicNetwork
		}
	}
	return ruleTopics[f.RuleID]
}

func isServer(r findings.ObjectRef) bool {
	return r.Kind == "Node" || r.Kind == "Controller" || r.Kind == "Host"
}

// FromHostExporter reports whether an alert's series come from an exporter of
// its host, such as node-exporter: then its pod, namespace and service
// labels name the exporter Prometheus scraped, not what the alert is
// about, which is the host.
func FromHostExporter(l map[string]string) bool {
	for _, k := range []string{"job", "container", "service", "endpoint", "pod"} {
		v := strings.ToLower(l[k])
		if strings.Contains(v, "node-exporter") || strings.Contains(v, "node_exporter") {
			return true
		}
	}
	return false
}

// exporterHost finds the host of an exporter's alert: its node label, the
// address it was scraped at, or the node its pod runs on.
func exporterHost(s *snapshot.Snapshot, l map[string]string, ns string) (findings.ObjectRef, bool) {
	if node := first(l, "node", "nodename", "kubernetes_node"); node != "" && (s == nil || s.Node(node) != nil) {
		return findings.ObjectRef{Kind: "Node", Name: node}, true
	}
	if inst := l["instance"]; inst != "" {
		if ref, ok := hostOf(s, inst); ok {
			return ref, true
		}
	}
	if pod := first(l, "pod", "exported_pod"); s != nil && pod != "" {
		for _, p := range s.Pods {
			if p.Name == pod && (ns == "" || p.Namespace == ns) && p.Spec.NodeName != "" {
				return findings.ObjectRef{Kind: "Node", Name: p.Spec.NodeName}, true
			}
		}
	}
	return findings.ObjectRef{}, false
}

func first(l map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := l[k]; v != "" {
			return v
		}
	}
	return ""
}

// podOwner returns the app a pod belongs to.
func podOwner(s *snapshot.Snapshot, ns, name string) (findings.ObjectRef, bool) {
	if s == nil {
		return findings.ObjectRef{}, false
	}
	for _, p := range s.Pods {
		if p.Namespace == ns && p.Name == name {
			w := s.WorkloadOf(p)
			if w.Kind == "Pod" {
				return findings.ObjectRef{}, false
			}
			return findings.ObjectRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}, true
		}
	}
	return findings.ObjectRef{}, false
}

// deploymentOf returns the Deployment that owns a ReplicaSet.
func deploymentOf(s *snapshot.Snapshot, ns, rs string) (findings.ObjectRef, bool) {
	if s == nil {
		return findings.ObjectRef{}, false
	}
	for _, r := range s.ReplicaSets {
		if r.Namespace == ns && r.Name == rs {
			if o := metav1.GetControllerOf(r); o != nil && o.Kind == "Deployment" {
				return findings.ObjectRef{Kind: "Deployment", Namespace: ns, Name: o.Name}, true
			}
		}
	}
	return findings.ObjectRef{}, false
}

// hostOf finds the node or controller an instance label points at: the
// node-exporter target k0s-monitor matched to a node, a node's address or
// name, or a controller's address.
func hostOf(s *snapshot.Snapshot, instance string) (findings.ObjectRef, bool) {
	if s == nil {
		return findings.ObjectRef{}, false
	}
	if m := s.Metrics; m != nil {
		for name, n := range m.Nodes {
			if n.Instance == instance {
				return findings.ObjectRef{Kind: "Node", Name: name}, true
			}
		}
	}
	host := instance
	if h, _, err := net.SplitHostPort(instance); err == nil {
		host = strings.Trim(h, "[]")
	}
	for _, n := range s.Nodes {
		if n.Name == host || hasAddress(n, host) {
			return findings.ObjectRef{Kind: "Node", Name: n.Name}, true
		}
	}
	if cp := s.ControlPlane; cp != nil {
		for _, c := range cp.Controllers {
			if c.Host() == host || c.Name == host {
				return findings.ObjectRef{Kind: "Controller", Name: c.Label()}, true
			}
		}
	}
	return findings.ObjectRef{}, false
}

func hasAddress(n *corev1.Node, host string) bool {
	for _, a := range n.Status.Addresses {
		if a.Address == host {
			return true
		}
	}
	return false
}
