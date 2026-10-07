package report

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/yaml"

	"k0s_monitor/internal/remedy"
	"k0s_monitor/internal/snapshot"
)

func table(header string, rows [][]string) string {
	var b bytes.Buffer
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, header)
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	tw.Flush()
	return b.String()
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func age(now, t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := now.Sub(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// nodeRoles reads node-role.kubernetes.io/<role> labels.
func nodeRoles(n *corev1.Node) string {
	var roles []string
	for k := range n.Labels {
		if r, ok := strings.CutPrefix(k, "node-role.kubernetes.io/"); ok && r != "" {
			roles = append(roles, r)
		}
	}
	sort.Strings(roles)
	return strings.Join(roles, ",")
}

func nodeAddress(n *corev1.Node, t corev1.NodeAddressType) string {
	for _, a := range n.Status.Addresses {
		if a.Type == t {
			return a.Address
		}
	}
	return ""
}

func gib(q resource.Quantity) string {
	return fmt.Sprintf("%.1fGi", float64(q.Value())/(1<<30))
}

// nodesText lists the nodes like `kubectl get nodes -o wide`, with their
// capacity, the conditions that aren't normal and their taints.
func nodesText(s *snapshot.Snapshot) string {
	var rows [][]string
	var details []string
	for _, n := range s.Nodes {
		status := "NotReady"
		var odd []string
		for _, c := range n.Status.Conditions {
			switch {
			case c.Type == corev1.NodeReady:
				if c.Status == corev1.ConditionTrue {
					status = "Ready"
				} else {
					odd = append(odd, fmt.Sprintf("Ready=%s (%s: %s, since %s)", c.Status, c.Reason, oneLine(c.Message), c.LastTransitionTime.UTC().Format(time.RFC3339)))
				}
			case c.Status == corev1.ConditionTrue:
				odd = append(odd, fmt.Sprintf("%s (%s: %s, since %s)", c.Type, c.Reason, oneLine(c.Message), c.LastTransitionTime.UTC().Format(time.RFC3339)))
			}
		}
		if n.Spec.Unschedulable {
			status += ",SchedulingDisabled"
		}
		ni := n.Status.NodeInfo
		rows = append(rows, []string{n.Name, status, dash(nodeRoles(n)), age(s.Now, n.CreationTimestamp.Time), dash(ni.KubeletVersion),
			dash(nodeAddress(n, corev1.NodeInternalIP)), dash(ni.OSImage), dash(ni.KernelVersion), dash(ni.ContainerRuntimeVersion),
			n.Status.Capacity.Cpu().String(), gib(*n.Status.Capacity.Memory()), fmt.Sprint(len(s.PodsOnNode(n.Name)))})
		var taints []string
		for _, t := range n.Spec.Taints {
			taints = append(taints, t.ToString())
		}
		if len(odd) > 0 || len(taints) > 0 {
			d := n.Name + ":\n"
			for _, o := range odd {
				d += "  condition: " + o + "\n"
			}
			for _, t := range taints {
				d += "  taint: " + t + "\n"
			}
			details = append(details, d)
		}
	}
	out := table("NAME\tSTATUS\tROLES\tAGE\tVERSION\tINTERNAL-IP\tOS-IMAGE\tKERNEL\tRUNTIME\tCPU\tMEMORY\tPODS", rows)
	if len(details) > 0 {
		out += "\nConditions that aren't normal, and taints\n\n" + strings.Join(details, "\n")
	}
	if !s.Has(snapshot.KindNode) {
		out = "k0s-monitor can't read the nodes.\n"
	}
	return out
}

// eventsText lists the warning events k0s-monitor knows, newest first.
func eventsText(s *snapshot.Snapshot) string {
	var evs []*corev1.Event
	for _, e := range s.Events {
		if e.Type == corev1.EventTypeWarning {
			evs = append(evs, e)
		}
	}
	if len(evs) == 0 {
		return ""
	}
	last := func(e *corev1.Event) time.Time {
		switch {
		case !e.LastTimestamp.IsZero():
			return e.LastTimestamp.Time
		case !e.EventTime.IsZero():
			return e.EventTime.Time
		}
		return e.CreationTimestamp.Time
	}
	sort.SliceStable(evs, func(i, j int) bool { return last(evs[i]).After(last(evs[j])) })
	cut := 0
	if len(evs) > maxEvents {
		cut = len(evs) - maxEvents
		evs = evs[:maxEvents]
	}
	var rows [][]string
	for _, e := range evs {
		obj := strings.ToLower(e.InvolvedObject.Kind) + "/" + e.InvolvedObject.Name
		if e.InvolvedObject.Namespace != "" {
			obj = e.InvolvedObject.Namespace + "/" + obj
		}
		rows = append(rows, []string{last(e).UTC().Format("2006-01-02 15:04:05"), e.Reason, obj, fmt.Sprint(max(e.Count, 1)), remedy.RedactText(oneLine(e.Message))})
	}
	out := table("LAST SEEN (UTC)\tREASON\tOBJECT\tCOUNT\tMESSAGE", rows)
	if cut > 0 {
		out += fmt.Sprintf("\n%d older warning events are left out.\n", cut)
	}
	return out
}

// k0sText describes the k0s control plane as k0s-monitor sees it.
func k0sText(s *snapshot.Snapshot) string {
	var b bytes.Buffer
	if v, from, ok := s.ExpectedVersion(); ok {
		fmt.Fprintf(&b, "Expected k0s version: %s (%s)\n\n", v.Raw, dash(from))
	}
	var vs [][]string
	for _, nv := range s.K0sVersions() {
		role := "worker"
		if nv.Controller {
			role = "controller"
		}
		vs = append(vs, []string{nv.Name, role, nv.Version.Raw})
	}
	if len(vs) > 0 {
		b.WriteString("k0s versions\n\n")
		b.WriteString(table("NODE\tROLE\tK0S", vs))
		b.WriteString("\n")
	}
	cp := s.ControlPlane
	if cp == nil {
		b.WriteString("The controllers couldn't be asked about their health.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "Address clients use: %s\n", dash(cp.Server))
	if f := s.Fallback; f != nil {
		fmt.Fprintf(&b, "That address doesn't answer (%s), so k0s-monitor reads the cluster through controller %s at %s since %s.\n",
			f.Error, f.Controller, f.Address, f.Since.UTC().Format(time.RFC3339))
	}
	b.WriteString("\nControllers\n\n")
	var rows [][]string
	for _, c := range cp.Controllers {
		state := "ok"
		switch {
		case !c.Reached:
			state = "no answer: " + oneLine(c.Error)
		case len(c.Failing) > 0:
			state = "failing: " + strings.Join(c.FailingNames(), ", ")
		}
		cert := "-"
		if c.Cert != nil {
			cert = c.Cert.NotAfter.UTC().Format("2006-01-02")
		}
		rows = append(rows, []string{dash(c.Name), dash(c.Address), strings.Join(c.From, ","), dash(c.Version), dash(c.K0sVersion), cert, state})
	}
	b.WriteString(table("NAME\tADDRESS\tFOUND IN\tKUBERNETES\tK0S\tCERT EXPIRES\tHEALTH", rows))
	for _, c := range cp.Controllers {
		for _, ch := range append(append([]snapshot.Check{}, c.Failing...), c.LiveFailing...) {
			fmt.Fprintf(&b, "  %s: %s %s\n", c.Label(), ch.Name, oneLine(ch.Message))
		}
	}
	if cp.EtcdDBBytes > 0 {
		fmt.Fprintf(&b, "\netcd database: %.0f MiB", cp.EtcdDBBytes/(1<<20))
		if cp.EtcdQuotaBytes > 0 {
			fmt.Fprintf(&b, " of a %.0f MiB quota", cp.EtcdQuotaBytes/(1<<20))
		}
		b.WriteString("\n")
	}
	if len(cp.Plans) > 0 {
		b.WriteString("\nUpdates (Autopilot plans)\n\n")
		for _, p := range cp.Plans {
			fmt.Fprintf(&b, "%s: %s, created %s\n", p.Name, p.State, p.Created.UTC().Format(time.RFC3339))
			for _, c := range p.Commands {
				fmt.Fprintf(&b, "  %s %s: %s\n", c.Kind, c.Version, c.State)
				for _, t := range c.Targets {
					fmt.Fprintf(&b, "    %s: %s\n", t.Name, t.State)
				}
			}
		}
	}
	if cp.ChartsRead {
		b.WriteString("\nAdd-ons (Helm charts)\n\n")
		if len(cp.Charts) == 0 {
			b.WriteString("none\n")
		} else {
			var rows [][]string
			for _, c := range cp.Charts {
				rows = append(rows, []string{c.Addon(), c.ChartName, dash(c.Version), dash(c.Installed), dash(c.TargetNamespace), dash(remedy.RedactText(oneLine(c.Error)))})
			}
			b.WriteString(table("NAME\tCHART\tWANTED\tINSTALLED\tNAMESPACE\tERROR", rows))
		}
	}
	return b.String()
}

// k0sConfigYAML is k0s's ClusterConfig, which k0s-monitor read with its
// secret-looking values masked, or nil.
func k0sConfigYAML(s *snapshot.Snapshot) []byte {
	cp := s.ControlPlane
	if cp == nil || cp.Config == nil {
		return nil
	}
	out, err := yaml.Marshal(map[string]any{"apiVersion": "k0s.k0sproject.io/v1beta1", "kind": "ClusterConfig", "spec": cp.Config.Spec})
	if err != nil {
		return nil
	}
	return append([]byte("# From: "+cp.Config.From+". Secret-looking values are hidden.\n"), out...)
}
