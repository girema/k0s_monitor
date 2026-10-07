// Package correlate folds symptoms under their root cause, so one incident
// shows up as one problem (plan section 8.2).
package correlate

import (
	"fmt"
	"sort"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/priority"
)

// podLevel are the rules that describe why pods of a workload fail.
var podLevel = map[string]bool{
	"pod.crashloop":      true,
	"pod.oomkilled":      true,
	"pod.image-pull":     true,
	"pod.config-error":   true,
	"pod.run-error":      true,
	"pod.unschedulable":  true,
	"pod.stuck-creating": true,
	"pod.not-ready":      true,
	"pod.probe-kills":    true,
}

// workloadLevel are the rules that report a workload with too few working
// pods, or a job whose runs fail. Their pods' problems explain them.
var workloadLevel = map[string]bool{
	"deploy.unavailable": true,
	"sts.unavailable":    true,
	"ds.unavailable":     true,
	"job.failed":         true,
	"cronjob.failing":    true,
}

// ReplicasDown marks a finding that, like the workload-level rules, says
// a workload has too few working pods (a product pack's replicas check):
// its pods' problems explain it.
const ReplicasDown = "replicas-down"

// onNode are the rules whose problem goes away with a node that is down:
// they fold under node.not-ready when every node they name is not ready.
var onNode = map[string]bool{
	"dns.unhealthy":           true,
	"pod.stuck-terminating":   true,
	"cni.unhealthy":           true,
	"konnectivity.agent-down": true,
	"kube-proxy.unhealthy":    true,
}

// systemComponent are the rules about a k0s system component, which fold
// under the problem of the component's own pods.
var systemComponent = map[string]bool{
	"dns.unhealthy":           true,
	"cni.unhealthy":           true,
	"konnectivity.agent-down": true,
	"kube-proxy.unhealthy":    true,
}

// Fold sets ParentID on findings that are symptoms of another finding and
// returns the findings ordered for display: each root cause by score, with
// its symptoms right after it. A root cause is as urgent as its worst
// symptom, so its score is raised to that symptom's score when lower.
// Findings must already be scored.
func Fold(fs []*findings.Finding) []*findings.Finding {
	for _, f := range fs {
		f.ParentID = ""
	}
	notReadyNodes := map[string]*findings.Finding{}
	sickNodes := map[string]*findings.Finding{}     // not ready or under pressure
	pressureNodes := map[string]*findings.Finding{} // under pressure
	cniNodes := map[string]*findings.Finding{}
	pendingClaims := map[findings.ObjectRef]*findings.Finding{}
	var noDefaultClass, apiServiceDown *findings.Finding
	// serviceDown is k0s's own service not running, by host name.
	serviceDown := map[string]*findings.Finding{}
	for _, f := range fs {
		switch f.RuleID {
		case "vm.service-down":
			serviceDown[f.Resource.Name] = f
		case "node.not-ready", "node.pressure":
			if f.RuleID == "node.not-ready" {
				notReadyNodes[f.Resource.Name] = f
			} else {
				pressureNodes[f.Resource.Name] = f
			}
			if cur := sickNodes[f.Resource.Name]; cur == nil || f.Score > cur.Score {
				sickNodes[f.Resource.Name] = f
			}
		case "cni.unhealthy":
			for _, n := range f.Links.Nodes {
				cniNodes[n] = f
			}
		case "pvc.pending":
			if !f.Links.WaitsForPod {
				pendingClaims[f.Resource] = f
			}
		case "sc.no-default":
			noDefaultClass = f
		case "apiservice.unavailable":
			if apiServiceDown == nil || f.Score > apiServiceDown.Score {
				apiServiceDown = f
			}
		}
	}
	// servesWorkloads finds the pod- or workload-level problem of the
	// workloads behind a finding (a Service, webhook or API).
	servesWorkloads := func(f *findings.Finding) *findings.Finding {
		return best(fs, f, func(c *findings.Finding) bool {
			if !(podLevel[c.RuleID] || workloadLevel[c.RuleID] || c.RuleID == "dns.unhealthy") {
				return false
			}
			for _, w := range f.Links.Workloads {
				if c.Resource == w || contains(c.Links.Workloads, w) {
					return true
				}
			}
			return false
		})
	}

	for _, f := range fs {
		var parent *findings.Finding
		switch {
		case workloadLevel[f.RuleID] || f.Links.Cause == ReplicasDown:
			parent = best(fs, f, func(c *findings.Finding) bool {
				return podLevel[c.RuleID] && c.Resource == f.Resource
			})
		case f.RuleID == "svc.no-endpoints":
			// A webhook or API that depends on the Service tells more.
			parent = best(fs, f, func(c *findings.Finding) bool {
				return (c.RuleID == "webhook.blocking" || c.RuleID == "apiservice.unavailable") && contains(c.Links.Services, f.Resource)
			})
			if parent == nil {
				parent = servesWorkloads(f)
			}
		case f.RuleID == "webhook.blocking" || f.RuleID == "apiservice.unavailable":
			parent = servesWorkloads(f)
		case f.RuleID == "pod.crashloop" && f.Links.Cause == "dns":
			// The app can't resolve names because the cluster's DNS is down.
			parent = best(fs, f, func(c *findings.Finding) bool { return c.RuleID == "dns.unhealthy" })
		case f.RuleID == "pod.crashloop" && f.Links.Cause == "dependency":
			// The app crashes because a service it needs doesn't answer:
			// that service's problem is the cause.
			parent = best(fs, f, func(c *findings.Finding) bool {
				if c.RuleID == "svc.no-endpoints" && contains(f.Links.Services, c.Resource) {
					return true
				}
				return (podLevel[c.RuleID] || workloadLevel[c.RuleID]) && contains(f.Links.DependsOn, c.Resource)
			})
		case f.RuleID == "pod.unschedulable":
			parent = firstClaim(f.Links.Claims, pendingClaims)
			if parent == nil {
				parent = allOn(f.Links.BlockedBy, sickNodes)
			}
		case f.RuleID == "pod.stuck-creating":
			switch f.Links.Cause {
			case "network":
				parent = allOn(f.Links.Nodes, cniNodes)
			case "storage":
				parent = best(fs, f, func(c *findings.Finding) bool {
					if c.RuleID != "volume.mount-failure" {
						return false
					}
					for _, a := range f.Affected {
						if contains(c.Affected, a) {
							return true
						}
					}
					return false
				})
				if parent == nil {
					parent = firstClaim(f.Links.Claims, pendingClaims)
				}
			}
		case systemComponent[f.RuleID]:
			// CoreDNS or the add-on is down because its own pods fail.
			parent = best(fs, f, func(c *findings.Finding) bool {
				return podLevel[c.RuleID] && c.Resource == f.Resource
			})
		case f.RuleID == "pvc.pending":
			switch {
			case f.Links.WaitsForPod:
				parent = best(fs, f, func(c *findings.Finding) bool {
					if c.RuleID != "pod.unschedulable" {
						return false
					}
					for _, w := range f.Links.Workloads {
						if c.Resource == w {
							return true
						}
					}
					return false
				})
			case f.Links.Cause == "no-default-class":
				parent = noDefaultClass
			}
		case f.RuleID == "pod.evicted":
			if f.Links.Cause == "node-pressure" {
				parent = allOn(f.Links.Nodes, pressureNodes)
			}
		case f.RuleID == "node.network-unavailable":
			parent = cniNodes[f.Resource.Name]
		case f.RuleID == "node.not-ready":
			// The node stopped responding because k0s stopped on it.
			parent = serviceDown[f.Resource.Name]
		case f.RuleID == "controllers.count" || f.RuleID == "apiserver.readyz":
			// The controller is down because k0s stopped on it.
			if p := serviceDown[f.Resource.Name]; p != nil && p.Links.Cause == "k0scontroller" {
				parent = p
			}
		case f.RuleID == "pvc.usage":
			// The forecast says the same, with when.
			parent = best(fs, f, func(c *findings.Finding) bool {
				return c.RuleID == "pvc.fill-forecast" && c.Resource == f.Resource
			})
		case f.RuleID == "node.pressure":
			// DiskPressure is what the full disk leads to.
			parent = best(fs, f, func(c *findings.Finding) bool {
				return c.RuleID == "node.fs-high" && c.Resource == f.Resource && f.Links.Cause == "disk"
			})
		case f.RuleID == "container.near-limit":
			parent = best(fs, f, func(c *findings.Finding) bool {
				return c.RuleID == "pod.oomkilled" && c.Resource == f.Resource
			})
		case f.RuleID == "hpa.no-metrics":
			if f.Links.Cause == "metrics-api" {
				parent = best(fs, f, func(c *findings.Finding) bool {
					return c.RuleID == "apiservice.unavailable" && c.Resource.Name == "v1beta1.metrics.k8s.io"
				})
			}
		case f.RuleID == "ns.stuck-terminating":
			if f.Links.Cause == "discovery" {
				parent = apiServiceDown
			}
		}
		if parent == nil && (podLevel[f.RuleID] || workloadLevel[f.RuleID] || onNode[f.RuleID]) {
			parent = allOn(f.Links.Nodes, notReadyNodes)
		}
		if parent != nil && parent != f {
			f.ParentID = parent.ID
		}
	}
	resolveRoots(fs)
	raiseRoots(fs)
	return order(fs)
}

// firstClaim returns the problem of the first claim that has one.
func firstClaim(claims []findings.ObjectRef, problems map[findings.ObjectRef]*findings.Finding) *findings.Finding {
	for _, claim := range claims {
		if p := problems[claim]; p != nil {
			return p
		}
	}
	return nil
}

// allOn returns the most urgent node problem when every one of the nodes
// has one, or nil.
func allOn(nodes []string, problems map[string]*findings.Finding) *findings.Finding {
	if len(nodes) == 0 {
		return nil
	}
	var parent *findings.Finding
	for _, n := range nodes {
		nf := problems[n]
		if nf == nil {
			return nil
		}
		if parent == nil || nf.Score > parent.Score {
			parent = nf
		}
	}
	return parent
}

// raiseRoots gives each root cause the score of its most urgent symptom,
// when that is higher: a full disk that stops CoreDNS is a cluster-wide
// outage, not a disk warning.
func raiseRoots(fs []*findings.Finding) {
	byID := map[string]*findings.Finding{}
	for _, f := range fs {
		byID[f.ID] = f
	}
	worst := map[string]*findings.Finding{}
	for _, f := range fs {
		root := byID[f.ParentID]
		if root == nil {
			continue
		}
		if w := worst[root.ID]; w == nil || f.Score > w.Score {
			worst[root.ID] = f
		}
	}
	for id, sym := range worst {
		root := byID[id]
		if sym.Score <= root.Score {
			continue
		}
		root.Score = sym.Score
		root.Priority = priority.Bucket(sym.Score)
		root.SetFact("Priority", fmt.Sprintf("raised to %s by %s: %s", root.Priority, sym.RuleID, sym.Title))
	}
}

func best(fs []*findings.Finding, self *findings.Finding, match func(*findings.Finding) bool) *findings.Finding {
	var out *findings.Finding
	for _, c := range fs {
		if c == self || !match(c) {
			continue
		}
		if out == nil || c.Score > out.Score || (c.Score == out.Score && c.ID < out.ID) {
			out = c
		}
	}
	return out
}

func contains(refs []findings.ObjectRef, r findings.ObjectRef) bool {
	for _, x := range refs {
		if x == r {
			return true
		}
	}
	return false
}

// resolveRoots points every symptom at the root of its chain and breaks
// cycles, so the display is never more than one level deep.
func resolveRoots(fs []*findings.Finding) {
	byID := map[string]*findings.Finding{}
	for _, f := range fs {
		byID[f.ID] = f
	}
	for _, f := range fs {
		seen := map[string]bool{f.ID: true}
		cur := f
		for cur.ParentID != "" {
			next := byID[cur.ParentID]
			if next == nil || seen[next.ID] {
				// Dangling or cyclic: stop at the last good link.
				if next != nil && seen[next.ID] {
					cur.ParentID = ""
				}
				break
			}
			seen[next.ID] = true
			cur = next
		}
		if cur != f {
			f.ParentID = cur.ID
		}
	}
}

// order sorts roots by score and puts each root's symptoms after it.
func order(fs []*findings.Finding) []*findings.Finding {
	var roots []*findings.Finding
	children := map[string][]*findings.Finding{}
	for _, f := range fs {
		if f.ParentID == "" {
			roots = append(roots, f)
		} else {
			children[f.ParentID] = append(children[f.ParentID], f)
		}
	}
	byScore := func(s []*findings.Finding) {
		sort.SliceStable(s, func(i, j int) bool {
			if s[i].Score != s[j].Score {
				return s[i].Score > s[j].Score
			}
			if s[i].RuleID != s[j].RuleID {
				return s[i].RuleID < s[j].RuleID
			}
			return s[i].Resource.String() < s[j].Resource.String()
		})
	}
	byScore(roots)
	out := make([]*findings.Finding, 0, len(fs))
	for _, r := range roots {
		out = append(out, r)
		kids := children[r.ID]
		byScore(kids)
		out = append(out, kids...)
	}
	return out
}
