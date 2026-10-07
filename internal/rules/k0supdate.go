package rules

import (
	"fmt"
	"sort"
	"strings"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// k0s versions and updates (plan section 10.2). The k0s version comes with
// the product and changes only through product updates, which may use
// k0s's Autopilot: so the steps say what to look at, and that the fix is a
// product update, never a manual upgrade.

// productUpdateStep says that the k0s version changes through a product
// update, not by hand.
func productUpdateStep(f *findings.Finding) {
	f.AddStep(findings.Step{Text: "The k0s version comes with your product: nodes are brought to its version through a product update, not by hand. Send the report to your support team.",
		Plain: "Send the report to your support team: they bring these servers to the right version with a product update"})
}

// ---------------------------------------------------------------------------
// C10 k0s.version-drift

var versionDriftRule = Rule{
	ID: "k0s.version-drift", Code: "C10", Category: findings.ControlPlane,
	Needs: []snapshot.Kind{snapshot.KindControlPlane, snapshot.KindNode},
	Eval:  evalVersionDrift,
}

// versionPlain is a version for people: 1.36.4 for v1.36.4+k0s.1.
func versionPlain(v snapshot.K0sVersion) string { return strings.TrimPrefix(v.Kubernetes(), "v") }

func evalVersionDrift(c *Context) []*findings.Finding {
	// While an update runs, nodes differ on purpose; C08 watches it.
	if c.S.ControlPlane == nil || c.S.UpdateRunning() {
		return nil
	}
	want, from, ok := c.S.ExpectedVersion()
	if !ok {
		return nil
	}
	all := c.S.K0sVersions()
	var off []snapshot.NodeVersion
	for _, nv := range all {
		if !nv.Version.Matches(want) {
			off = append(off, nv)
		}
	}
	if len(off) == 0 {
		return nil
	}
	versions, byVersion := groupVersions(off)

	f := c.newFinding(findings.Medium, findings.ObjectRef{Kind: "K0s", Name: "version"})
	f.System = true
	f.Impact.ClusterWide = true
	var names []string
	for _, nv := range off {
		names = append(names, nv.Name)
	}
	f.Links.Nodes = names
	f.AddFact("Expected", want.Raw+" ("+from+")")
	for _, v := range versions {
		f.AddFact("Runs "+v, strings.Join(byVersion[v], ", "))
	}
	f.AddFact("On the expected version", fmt.Sprintf("%d of %d", len(all)-len(off), len(all)))

	whole := len(off) == len(all)
	switch {
	case whole && len(versions) == 1:
		f.Title = fmt.Sprintf("Cluster runs k0s %s, not %s", versions[0], want.Raw)
		f.Summary = fmt.Sprintf("Every node runs k0s %s, but %s is expected (%s).", versions[0], want.Raw, from)
		f.Remedy.LikelyCause = "The cluster was updated, or installed with another version, and the expected version wasn't changed with it."
	case len(off) == 1:
		f.Title = fmt.Sprintf("%s runs k0s %s, not %s", off[0].Name, off[0].Version.Raw, want.Raw)
		f.Summary = fmt.Sprintf("%s runs k0s %s while %s is expected (%s). No update is running, so this is usually a manual change, a node installed with another version, or an update that didn't finish on it.", off[0].Name, off[0].Version.Raw, want.Raw, from)
	default:
		f.Title = fmt.Sprintf("%d of %d nodes run another k0s version than %s", len(off), len(all), want.Raw)
		f.Summary = fmt.Sprintf("%s is expected (%s), but %s. No update is running, so this is usually a manual change, nodes installed with another version, or an update that didn't finish.", want.Raw, from, versionList(versions, byVersion))
	}
	if f.Remedy.LikelyCause == "" {
		f.Remedy.LikelyCause = "An update that didn't reach every node, a node installed or reinstalled with another k0s version, or a manual change."
	}
	f.AddStep(findings.Step{Text: "See the version of every node and controller", Plain: "See which servers run which version",
		Command: "kubectl get nodes -o custom-columns=NODE:.metadata.name,VERSION:.status.nodeInfo.kubeletVersion\n" +
			"kubectl get controlnodes.autopilot.k0sproject.io -o custom-columns=CONTROLLER:.metadata.name,K0S:.status.k0sVersion"})
	f.AddStep(findings.Step{Text: "See the k0s installed on a node that differs", Plain: "On one of those servers, see the installed version",
		Command: "sudo k0s version", Host: off[0].Name})
	productUpdateStep(f)

	servers := fmt.Sprintf("%d servers run", len(off))
	who := fmt.Sprintf("%d of the cluster's %d servers run another version", len(off), len(all))
	if len(off) == 1 {
		servers = "The server " + off[0].Name + " runs"
		who = off[0].Name + " runs version " + versionPlain(off[0].Version)
	}
	f.Plain = findings.PlainText{
		Title:        servers + " another version of the cluster software",
		WhatHappened: fmt.Sprintf("%s, but every server should run %s.", who, versionPlain(want)),
		Why:          "Servers on different versions can behave differently, and some combinations aren't supported.",
		WhatToDo:     "Send the report to your support team: they bring these servers to the right version with a product update.",
	}
	if whole && len(versions) == 1 {
		f.Plain.Title = "The cluster runs another version of the cluster software than expected"
		f.Plain.WhatHappened = fmt.Sprintf("Every server runs version %s, but %s is expected.", strings.TrimPrefix(strings.SplitN(versions[0], "+", 2)[0], "v"), versionPlain(want))
		f.Plain.Why = "Either the cluster was updated and k0s-monitor's setting wasn't, or the update your product expects didn't happen."
		f.Plain.WhatToDo = "If the cluster was updated on purpose, change the expected version in the cluster's settings. Otherwise send the report to your support team."
	}
	return []*findings.Finding{f}
}

// groupVersions groups nodes by the version they run. A kubelet reports
// v1.36.4+k0s, a controller v1.36.4+k0s.1: those are one version, shown
// with its build.
func groupVersions(nvs []snapshot.NodeVersion) ([]string, map[string][]string) {
	type group struct {
		v     snapshot.K0sVersion
		names []string
	}
	var groups []*group
	for _, nv := range nvs {
		var g *group
		for _, x := range groups {
			if x.v.Matches(nv.Version) {
				g = x
				break
			}
		}
		if g == nil {
			g = &group{v: nv.Version}
			groups = append(groups, g)
		}
		if g.v.Build == "" && nv.Version.Build != "" {
			g.v = nv.Version
		}
		g.names = append(g.names, nv.Name)
	}
	byVersion := map[string][]string{}
	var versions []string
	for _, g := range groups {
		versions = append(versions, g.v.Raw)
		byVersion[g.v.Raw] = g.names
	}
	sort.Strings(versions)
	return versions, byVersion
}

func versionList(versions []string, byVersion map[string][]string) string {
	var parts []string
	for _, v := range versions {
		ns := byVersion[v]
		verb := "run"
		if len(ns) == 1 {
			verb = "runs"
		}
		parts = append(parts, fmt.Sprintf("%s %s %s", strings.Join(ns, ", "), verb, v))
	}
	return strings.Join(parts, "; ")
}

// ---------------------------------------------------------------------------
// C08 k0s.update-stuck

var updateStuckRule = Rule{
	ID: "k0s.update-stuck", Code: "C08", Category: findings.ControlPlane,
	Needs: []snapshot.Kind{snapshot.KindControlPlane},
	Eval:  evalUpdateStuck,
}

func targetsIn(p *snapshot.Plan, states ...string) []snapshot.PlanTarget {
	var out []snapshot.PlanTarget
	for _, t := range p.Targets() {
		for _, s := range states {
			if t.State == s {
				out = append(out, t)
			}
		}
	}
	return out
}

func targetNames(ts []snapshot.PlanTarget) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return out
}

func evalUpdateStuck(c *Context) []*findings.Finding {
	cp := c.S.ControlPlane
	if cp == nil {
		return nil
	}
	stuckAfter := c.T.UpdateStuckAfter.D()
	var out []*findings.Finding
	for _, p := range cp.Plans {
		what := "k0s update"
		if v := p.Version(); v != "" {
			what += " to " + v
		}
		plainWhat := "An update of the cluster software"
		if v, ok := snapshot.ParseK0sVersion(p.Version()); ok {
			plainWhat = "The update of the cluster software to version " + versionPlain(v)
		}
		var nodes []snapshot.PlanTarget
		var title, summary, cause, plainHappened string
		stuck := false
		since := p.Created
		switch p.State {
		case snapshot.PlanApplyFailed:
			nodes = targetsIn(p, snapshot.SignalApplyFailed)
			on := strings.Join(targetNames(nodes), ", ")
			if on == "" {
				on = "a node"
			}
			title = fmt.Sprintf("%s failed on %s", what, on)
			summary = fmt.Sprintf("Autopilot's plan %s couldn't apply the %s on %s. The update stopped there, so the nodes now run different versions.", p.Name, what, on)
			cause = "k0s on that node couldn't install or start the new version: a download that failed, a full disk, or a new version that doesn't start there."
			plainHappened = plainWhat + " failed on " + on + "."
		case snapshot.PlanIncompleteTargets:
			nodes = targetsIn(p, snapshot.SignalMissingNode, snapshot.SignalMissingPlatform)
			missing := strings.Join(targetNames(nodes), ", ")
			title = fmt.Sprintf("%s can't finish: nodes missing", what)
			summary = fmt.Sprintf("Autopilot's plan %s names nodes it can't update.", p.Name)
			if missing != "" {
				title = fmt.Sprintf("%s can't finish: %s missing", what, missing)
				summary = fmt.Sprintf("Autopilot's plan %s names %s, which it can't find or has no download for.", p.Name, missing)
			}
			cause = "The plan lists nodes that were removed or renamed, or has no download for their platform (for example arm64)."
			plainHappened = plainWhat + " names servers it can't find."
		case snapshot.PlanWarning:
			desc := planDescription(p)
			title = fmt.Sprintf("%s refused", what)
			summary = fmt.Sprintf("Autopilot didn't start plan %s.", p.Name)
			if desc != "" {
				title += ": " + desc
				summary = fmt.Sprintf("Autopilot didn't start plan %s: %s.", p.Name, desc)
			}
			cause = "Autopilot checks that the update is possible before it starts, for example that the new version isn't too far from the current one."
			plainHappened = plainWhat + " was refused before it started."
		case snapshot.PlanRestricted:
			title = fmt.Sprintf("%s not allowed on some nodes", what)
			summary = fmt.Sprintf("Autopilot's plan %s updates controllers or workers that Autopilot is set to leave alone, so it doesn't run.", p.Name)
			cause = "Autopilot is set to leave out controllers or workers, and the plan includes them."
			plainHappened = plainWhat + " isn't allowed to run on some servers."
		case "", snapshot.PlanSchedulable, snapshot.PlanSchedulableWait:
			if p.State == "" {
				if c.S.Now.Sub(p.Created) < stuckAfter {
					continue
				}
				title = fmt.Sprintf("%s hasn't started in %s", what, ago(c.S.Now.Sub(p.Created)))
				summary = fmt.Sprintf("Autopilot's plan %s was made %s ago and Autopilot hasn't picked it up.", p.Name, ago(c.S.Now.Sub(p.Created)))
				cause = "Autopilot doesn't run on the controllers, or can't read the plan."
				plainHappened = plainWhat + " hasn't started."
				stuck = true
				break
			}
			for _, t := range targetsIn(p, snapshot.SignalSent) {
				if !t.Updated.IsZero() && c.S.Now.Sub(t.Updated) >= stuckAfter {
					nodes = append(nodes, t)
				}
			}
			if len(nodes) == 0 {
				continue
			}
			since = nodes[0].Updated
			for _, t := range nodes {
				if t.Updated.Before(since) {
					since = t.Updated
				}
			}
			on := strings.Join(targetNames(nodes), ", ")
			took := ago(c.S.Now.Sub(since))
			title = fmt.Sprintf("%s stuck on %s for %s", what, on, took)
			summary = fmt.Sprintf("Autopilot's plan %s told %s to update %s ago, and it hasn't finished. The nodes after it wait.", p.Name, on, took)
			cause = "k0s on that node is downloading the new version, can't restart with it, or the node is down."
			plainHappened = fmt.Sprintf("%s has been waiting on %s for %s.", plainWhat, on, agoPlain(c.S.Now.Sub(since)))
			stuck = true
		default:
			continue
		}

		f := c.newFinding(findings.High, findings.ObjectRef{Kind: "Plan", Name: p.Name})
		f.System = true
		f.Impact.ClusterWide = true
		if !since.IsZero() {
			s := since
			f.Since = &s
		}
		f.Links.Nodes = targetNames(nodes)
		f.AddFact("Plan", p.Name+" ("+snapshot.PlanStateText(p.State)+")")
		if v := p.Version(); v != "" {
			f.AddFact("Updates to", v)
		}
		if !p.Created.IsZero() {
			f.AddFact("Made", p.Created.UTC().Format("2006-01-02 15:04 UTC"))
		}
		f.AddFact("Nodes", planProgress(p))
		if d := planDescription(p); d != "" && p.State != snapshot.PlanWarning {
			f.AddFact("Autopilot says", d)
		}
		// Each node keeps its own part of the update, with the reason.
		var failedURL string
		for _, t := range nodes {
			sig, ok := c.S.UpdateSignalOf(t)
			if !ok || sig.Status == "" {
				continue
			}
			f.AddFact(t.Name, snapshot.SignalStatusText(sig.Status))
			if sig.Status == "FailedDownload" && failedURL == "" {
				failedURL = sig.URL
				if failedURL != "" {
					cause = fmt.Sprintf("%s couldn't download the new k0s from %s. Every node must reach that address.", t.Name, failedURL)
				} else {
					cause = t.Name + " couldn't download the new k0s. Every node must reach the plan's download address."
				}
			}
		}
		f.Title, f.Summary, f.Remedy.LikelyCause = title, summary, cause
		f.AddStep(findings.Step{Text: "See the plan's state on every node", Plain: "See how far the update got",
			Command: "kubectl get plans.autopilot.k0sproject.io " + p.Name + " -o yaml"})
		if len(nodes) > 0 {
			unit := "k0sworker"
			if nodes[0].Controller {
				unit = "k0scontroller"
			}
			f.AddStep(findings.Step{Text: "Read k0s's log on " + nodes[0].Name, Plain: "On that server, read what the update did",
				Command: "sudo journalctl -u " + unit + " -n 200 --no-pager | grep -iE 'autopilot|update|error'", Host: nodes[0].Name})
			if failedURL != "" {
				f.AddStep(findings.Step{Text: "Check that the node reaches the download", Plain: "Check that the server can reach the update's download",
					Command: "curl -sSI --max-time 10 '" + failedURL + "' | head -n 1", Host: nodes[0].Name})
			}
		}
		productUpdateStep(f)
		plainTitle := "An update of the cluster software didn't finish"
		if stuck {
			plainTitle = "An update of the cluster software is stuck"
		}
		f.Plain = findings.PlainText{
			Title:        plainTitle,
			WhatHappened: plainHappened,
			Why:          "Until it finishes, the servers may run different versions, and the next product update may not start.",
			WhatToDo:     "Send the report to your support team.",
		}
		out = append(out, f)
	}
	return out
}

// planDescription is what Autopilot wrote about the plan's commands.
func planDescription(p *snapshot.Plan) string {
	var ds []string
	for _, c := range p.Commands {
		if c.Description != "" {
			ds = append(ds, c.Description)
		}
	}
	return strings.Join(ds, "; ")
}

// planProgress counts the plan's nodes by state: "2 updated, 1 failed".
func planProgress(p *snapshot.Plan) string {
	counts := map[string]int{}
	var order []string
	for _, t := range p.Targets() {
		s := snapshot.TargetStateText(t.State)
		if counts[s] == 0 {
			order = append(order, s)
		}
		counts[s]++
	}
	if len(order) == 0 {
		return "none yet"
	}
	var parts []string
	for _, s := range order {
		parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
	}
	return strings.Join(parts, ", ")
}
