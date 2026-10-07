package rules

import (
	"fmt"
	"strings"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// V05: k0s's own service on a host is not running, or keeps restarting,
// as node-exporter's systemd collector reports it. On a worker, the
// kubelet and containerd stop with it, so the node soon stops responding:
// node.not-ready folds under this. On a controller, its API server and
// etcd member stop.

var serviceDownRule = Rule{
	ID: "vm.service-down", Code: "V05", Category: findings.Nodes,
	Needs: []snapshot.Kind{snapshot.KindMetrics},
	Eval:  evalServiceDown,
}

// restartsTooMany is how many restarts in 15 minutes count as restarting
// over and over.
const restartsTooMany = 3

func evalServiceDown(c *Context) []*findings.Finding {
	if c.S.Metrics == nil {
		return nil
	}
	var out []*findings.Finding
	for _, s := range c.S.Metrics.Services {
		restarts := snapshot.Known(s.Restarts15m) && s.Restarts15m >= restartsTooMany
		down := s.State != "active"
		if !down && !restarts {
			continue
		}
		unit := strings.TrimSuffix(s.Unit, ".service")
		controller := unit == "k0scontroller"
		host, ref, plainHost := serviceHost(c.S, s)
		sev := findings.Critical
		if !down || s.State == "activating" {
			sev = findings.High
		}
		f := c.newFinding(sev, ref)
		f.System = true
		f.Links.Cause = unit
		f.Impact.ClusterWide = controller
		if controller {
			// A controller's k0s is the control plane, not a server that
			// runs apps.
			f.Category = findings.ControlPlane
		}
		if s.Node != "" {
			f.Links.Nodes = []string{s.Node}
		}
		f.AddFact("Service", s.Unit)
		f.AddFact("State", s.State)
		if snapshot.Known(s.Restarts15m) {
			f.AddFact("Restarts in 15 min", fmt.Sprintf("%.0f", s.Restarts15m))
		}
		f.AddFact("Reported by", "node-exporter "+s.Instance+" (systemd collector)")

		what := "its kubelet and containerd stop with it: the node stops responding and its pods stop"
		plainWhat := "the apps on it stop"
		if controller {
			what = "its API server and etcd member stop with it, so the cluster has one controller less"
			plainWhat = "the cluster has one control plane server less"
		}
		switch {
		case down && s.State == "activating":
			f.Title = fmt.Sprintf("%s on %s is starting again and again", s.Unit, host)
			f.Summary = fmt.Sprintf("systemd keeps starting %s on %s: k0s exits shortly after it starts. While it isn't running, %s.", s.Unit, host, what)
		case down:
			f.Title = fmt.Sprintf("%s is %s on %s", s.Unit, s.State, host)
			f.Summary = fmt.Sprintf("systemd reports %s on %s as %s: k0s isn't running there. Without it, %s.", s.Unit, host, s.State, what)
		default:
			f.Title = fmt.Sprintf("%s restarted %.0f times in 15 min on %s", s.Unit, s.Restarts15m, host)
			f.Summary = fmt.Sprintf("%s runs on %s, but systemd restarted it %.0f times in the last 15 minutes: k0s keeps exiting. Each time, %s for a moment.", s.Unit, host, s.Restarts15m, what)
		}
		switch s.State {
		case "inactive":
			f.Remedy.LikelyCause = "The service was stopped, or the host restarted and the service isn't enabled to start with it."
		default:
			f.Remedy.LikelyCause = "k0s exits with an error: its configuration, a full disk, its certificates, or a port another program holds. Its log says which."
		}
		f.AddStep(findings.Step{Text: "On the host: see the service's state and why k0s stopped",
			Plain:   "If you can log in to it, read why k0s stopped.",
			Command: fmt.Sprintf("sudo systemctl status %s --no-pager\nsudo journalctl -u %s --since '30 min ago' --no-pager | tail -n 100", unit, unit), Host: host})
		f.AddStep(findings.Step{Text: "Check that its disk is not full", Plain: "Check that its disk is not full.",
			Command: "df -h / /var/lib/k0s", Host: host})
		start := fmt.Sprintf("sudo systemctl enable --now %s\nsudo k0s status", unit)
		f.AddStep(findings.Step{Text: "Once the cause is fixed, start it (and have it start with the host)",
			Plain: "Once the cause is fixed, start k0s again.", Command: start, Host: host})

		f.Plain = findings.PlainText{
			Title:        fmt.Sprintf("k0s has stopped on %s", plainHost),
			WhatHappened: fmt.Sprintf("k0s, the program that runs the cluster on %s, isn't running.", plainHost),
			Why:          fmt.Sprintf("While it is stopped, %s.", plainWhat),
			WhatToDo:     "Whoever can log in to that server should read why k0s stopped, fix it and start k0s again (steps below), or send the report to your support team.",
		}
		if !down {
			f.Plain.Title = fmt.Sprintf("k0s keeps restarting on %s", plainHost)
			f.Plain.WhatHappened = fmt.Sprintf("k0s, the program that runs the cluster on %s, stopped and started again %.0f times in the last 15 minutes.", plainHost, s.Restarts15m)
			f.Plain.Why = fmt.Sprintf("Each time it stops, %s for a moment.", plainWhat)
		}
		out = append(out, f)
	}
	return out
}

// serviceHost names the host of a service: its node, else the controller
// at its address, else the address itself. It returns the name for the
// texts, the object, and the name in Basic mode's words.
func serviceHost(s *snapshot.Snapshot, svc snapshot.ServiceState) (string, findings.ObjectRef, string) {
	if svc.Node != "" {
		return svc.Node, findings.ObjectRef{Kind: "Node", Name: svc.Node}, "server " + svc.Node
	}
	if cp := s.ControlPlane; cp != nil {
		for _, ctl := range cp.Controllers {
			if ctl.Host() == svc.Host() || ctl.Name == svc.Host() {
				return ctl.Label(), findings.ObjectRef{Kind: "Controller", Name: ctl.Label()}, "control plane server " + ctl.Label()
			}
		}
	}
	return svc.Host(), findings.ObjectRef{Kind: "Host", Name: svc.Host()}, "server " + svc.Host()
}
