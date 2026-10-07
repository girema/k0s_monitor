package cluster

import (
	"fmt"

	"k0s_monitor/internal/findings"
)

// UnreachableRuleID is the fleet-level rule F01.
const UnreachableRuleID = "cluster.unreachable"

// Unreachable builds the F01 finding for a cluster that could not be reached.
func Unreachable(name string, ce *ConnError) *findings.Finding {
	res := findings.ObjectRef{Kind: "Cluster", Name: name}
	f := findings.New(name, UnreachableRuleID, findings.Fleet, findings.Critical, res)
	f.System = true
	f.Impact.ClusterWide = true
	f.Title = ce.Plain
	f.Summary = ce.Plain
	if ce.Hint != "" {
		f.Summary += " " + ce.Hint
	}
	f.AddFact("Server", ce.Server)
	f.AddFact("Problem", string(ce.Kind))
	f.AddFact("Details", ce.Detail())
	f.Remedy.LikelyCause = ce.Hint
	if ce.Server != "" && ce.Kind != KindConfig {
		f.AddStep(findings.Step{
			Text:    "Test the API server from this machine (any HTTP answer, even 401, means it is reachable)",
			Command: fmt.Sprintf("curl -sk --max-time 10 %s/livez; echo", ce.Server),
			Host:    "jump host",
		})
	}
	switch ce.Kind {
	case KindRefused, KindTimeout:
		f.AddStep(findings.Step{
			Text:    "On a controller: check that k0s is running",
			Command: "sudo k0s status\nsudo systemctl status k0scontroller",
			Host:    "controller",
		})
	case KindUnauthorized, KindUnknownCA, KindCertExpired:
		f.AddStep(findings.Step{
			Text:    "On a controller: create a fresh kubeconfig and upload it",
			Command: "sudo k0s kubeconfig admin > cluster.config",
			Host:    "controller",
		})
	}
	f.Plain = findings.PlainText{
		Title:        fmt.Sprintf("The cluster %s can't be reached", name),
		WhatHappened: ce.Plain,
		Why:          plainWhy(ce.Kind),
		WhatToDo:     ce.Hint,
	}
	return f
}

func plainWhy(k ErrorKind) string {
	switch k {
	case KindDNS:
		return "The address in the cluster file can't be found on the network."
	case KindTimeout:
		return "The cluster doesn't answer. It may be switched off, or the network between this machine and the cluster is blocked."
	case KindRefused:
		return "The cluster's machine answers, but the cluster service on it isn't running."
	case KindUnknownCA, KindCertName, KindCertExpired, KindTLS:
		return "The secure connection can't be trusted, so it is not used."
	case KindUnauthorized, KindForbidden:
		return "The cluster doesn't accept the login in the cluster file."
	case KindConfig:
		return "The cluster file is missing or incomplete."
	}
	return ""
}
