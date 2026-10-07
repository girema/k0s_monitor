package rules

import (
	"fmt"
	"net"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/remedy"
	"k0s_monitor/internal/snapshot"
)

// crashLogOf returns the crash log that explains a group of crashing
// containers best: the worst one's when it names a known error, else the
// first that does, else the worst one's.
func crashLogOf(s *snapshot.Snapshot, g *workloadGroup, h containerHit) *snapshot.CrashLog {
	worst := s.CrashLog(h.pod.Namespace, h.pod.Name, h.status.Name)
	if worst != nil && len(worst.Matches) > 0 {
		return worst
	}
	for _, o := range g.hits {
		if cl := s.CrashLog(o.pod.Namespace, o.pod.Name, o.status.Name); cl != nil && len(cl.Matches) > 0 {
			return cl
		}
	}
	return worst
}

// dependencyErrors are the errors that mean a service the app depends on
// doesn't answer.
var dependencyErrors = map[string]bool{
	"conn-refused": true, "timeout": true, "no-route": true, "conn-reset": true,
}

// explainCrash adds what the log of the last crash says to a crash-loop
// finding: the known error, its likely cause and what to check, and the
// service it points at for correlation.
func explainCrash(c *Context, f *findings.Finding, cl *snapshot.CrashLog, w snapshot.Workload) {
	if cl == nil {
		return
	}
	if cl.Error != "" {
		f.AddFact("Crash log", cl.Error)
		return
	}
	if len(cl.Matches) == 0 {
		if n := len(cl.Lines); n > 0 {
			f.AddFact("Log says", cl.Lines[n-1])
		}
		return
	}
	m := cl.Matches[0]
	f.Title += ": " + m.Title()
	f.Summary += " Its log says: " + m.Title() + "."
	line := m.Line
	if m.Count > 1 {
		line += fmt.Sprintf(" (%d such lines)", m.Count)
	}
	f.AddFact("Log says", line)
	if len(cl.Matches) > 1 {
		var also []string
		for _, o := range cl.Matches[1:] {
			also = append(also, o.Title())
		}
		f.AddFact("Also in the log", strings.Join(also, "; "))
	}
	f.Remedy.LikelyCause = m.Cause()
	// Basic mode shows this step's technical text: the plain one is what to
	// do already.
	step := findings.Step{Text: m.Hint()}

	ns := cl.Namespace
	switch {
	case m.ID == "dns":
		f.Links.Cause = "dns"
		if host := m.Var("host"); host != "" {
			step.Command = fmt.Sprintf("kubectl -n %s get services", serviceNamespace(host, ns))
		}
	case dependencyErrors[m.ID]:
		target := m.Var("target")
		if svc := serviceOf(c.S, ns, target); svc != nil {
			ref := findings.ObjectRef{Kind: "Service", Namespace: svc.Namespace, Name: svc.Name}
			f.Links.Cause = "dependency"
			f.Links.Services = append(f.Links.Services, ref)
			for _, dw := range c.S.SelectWorkloads(svc.Namespace, svc.Spec.Selector) {
				if dw != w {
					f.Links.DependsOn = append(f.Links.DependsOn, workloadRef(dw))
				}
			}
			f.AddFact("Depends on", fmt.Sprintf("Service %s/%s", svc.Namespace, svc.Name))
			step.Command = fmt.Sprintf("kubectl -n %s get endpointslices -l kubernetes.io/service-name=%s", svc.Namespace, svc.Name)
		}
	}
	f.Remedy.Steps = append([]findings.Step{step}, f.Remedy.Steps...)

	f.Plain.Why = m.Plain()
	if !isK0sManaged(w) {
		f.Plain.WhatToDo = m.PlainHint()
	}
}

// serviceNamespace is the namespace a host name like "name.namespace" or
// "name.namespace.svc.cluster.local" points into.
func serviceNamespace(host, ns string) string {
	parts := strings.Split(host, ".")
	if len(parts) >= 2 && parts[1] != "svc" && parts[1] != "" {
		return parts[1]
	}
	return ns
}

// serviceOf finds the Service a connection target ("host:port", a host
// name or a ClusterIP) from a pod in namespace ns reaches, or nil.
func serviceOf(s *snapshot.Snapshot, ns, target string) *corev1.Service {
	if target == "" {
		return nil
	}
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, svc := range s.Services {
			for _, cip := range append([]string{svc.Spec.ClusterIP}, svc.Spec.ClusterIPs...) {
				if cip == host {
					return svc
				}
			}
		}
		return nil
	}
	parts := strings.Split(strings.TrimSuffix(host, "."), ".")
	// name.namespace[.svc.cluster.local], then name, then a pod of a
	// headless Service: pod.name.
	candidates := [][2]string{}
	if len(parts) >= 2 {
		candidates = append(candidates, [2]string{parts[1], parts[0]})
	}
	candidates = append(candidates, [2]string{ns, parts[0]})
	if len(parts) >= 2 {
		candidates = append(candidates, [2]string{ns, parts[1]})
	}
	for _, cand := range candidates {
		if svc := s.Service(cand[0], cand[1]); svc != nil {
			return svc
		}
	}
	return nil
}

// exitText is how a crash's exit code reads in Full mode.
func exitText(code int32, reason string) string {
	return remedy.ExitCode(code, reason).Technical
}
