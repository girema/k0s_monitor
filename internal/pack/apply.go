package pack

import (
	"path"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
)

// appKinds are the kinds an app (a friendly name) can be.
var appKinds = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true, "CronJob": true, "Job": true, "ReplicaSet": true, "Pod": true}

// appRef is an app a problem is about, with its labels when known.
type appRef struct {
	findings.ObjectRef
	labels map[string]string
}

// appsOf lists the apps a problem is about: its own object when that is an
// app, the app of its pod, the apps that use its volume claim or that its
// Service selects, and the apps correlation linked to it.
func appsOf(f *findings.Finding, s *snapshot.Snapshot) []appRef {
	var out []appRef
	seen := map[findings.ObjectRef]bool{}
	add := func(r findings.ObjectRef) {
		if r.IsZero() || seen[r] || !appKinds[r.Kind] {
			return
		}
		seen[r] = true
		a := appRef{ObjectRef: r}
		if s != nil {
			if m := s.WorkloadMeta(snapshot.Workload{Kind: r.Kind, Namespace: r.Namespace, Name: r.Name}); m != nil {
				a.labels = m.Labels
			}
		}
		out = append(out, a)
	}
	pod := func(ns, name string) *corev1.Pod {
		if s == nil {
			return nil
		}
		for _, p := range s.Pods {
			if p.Namespace == ns && p.Name == name {
				return p
			}
		}
		return nil
	}
	addPod := func(r findings.ObjectRef) {
		if p := pod(r.Namespace, r.Name); p != nil {
			w := s.WorkloadOf(p)
			add(findings.ObjectRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name})
		}
	}
	switch r := f.Resource; r.Kind {
	case "Pod":
		addPod(r)
		add(r)
	case "PersistentVolumeClaim":
		if s != nil {
			for _, p := range s.PodsUsingClaim(r.Namespace, r.Name) {
				w := s.WorkloadOf(p)
				add(findings.ObjectRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name})
			}
		}
	case "Service":
		if s != nil {
			if svc := s.Service(r.Namespace, r.Name); svc != nil && len(svc.Spec.Selector) > 0 {
				for _, w := range s.SelectWorkloads(r.Namespace, svc.Spec.Selector) {
					add(findings.ObjectRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name})
				}
			}
		}
	default:
		add(r)
	}
	for _, w := range f.Links.Workloads {
		add(w)
	}
	for _, a := range f.Affected {
		if a.Kind == "Pod" {
			addPod(a)
		}
	}
	return out
}

func (s *Select) matchApp(a appRef) bool {
	return s.matchObject(a.Kind, a.Namespace, a.Name, a.labels)
}

// matchesRule reports whether a guide is for a rule.
func (g *Guide) matchesRule(id string) bool {
	if len(g.Rules) == 0 {
		return true
	}
	for _, r := range g.Rules {
		if ok, _ := path.Match(r, id); ok {
			return true
		}
	}
	return false
}

// matchesProblem reports whether a guide's selector matches a problem: its
// own object, or one of its apps.
func (g *Guide) matchesProblem(f *findings.Finding, apps []appRef) bool {
	if g.Select == nil {
		return true
	}
	if g.Select.matchObject(f.Resource.Kind, f.Resource.Namespace, f.Resource.Name, nil) {
		return true
	}
	for _, a := range apps {
		if g.Select.matchApp(a) {
			return true
		}
	}
	return false
}

// app returns the friendly name of an app, and the pack that gives it.
func app(packs []*Pack, a appRef) (*App, *Pack) {
	for _, p := range packs {
		for i := range p.Apps {
			if p.Apps[i].Select.matchApp(a) {
				return &p.Apps[i], p
			}
		}
	}
	return nil, nil
}

// apply adds what the packs say to the findings: guides first, then the
// apps' friendly names in the Basic mode texts, and links.
func apply(packs []*Pack, fs []*findings.Finding, s *snapshot.Snapshot) {
	if len(packs) == 0 {
		return
	}
	for _, f := range fs {
		apps := appsOf(f, s)
		var steps []findings.Step
		replaced := map[string]bool{}
		for _, p := range packs {
			for i := range p.Guides {
				g := &p.Guides[i]
				if !g.matchesRule(f.RuleID) || !g.matchesProblem(f, apps) {
					continue
				}
				set := func(field string, dst *string, v string) {
					if v != "" && !replaced[field] {
						*dst, replaced[field] = v, true
					}
				}
				set("whatToDo", &f.Plain.WhatToDo, g.WhatToDo)
				set("why", &f.Plain.Why, g.Why)
				set("likelyCause", &f.Remedy.LikelyCause, g.LikelyCause)
				for _, st := range g.Steps {
					cmd := st.Command
					if st.Host == "" {
						cmd = findings.K0sKubectl(cmd)
					}
					steps = append(steps, findings.Step{Text: st.Text, Plain: st.Plain, Command: cmd, Host: st.Host, Pack: p.Name})
				}
				for _, d := range g.Docs {
					addDoc(f, findings.Doc{Title: d.Title, URL: d.URL, Pack: p.Name})
				}
			}
		}
		if len(steps) > 0 {
			f.Remedy.Steps = append(steps, f.Remedy.Steps...)
		}
		for _, a := range apps {
			ap, p := app(packs, a)
			if ap == nil {
				continue
			}
			if f.App == "" {
				f.App = ap.Name
			}
			if a.Kind != "Pod" {
				f.Plain = renamePlain(f.Plain, a.Name, ap.Name)
				for i := range f.Remedy.Steps {
					f.Remedy.Steps[i].Plain = replaceName(f.Remedy.Steps[i].Plain, a.Name, ap.Name)
				}
			}
			if ap.Docs != "" {
				addDoc(f, findings.Doc{Title: "About " + ap.Name, URL: ap.Docs, Pack: p.Name})
			}
		}
	}
}

func addDoc(f *findings.Finding, d findings.Doc) {
	for _, x := range f.Docs {
		if x.URL == d.URL {
			return
		}
	}
	f.Docs = append(f.Docs, d)
}

func renamePlain(t findings.PlainText, old, name string) findings.PlainText {
	t.Title = replaceName(t.Title, old, name)
	t.WhatHappened = replaceName(t.WhatHappened, old, name)
	t.Why = replaceName(t.Why, old, name)
	t.WhatToDo = replaceName(t.WhatToDo, old, name)
	return t
}

// nameChar reports whether a byte can be part of a Kubernetes name, so a
// name inside a longer one (payments-api in payments-api-7c9f8) is left
// alone.
func nameChar(b byte) bool {
	return b == '-' || b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// replaceName replaces the whole-name mentions of old in a text. A dot
// ends a name at the end of a sentence, and continues it otherwise
// (payments-api.shop.svc).
func replaceName(text, old, name string) string {
	if old == "" || old == name || !strings.Contains(text, old) {
		return text
	}
	var b strings.Builder
	last := 0
	for from := 0; ; {
		i := strings.Index(text[from:], old)
		if i < 0 {
			break
		}
		i += from
		end := i + len(old)
		whole := (i == 0 || !nameChar(text[i-1]) && text[i-1] != '.' && text[i-1] != '/') &&
			(end == len(text) || !nameChar(text[end]) && !(text[end] == '.' && end+1 < len(text) && nameChar(text[end+1])))
		if whole {
			b.WriteString(text[last:i])
			b.WriteString(name)
			last = end
		}
		from = end
	}
	b.WriteString(text[last:])
	return b.String()
}
