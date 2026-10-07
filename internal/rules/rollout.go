package rules

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/remedy"
	"k0s_monitor/internal/snapshot"
)

// rolloutWindow is how recent an update must be for a problem to be put
// down to it.
const rolloutWindow = 24 * time.Hour

// afterRollout are the rules whose failing pods an update can explain.
var afterRollout = map[string]bool{
	"pod.crashloop": true, "pod.oomkilled": true, "pod.image-pull": true, "pod.config-error": true,
	"pod.run-error": true, "pod.not-ready": true, "pod.probe-kills": true, "pod.unschedulable": true,
	"pod.stuck-creating": true,
}

// recentRollout returns the update of a Deployment that every failing pod
// comes from, when it happened within rolloutWindow and an earlier revision
// exists to compare with and go back to.
func recentRollout(s *snapshot.Snapshot, w snapshot.Workload, pods []*corev1.Pod) *findings.Rollout {
	if w.Kind != "Deployment" || len(pods) == 0 || isK0sManaged(w) {
		return nil
	}
	revs := s.Revisions(w.Namespace, w.Name)
	if len(revs) < 2 {
		return nil
	}
	cur, prev := revs[0], revs[1]
	at := cur.ReplicaSet.CreationTimestamp.Time
	if at.IsZero() || s.Now.Sub(at) > rolloutWindow {
		return nil
	}
	for _, p := range pods {
		if snapshot.ReplicaSetOf(p) != cur.ReplicaSet.Name {
			return nil
		}
	}
	return &findings.Rollout{
		Workload: workloadRef(w), Revision: cur.Number, Previous: prev.Number, At: at,
		Changes: remedy.TemplateChanges(&prev.ReplicaSet.Spec.Template, &cur.ReplicaSet.Spec.Template),
	}
}

// explainRollouts adds what changed to the findings about failing pods
// that all come from a recent update of their Deployment, and how to undo
// it.
func explainRollouts(c *Context, fs []*findings.Finding) {
	for _, f := range fs {
		if !afterRollout[f.RuleID] || len(f.Links.Workloads) == 0 {
			continue
		}
		wr := f.Links.Workloads[0]
		w := snapshot.Workload{Kind: wr.Kind, Namespace: wr.Namespace, Name: wr.Name}
		var pods []*corev1.Pod
		for _, a := range f.Affected {
			if a.Kind != "Pod" {
				continue
			}
			for _, p := range c.S.PodsOf(w) {
				if p.Name == a.Name {
					pods = append(pods, p)
				}
			}
		}
		r := recentRollout(c.S, w, pods)
		if r == nil {
			continue
		}
		f.Rollout = r
		when := ago(c.S.Now.Sub(r.At))
		changed := changeSummary(r.Changes, 3)
		f.AddFact("Started with", fmt.Sprintf("the update to revision %d, %s ago", r.Revision, when))

		cause := fmt.Sprintf("Every failing pod comes from the update %s ago (revision %d), which changed: %s.", when, r.Revision, changed)
		if f.Remedy.LikelyCause != "" {
			cause = f.Remedy.LikelyCause + " " + cause
		}
		f.Remedy.LikelyCause = cause
		text := fmt.Sprintf("Undo the update: go back to revision %d", r.Previous)
		plain := "Undo the update: this brings back the version that worked. It is safe: the update can be made again once it is corrected."
		if m := c.S.Deployment(w.Namespace, w.Name); m != nil && managedByTool(m.Labels, m.Annotations) {
			text += ". A tool like Helm or Argo CD installs it: roll back there, or it puts the update back"
			plain = "Undo the update in the tool that installs the app (such as Helm or Argo CD): undoing it here only lasts until that tool puts the update back."
		}
		f.Remedy.Steps = append([]findings.Step{{
			Text:    text,
			Plain:   plain,
			Command: fmt.Sprintf("kubectl -n %s rollout undo deploy/%s --to-revision=%d", w.Namespace, w.Name, r.Previous),
		}}, f.Remedy.Steps...)

		f.Plain.Why = strings.TrimSpace(f.Plain.Why + " " + fmt.Sprintf("It started when the %s was updated %s ago.", w.PlainNoun(), agoPlain(c.S.Now.Sub(r.At))))
		f.Plain.WhatToDo = "Undo that update first (step 1): it usually fixes this, and it can be redone later. " + f.Plain.WhatToDo
	}
}

// changeSummary lists the first n changes, and how many more there are.
func changeSummary(cs []remedy.Change, n int) string {
	if len(cs) == 0 {
		return "nothing in its pods that k0s-monitor compares (images, commands, environment, resources, probes, volumes)"
	}
	var parts []string
	for i, c := range cs {
		if i == n {
			parts = append(parts, fmt.Sprintf("and %d more", len(cs)-n))
			break
		}
		parts = append(parts, c.String())
	}
	return strings.Join(parts, "; ")
}

// managedByTool reports whether a deployment tool installs the object, so a
// manual rollback would be undone.
func managedByTool(labels, annotations map[string]string) bool {
	if labels["app.kubernetes.io/managed-by"] != "" && labels["app.kubernetes.io/managed-by"] != "kubectl" {
		return true
	}
	for k := range annotations {
		if strings.HasPrefix(k, "meta.helm.sh/") || strings.HasPrefix(k, "argocd.argoproj.io/") || strings.HasPrefix(k, "kustomize.toolkit.fluxcd.io/") {
			return true
		}
	}
	for k := range labels {
		if strings.HasPrefix(k, "argocd.argoproj.io/") || strings.HasPrefix(k, "kustomize.toolkit.fluxcd.io/") || strings.HasPrefix(k, "helm.toolkit.fluxcd.io/") {
			return true
		}
	}
	return false
}
