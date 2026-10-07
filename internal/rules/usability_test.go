package rules_test

import (
	"path/filepath"
	"strings"
	"testing"

	"k0s_monitor/internal/config"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/fleet"
	"k0s_monitor/internal/snapshot"
)

// The clusters of the usability round (test/usability): its tasks rely on
// these problems, and on nothing else being more urgent.

func usabilityScan(t *testing.T, name string) []*findings.Finding {
	t.Helper()
	s, err := snapshot.FromYAMLFile(name, filepath.Join("..", "..", "test", "usability", "clusters", name+".yaml"), now)
	if err != nil {
		t.Fatalf("loading %s: %v", name, err)
	}
	fs, skipped := fleet.EvaluateSnapshot(s, config.DefaultThresholds(), "")
	if len(skipped) > 0 {
		t.Fatalf("%s: unexpected skipped rules: %+v", name, skipped)
	}
	return fs
}

// urgent are the problems Basic mode lists first: P1 and P2, not folded
// under another.
func urgent(fs []*findings.Finding) []string {
	var out []string
	for _, f := range fs {
		if f.ParentID == "" && (f.Priority == findings.P1 || f.Priority == findings.P2) {
			out = append(out, string(f.Priority)+" "+f.RuleID+" "+f.Resource.String())
		}
	}
	return out
}

func TestUsabilityClusters(t *testing.T) {
	t.Run("shop-prod", func(t *testing.T) {
		fs := usabilityScan(t, "shop-prod")
		want := []string{"P1 pvc.fill-forecast shop/persistentvolumeclaim/data-postgres-0", "P2 pod.crashloop shop/deployment/web"}
		if got := urgent(fs); strings.Join(got, "; ") != strings.Join(want, "; ") {
			t.Errorf("urgent problems: got %v, want %v", got, want)
		}
		// T4: will anything run out, and when.
		full := find(t, fs, "pvc.fill-forecast", "shop/persistentvolumeclaim/data-postgres-0")
		if !strings.Contains(full.Plain.Title, "about 4 hours") {
			t.Errorf("forecast: %q", full.Plain.Title)
		}
		// T2, T3: the crash started with an update, and undoing it is the
		// first step.
		crash := find(t, fs, "pod.crashloop", "shop/deployment/web")
		if crash.Rollout == nil || !strings.HasPrefix(crash.Plain.WhatToDo, "Undo that update first") {
			t.Errorf("crash: rollout %v, what to do %q", crash.Rollout, crash.Plain.WhatToDo)
		}
		if len(crash.Remedy.Steps) == 0 || !strings.HasPrefix(crash.Remedy.Steps[0].Plain, "Undo the update") {
			t.Errorf("crash: first step %+v", crash.Remedy.Steps)
		}
	})
	t.Run("shop-staging", func(t *testing.T) {
		fs := usabilityScan(t, "shop-staging")
		// T6: a server stopped, and the app down is folded under it.
		node := find(t, fs, "node.not-ready", "node/worker-3")
		if node.Priority != findings.P1 || node.ParentID != "" {
			t.Errorf("worker-3: %s, parent %q", node.Priority, node.ParentID)
		}
		down := find(t, fs, "deploy.unavailable", "shop/deployment/checkout")
		if down.ParentID != node.ID {
			t.Errorf("checkout is not folded under worker-3: parent %q", down.ParentID)
		}
	})
	t.Run("office", func(t *testing.T) {
		// T1: a cluster with nothing to do.
		for _, f := range usabilityScan(t, "office") {
			t.Errorf("unexpected problem: %s %s %s", f.Priority, f.RuleID, f.Resource.String())
		}
	})
}
