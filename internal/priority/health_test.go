package priority

import (
	"testing"

	"k0s_monitor/internal/findings"
)

// An overview of 62/100, Degraded, from these category scores.
func TestHealthMatchesMockup(t *testing.T) {
	var fs []*findings.Finding
	add := func(c findings.Category, p findings.Priority, n int, symptom bool) {
		for i := 0; i < n; i++ {
			f := &findings.Finding{Category: c, Priority: p}
			if symptom {
				f.ParentID = "root"
			}
			fs = append(fs, f)
		}
	}
	add(findings.Nodes, findings.P1, 1, false)
	add(findings.Nodes, findings.P2, 1, false)
	add(findings.Nodes, findings.P1, 4, true)         // 100-30-12-8 = 50
	add(findings.Workloads, findings.P1, 2, false)    //
	add(findings.Workloads, findings.P3, 1, false)    //
	add(findings.Workloads, findings.P4, 1, false)    //
	add(findings.Workloads, findings.P2, 3, true)     // 100-60-4-1-6 = 29
	add(findings.Storage, findings.P1, 1, false)      // 70
	add(findings.Network, findings.P2, 4, true)       // 92
	add(findings.ControlPlane, findings.P3, 1, false) // 96
	add(findings.Fleet, findings.P1, 1, false)        // not scored
	resolved := &findings.Finding{Category: findings.Storage, Priority: findings.P1, State: findings.StateResolved}
	fs = append(fs, resolved)

	h := HealthOf(fs)
	want := map[findings.Category]int{findings.Nodes: 50, findings.Workloads: 29, findings.Storage: 70, findings.Network: 92, findings.ControlPlane: 96}
	for _, c := range h.Categories {
		if c.Score != want[c.Category] {
			t.Errorf("%s = %d, want %d", c.Category, c.Score, want[c.Category])
		}
	}
	if h.Score != 62 || h.Label != "Degraded" {
		t.Errorf("overall = %d %s, want 62 Degraded", h.Score, h.Label)
	}
	if h.Categories[1].Label != "Critical" || h.Categories[0].Roots[findings.P1] != 1 || h.Categories[0].Symptoms != 4 {
		t.Errorf("categories = %+v", h.Categories)
	}
}

func TestHealthFloorsAtZero(t *testing.T) {
	var fs []*findings.Finding
	for i := 0; i < 5; i++ {
		fs = append(fs, &findings.Finding{Category: findings.Nodes, Priority: findings.P1})
	}
	h := HealthOf(fs)
	if h.Categories[0].Score != 0 || h.Score != 75 || h.Label != "Warning" {
		t.Errorf("got %+v", h)
	}
	if HealthOf(nil).Score != 100 {
		t.Error("an empty cluster is fully healthy")
	}
}

// One P1 costs too few points to leave 90, but something to fix now is
// never "Healthy".
func TestHealthWithAP1IsNotHealthy(t *testing.T) {
	h := HealthOf([]*findings.Finding{{Category: findings.Storage, Priority: findings.P1}})
	if h.Score != 94 || h.Label != "Warning" {
		t.Errorf("one P1: %d %s, want 94 Warning", h.Score, h.Label)
	}
	h = HealthOf([]*findings.Finding{{Category: findings.Storage, Priority: findings.P2}, {Category: findings.Storage, Priority: findings.P1, State: findings.StateResolved}})
	if h.Label != "Healthy" {
		t.Errorf("a P2 and a resolved P1: %d %s, want Healthy", h.Score, h.Label)
	}
}
